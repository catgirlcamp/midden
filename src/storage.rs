use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use object_store::{
    GetOptions, GetRange, ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, buffered::BufWriter,
    local::LocalFileSystem, path::Path as ObjectPath,
};
use tokio::io::AsyncWriteExt;

use crate::config::{AppConfig, StorageBackend};

#[derive(Clone)]
pub struct BlobStorage {
    store: Arc<dyn ObjectStore>,
    prefix: Option<String>,
}

/// A blob read, carrying the lengths the object store reported alongside the bytes.
///
/// Callers need both to describe the response honestly: `size` is the whole object and `range` is
/// the part this stream covers.
pub struct BlobStream {
    pub size: u64,
    pub range: std::ops::Range<u64>,
    pub stream: BoxStream<'static, object_store::Result<Bytes>>,
}

impl BlobStream {
    fn new(result: object_store::GetResult) -> Self {
        let size = result.meta.size;
        let range = result.range.clone();
        Self {
            size,
            range,
            stream: result.into_stream(),
        }
    }
}

impl BlobStorage {
    const STREAM_UPLOAD_BUFFER_BYTES: usize = 5 * 1024 * 1024;

    pub async fn from_config(config: &AppConfig) -> anyhow::Result<Self> {
        match config.storage.backend {
            StorageBackend::Local => {
                tokio::fs::create_dir_all(&config.storage.local.path).await?;
                let store = LocalFileSystem::new_with_prefix(&config.storage.local.path)?;
                Ok(Self {
                    store: Arc::new(store),
                    prefix: None,
                })
            }
            StorageBackend::S3 => {
                let s3 = &config.storage.s3;
                if s3.bucket.trim().is_empty() {
                    anyhow::bail!("storage.s3.bucket is required when storage.backend = \"s3\"");
                }

                let mut builder = AmazonS3Builder::new()
                    .with_bucket_name(&s3.bucket)
                    .with_allow_http(s3.allow_http)
                    .with_virtual_hosted_style_request(s3.virtual_hosted_style);

                if !s3.region.trim().is_empty() {
                    builder = builder.with_region(&s3.region);
                }
                if let Some(endpoint) = &s3.endpoint {
                    builder = builder.with_endpoint(endpoint);
                }
                if let Some(access_key_id) = &s3.access_key_id {
                    builder = builder.with_access_key_id(access_key_id);
                }
                if let Some(secret_access_key) = &s3.secret_access_key {
                    builder = builder.with_secret_access_key(secret_access_key);
                }

                Ok(Self {
                    store: Arc::new(builder.build()?),
                    prefix: s3.prefix.clone().filter(|prefix| !prefix.is_empty()),
                })
            }
        }
    }

    pub async fn put_blob(&self, hash: &str, bytes: Bytes) -> anyhow::Result<()> {
        let path = self.object_path(hash)?;
        self.store
            .put(&path, object_store::PutPayload::from_bytes(bytes))
            .await?;
        Ok(())
    }

    pub async fn put_blob_from_path(
        &self,
        hash: &str,
        source_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let mut source = tokio::fs::File::open(source_path).await?;
        let mut writer = BufWriter::with_capacity(
            Arc::clone(&self.store),
            self.object_path(hash)?,
            Self::STREAM_UPLOAD_BUFFER_BYTES,
        );
        tokio::io::copy(&mut source, &mut writer).await?;
        writer.shutdown().await?;
        Ok(())
    }

    pub async fn get_blob(&self, hash: &str) -> anyhow::Result<Bytes> {
        Ok(self
            .store
            .get(&self.object_path(hash)?)
            .await?
            .bytes()
            .await?)
    }

    /// Size of a stored blob, as recorded by the object store rather than by our own metadata.
    pub async fn blob_size(&self, hash: &str) -> anyhow::Result<u64> {
        Ok(self.store.head(&self.object_path(hash)?).await?.size)
    }

    pub async fn get_blob_stream(&self, hash: &str) -> anyhow::Result<BlobStream> {
        let path = self.object_path(hash)?;
        Ok(BlobStream::new(self.store.get(&path).await?))
    }

    pub async fn get_blob_range_stream(
        &self,
        hash: &str,
        range: GetRange,
    ) -> anyhow::Result<BlobStream> {
        let path = self.object_path(hash)?;
        let options = GetOptions {
            range: Some(range),
            ..Default::default()
        };
        Ok(BlobStream::new(self.store.get_opts(&path, options).await?))
    }

    pub async fn delete_blob(&self, hash: &str) -> anyhow::Result<()> {
        match self.store.delete(&self.object_path(hash)?).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn exists(&self, hash: &str) -> anyhow::Result<bool> {
        match self.store.head(&self.object_path(hash)?).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn health(&self) -> bool {
        let prefix = self
            .prefix
            .as_ref()
            .map(|prefix| ObjectPath::from(prefix.trim_matches('/').to_string()));
        let mut stream = self.store.list(prefix.as_ref());
        matches!(stream.next().await, None | Some(Ok(_)))
    }

    pub async fn list_hashes(&self) -> anyhow::Result<Vec<String>> {
        let prefix = self
            .prefix
            .as_ref()
            .map(|prefix| ObjectPath::from(prefix.trim_matches('/').to_string()));
        let mut stream = self.store.list(prefix.as_ref());
        let mut hashes = Vec::new();
        while let Some(meta) = stream.next().await {
            let meta = meta?;
            if let Some(hash) = object_hash_from_path(meta.location.as_ref()) {
                hashes.push(hash);
            }
        }
        hashes.sort();
        hashes.dedup();
        Ok(hashes)
    }

    fn object_path(&self, hash: &str) -> anyhow::Result<ObjectPath> {
        let safe_hash = crate::util::canonical_blob_hash(hash)?;
        let first = safe_hash.get(0..2).unwrap_or("xx");
        let second = safe_hash.get(2..4).unwrap_or("xx");
        let path = match &self.prefix {
            Some(prefix) => format!(
                "{}/{}/{}/{}",
                prefix.trim_matches('/'),
                first,
                second,
                safe_hash
            ),
            None => format!("{first}/{second}/{safe_hash}"),
        };
        Ok(ObjectPath::from(path))
    }
}

fn object_hash_from_path(path: &str) -> Option<String> {
    crate::util::canonical_blob_hash(path.rsplit('/').next()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_storage_round_trips_blobs() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.storage.local.path = temp.path().join("blobs");
        let storage = BlobStorage::from_config(&config).await.unwrap();
        let hash = crate::util::sha256_hex(b"hello");
        storage
            .put_blob(&hash, Bytes::from_static(b"hello"))
            .await
            .unwrap();
        assert!(storage.exists(&hash).await.unwrap());
        assert_eq!(
            storage.get_blob(&hash).await.unwrap(),
            Bytes::from_static(b"hello")
        );
        assert_eq!(storage.list_hashes().await.unwrap(), vec![hash]);
        assert!(storage.exists("ab-cd").await.is_err());
    }

    #[test]
    fn extracts_hash_from_backend_path() {
        let hash = "aa".repeat(32);
        assert_eq!(
            object_hash_from_path(&format!("aa/bb/{hash}")).as_deref(),
            Some(hash.as_str())
        );
        assert_eq!(object_hash_from_path("aa/bb/aabbcc"), None);
        assert_eq!(object_hash_from_path("aa/not-a-hash"), None);
    }

    #[tokio::test]
    #[ignore = "requires MIDDEN_TEST_S3_* integration environment"]
    async fn s3_storage_round_trip_when_configured() {
        let required = |name| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} must be set when this ignored test is invoked"))
        };
        let mut config = AppConfig::default();
        config.storage.backend = crate::config::StorageBackend::S3;
        config.storage.s3.bucket = required("MIDDEN_TEST_S3_BUCKET");
        config.storage.s3.region = required("MIDDEN_TEST_S3_REGION");
        config.storage.s3.endpoint = Some(required("MIDDEN_TEST_S3_ENDPOINT"));
        config.storage.s3.access_key_id = Some(required("MIDDEN_TEST_S3_ACCESS_KEY_ID"));
        config.storage.s3.secret_access_key = Some(required("MIDDEN_TEST_S3_SECRET_ACCESS_KEY"));
        config.storage.s3.prefix = Some(format!("midden-test-{}", crate::util::public_id()));
        config.storage.s3.allow_http = true;

        let storage = BlobStorage::from_config(&config).await.unwrap();
        let hash = crate::util::sha256_hex(format!("s3-{}", crate::util::public_id()).as_bytes());
        storage
            .put_blob(&hash, Bytes::from_static(b"s3 smoke"))
            .await
            .unwrap();
        assert!(storage.exists(&hash).await.unwrap());
        assert_eq!(
            storage.get_blob(&hash).await.unwrap(),
            Bytes::from_static(b"s3 smoke")
        );
        assert!(storage.list_hashes().await.unwrap().contains(&hash));
        storage.delete_blob(&hash).await.unwrap();
        assert!(!storage.exists(&hash).await.unwrap());
    }
}
