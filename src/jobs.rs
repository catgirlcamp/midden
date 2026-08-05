use std::{collections::BTreeSet, time::Duration};

use serde::Serialize;

use crate::{
    app::AppState,
    config::{RuntimeSettings, ScanDecision},
    processing,
    scanner::{self, ScanInput},
    util,
};

#[derive(Debug, Default, Serialize)]
pub struct JobSummary {
    pub expired_files: u64,
    pub expired_pastes: u64,
    pub expired_auth_rows: u64,
    pub deleted_blobs: u64,
    pub deleted_temp_files: u64,
    pub scanner_retries: u64,
    pub metadata_updates: u64,
    pub missing_blobs: usize,
    pub orphaned_blobs: usize,
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut last_storage_verify = 0_i64;
        loop {
            let interval = match state.settings().await {
                Ok(settings) => {
                    if settings.jobs.enabled {
                        let now = util::now_ts();
                        let include_storage_verify = now - last_storage_verify
                            >= settings.jobs.storage_verify_interval_seconds as i64;
                        let result = run_pass(&state, &settings, include_storage_verify).await;
                        if result.is_ok() && include_storage_verify {
                            last_storage_verify = now;
                        }
                        if let Err(err) = result {
                            tracing::warn!(error = %err, "background job pass failed");
                        }
                    }
                    settings.jobs.interval_seconds.max(30)
                }
                Err(err) => {
                    tracing::warn!(error = %err, "background jobs could not load settings");
                    300
                }
            };
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    });
}

pub async fn run_once(state: &AppState, settings: &RuntimeSettings) -> anyhow::Result<JobSummary> {
    run_pass(state, settings, true).await
}

async fn run_pass(
    state: &AppState,
    settings: &RuntimeSettings,
    include_storage_verify: bool,
) -> anyhow::Result<JobSummary> {
    let mut summary = cleanup_expired(state).await?;
    let retry_count = retry_scanners(state, settings).await?;
    let metadata_updates = process_file_metadata(state, settings).await?;
    let storage = if include_storage_verify {
        verify_storage(state).await?
    } else {
        (0, 0)
    };
    summary.scanner_retries = retry_count;
    summary.metadata_updates = metadata_updates;
    summary.missing_blobs = storage.0;
    summary.orphaned_blobs = storage.1;
    Ok(summary)
}

pub async fn cleanup_expired(state: &AppState) -> anyhow::Result<JobSummary> {
    // Keep zero-ref selection and object deletion atomic with respect to in-process uploads.
    let _upload_guard = state.upload_quota_lock.lock().await;
    let mut summary = JobSummary::default();
    let expired_files = state.db.expired_files().await?;
    for file in expired_files {
        state.db.expire_file_and_release_blob(&file.id).await?;
        summary.expired_files += 1;
    }
    summary.deleted_blobs =
        crate::commands::cleanup_zero_ref_blobs(&state.db, &state.storage).await?;

    summary.expired_pastes = state.db.expire_due_pastes().await?;

    summary.expired_auth_rows = state.db.cleanup_expired_auth_state().await?;
    Ok(summary)
}

async fn retry_scanners(state: &AppState, settings: &RuntimeSettings) -> anyhow::Result<u64> {
    if !settings.scanning.enabled || settings.scanning.adapters.is_empty() {
        return Ok(0);
    }

    let candidates = state
        .db
        .scanner_retry_file_candidates(settings.jobs.scanner_retry_limit as i64)
        .await?;
    let mut retried = 0;
    for file in candidates {
        let bytes = state.storage.get_blob(&file.blob_hash).await?;
        let scan = scanner::scan_upload(
            &settings.scanning,
            ScanInput {
                bytes: Some(&bytes),
                path: None,
                size_bytes: file.size_bytes,
                filename: file.original_filename.as_deref(),
                content_type: file.content_type.as_deref(),
                hash: &file.blob_hash,
                public_id: &file.public_id,
                temp_dir: settings.uploads.temp_dir.as_deref(),
            },
        )
        .await;
        for report in &scan.reports {
            state
                .db
                .record_scan_result(
                    "file",
                    &file.public_id,
                    &report.adapter,
                    &format!("{:?}", report.decision).to_lowercase(),
                    &report.detail,
                )
                .await?;
        }
        let next_state = match scan.decision {
            ScanDecision::Allow => "active",
            ScanDecision::Quarantine | ScanDecision::Reject => "quarantined",
        };
        if file.state != next_state {
            state
                .db
                .update_file_state_by_public_id(
                    &file.public_id,
                    next_state,
                    None,
                    "background scanner retry",
                )
                .await?;
        }
        retried += 1;
    }
    Ok(retried)
}

async fn process_file_metadata(
    state: &AppState,
    settings: &RuntimeSettings,
) -> anyhow::Result<u64> {
    if !settings.processing.metadata_extraction && !settings.processing.thumbnails {
        return Ok(0);
    }
    let files = state
        .db
        .files_needing_processing(
            settings.processing.metadata_extraction,
            settings.processing.thumbnails,
            settings.jobs.metadata_limit as i64,
        )
        .await?;
    let mut updated = 0;
    for file in files {
        let content_type = file
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        let mut metadata_json = file.metadata_json.clone();
        let mut thumbnail_hash = file.thumbnail_hash.clone();
        let mut bytes_cache = None;
        let mut update_committed_with_thumbnail = false;

        if settings.processing.metadata_extraction && metadata_json.is_none() {
            let bytes = state.storage.get_blob(&file.blob_hash).await?;
            let dimensions = file
                .image_width
                .zip(file.image_height)
                .or_else(|| util::image_dimensions(&bytes));
            metadata_json = Some(processing::file_metadata_json(
                content_type,
                file.size_bytes,
                dimensions,
                false,
            )?);
            bytes_cache = Some(bytes);
        }

        if settings.processing.thumbnails && thumbnail_hash.is_none() {
            let bytes = match bytes_cache.take() {
                Some(bytes) => bytes,
                None => state.storage.get_blob(&file.blob_hash).await?,
            };
            // Decoding is CPU-bound and sized by the image's declared dimensions, not the file, so
            // it must not run on a runtime worker.
            let limits = processing::ThumbnailLimits::from_config(&settings.processing);
            let content_type = content_type.to_string();
            let source = bytes.clone();
            let derived = tokio::task::spawn_blocking(move || {
                processing::thumbnail_derivative(&content_type, &source, limits)
            })
            .await?;
            if let Some(thumbnail) = derived {
                let hash = util::sha256_hex_bytes(&thumbnail);
                let mut blob_mutation = state.db.begin_blob_mutation(&hash).await?;
                blob_mutation
                    .create_blob_if_missing(thumbnail.len() as i64, Some("image/png"))
                    .await?;
                if !state.storage.exists(&hash).await? {
                    state.storage.put_blob(&hash, thumbnail).await?;
                }
                let attached = blob_mutation
                    .attach_thumbnail(&file.public_id, metadata_json.as_deref())
                    .await?;
                blob_mutation.commit().await?;
                if attached {
                    thumbnail_hash = Some(hash);
                    update_committed_with_thumbnail = true;
                    updated += 1;
                } else {
                    let current = state.db.file_by_public_id(&file.public_id).await?;
                    thumbnail_hash = current.thumbnail_hash;
                    if current.metadata_json.is_some() {
                        metadata_json = current.metadata_json;
                    }
                }
            }
        }

        if !update_committed_with_thumbnail
            && (metadata_json != file.metadata_json || thumbnail_hash != file.thumbnail_hash)
        {
            state
                .db
                .update_file_metadata(&file.public_id, metadata_json.as_deref())
                .await?;
            updated += 1;
        }
    }
    Ok(updated)
}

async fn verify_storage(state: &AppState) -> anyhow::Result<(usize, usize)> {
    let db_hashes = state
        .db
        .blob_hashes()
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let backend_hashes = state
        .storage
        .list_hashes()
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let missing = db_hashes.difference(&backend_hashes).count();
    let orphaned = backend_hashes.difference(&db_hashes).count();
    if missing > 0 || orphaned > 0 {
        tracing::warn!(
            missing,
            orphaned,
            "background storage verification found drift"
        );
    }
    Ok((missing, orphaned))
}
