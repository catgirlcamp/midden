use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

#[cfg(test)]
use sqlx::AssertSqlSafe;
use sqlx::{
    Any, AnyPool, ConnectOptions, Row,
    any::{AnyArguments, AnyConnectOptions, AnyPoolOptions},
};

use crate::{
    config::{AppConfig, RuntimeSettings},
    util,
};

macro_rules! select_file_items {
    ($tail:literal) => {
        concat!(
            "SELECT id, public_id, blob_hash, original_filename, extension, content_type,
                    size_bytes, image_width, image_height, owner_user_id, delete_token_hash, expires_at,
                    visibility, metadata_json, thumbnail_hash, state, created_at
             FROM files ",
            $tail
        )
    };
}

macro_rules! select_pastes {
    ($tail:literal) => {
        concat!(
            "SELECT id, public_id, title, content, syntax, owner_user_id, delete_token_hash,
                    expires_at, visibility, state, created_at
             FROM pastes ",
            $tail
        )
    };
}

mod auth;
mod blob_mutations;
mod items;
mod migrations;
mod models;
mod moderation;
mod mutations;
mod schema;
mod search;
mod settings;

pub use models::*;
#[cfg(test)]
use schema::SCHEMA;

#[derive(Debug, Clone)]
pub struct Database {
    pool: AnyPool,
    kind: DatabaseKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseKind {
    Postgres,
    Sqlite,
}

impl Database {
    pub async fn connect(config: &AppConfig) -> anyhow::Result<Self> {
        sqlx::any::install_default_drivers();
        let url = &config.database.url;
        let kind = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            DatabaseKind::Postgres
        } else {
            DatabaseKind::Sqlite
        };
        let options = url
            .parse::<AnyConnectOptions>()?
            .disable_statement_logging();
        let pool = AnyPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect_with(options)
            .await?;
        Ok(Self { pool, kind })
    }

    fn query(&self, sql: &'static str) -> sqlx::query::Query<'static, Any, AnyArguments> {
        sqlx::query(self.rebind_sql(sql))
    }

    fn rebind_sql(&self, sql: &'static str) -> &'static str {
        if self.kind != DatabaseKind::Postgres {
            return sql;
        }

        static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static str>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut cache = cache.lock().expect("SQL rebind cache poisoned");
        if let Some(rebound) = cache.get(sql) {
            return rebound;
        }

        let mut index = 1;
        let mut rebound = String::with_capacity(sql.len() + 8);
        for ch in sql.chars() {
            if ch == '?' {
                rebound.push('$');
                rebound.push_str(&index.to_string());
                index += 1;
            } else {
                rebound.push(ch);
            }
        }
        let rebound = Box::leak(rebound.into_boxed_str());
        cache.insert(sql, rebound);
        rebound
    }

    pub async fn health(&self) -> bool {
        self.query("SELECT 1").execute(&self.pool).await.is_ok()
    }

    pub async fn audit(
        &self,
        actor_user_id: Option<&str>,
        action: &str,
        target: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO audit_events (id, actor_user_id, action, target, detail, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(actor_user_id)
        .bind(action)
        .bind(target)
        .bind(detail)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn check_rate_limit(
        &self,
        action: &str,
        identity: &str,
        config: Option<&crate::config::RateLimitConfig>,
    ) -> anyhow::Result<bool> {
        let Some(config) = config.filter(|config| config.enabled) else {
            return Ok(true);
        };
        if config.requests == 0 || config.window_seconds == 0 {
            return Ok(false);
        }
        let now = util::now_ts();
        let key = format!("{action}:{identity}");
        let reset_before = now.saturating_sub(config.window_seconds as i64);
        let result = self
            .query(
                "INSERT INTO rate_limit_buckets (key, window_start, count)
                 VALUES (?, ?, 1)
                 ON CONFLICT(key) DO UPDATE SET
                   window_start = CASE
                     WHEN rate_limit_buckets.window_start <= ? THEN excluded.window_start
                     ELSE rate_limit_buckets.window_start
                   END,
                   count = CASE
                     WHEN rate_limit_buckets.window_start <= ? THEN 1
                     ELSE rate_limit_buckets.count + 1
                   END
                 WHERE rate_limit_buckets.window_start <= ?
                    OR rate_limit_buckets.count < ?",
            )
            .bind(&key)
            .bind(now)
            .bind(reset_before)
            .bind(reset_before)
            .bind(reset_before)
            .bind(i64::from(config.requests))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        let mut config = AppConfig::default();
        config.database.url = "sqlite::memory:".to_string();
        config.database.max_connections = 1;
        let db = Database::connect(&config).await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    async fn assert_blob_mutation_lock_blocks(
        first: &Database,
        second: &Database,
        first_hash: &str,
        alias_hash: &str,
    ) {
        let first_mutation = first.begin_blob_mutation(first_hash).await.unwrap();
        let waiter_db = second.clone();
        let alias_hash = alias_hash.to_string();
        let mut waiter =
            tokio::spawn(async move { waiter_db.begin_blob_mutation(&alias_hash).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(75), &mut waiter)
                .await
                .is_err(),
            "a storage-path alias acquired a second blob lock"
        );
        first_mutation.commit().await.unwrap();
        let second_mutation = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("waiting blob mutation should resume after commit")
            .expect("blob mutation task should not panic")
            .expect("waiting blob mutation should acquire its lock");
        second_mutation.commit().await.unwrap();
    }

    async fn seed_public_file(db: &Database, public_id: &str, created_at: i64) {
        let hash = format!("{:064x}", public_id.len() * 7 + created_at as usize);
        db.create_blob_if_missing(&hash, 4, Some("text/plain"))
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: public_id,
            public_id,
            blob_hash: &hash,
            original_filename: Some("f.txt"),
            extension: Some("txt"),
            content_type: Some("text/plain"),
            size_bytes: 4,
            image_width: None,
            image_height: None,
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "public",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();
        db.query("UPDATE files SET created_at = ? WHERE public_id = ?")
            .bind(created_at)
            .bind(public_id)
            .execute(&db.pool)
            .await
            .unwrap();
    }

    /// Walks the public file listing the way the browse handler does and returns every id seen.
    async fn page_through_public_files(db: &Database, limit: i64) -> Vec<String> {
        let mut cursor: Option<PageCursor> = None;
        let mut seen = Vec::new();
        loop {
            let page = db.public_files(None, cursor.as_ref(), limit).await.unwrap();
            if page.is_empty() {
                return seen;
            }
            seen.extend(page.iter().map(|file| file.public_id.clone()));
            assert!(seen.len() < 100, "pagination did not terminate: {seen:?}");
            cursor = page.last().map(|file| PageCursor {
                created_at: file.created_at,
                public_id: file.public_id.clone(),
            });
            if (page.len() as i64) < limit {
                return seen;
            }
        }
    }

    #[tokio::test]
    async fn public_paging_returns_items_sharing_a_timestamp_exactly_once() {
        let db = test_db().await;
        for public_id in ["tied-a", "tied-b", "tied-c", "tied-d"] {
            seed_public_file(&db, public_id, 5_000).await;
        }
        seed_public_file(&db, "older", 4_000).await;

        let mut seen = page_through_public_files(&db, 2).await;
        let total = seen.len();
        seen.sort();
        seen.dedup();

        assert_eq!(seen.len(), total, "pagination repeated an item");
        assert_eq!(
            seen,
            vec!["older", "tied-a", "tied-b", "tied-c", "tied-d"],
            "items sharing a created_at must not fall through the cursor"
        );
    }

    #[tokio::test]
    async fn public_paging_is_stable_when_one_listing_is_much_denser() {
        let db = test_db().await;
        for index in 0..6 {
            seed_public_file(&db, &format!("file{index}"), 9_000 + index).await;
        }
        db.create_paste(NewPaste {
            id: "old-paste",
            public_id: "oldpaste",
            title: None,
            content: "old",
            syntax: None,
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "public",
        })
        .await
        .unwrap();
        db.query("UPDATE pastes SET created_at = 1")
            .execute(&db.pool)
            .await
            .unwrap();

        // A sparse paste listing must not drag the file cursor past unseen files.
        let files = page_through_public_files(&db, 3).await;

        assert_eq!(
            files.len(),
            6,
            "every public file must remain reachable through pagination"
        );
    }

    #[test]
    fn page_cursors_round_trip_through_urls() {
        let cursor = PageCursor {
            created_at: 1_700_000_000,
            public_id: "aB3-_xyz".to_string(),
        };
        assert_eq!(cursor.to_string().parse::<PageCursor>().unwrap(), cursor);
        assert!("nonsense".parse::<PageCursor>().is_err());
        assert!("123.".parse::<PageCursor>().is_err());
    }

    #[tokio::test]
    async fn report_filters_reach_past_the_newest_rows() {
        let db = test_db().await;
        // Bury one open report under more resolved reports than the query's row budget.
        db.create_report("file", "buried", None, "spam", "")
            .await
            .unwrap();
        db.query("UPDATE reports SET created_at = 0")
            .execute(&db.pool)
            .await
            .unwrap();
        for index in 0..600 {
            db.create_report("paste", &format!("noise{index}"), None, "other", "")
                .await
                .unwrap();
        }
        db.query("UPDATE reports SET state = 'resolved' WHERE item_public_id != 'buried'")
            .execute(&db.pool)
            .await
            .unwrap();

        let open = db
            .list_reports_filtered(Some("open"), None, None, None)
            .await
            .unwrap();

        assert_eq!(
            open.len(),
            1,
            "filters must be applied by the query, not to an already-truncated page"
        );
        assert_eq!(open[0].item_public_id, "buried");
    }

    #[tokio::test]
    async fn report_filters_combine_state_kind_reason_and_age() {
        let db = test_db().await;
        for (kind, public_id, reason) in [
            ("file", "match", "Spam And Abuse"),
            ("paste", "wrong-kind", "spam"),
            ("file", "wrong-reason", "copyright"),
        ] {
            db.create_report(kind, public_id, None, reason, "")
                .await
                .unwrap();
        }
        db.create_report("file", "too-old", None, "spam", "")
            .await
            .unwrap();
        db.query("UPDATE reports SET created_at = 0 WHERE item_public_id = 'too-old'")
            .execute(&db.pool)
            .await
            .unwrap();

        let reports = db
            .list_reports_filtered(
                Some("open"),
                Some("file"),
                Some("SPAM"),
                Some(util::now_ts() - 60),
            )
            .await
            .unwrap();

        assert_eq!(
            reports
                .iter()
                .map(|report| report.item_public_id.as_str())
                .collect::<Vec<_>>(),
            vec!["match"],
            "reason matching stays case-insensitive and substring-based"
        );
    }

    #[tokio::test]
    async fn migrates_and_reads_runtime_settings() {
        let db = test_db().await;
        let config = AppConfig::default();
        let mut settings = db.runtime_settings(&config).await.unwrap();
        assert!(settings.features.files);
        settings.features.pastes = false;
        db.set_json_setting("features", &settings.features)
            .await
            .unwrap();
        let settings = db.runtime_settings(&config).await.unwrap();
        assert!(!settings.features.pastes);
    }

    #[tokio::test]
    async fn config_runtime_settings_include_operator_controls() {
        let db = test_db().await;
        let config = AppConfig::default();
        let settings = db.runtime_settings(&config).await.unwrap();

        assert_eq!(
            settings.security.rate_limit_backend,
            crate::config::RateLimitBackend::Memory
        );
        assert_eq!(
            settings.metrics.access,
            crate::config::MetricsAccessMode::Admin
        );
        assert!(!settings.metrics.enabled);
        assert!(
            settings
                .limits
                .expiry
                .allowed_presets
                .contains(&"7d".to_string())
        );
        assert!(settings.security.url_upload.request_timeout_seconds > 0);
        assert!(
            settings
                .security
                .content_policy
                .forced_attachment_mime_types
                .contains(&"text/html".to_string())
        );
        assert!(settings.tokens.default_ttl_seconds.is_none());
        assert!(settings.processing.thumbnail_max_dimension > 0);
        assert!(settings.moderation.notify_webhook_url.is_none());

        let mut metrics = settings.metrics.clone();
        metrics.access = crate::config::MetricsAccessMode::Admin;
        db.set_json_setting("metrics", &metrics).await.unwrap();
        let settings = db.runtime_settings(&config).await.unwrap();
        assert_eq!(
            settings.metrics.access,
            crate::config::MetricsAccessMode::Admin
        );
    }

    #[tokio::test]
    async fn owner_upsert_sets_owner_role() {
        let db = test_db().await;
        let user = db
            .upsert_owner("root@example.test", "root", Some("hash"))
            .await
            .unwrap();
        assert_eq!(user.role, Role::Owner);
    }

    #[tokio::test]
    async fn creating_file_item_increments_blob_ref_once() {
        let db = test_db().await;
        db.create_blob_if_missing("abc123", 4, Some("text/plain"))
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: "file-1",
            public_id: "pub123",
            blob_hash: "abc123",
            original_filename: Some("a.txt"),
            extension: Some("txt"),
            content_type: Some("text/plain"),
            size_bytes: 4,
            image_width: None,
            image_height: None,
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();
        assert_eq!(db.blob_ref_count("abc123").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn creating_file_item_without_blob_rolls_back_item_insert() {
        let db = test_db().await;
        let result = db
            .create_file_item(NewFileItem {
                id: "missing-blob-file",
                public_id: "missingblobpub",
                blob_hash: "missingblobhash",
                original_filename: Some("missing.txt"),
                extension: Some("txt"),
                content_type: Some("text/plain"),
                size_bytes: 4,
                image_width: None,
                image_height: None,
                owner_user_id: None,
                delete_token_hash: None,
                expires_at: None,
                visibility: "unlisted",
                metadata_json: None,
                thumbnail_hash: None,
                state: "active",
            })
            .await;
        assert!(result.is_err());
        assert!(db.file_by_public_id("missingblobpub").await.is_err());
    }

    #[tokio::test]
    async fn zero_ref_blobs_are_not_required_inventory() {
        let db = test_db().await;
        db.create_blob_if_missing("releasedhash", 4, Some("text/plain"))
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: "released-file",
            public_id: "releasedpub",
            blob_hash: "releasedhash",
            original_filename: Some("released.txt"),
            extension: Some("txt"),
            content_type: Some("text/plain"),
            size_bytes: 4,
            image_width: None,
            image_height: None,
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();

        let zero_ref_hash = db
            .delete_file_and_release_blob("released-file", None, "test release")
            .await
            .unwrap();
        assert_eq!(zero_ref_hash.as_deref(), Some("releasedhash"));

        assert!(
            !db.blob_hashes()
                .await
                .unwrap()
                .contains(&"releasedhash".to_string())
        );
    }

    #[tokio::test]
    async fn scanner_retry_candidates_use_latest_scan_result() {
        let db = test_db().await;
        db.create_blob_if_missing("scanretryhash", 4, Some("text/plain"))
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: "scan-retry-file",
            public_id: "scanretrypub",
            blob_hash: "scanretryhash",
            original_filename: Some("scan.txt"),
            extension: Some("txt"),
            content_type: Some("text/plain"),
            size_bytes: 4,
            image_width: None,
            image_height: None,
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();
        db.record_scan_result(
            "file",
            "scanretrypub",
            "webhook",
            "allow",
            "webhook returned HTTP 500",
        )
        .await
        .unwrap();
        assert_eq!(db.scanner_retry_file_candidates(10).await.unwrap().len(), 1);

        db.record_scan_result("file", "scanretrypub", "webhook", "allow", "clean")
            .await
            .unwrap();
        assert!(
            db.scanner_retry_file_candidates(10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn thumbnail_candidates_are_limited_to_supported_image_types() {
        let db = test_db().await;
        for (id, public_id, content_type) in [
            ("thumb-text", "thumbtext", "text/plain"),
            ("thumb-png", "thumbpng", "image/png"),
        ] {
            db.create_blob_if_missing(public_id, 4, Some(content_type))
                .await
                .unwrap();
            db.create_file_item(NewFileItem {
                id,
                public_id,
                blob_hash: public_id,
                original_filename: Some("file"),
                extension: None,
                content_type: Some(content_type),
                size_bytes: 4,
                image_width: None,
                image_height: None,
                owner_user_id: None,
                delete_token_hash: None,
                expires_at: None,
                visibility: "unlisted",
                metadata_json: None,
                thumbnail_hash: None,
                state: "active",
            })
            .await
            .unwrap();
        }

        let candidates = db.files_needing_processing(false, true, 10).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].public_id, "thumbpng");
    }

    #[tokio::test]
    async fn additive_migration_preserves_old_user_rows() {
        let mut config = AppConfig::default();
        config.database.url = "sqlite::memory:".to_string();
        config.database.max_connections = 1;
        let db = Database::connect(&config).await.unwrap();
        db.query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
             )",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        db.query(
            "INSERT INTO users (id, email, username, password_hash, role, created_at)
             VALUES ('old-user', 'old@example.test', 'old', 'hash', 'admin', 1234)",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        db.migrate().await.unwrap();

        let user = db.user_by_email("old@example.test").await.unwrap();
        assert_eq!(user.id, "old-user");
        assert_eq!(user.role, Role::Admin);
        assert_eq!(user.email_verified_at, Some(1234));
        assert!(!user.two_factor_enabled);
    }

    #[tokio::test]
    async fn versioned_migrations_are_recorded_and_idempotent() {
        let mut config = AppConfig::default();
        config.database.url = "sqlite::memory:".to_string();
        config.database.max_connections = 1;
        let db = Database::connect(&config).await.unwrap();

        db.migrate().await.unwrap();
        db.migrate().await.unwrap();

        let row = db
            .query("SELECT COUNT(*) AS count FROM schema_migrations")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(row.try_get::<i64, _>("count").unwrap(), 6);
        let rows = db
            .query("SELECT version, name FROM schema_migrations ORDER BY version")
            .fetch_all(&db.pool)
            .await
            .unwrap();
        let ledger = rows
            .iter()
            .map(|row| {
                (
                    row.try_get::<i64, _>("version").unwrap(),
                    row.try_get::<String, _>("name").unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ledger,
            vec![
                (1, "baseline_schema".to_string()),
                (2, "identity_columns_and_email_backfill".to_string()),
                (3, "token_lifecycle_columns".to_string()),
                (4, "item_lifecycle_columns".to_string()),
                (5, "postgres_i64_columns_bigint".to_string()),
                (6, "blob_mutation_locks".to_string()),
            ]
        );
        for &(table, column) in migrations::POSTGRES_I64_COLUMNS
            .iter()
            .filter(|(table, _)| *table != "schema_migrations")
        {
            let declared_type = db
                .query("SELECT type FROM pragma_table_info(?) WHERE name = ?")
                .bind(table)
                .bind(column)
                .fetch_one(&db.pool)
                .await
                .unwrap()
                .try_get::<String, _>("type")
                .unwrap();
            assert_eq!(declared_type, "INTEGER", "{table}.{column}");
        }
    }

    #[tokio::test]
    async fn concurrent_sqlite_migrations_serialize_one_complete_ledger() {
        let filename = format!(".midden-migration-test-{}.db", util::public_id());
        let path = std::env::current_dir().unwrap().join(&filename);
        let mut config = AppConfig::default();
        config.database.url = format!("sqlite://{filename}?mode=rwc");
        config.database.max_connections = 2;
        let first = Database::connect(&config).await.unwrap();
        let second = Database::connect(&config).await.unwrap();

        let (first_result, second_result) = tokio::join!(first.migrate(), second.migrate());
        first_result.unwrap();
        second_result.unwrap();

        let row = first
            .query(
                "SELECT COUNT(*) AS count, COUNT(DISTINCT version) AS distinct_count
                 FROM schema_migrations",
            )
            .fetch_one(&first.pool)
            .await
            .unwrap();
        assert_eq!(row.try_get::<i64, _>("count").unwrap(), 6);
        assert_eq!(row.try_get::<i64, _>("distinct_count").unwrap(), 6);

        first.pool.close().await;
        second.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn sqlite_blob_mutation_lock_serializes_storage_path_aliases() {
        let filename = format!(".midden-blob-lock-test-{}.db", util::public_id());
        let path = std::env::current_dir().unwrap().join(&filename);
        let mut config = AppConfig::default();
        config.database.url = format!("sqlite://{filename}?mode=rwc");
        config.database.max_connections = 2;
        let first = Database::connect(&config).await.unwrap();
        first.migrate().await.unwrap();
        let second = Database::connect(&config).await.unwrap();
        let canonical = "ab".repeat(32);
        let upper = canonical.to_ascii_uppercase();
        let invalid_alias = format!("{}-{}", &upper[..32], &upper[32..]);

        assert_blob_mutation_lock_blocks(&first, &second, &canonical, &upper).await;
        assert!(first.begin_blob_mutation(&invalid_alias).await.is_err());

        let row = first
            .query("SELECT COUNT(*) AS count FROM blob_mutation_locks")
            .fetch_one(&first.pool)
            .await
            .unwrap();
        assert_eq!(row.try_get::<i64, _>("count").unwrap(), 0);
        first.pool.close().await;
        second.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn stale_thumbnail_workers_cannot_overwrite_a_live_reference_or_metadata() {
        let db = test_db().await;
        let primary_hash = "11".repeat(32);
        let first_thumbnail_hash = "22".repeat(32);
        let stale_thumbnail_hash = "33".repeat(32);
        db.create_blob_if_missing(&primary_hash, 4, Some("image/png"))
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: "thumbnail-race-file",
            public_id: "thumbnail-race-public",
            blob_hash: &primary_hash,
            original_filename: None,
            extension: Some("png"),
            content_type: Some("image/png"),
            size_bytes: 4,
            image_width: Some(1),
            image_height: Some(1),
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
            metadata_json: Some("existing metadata"),
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();

        let mut first = db.begin_blob_mutation(&first_thumbnail_hash).await.unwrap();
        first
            .create_blob_if_missing(4, Some("image/png"))
            .await
            .unwrap();
        assert!(
            first
                .attach_thumbnail("thumbnail-race-public", Some("first metadata"))
                .await
                .unwrap()
        );
        first.commit().await.unwrap();

        let mut stale = db.begin_blob_mutation(&stale_thumbnail_hash).await.unwrap();
        stale
            .create_blob_if_missing(4, Some("image/png"))
            .await
            .unwrap();
        assert!(
            !stale
                .attach_thumbnail("thumbnail-race-public", Some("stale metadata"))
                .await
                .unwrap()
        );
        stale.commit().await.unwrap();

        let file = db.file_by_public_id("thumbnail-race-public").await.unwrap();
        assert_eq!(
            file.thumbnail_hash.as_deref(),
            Some(first_thumbnail_hash.as_str())
        );
        assert_eq!(file.metadata_json.as_deref(), Some("existing metadata"));

        let mut live_thumbnail = db.begin_blob_mutation(&first_thumbnail_hash).await.unwrap();
        assert!(!live_thumbnail.is_unreferenced().await.unwrap());
        live_thumbnail.commit().await.unwrap();

        let mut stale_thumbnail = db.begin_blob_mutation(&stale_thumbnail_hash).await.unwrap();
        assert!(stale_thumbnail.is_unreferenced().await.unwrap());
        assert!(stale_thumbnail.delete_if_unreferenced().await.unwrap());
        stale_thumbnail.commit().await.unwrap();
    }

    #[tokio::test]
    async fn migration_ledger_rejects_newer_schema_versions() {
        let db = test_db().await;
        db.query(
            "INSERT INTO schema_migrations (version, name, applied_at)
             VALUES (99, 'future_migration', 1)",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        let error = db.migrate().await.unwrap_err().to_string();

        assert!(error.contains("newer than this binary"), "{error}");
    }

    #[tokio::test]
    async fn migration_ledger_rejects_known_version_name_mismatches() {
        let db = test_db().await;
        db.query("UPDATE schema_migrations SET name = 'wrong_name' WHERE version = 2")
            .execute(&db.pool)
            .await
            .unwrap();

        let error = db.migrate().await.unwrap_err().to_string();

        assert!(error.contains("expected"), "{error}");
        assert!(error.contains("wrong_name"), "{error}");
    }

    #[tokio::test]
    async fn email_verification_backfill_retries_when_column_already_exists() {
        let mut config = AppConfig::default();
        config.database.url = "sqlite::memory:".to_string();
        config.database.max_connections = 1;
        let db = Database::connect(&config).await.unwrap();
        db.query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                role TEXT NOT NULL,
                is_disabled INTEGER NOT NULL DEFAULT 0,
                email_verified_at INTEGER,
                created_at INTEGER NOT NULL
             )",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        db.query(
            "INSERT INTO users (
                id, email, username, password_hash, role, is_disabled,
                email_verified_at, created_at
             ) VALUES ('interrupted', 'interrupted@example.test', 'interrupted', 'hash',
                       'user', 0, NULL, 4321)",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        db.migrate().await.unwrap();

        let user = db.user_by_email("interrupted@example.test").await.unwrap();
        assert_eq!(user.email_verified_at, Some(4321));
    }

    #[tokio::test]
    async fn adopting_complete_unversioned_schema_preserves_ambiguous_unverified_users() {
        let mut config = AppConfig::default();
        config.database.url = "sqlite::memory:".to_string();
        config.database.max_connections = 1;
        let db = Database::connect(&config).await.unwrap();
        for statement in SCHEMA
            .split(';')
            .map(str::trim)
            .filter(|sql| !sql.is_empty())
        {
            sqlx::query(statement).execute(&db.pool).await.unwrap();
        }
        db.query(
            "INSERT INTO users (
                id, email, username, password_hash, role, is_disabled,
                email_verified_at, two_factor_enabled, created_at
             ) VALUES ('current-user', 'current@example.test', 'current', 'hash',
                       'user', 0, NULL, 0, 9876)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        db.migrate().await.unwrap();

        let user = db.user_by_email("current@example.test").await.unwrap();
        assert_eq!(user.email_verified_at, None);
        let row = db
            .query("SELECT COUNT(*) AS count FROM schema_migrations")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(row.try_get::<i64, _>("count").unwrap(), 6);
    }

    #[tokio::test]
    async fn item_state_regressions_cover_moderation_delete_and_expiry() {
        let db = test_db().await;
        db.create_blob_if_missing("statehash", 4, Some("text/plain"))
            .await
            .unwrap();
        let file = db
            .create_file_item(NewFileItem {
                id: "state-file",
                public_id: "statepub",
                blob_hash: "statehash",
                original_filename: Some("state.txt"),
                extension: Some("txt"),
                content_type: Some("text/plain"),
                size_bytes: 4,
                image_width: None,
                image_height: None,
                owner_user_id: None,
                delete_token_hash: Some("delete-hash"),
                expires_at: Some(util::now_ts() - 1),
                visibility: "unlisted",
                metadata_json: None,
                thumbnail_hash: None,
                state: "active",
            })
            .await
            .unwrap();

        assert_eq!(db.expired_files().await.unwrap().len(), 1);
        db.expire_file_and_release_blob(&file.id).await.unwrap();
        assert!(
            db.active_file_by_public_id("statepub")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.file_by_public_id("statepub").await.unwrap().state,
            "expired"
        );
        assert!(
            !db.update_file_state_by_public_id("statepub", "active", None, "regression")
                .await
                .unwrap()
        );
        assert_eq!(
            db.file_by_public_id("statepub").await.unwrap().state,
            "expired"
        );
    }

    #[tokio::test]
    #[ignore = "requires MIDDEN_TEST_POSTGRES_URL"]
    async fn postgres_migration_smoke_when_configured() {
        let database_url = std::env::var("MIDDEN_TEST_POSTGRES_URL")
            .expect("MIDDEN_TEST_POSTGRES_URL must be set when this ignored test is invoked");
        let suffix = util::public_id()
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
            .collect::<String>();
        let schema = format!("midden_migration_{suffix}");
        let mut admin_config = AppConfig::default();
        admin_config.database.url = database_url.clone();
        let admin = Database::connect(&admin_config).await.unwrap();
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin.pool)
            .await
            .unwrap();

        let mut isolated_url = url::Url::parse(&database_url).unwrap();
        isolated_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let mut config = AppConfig::default();
        config.database.url = isolated_url.to_string();
        let db = Database::connect(&config).await.unwrap();
        db.query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                role TEXT NOT NULL,
                is_disabled INTEGER NOT NULL DEFAULT 0,
                email_verified_at INTEGER,
                created_at INTEGER NOT NULL
             )",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        db.query(
            "INSERT INTO users (
                id, email, username, password_hash, role, is_disabled,
                email_verified_at, created_at
             ) VALUES ('legacy-postgres', 'legacy-postgres@example.test', 'legacy-postgres',
                       'hash', 'user', 0, NULL, 2468)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let concurrent = db.clone();
        let (first_migration, second_migration) = tokio::join!(db.migrate(), concurrent.migrate());
        first_migration.unwrap();
        second_migration.unwrap();
        let legacy = db
            .user_by_email("legacy-postgres@example.test")
            .await
            .unwrap();
        assert_eq!(legacy.email_verified_at, Some(2468));
        let row = db
            .query("SELECT COUNT(*) AS count FROM schema_migrations")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(row.try_get::<i64, _>("count").unwrap(), 6);

        let lock_hash = "cd".repeat(32);
        assert_blob_mutation_lock_blocks(&db, &db, &lock_hash, &lock_hash.to_ascii_uppercase())
            .await;
        let zero_ref_hash = "ef".repeat(32);
        let mut zero_ref_mutation = db
            .begin_blob_mutation(&zero_ref_hash.to_ascii_uppercase())
            .await
            .unwrap();
        zero_ref_mutation
            .create_blob_if_missing(1, None)
            .await
            .unwrap();
        assert!(zero_ref_mutation.is_unreferenced().await.unwrap());
        assert!(zero_ref_mutation.delete_if_unreferenced().await.unwrap());
        zero_ref_mutation.commit().await.unwrap();

        for &(table, column) in migrations::POSTGRES_I64_COLUMNS {
            let data_type = db
                .query(
                    "SELECT data_type FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
                )
                .bind(table)
                .bind(column)
                .fetch_one(&db.pool)
                .await
                .unwrap()
                .try_get::<String, _>("data_type")
                .unwrap();
            assert_eq!(data_type, "bigint", "{table}.{column}");
        }

        let beyond_postgres_integer = i64::from(i32::MAX) + 1;
        db.query("UPDATE users SET created_at = ? WHERE id = 'legacy-postgres'")
            .bind(beyond_postgres_integer)
            .execute(&db.pool)
            .await
            .unwrap();
        let legacy = db
            .user_by_email("legacy-postgres@example.test")
            .await
            .unwrap();
        assert_eq!(legacy.created_at, beyond_postgres_integer);

        let email = format!("postgres-smoke-{suffix}@example.test");
        let user = db
            .create_user(
                &email,
                &format!("postgres-smoke-{suffix}"),
                Some("hash"),
                Role::User,
            )
            .await
            .unwrap();
        assert_eq!(user.email, email);
        db.create_blob_if_missing("postgres-large-blob", beyond_postgres_integer, None)
            .await
            .unwrap();
        db.create_file_item(NewFileItem {
            id: "postgres-large-file",
            public_id: &format!("postgres-large-{suffix}"),
            blob_hash: "postgres-large-blob",
            original_filename: None,
            extension: None,
            content_type: None,
            size_bytes: beyond_postgres_integer,
            image_width: None,
            image_height: None,
            owner_user_id: Some(&user.id),
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();
        let usage = db.file_usage_for_user(Some(&user.id)).await.unwrap();
        assert_eq!(usage.storage_bytes, beyond_postgres_integer);
        db.pool.close().await;
        sqlx::query(AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin.pool)
            .await
            .unwrap();
    }
}
