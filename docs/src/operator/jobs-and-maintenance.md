# Jobs And Maintenance

Midden runs background jobs while serving and exposes a one-shot job command for operators.

## Configuration

```toml
[jobs]
enabled = true
interval_seconds = 300
metadata_limit = 25
scanner_retry_limit = 10
storage_verify_interval_seconds = 3600

[uploads]
temp_file_max_age_seconds = 86400
```

The runtime enforces a minimum sleep interval of 30 seconds.

## Job Work

Each pass can:

- Expire due files and delete unreferenced blobs.
- Expire due pastes.
- Clean expired sessions, password reset tokens, email verification tokens, two-factor challenges, invite tokens, OIDC auth state, and spent rate-limit buckets.
- Reclaim scratch files in the upload temp directory left behind by aborted uploads, timed-out scans, or a hard restart. Only files Midden created are considered, and only once they have gone untouched for `uploads.temp_file_max_age_seconds` (default 24h). Raise that window if you accept uploads slower than it.
- Retry scanner decisions for candidate files.
- Extract file metadata.
- Create thumbnail derivatives.
- Verify database blob references against backend object storage.

## Run Once

```console
midden --config midden.toml jobs run-once
```

The command prints a summary:

```text
jobs complete: expired_files=0, expired_pastes=0, expired_auth_rows=0, deleted_blobs=0, deleted_temp_files=0, scanner_retries=0, metadata_updates=0, missing_blobs=0, orphaned_blobs=0
```

The admin jobs page exposes the same one-shot run for admins.

The in-process background, admin, and one-shot job paths serialize blob cleanup with uploads. By contrast, `storage gc` is a separate maintenance process and must be run with all Midden server and job processes stopped; see [Storage](./storage.md#garbage-collection).

## Storage Drift

When storage verification finds missing or orphaned blobs, Midden logs a warning and includes counts in the job summary. Use `storage verify` for a direct operator check.
