# Uploads And Processing

Upload behavior is split between route handlers, multipart reading, content resolution, scanner integration, persistence, and background processing.

## Upload Flow

1. Route handler checks feature flags, policy, CSRF when applicable, and rate limits.
2. Multipart or URL upload is read to a temporary file.
3. Content type is resolved from sniffed bytes, declared content type, filename extension, then `application/octet-stream`.
4. MIME policy, filename length, blocked hashes, blocked MIME types, and quota are checked.
5. Optional metadata stripping rewrites JPEG or PNG uploads.
6. SHA-256 hash is computed.
7. External scanners run.
8. Blob row and file item row are created.
9. Blob bytes are written if the object does not already exist.
10. Scanner results are recorded.
11. Active uploads return URLs; quarantined or rejected uploads return errors.

## URL Upload

URL upload validates scheme, host, ports, redirects, timeouts, response size, and private IP behavior before reading the response.

## Temporary Files

Uploads stream to `midden-upload-*.part` in `uploads.temp_dir`, and the command scanner writes `midden-scan-*` when it has no path to hand the adapter directly.

Every path that creates one is responsible for removing it: `UploadedFile` drops its temp file, and the URL reader wraps its path in an RAII guard so a mid-stream error cleans up too. Those guards only fire when the process stays alive, so `cleanup_temp_files` in `src/jobs.rs` sweeps anything left by a kill or a panic. Anything added that writes into the temp directory should use one of the two known prefixes so the sweep can recognise it.

## Processing

`src/processing.rs` handles MIME sniffing, metadata JSON, metadata stripping helpers, image dimensions, and thumbnail derivatives.

Background jobs fill missing metadata and thumbnails for existing files when configured:

```toml
[processing]
metadata_extraction = true
thumbnails = true
```

`thumbnail_derivative` is CPU-bound and allocates in proportion to the decoded image, which an uploader controls independently of file size. It takes a `ThumbnailLimits` that caps source dimensions and decoder allocation, and callers must run it under `spawn_blocking`. The same rule applies to paste highlighting in `src/web/pastes.rs`.

## Storage

`src/storage.rs` wraps `object_store` for local and S3-compatible backends. Blob paths are derived from sanitized hex hashes and optional S3 prefixes.

## Tests

Upload-related changes should include focused tests for resolver behavior plus route-level tests when policies, forms, or API behavior changes.
