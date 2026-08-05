# Configuration

Midden loads configuration from TOML and environment variables.

## Source Order

The effective precedence, from lowest to highest, is:

1. Compiled defaults.
2. An explicit `--config PATH`, which must exist, or the optional `midden.toml` when no path is provided.
3. Persisted admin settings for runtime-adjustable sections.
4. Explicit `MIDDEN__` environment fields.

Environment precedence is field-level. For example, `MIDDEN__SECURITY__SECURE_COOKIES=true` locks only `security.secure_cookies` to the environment value. Other fields in the persisted `security` section, such as rate limits and content policy, continue to come from the admin settings row. Removing the environment variable makes the persisted value for that field effective again.

Use this command to inspect the compiled defaults:

```console
midden config print-defaults
```

Use this command before deploys:

```console
midden --config midden.toml config check
```

## Primary Sections

- `[server]`: bind address, public base URL, optional template/static directories, reverse proxy mode and trusted proxy hop count.
- `[database]`: SQL connection URL and pool size.
- `[storage]`: local or S3-compatible blob storage.
- `[features]`: feature switches for files, pastes, accounts, API, reports, URL upload, previews, browse, auth modes, and paste editing.
- `[limits]`: upload sizes, paste sizes, expiry defaults, expiry guardrails, anonymous quota, and role quotas.
- `[branding]`: instance name, tagline, colors, custom CSS, footer links, notices, Open Graph behavior, and takedown text.
- `[policy]`: signup mode and action requirements.
- `[security]`: cookies, content disposition, MIME policy, URL upload restrictions, and rate limits.
- `[delivery]`: cache behavior, file origin, isolated file origin, and signed internal URLs.
- `[smtp]` and `[oidc]`: email and OIDC login.
- `[scanning]`: command, webhook, or ClamAV upload scanners, and the per-adapter timeout.
- `[processing]`: metadata extraction, metadata stripping, thumbnails, and image decode limits.
- `[jobs]`, `[metrics]`, `[tokens]`, `[moderation]`, and `[uploads]`: operational controls, including how long scratch files are kept.

## Resource Guardrails

Several settings exist to bound work an untrusted caller can trigger. The defaults are safe; loosen them only deliberately.

| Setting | Default | Bounds |
| --- | --- | --- |
| `scanning.timeout_seconds` | `30` | How long one scanner adapter may hold an upload request |
| `processing.thumbnail_source_max_pixels` | `16384` | Largest source image side that will be decoded for a thumbnail |
| `processing.thumbnail_source_max_alloc_bytes` | `268435456` | Memory the image decoder may allocate |
| `uploads.temp_file_max_age_seconds` | `86400` | How long an untouched scratch file survives before the cleanup job removes it |
| `server.trusted_proxy_hops` | `1` | Which `X-Forwarded-For` hop is believed when `behind_proxy` is set |

The two thumbnail limits matter because a small upload can declare enormous dimensions; the decoded bitmap, not the file, drives memory use. A source beyond either limit simply gets no thumbnail.

## Runtime Settings

The admin settings UI persists selected sections to the `settings` table as JSON. When a request runs, Midden merges those persisted settings over the startup configuration, then reapplies only the exact runtime fields controlled by `MIDDEN__` variables. File-only sections such as database and storage still come from startup configuration.

This means changing a TOML value does not automatically override a value already saved in the admin UI. Use the admin UI as the current source for runtime-adjustable settings unless an exact field is explicitly controlled by the environment.
