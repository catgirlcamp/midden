# Architecture

Midden is a single Rust binary with focused modules around configuration, state, storage, database access, processing, web routing, jobs, metrics, and mail.

## Entry Point

`src/main.rs` defines the CLI:

- `serve`
- `migrate`
- `config check`
- `config print-defaults`
- `owner create`
- `owner reset-password`
- `storage gc`
- `storage verify`
- `storage export`
- `storage import`
- `jobs run-once`
- `user set-role`

`serve` builds `AppState`, runs migrations, starts background jobs, builds the router, and listens with graceful shutdown.

## App State

`src/app.rs` builds shared state:

- Parsed `AppConfig`.
- `Database`.
- `BlobStorage`.
- Built-in or disk templates.
- `Mailer`.
- Metrics registry.
- Rate limiter.
- Upload quota lock.

Handlers call `state.settings().await` to load runtime settings merged from config and the database.

## Web Layer

`src/web.rs` owns router registration and cross-cutting middleware. Handler modules live under `src/web/`:

- `auth.rs`
- `account.rs`
- `files.rs`
- `pastes.rs`
- `items.rs`
- `browse.rs`
- `admin.rs`
- `api.rs`
- `system.rs`
- `upload.rs`
- `oidc.rs`
- `support.rs`

Keep route registration centralized unless there is a clear reason to split it further. The `/{slug}` file route is a catch-all and must remain after more specific routes.

### Blocking Work

Handlers share a small pool of runtime workers, so anything CPU-bound has to move to `spawn_blocking` before it can stall unrelated requests. This applies to work whose cost an untrusted caller influences:

- Password hashing and verification. `util::hash_password` and `util::verify_password` are async and do this for you; the argon2 calls themselves are private to `src/util.rs` so there is no way to reach them from a handler by accident.
- Thumbnail decoding, sized by an image's declared dimensions rather than its bytes.
- Paste syntax highlighting, sized by paste length.

When adding something similar, prefer making the async wrapper the only reachable API rather than relying on reviewers to notice.

## Persistence

`src/db.rs` and `src/db/` contain schema, models, auth, item, moderation, search, and settings methods. The schema string creates tables for settings, users, sessions, API tokens, auth flows, blobs, files, pastes, revisions, reports, scanner results, audit events, rate-limit buckets, and moderation notes.
