# Troubleshooting

## Configuration Fails To Load

Run:

```console
midden --config midden.toml config check
```

Common causes:

- Explicit `--config` path does not exist.
- Invalid enum values such as an unknown action rule or delete policy.
- `delivery.isolated_file_origin = true` without `delivery.public_file_base_url`.
- `delivery.public_file_base_url` carrying a path rather than a bare scheme and host.
- `delivery.signed_internal_urls = true` without `delivery.internal_url_secret`.
- S3 backend selected without `storage.s3.bucket`.

## Uploads Are Rejected

Check:

- `limits.max_upload_bytes`.
- `security.content_policy.allowed_mime_types`.
- `security.reject_mime_mismatch`.
- `scanning.blocked_hashes`.
- `scanning.blocked_mime_types`.
- Scanner adapter status and `default_on_error`.
- User or anonymous quotas.

## Valid Media Shows As `application/octet-stream`

Midden sniffs common formats, then falls back to declared MIME type, filename extension, and finally `application/octet-stream`. Make sure clients send a useful filename or content type when the bytes cannot be sniffed.

## URL Upload Cannot Fetch A URL

Check:

- `features.upload_by_url`.
- URL scheme is `http` or `https`.
- `security.url_upload.block_private_ips`.
- Allowed or blocked host lists.
- Allowed or blocked port lists.
- Connect and request timeouts.
- `security.url_upload.max_response_bytes`.

## Login Links Are Missing

Check:

- `features.accounts`.
- `features.local_login`.
- `features.oidc_login`.
- `policy.signup`.
- Full OIDC provider configuration if local login is disabled.

## Metrics Return 403 Or 404

- 404: `metrics.enabled` is false.
- 403 in `admin` mode: request is not from an admin session.
- 403 in `token` mode: missing or mismatched bearer token.
- 403 in `loopback` mode: the resolved client IP is not loopback. With `behind_proxy = true`, check that `server.trusted_proxy_hops` matches how many proxies actually append to `X-Forwarded-For`; if the header is shorter than that, Midden falls back to the socket peer address.

## Public Browse Is Empty

Public browse only lists items with `visibility = "public"` and requires:

```toml
[features]
public_browse = true
```

Unlisted items are reachable by direct link but do not appear in browse.
