# Security Policy

Midden exposes security controls through feature flags, action policies, content policy, URL upload restrictions, rate limits, delivery settings, and moderation states.

## Action Rules

Action rules accept:

```text
disabled
anonymous
authenticated
moderator
admin
owner
```

Example:

```toml
[policy]
upload_file = "anonymous"
create_paste = "anonymous"
use_api = "anonymous"
view_item = "anonymous"
delete_own_item = "authenticated"
delete_policy = "delete_tokens"
claim_anonymous_item = "authenticated"
create_account = "disabled"
```

## Delete Policy

`delete_policy` accepts:

- `disabled`: anonymous delete tokens cannot delete.
- `delete_tokens`: anonymous delete tokens can delete.
- `no_anonymous_delete`: only authorized account users can delete.
- `claim_later`: anonymous items can be claimed by an account with the token.

## Content Policy

```toml
[security.content_policy]
allowed_mime_types = []
forced_attachment_mime_types = ["image/svg+xml", "text/html", "application/javascript", "text/javascript"]
risky_mime_mode = "attachment"
max_filename_bytes = 180
```

If `allowed_mime_types` is empty, all MIME types are accepted unless blocked by scanner settings. Forced attachment types are served as downloads to reduce browser execution risk.

`risky_mime_mode` accepts:

- `attachment`: serve risky types as attachments.
- `inline_on_isolated_origin`: allow inline only on the isolated file origin.
- `plaintext`: serve risky types as text/plain.

## MIME Mismatch Rejection

```toml
[security]
reject_mime_mismatch = true
```

When enabled, Midden rejects uploads where sniffed content conflicts with the declared or filename-derived MIME type.

## URL Upload Restrictions

URL upload blocks private and local IPs by default and supports allow/block lists for ports and hosts. Keep `block_private_ips = true` unless the instance is strictly internal and you understand the SSRF risk.

## Rate Limits

Rate limits are disabled unless a named action is configured.

```toml
[security.rate_limits.login]
enabled = true
requests = 10
window_seconds = 300
```

Common action names include `upload_file`, `upload_by_url`, `create_paste`, `login`, `password_reset`, `report`, `api_upload_file`, `api_create_paste`, `api_delete_file`, `api_delete_paste`, `api_create_token`, `api_create_report`, `api_list_files`, and `api_list_pastes`.

### Identity

Limits are counted per authenticated user, or per client IP for anonymous callers. Getting the IP right matters: if every anonymous caller resolves to the same identity, one client can exhaust a limit for everyone.

Behind a reverse proxy, set both:

```toml
[server]
behind_proxy = true
trusted_proxy_hops = 1
```

`trusted_proxy_hops` must match the number of proxies that append to `X-Forwarded-For`. Midden counts from the right, because only the right-most entries were written by infrastructure you control. See [Delivery And CDN](./delivery-and-cdn.md#reverse-proxies).

With `behind_proxy = false`, forwarding headers are ignored and the socket peer address is used.

### Backends

```toml
[security]
rate_limit_backend = "memory"
```

`memory` counts per process, so a multi-process or multi-replica deployment enforces the configured limit once per replica, and its counters reset on restart. `database` shares counters across replicas at the cost of a write per checked request; its rows are reclaimed by the [cleanup job](./jobs-and-maintenance.md).

## Credential Revocation

Changing a password from the account page signs out that account's other sessions and keeps the one making the change.

Completing a password reset is treated as account recovery: it drops every session for the account and revokes all of its API tokens. Users who automate against Midden need to mint a new token after a reset.

## Branding And CSS

`branding.accent_color` is interpolated into a stylesheet, so it is restricted to characters that can appear in a CSS color value. Values containing `;`, `{`, `}`, quotes, or `*` are rejected at save time and by `config check`.

`branding.custom_css` is inserted verbatim and is deliberately not restricted. It is a file-only setting rather than an admin UI field; treat it as trusted operator input.
