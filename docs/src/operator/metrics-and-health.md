# Metrics And Health

Midden exposes health endpoints and optional Prometheus/OpenMetrics metrics.

## Health

```text
GET /healthz
GET /readyz
```

`/healthz` returns `ok` when the HTTP server is alive.

`/readyz` checks database and storage health and returns:

```text
database=true
storage=true
```

If either dependency is unavailable, it returns HTTP 503 with the failed dependency state.

## Metrics

```toml
[metrics]
enabled = true
access = "admin"
```

Metrics are served at:

```text
GET /metrics
```

The response content type is OpenMetrics text.

## Access Modes

`metrics.access` accepts:

- `public`: no authentication.
- `admin`: current web session must be an admin or owner.
- `token`: request must include `Authorization: Bearer <metrics bearer token>`.
- `loopback`: request client IP must be loopback.

Token mode requires:

```toml
[metrics]
access = "token"
bearer_token = "change-me"
```

Loopback mode consults forwarding headers only when `server.behind_proxy = true`, and then reads the client IP from the hop `server.trusted_proxy_hops` in from the right of `X-Forwarded-For`. See [Delivery And CDN](./delivery-and-cdn.md#reverse-proxies) for how that hop is chosen.

With `behind_proxy = false` the headers are ignored entirely and the socket peer address decides. Do not enable `behind_proxy` unless a proxy really is in front of Midden: it tells Midden to believe headers that a direct caller would otherwise be free to invent.

## Metric Names

Registered metrics include:

- `uploads`
- `pastes`
- `upload_bytes`
- `served_files`
- `reports`
- `scanner_outcomes`
- `rate_limit_rejections`
- `request_latency_seconds`
