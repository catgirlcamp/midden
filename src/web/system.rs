use super::*;

pub(super) async fn robots_txt(State(state): State<AppState>) -> AppResult<Response> {
    let settings = state.settings().await?;
    let body = if settings.features.public_browse && settings.discovery.robots_index {
        "User-agent: *\nAllow: /browse\n"
    } else {
        "User-agent: *\nDisallow: /\n"
    };
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response())
}

pub(super) async fn healthz() -> &'static str {
    "ok\n"
}

pub(super) async fn readyz(State(state): State<AppState>) -> Response {
    let database = state.db.health().await;
    let storage = state.storage.health().await;
    if database && storage {
        (StatusCode::OK, "database=true\nstorage=true\n").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("database={database}\nstorage={storage}\n"),
        )
            .into_response()
    }
}

pub(super) async fn metrics(
    State(state): State<AppState>,
    request: Request,
) -> AppResult<Response> {
    let headers = request.headers().clone();
    let jar = CookieJar::from_headers(&headers);
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .cloned();
    let settings = state.settings().await?;
    if !settings.metrics.enabled {
        return Err(AppError::NotFound);
    }
    match settings.metrics.access {
        crate::config::MetricsAccessMode::Public => {}
        crate::config::MetricsAccessMode::Admin => {
            let user = current_user(&state, &jar).await?;
            if !policy::can_admin(user.as_ref()) {
                return Err(AppError::Forbidden);
            }
        }
        crate::config::MetricsAccessMode::Token => {
            let expected = settings
                .metrics
                .bearer_token
                .as_deref()
                .filter(|token| !token.is_empty())
                .ok_or(AppError::Forbidden)?;
            let provided = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            if provided != Some(expected) {
                return Err(AppError::Forbidden);
            }
        }
        crate::config::MetricsAccessMode::Loopback => {
            let peer_ip = peer.map(|ConnectInfo(addr)| addr.ip());
            let ip = client_ip(&state.config.server, &headers, peer_ip);
            if !ip.is_some_and(|ip| ip.is_loopback()) {
                return Err(AppError::Forbidden);
            }
        }
    }
    let mut body = String::new();
    encode(&mut body, &state.registry)
        .map_err(|err| AppError::Other(anyhow::anyhow!("metrics encode failed: {err}")))?;
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/openmetrics-text; version=1.0.0; charset=utf-8"),
        )],
        body,
    )
        .into_response())
}

pub(super) async fn static_asset(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> AppResult<Response> {
    if path.contains("..") || path.starts_with('/') {
        return Err(AppError::NotFound);
    }
    let settings = state.settings().await?;
    if let Some(static_dir) = &state.config.server.static_dir {
        let disk_path = static_dir.join(&path);
        if disk_path.exists() && disk_path.is_file() {
            let bytes = tokio::fs::read(&disk_path).await?;
            let content_type = mime_guess::from_path(&disk_path).first_or_octet_stream();
            let mut response = (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(content_type.as_ref()).unwrap(),
                )],
                bytes,
            )
                .into_response();
            insert_cache_control(
                &mut response,
                settings.delivery.static_cache_seconds,
                CacheScope::Public,
            );
            return Ok(response);
        }
    }
    let mut response = match path.as_str() {
        "midden.css" => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            )],
            include_str!("../../static/midden.css"),
        )
            .into_response(),
        "midden.js" => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            )],
            include_str!("../../static/midden.js"),
        )
            .into_response(),
        "vendor/htmx.min.js" => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            )],
            include_str!("../../static/vendor/htmx.min.js"),
        )
            .into_response(),
        "vendor/alpine.min.js" => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            )],
            include_str!("../../static/vendor/alpine.min.js"),
        )
            .into_response(),
        _ => return Err(AppError::NotFound),
    };
    insert_cache_control(
        &mut response,
        settings.delivery.static_cache_seconds,
        CacheScope::Public,
    );
    Ok(response)
}
