use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Instant,
};

use axum::{
    Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, MatchedPath, Multipart, Path, Query, Request, State,
        connect_info::ConnectInfo,
    },
    handler::Handler,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use prometheus_client::encoding::text::encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

use crate::{
    app::{AppError, AppResult, AppState},
    config::{
        ActionRule, ContentDispositionMode, DeletePolicy, FeatureConfig, HomepageBlock,
        PolicyConfig, RateLimitBackend, RateLimitConfig, RiskyMimeMode, RuntimeSettings,
        ScanDecision, ScannerAdapterConfig, SignupMode,
    },
    db::{FileItem, NewFileItem, Paste, Role, User},
    policy, processing, quota,
    scanner::{self, ScanInput},
    util,
};

mod account;
mod admin;
mod api;
mod api_paths;
mod auth;
mod browse;
mod files;
mod items;
mod oidc;
mod openapi;
mod pastes;
mod support;
mod system;
mod upload;

use account::*;
use admin::*;
use api::*;
use auth::*;
use browse::*;
use files::*;
use items::*;
use pastes::*;
use support::*;
use system::*;
use upload::*;

#[cfg(test)]
mod tests;

const CSRF_COOKIE: &str = "midden_csrf";
const CSRF_FIELD: &str = "csrf_token";
const TWO_FACTOR_CHALLENGE_COOKIE: &str = "midden_2fa_challenge";

#[derive(Clone)]
pub struct RequestContext {
    pub templates: crate::templates::Templates,
    pub settings: crate::config::RuntimeSettings,
    pub current_user: Option<crate::db::User>,
    pub csrf_token: Option<String>,
    pub is_htmx: bool,
    /// Address of the socket the request arrived on, before any forwarding headers are consulted.
    pub peer_ip: Option<IpAddr>,
    /// Host the request was addressed to, resolved once from the URI authority or `Host` header.
    pub request_origin: Option<RequestOrigin>,
}

tokio::task_local! {
    pub static REQUEST_CONTEXT: RequestContext;
}

async fn request_context_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/healthz" {
        return next.run(request).await;
    }
    let settings = match state.settings().await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "failed to load settings in middleware");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("internal server error".to_string()),
            )
                .into_response();
        }
    };
    let request_origin = RequestOrigin::from_request(request.uri(), &headers);
    let isolated_file_host = matches_file_host(&settings, request_origin.as_ref());
    let current_user = if isolated_file_host {
        None
    } else {
        match current_user(&state, &jar).await {
            Ok(user) => user,
            Err(err) => {
                tracing::error!(error = %err, "failed to load current user in middleware");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("internal server error".to_string()),
                )
                    .into_response();
            }
        }
    };
    let existing_csrf_token = (!isolated_file_host)
        .then(|| {
            jar.get(CSRF_COOKIE)
                .map(|cookie| cookie.value().to_string())
        })
        .flatten();
    let needs_csrf_cookie = !isolated_file_host && existing_csrf_token.is_none();
    let csrf_token = if isolated_file_host {
        None
    } else {
        Some(existing_csrf_token.unwrap_or_else(util::secret_token))
    };
    if needs_csrf_cookie && let Some(token) = csrf_token.as_deref() {
        let cookie_header = request
            .headers()
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(|value| format!("{value}; {CSRF_COOKIE}={token}"))
            .unwrap_or_else(|| format!("{CSRF_COOKIE}={token}"));
        if let Ok(value) = HeaderValue::from_str(&cookie_header) {
            request.headers_mut().insert(header::COOKIE, value);
        }
    }
    let is_htmx = htmx_request(&headers);
    let secure_cookies = settings.security.secure_cookies;
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let ctx = RequestContext {
        templates: state.templates.clone(),
        settings,
        current_user,
        csrf_token: csrf_token.clone(),
        is_htmx,
        peer_ip,
        request_origin,
    };

    let mut response = REQUEST_CONTEXT
        .scope(ctx, async { next.run(request).await })
        .await;
    if needs_csrf_cookie && let Some(token) = csrf_token {
        let mut cookie = Cookie::new(CSRF_COOKIE, token);
        cookie.set_path("/");
        cookie.set_same_site(SameSite::Lax);
        cookie.set_secure(secure_cookies);
        if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

/// Route patterns the isolated file origin is allowed to answer.
///
/// These are matched against `MatchedPath`, so the list is checked against the routes the router
/// actually registered rather than against a re-implementation of path matching. A new app route
/// cannot become reachable on the file host by being forgotten here — it has to be added.
const FILE_HOST_ROUTES: &[&str] = &[
    "/files/{id}/raw",
    "/files/{id}/thumbnail",
    "/{slug}",
    "/robots.txt",
];

pub fn router(state: AppState) -> Router {
    let metrics_state = state.clone();

    let file_routes = Router::new()
        .route("/files/{id}/raw", get(raw_file))
        .route("/files/{id}/thumbnail", get(thumbnail_file))
        .route("/internal/files/{id}/raw", get(internal_raw_file))
        .route("/{slug}", get(file_slug));

    let app_routes = Router::new()
        .route(
            "/",
            get(index).post(upload_form_file.layer(DefaultBodyLimit::disable())),
        )
        .route("/url-upload", get(url_upload_form).post(url_upload))
        .route("/static/{*path}", get(static_asset))
        .route("/browse", get(public_browse))
        .route("/robots.txt", get(robots_txt))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route(api_paths::DOCS, get(api_docs))
        .route(api_paths::OPENAPI, get(api_openapi))
        .route(api_paths::MY_FILES, get(api_list_my_files))
        .route(api_paths::MY_PASTES, get(api_list_my_pastes))
        .route(
            api_paths::FILES,
            post(api_upload_file.layer(DefaultBodyLimit::disable())),
        )
        .route(api_paths::FILE, delete(api_delete_file))
        .route(api_paths::PASTES, post(api_create_paste))
        .route(api_paths::PASTE, delete(api_delete_paste))
        .route(api_paths::REPORTS, post(api_create_report))
        .route(api_paths::CLAIM, post(api_claim_item))
        .route(
            api_paths::TOKENS,
            get(api_list_tokens).post(api_create_token),
        )
        .route(api_paths::TOKEN, delete(api_revoke_token))
        .route(api_paths::ADMIN_REPORTS, get(api_admin_reports))
        .route(api_paths::ADMIN_REPORT, patch(api_admin_update_report))
        .route(api_paths::ADMIN_ITEM, patch(api_admin_update_item))
        .route(api_paths::ADMIN_SEARCH, get(api_admin_search))
        .route("/p/new", get(new_paste).post(create_paste))
        .route("/p/{id}/edit", get(edit_paste_form).post(update_paste))
        .route("/p/{id}", get(show_paste))
        .route("/p/{id}/raw", get(raw_paste))
        .route("/report/{kind}/{id}", get(report_form).post(create_report))
        .route("/delete/{kind}/{id}", get(delete_form).post(delete_item))
        .route("/claim/{kind}/{id}", get(claim_form).post(claim_item))
        .route("/auth/login", get(login_form).post(login))
        .route("/auth/logout", post(logout))
        .route(
            "/auth/password-reset",
            get(password_reset_request_form).post(password_reset_request),
        )
        .route(
            "/auth/password-reset/{token}",
            get(password_reset_form).post(password_reset_submit),
        )
        .route("/auth/verify-email/{token}", get(verify_email))
        .route("/auth/2fa", get(two_factor_form).post(two_factor_submit))
        .route("/auth/oidc/login", get(oidc::login))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/register", get(register_form).post(register))
        .route("/account", get(account))
        .route(
            "/account/email-verification",
            post(account_send_email_verification),
        )
        .route("/account/oidc/link", get(oidc::account_link))
        .route("/account/password", post(account_change_password))
        .route(
            "/account/two-factor/enable",
            post(account_enable_two_factor),
        )
        .route(
            "/account/two-factor/disable",
            post(account_disable_two_factor),
        )
        .route("/account/deactivate", post(account_deactivate))
        .route("/account/tokens", post(account_create_token))
        .route("/account/tokens/{id}/revoke", post(account_revoke_token))
        .route("/account/items/bulk", post(account_bulk_items))
        .route("/admin", get(admin))
        .route("/admin/jobs", get(admin_jobs).post(admin_jobs_run_once))
        .route("/admin/search", get(admin_search))
        .route("/admin/users", get(admin_users).post(admin_create_user))
        .route("/admin/users/invites", post(admin_create_invite))
        .route(
            "/admin/users/invites/{id}/revoke",
            post(admin_revoke_invite),
        )
        .route("/admin/users/{id}/role", post(admin_set_user_role))
        .route("/admin/users/{id}/disable", post(admin_disable_user))
        .route("/admin/users/{id}/enable", post(admin_enable_user))
        .route("/admin/settings", post(admin_update_settings))
        .route("/admin/reports", get(admin_reports))
        .route("/admin/reports/bulk", post(admin_bulk_update_reports))
        .route("/admin/reports/{id}", post(admin_update_report))
        .route(
            "/admin/items/{kind}/{id}",
            get(admin_item).post(admin_update_item),
        )
        .layer(CompressionLayer::new());

    Router::new()
        .merge(app_routes)
        .merge(file_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            file_origin_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_context_middleware,
        ))
        .layer(middleware::from_fn(api_error_middleware))
        .layer(middleware::from_fn_with_state(
            metrics_state,
            request_metrics_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Restricts the isolated file origin to the routes that serve file bytes.
async fn file_origin_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // `/healthz` skips the request context, so it has no cached settings to reuse and no reason to
    // pay for a database round trip on every probe.
    if request.uri().path() == "/healthz" {
        return next.run(request).await;
    }
    let settings = match state.settings().await {
        Ok(settings) => settings,
        // Failing open here would serve the whole application from the file origin. The request
        // context middleware already rejects this case; this is the belt to its braces.
        Err(err) => {
            tracing::error!(error = %err, "failed to load settings in file origin middleware");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("internal server error".to_string()),
            )
                .into_response();
        }
    };
    if is_isolated_file_host(&settings, &headers) && !is_file_host_route(&request) {
        return AppError::NotFound.into_response();
    }
    next.run(request).await
}

fn is_file_host_route(request: &Request) -> bool {
    request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|matched| FILE_HOST_ROUTES.contains(&matched.as_str()))
}

async fn request_metrics_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let response = next.run(request).await;
    state
        .metrics
        .request_latency
        .observe(started.elapsed().as_secs_f64());
    response
}

async fn api_error_middleware(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let wants_json = path.starts_with("/api/");
    let response = next.run(request).await;
    if wants_json && (response.status().is_client_error() || response.status().is_server_error()) {
        let status = response.status();
        let (mut parts, _) = response.into_parts();
        let json_response =
            (status, axum::Json(api::ApiErrorResponse::new(status))).into_response();
        let (json_parts, body) = json_response.into_parts();
        parts.headers.remove(header::CONTENT_LENGTH);
        if let Some(content_type) = json_parts.headers.get(header::CONTENT_TYPE) {
            parts
                .headers
                .insert(header::CONTENT_TYPE, content_type.clone());
        }
        return Response::from_parts(parts, body);
    }
    response
}
