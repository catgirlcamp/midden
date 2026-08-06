use super::*;
use crate::jobs;
use axum::body::Body;
use http::Request;
use http_body_util::BodyExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tower::ServiceExt;

async fn test_state(issuer_url: String) -> AppState {
    test_state_with(issuer_url, |_| {}).await
}

async fn test_state_with(
    issuer_url: String,
    mutate: impl FnOnce(&mut crate::config::AppConfig),
) -> AppState {
    let mut config = crate::config::AppConfig::default();
    config.database.url = "sqlite::memory:".to_string();
    config.database.max_connections = 1;
    config.storage.local.path =
        std::env::temp_dir().join(format!("midden-test-{}", util::public_id()));
    config.features.oidc_login = true;
    config.oidc.enabled = true;
    config.oidc.issuer_url = Some(issuer_url);
    config.oidc.client_id = Some("midden-test".to_string());
    config.oidc.allowed_domains = vec!["example.test".to_string()];
    config.oidc.allowed_groups = vec!["admins".to_string()];
    config
        .oidc
        .role_mappings
        .insert("admins".to_string(), "admin".to_string());
    mutate(&mut config);
    let state = AppState::new(config).await.unwrap();
    state.db.migrate().await.unwrap();
    state
}

async fn spawn_oidc_provider(userinfo: serde_json::Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let base_for_task = base_url.clone();
    let userinfo = Arc::new(userinfo.to_string());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let base = base_for_task.clone();
            let userinfo = userinfo.clone();
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let body = match path {
                    "/.well-known/openid-configuration" => serde_json::json!({
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                        "userinfo_endpoint": format!("{base}/userinfo")
                    })
                    .to_string(),
                    "/token" => {
                        serde_json::json!({ "access_token": "mock-access-token" }).to_string()
                    }
                    "/userinfo" => userinfo.to_string(),
                    _ => "{}".to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    base_url
}

async fn spawn_http_app(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = state.router();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

async fn user_with_api_token(
    state: &AppState,
    email: &str,
    username: &str,
    role: Role,
    scopes: &[&str],
) -> (User, String) {
    let user = state
        .db
        .create_user(email, username, Some("password-hash"), role)
        .await
        .unwrap();
    let token = format!("mdd_{}", util::secret_token());
    let scopes = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<Vec<_>>();
    state
        .db
        .create_api_token_with_expiry(&user.id, "test", &util::hash_token(&token), &scopes, None)
        .await
        .unwrap();
    (user, token)
}

fn hex_fixture(input: &str) -> Vec<u8> {
    let compact = input
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn csrf_cookie_from(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find_map(|cookie| cookie.strip_prefix("midden_csrf=").map(ToOwned::to_owned))
        .unwrap()
}

fn csrf_cookie_from_http(headers: &HeaderMap) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find_map(|cookie| cookie.strip_prefix("midden_csrf=").map(ToOwned::to_owned))
        .unwrap()
}

async fn response_body(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

async fn file_delivery_state() -> AppState {
    let mut config = crate::config::AppConfig::default();
    config.database.url = "sqlite::memory:".to_string();
    config.database.max_connections = 1;
    config.server.public_base_url = "https://midden.example".to_string();
    config.delivery.public_file_base_url = Some("https://files.midden.example".to_string());
    config.delivery.isolated_file_origin = true;
    config.storage.local.path =
        std::env::temp_dir().join(format!("midden-file-delivery-test-{}", util::public_id()));
    let state = AppState::new(config).await.unwrap();
    state.db.migrate().await.unwrap();
    state
}

async fn create_test_file(
    state: &AppState,
    public_id: &str,
    filename: &str,
    content_type: &str,
    bytes: &'static [u8],
) -> FileItem {
    let bytes = Bytes::from_static(bytes);
    let hash = util::sha256_hex_bytes(&bytes);
    state
        .db
        .create_blob_if_missing(&hash, bytes.len() as i64, Some(content_type))
        .await
        .unwrap();
    state.storage.put_blob(&hash, bytes.clone()).await.unwrap();
    let extension = util::normalize_extension(Some(filename), Some(content_type));
    state
        .db
        .create_file_item(NewFileItem {
            id: &uuid::Uuid::new_v4().to_string(),
            public_id,
            blob_hash: &hash,
            original_filename: Some(filename),
            extension: extension.as_deref(),
            content_type: Some(content_type),
            size_bytes: bytes.len() as i64,
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
        .unwrap()
}

async fn admin_session_state() -> (AppState, String) {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-ui-admin",
        "email": "unused-ui-admin@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let admin = state
        .db
        .create_user(
            "ui-admin@example.test",
            "ui-admin",
            Some("password-hash"),
            Role::Admin,
        )
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &admin.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    (state, session_token)
}

async fn user_session_state() -> (AppState, String) {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let user = state
        .db
        .create_user(
            "ui-user@example.test",
            "ui-user",
            Some("password-hash"),
            Role::User,
        )
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &user.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    (state, session_token)
}

fn admin_settings_form_body(csrf: &str, oidc_login: bool, local_login: bool) -> String {
    let mut fields = vec![
        ("feature_files", "on"),
        ("feature_pastes", "on"),
        ("feature_accounts", "on"),
        ("feature_api", "on"),
        ("feature_reports", "on"),
        ("max_upload_bytes", "2147483648"),
        ("max_paste_bytes", "1048576"),
        ("signup", "open"),
        ("policy_upload_file", "anonymous"),
        ("policy_create_paste", "anonymous"),
        ("policy_use_api", "anonymous"),
        ("policy_view_item", "anonymous"),
        ("policy_delete_own_item", "owner"),
        ("policy_claim_anonymous_item", "authenticated"),
        ("policy_create_account", "anonymous"),
        ("delete_policy", "delete_tokens"),
        ("content_disposition", "attachment"),
        ("risky_mime_mode", "attachment"),
        ("metrics_access", "public"),
        ("rate_limit_backend", "memory"),
        ("default_on_error", "allow"),
        ("instance_name", "Midden"),
        ("tagline", ""),
        ("accent_color", "#4f46e5"),
        ("dark_mode", "auto"),
        ("opengraph_description", ""),
        ("takedown_page_text", ""),
        ("csrf_token", csrf),
    ];
    if oidc_login {
        fields.push(("feature_oidc_login", "on"));
    }
    if local_login {
        fields.push(("feature_local_login", "on"));
    }
    fields
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

#[tokio::test]
async fn admin_ui_exposes_wide_shell_and_settings_affordances() {
    let (state, session_token) = admin_session_state().await;
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("class=\"page page--wide page--admin\""));
    assert!(body.contains("class=\"admin-nav\""));
    assert!(body.contains("data-admin-settings-form"));
    assert!(body.contains("class=\"settings-tabs\""));
    assert!(!body.contains("role=\"tablist\""));
    assert!(!body.contains("role=\"tab\""));
    assert!(!body.contains("role=\"tabpanel\""));
    assert!(body.contains("class=\"settings-save-bar\""));
    assert!(body.contains("data-settings-section=\"features\""));
    assert!(body.contains("data-secret-input"));
    assert!(body.contains("aria-pressed=\"false\""));
    assert!(body.contains("aria-controls=\""));
    assert!(body.contains("data-accent-preview"));
    assert!(body.contains("x-cloak"));
}

#[tokio::test]
async fn rendered_post_forms_include_server_csrf_fields() {
    let response = test_state("http://127.0.0.1".to_string())
        .await
        .router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let csrf = csrf_cookie_from_http(response.headers());
    let body = response_body(response).await;
    assert!(body.contains("name=\"csrf_token\""));
    assert!(body.contains(&format!("value=\"{csrf}\"")));
}

#[tokio::test]
async fn public_ui_hides_local_auth_links_when_local_login_disabled() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut settings = state.settings().await.unwrap();
    settings.features.local_login = false;
    settings.policy.signup = crate::config::SignupMode::Open;
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();
    state
        .db
        .set_json_setting("policy", &settings.policy)
        .await
        .unwrap();
    let router = state.router();

    let home_response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(home_response.status(), StatusCode::OK);
    let home = response_body(home_response).await;
    assert!(!home.contains("href=\"/register\""));

    let login_response = router
        .oneshot(
            Request::builder()
                .uri("/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let login = response_body(login_response).await;
    assert!(!login.contains("action=\"/auth/login\""));
    assert!(!login.contains("href=\"/auth/password-reset\""));
    assert!(!login.contains("href=\"/register\""));
    assert!(login.contains("href=\"/auth/oidc/login\""));
}

#[tokio::test]
async fn accounts_feature_disabled_hides_and_blocks_account_flows() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut settings = state.settings().await.unwrap();
    settings.features.accounts = false;
    settings.policy.signup = crate::config::SignupMode::Open;
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();
    state
        .db
        .set_json_setting("policy", &settings.policy)
        .await
        .unwrap();
    let router = state.router();

    let home_response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(home_response.status(), StatusCode::OK);
    let home = response_body(home_response).await;
    assert!(!home.contains("href=\"/auth/login\""));
    assert!(!home.contains("href=\"/register\""));

    for path in [
        "/auth/login",
        "/register",
        "/auth/password-reset",
        "/account",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn api_feature_disabled_hides_docs_and_account_tokens() {
    let (state, session_token) = user_session_state().await;
    let mut settings = state.settings().await.unwrap();
    settings.features.api = false;
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();
    let csrf = util::secret_token();
    let router = state.router();

    for path in ["/api/docs", "/api/openapi.json"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let account_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(account_response.status(), StatusCode::OK);
    let account = response_body(account_response).await;
    assert!(!account.contains("API Tokens"));
    assert!(!account.contains("action=\"/account/tokens\""));

    let create_token = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/tokens")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "name=blocked&scopes=files%3Aread&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_token.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn openapi_route_serves_complete_resolvable_contract() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri(super::api_paths::OPENAPI)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE].to_str().unwrap(),
        "application/json"
    );
    let document: serde_json::Value = serde_json::from_str(&response_body(response).await).unwrap();
    assert_eq!(document["openapi"], "3.1.0");

    let expected_paths = [
        super::api_paths::FILES,
        super::api_paths::FILE,
        super::api_paths::PASTES,
        super::api_paths::PASTE,
        super::api_paths::MY_FILES,
        super::api_paths::MY_PASTES,
        super::api_paths::CLAIM,
        super::api_paths::REPORTS,
        super::api_paths::TOKENS,
        super::api_paths::TOKEN,
        super::api_paths::ADMIN_REPORTS,
        super::api_paths::ADMIN_REPORT,
        super::api_paths::ADMIN_ITEM,
        super::api_paths::ADMIN_SEARCH,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let actual_paths = document["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual_paths, expected_paths);

    for path in [super::api_paths::FILE, super::api_paths::PASTE] {
        let parameters = document["paths"][path]["delete"]["parameters"]
            .as_array()
            .unwrap();
        assert!(parameters.iter().any(|parameter| {
            parameter["name"] == "x-delete-token"
                && parameter["in"] == "header"
                && parameter["required"] == false
        }));
    }

    fn assert_schema_references_resolve(document: &serde_json::Value, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
                    assert!(
                        document
                            .pointer(reference.strip_prefix('#').unwrap())
                            .is_some(),
                        "unresolved schema reference {reference}"
                    );
                }
                for value in object.values() {
                    assert_schema_references_resolve(document, value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    assert_schema_references_resolve(document, value);
                }
            }
            _ => {}
        }
    }
    assert_schema_references_resolve(&document, &document);
}

#[tokio::test]
async fn api_middleware_failures_keep_the_documented_json_error_shape() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    state
        .db
        .set_json_setting("features", &serde_json::json!("invalid features payload"))
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri(super::api_paths::OPENAPI)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE].to_str().unwrap(),
        "application/json"
    );
    let body: serde_json::Value = serde_json::from_str(&response_body(response).await).unwrap();
    assert_eq!(body["error"]["status"], 500);
    assert_eq!(body["error"]["code"], "internal_server_error");
    assert_eq!(body["error"]["message"], "Internal Server Error");
}

#[tokio::test]
async fn api_error_normalization_preserves_method_and_policy_headers() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let response = state
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(super::api_paths::FILES)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "POST");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: serde_json::Value = serde_json::from_str(&response_body(response).await).unwrap();
    assert_eq!(body["error"]["status"], 405);
}

#[tokio::test]
async fn reports_feature_disabled_hides_and_blocks_moderation_queue() {
    let (state, session_token) = admin_session_state().await;
    let mut settings = state.settings().await.unwrap();
    settings.features.reports = false;
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();
    let router = state.router();

    let admin_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_response.status(), StatusCode::OK);
    let admin = response_body(admin_response).await;
    assert!(!admin.contains("href=\"/admin/reports\""));
    assert!(admin.contains(
        "Report links and new report submissions stay unavailable while reports are disabled."
    ));

    let reports = router
        .oneshot(
            Request::builder()
                .uri("/admin/reports")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reports.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn password_reset_form_is_hidden_without_smtp() {
    let response = test_state("http://127.0.0.1".to_string())
        .await
        .router()
        .oneshot(
            Request::builder()
                .uri("/auth/password-reset")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("Email is not configured"));
    assert!(!body.contains("action=\"/auth/password-reset\""));
    assert!(!body.contains("Send reset link"));
}

#[tokio::test]
async fn admin_settings_rejects_disabling_all_sign_in_paths() {
    let (state, session_token) = admin_session_state().await;
    let csrf = util::secret_token();
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(admin_settings_form_body(&csrf, false, false)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await;
    assert!(body.contains("at least one sign-in method"));
    let settings = state.settings().await.unwrap();
    assert!(settings.features.local_login);
    assert!(settings.features.oidc_login);
}

#[tokio::test]
async fn admin_settings_persists_an_empty_expiry_preset_list() {
    let (state, session_token) = admin_session_state().await;
    assert!(
        !state
            .settings()
            .await
            .unwrap()
            .limits
            .expiry
            .allowed_presets
            .is_empty()
    );
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(admin_settings_form_body(&csrf, true, true)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        state
            .settings()
            .await
            .unwrap()
            .limits
            .expiry
            .allowed_presets
            .is_empty()
    );
}

#[tokio::test]
async fn static_assets_include_frontend_ux_helpers() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-static-ui",
        "email": "unused-static-ui@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let router = state.router();

    let css_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/midden.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(css_response.status(), StatusCode::OK);
    let css = response_body(css_response).await;
    assert!(css.contains(".page--wide"));
    assert!(css.contains("[x-cloak]"));
    assert!(css.contains(".status-badge"));
    assert!(css.contains(".table-card"));
    assert!(css.contains(".htmx-request"));
    assert!(css.contains(".drop-zone:focus-within"));
    assert!(css.contains("input[type=\"checkbox\"]"));
    assert!(css.contains("inline-size: auto"));
    assert!(css.contains("--accent-ink"));
    assert!(css.contains("--danger"));
    assert!(css.contains("--danger-ink"));
    assert!(css.contains("@media (pointer: coarse)"));
    assert!(css.contains(".status-badge--legal_hold"));
    assert!(css.contains(".status-badge--reject"));
    let normalized_css = css.replace("\r\n", "\n");
    assert!(normalized_css.contains("}\n\n.settings-tabs"));

    let js_response = router
        .oneshot(
            Request::builder()
                .uri("/static/midden.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(js_response.status(), StatusCode::OK);
    let js = response_body(js_response).await;
    assert!(js.contains("htmx:beforeRequest"));
    assert!(js.contains("data-copy-value"));
    assert!(js.contains("data-secret-toggle"));
    assert!(js.contains("aria-pressed"));
    assert!(js.contains("midden:settings-section:"));
    assert!(js.contains("data-upload-cancel"));
    assert!(js.contains("Uploading..."));
    assert!(js.contains("Copy failed"));
    assert!(js.contains("Promise.reject"));
}

#[tokio::test]
async fn public_upload_page_exposes_stateful_controls_and_hints() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-public-ui",
        "email": "unused-public-ui@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let response = state
        .router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("data-upload-cancel"));
    assert!(body.contains("id=\"upload-status\""));
    assert!(body.contains("id=\"upload-help\""));
    assert!(body.contains("aria-describedby=\"upload-help\""));
    assert!(body.contains("No file selected"));
    assert!(body.contains("name=\"csrf_token\""));
}

#[tokio::test]
async fn admin_settings_renders_without_user_role_quota() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-admin-settings",
        "email": "unused-admin-settings@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let admin = state
        .db
        .create_user(
            "admin-settings@example.test",
            "admin-settings",
            Some("password-hash"),
            Role::Admin,
        )
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &admin.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("User quota"));
    assert!(body.contains("name=\"user_storage_bytes\" value=\"\""));
}

#[tokio::test]
async fn admin_settings_renders_operator_controls() {
    let (state, session_token) = admin_session_state().await;
    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("View access"));
    assert!(body.contains("name=\"expiry_allow_never\""));
    assert!(body.contains("name=\"metrics_access\""));
    assert!(body.contains("name=\"rate_limit_backend\""));
    assert!(body.contains("name=\"url_request_timeout_seconds\""));
    assert!(body.contains("name=\"forced_attachment_mime_types\""));
    assert!(body.contains("name=\"risky_mime_mode\""));
    assert!(body.contains("name=\"delivery_public_file_base_url\""));
    assert!(body.contains("name=\"delivery_isolated_file_origin\""));
    assert!(body.contains("name=\"token_default_ttl_seconds\""));
    assert!(body.contains("name=\"thumbnail_max_dimension\""));
    assert!(body.contains("name=\"moderation_notify_webhook_url\""));
}

#[tokio::test]
async fn file_delivery_uses_isolated_origin_for_generated_urls() {
    let state = file_delivery_state().await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"isolated urls".to_vec())
                    .file_name("clip.mp4")
                    .mime_str("video/mp4")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::OK);
    let body: serde_json::Value = upload.json().await.unwrap();
    assert!(
        body["url"]
            .as_str()
            .unwrap()
            .starts_with("https://files.midden.example/")
    );
    assert!(
        body["raw_url"]
            .as_str()
            .unwrap()
            .starts_with("https://files.midden.example/files/")
    );
}

#[tokio::test]
async fn file_delivery_restricts_routes_to_the_configured_host() {
    let state = file_delivery_state().await;
    create_test_file(
        &state,
        "filehost1",
        "movie.mp4",
        "video/mp4",
        b"not really a movie",
    )
    .await;
    let router = state.router();

    let app_host_file = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/filehost1.mp4")
                .header(header::HOST, "midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(app_host_file.status(), StatusCode::NOT_FOUND);

    let file_host_app_route = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file_host_app_route.status(), StatusCode::NOT_FOUND);

    let file_host_file = router
        .oneshot(
            Request::builder()
                .uri("/filehost1.mp4")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file_host_file.status(), StatusCode::OK);
    assert_eq!(
        file_host_file.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap(),
        "inline; filename=\"movie.mp4\""
    );
}

#[tokio::test]
async fn file_delivery_keeps_risky_types_attachment_by_default() {
    let state = file_delivery_state().await;
    create_test_file(
        &state,
        "riskdef1",
        "index.html",
        "text/html",
        b"<script>alert(1)</script>",
    )
    .await;

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/riskdef1.html")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap(),
        "attachment; filename=\"index.html\""
    );
}

#[tokio::test]
async fn file_delivery_can_inline_risky_types_only_on_isolated_origin() {
    let state = file_delivery_state().await;
    let mut security = state.settings().await.unwrap().security;
    security.content_policy.risky_mime_mode = crate::config::RiskyMimeMode::InlineOnIsolatedOrigin;
    state
        .db
        .set_json_setting("security", &security)
        .await
        .unwrap();
    create_test_file(
        &state,
        "riskiso1",
        "index.html",
        "text/html",
        b"<h1>inline</h1>",
    )
    .await;

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/riskiso1.html")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap(),
        "inline; filename=\"index.html\""
    );
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS]
            .to_str()
            .unwrap(),
        "nosniff"
    );
    assert!(
        response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
}

#[tokio::test]
async fn file_delivery_can_serve_risky_types_as_plaintext() {
    let state = file_delivery_state().await;
    let mut security = state.settings().await.unwrap().security;
    security.content_policy.risky_mime_mode = crate::config::RiskyMimeMode::Plaintext;
    state
        .db
        .set_json_setting("security", &security)
        .await
        .unwrap();
    create_test_file(
        &state,
        "risktext1",
        "index.html",
        "text/html",
        b"<script>alert(1)</script>",
    )
    .await;

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/risktext1.html")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE].to_str().unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap(),
        "inline; filename=\"index.html\""
    );
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS]
            .to_str()
            .unwrap(),
        "nosniff"
    );
}

#[tokio::test]
async fn file_delivery_handles_range_requests() {
    let state = file_delivery_state().await;
    create_test_file(
        &state,
        "rangetest",
        "video.mp4",
        "video/mp4",
        b"0123456789abcdef",
    )
    .await;
    let router = state.router();

    // 1. Check full response (200 OK) with Accept-Ranges
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rangetest.mp4")
                .header(header::HOST, "files.midden.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap(),
        "16"
    );
    let body = response_body(response).await;
    assert_eq!(body, "0123456789abcdef");

    // 2. Check range request (206 Partial Content) - Range: bytes=0-4
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rangetest.mp4")
                .header(header::HOST, "files.midden.example")
                .header(header::RANGE, "bytes=0-4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes 0-4/16"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap(),
        "5"
    );
    let body = response_body(response).await;
    assert_eq!(body, "01234");

    // 3. Check range request (206 Partial Content) - Range: bytes=10-
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/rangetest.mp4")
                .header(header::HOST, "files.midden.example")
                .header(header::RANGE, "bytes=10-")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes 10-15/16"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap(),
        "6"
    );
    let body = response_body(response).await;
    assert_eq!(body, "abcdef");

    // 4. Check out of bounds range request (416 Range Not Satisfiable) - Range: bytes=20-30
    let response = router
        .oneshot(
            Request::builder()
                .uri("/rangetest.mp4")
                .header(header::HOST, "files.midden.example")
                .header(header::RANGE, "bytes=20-30")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes */16"
    );
}

#[tokio::test]
async fn index_page_exposes_selected_file_status() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-selected-file",
        "email": "unused-selected-file@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let response = state
        .router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("data-selected-file"));
    assert!(body.contains("No file selected"));
}

#[tokio::test]
async fn item_view_policy_and_retention_guardrails() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-access",
        "email": "unused-access@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let mut policy = state.settings().await.unwrap().policy;
    policy.view_item = ActionRule::Authenticated;
    state.db.set_json_setting("policy", &policy).await.unwrap();

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"authenticated viewers only".to_vec())
                    .file_name("private-ish.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let upload: serde_json::Value = upload.json().await.unwrap();
    let file_id = upload["id"].as_str().unwrap();

    assert_eq!(
        client
            .get(format!("{base}/files/{file_id}/raw"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let viewer = state
        .db
        .create_user(
            "viewer@example.test",
            "viewer",
            Some("password-hash"),
            Role::User,
        )
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &viewer.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/files/{file_id}/raw"))
            .header(header::COOKIE, format!("midden_session={session_token}"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let mut limits = state.settings().await.unwrap().limits;
    limits.expiry.allow_never = false;
    limits.expiry.anonymous_max_file_expiry = Some("1h".to_string());
    state.db.set_json_setting("limits", &limits).await.unwrap();
    let too_long = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().text("expires", "2h").part(
                "file",
                reqwest::multipart::Part::bytes(b"too long".to_vec())
                    .file_name("too-long.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(too_long.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn browser_upload_result_keeps_uploaded_file_as_links() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-browser-upload",
        "email": "unused-browser-upload@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    let home = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(home.status(), StatusCode::OK);
    let csrf = csrf_cookie_from(home.headers());
    let png = hex_fixture(include_str!("../../tests/fixtures/sample.png.hex"));
    let upload = client
        .post(format!("{base}/"))
        .header(header::COOKIE, format!("midden_csrf={csrf}"))
        .multipart(
            reqwest::multipart::Form::new()
                .text("csrf_token", csrf)
                .part(
                    "file",
                    reqwest::multipart::Part::bytes(png)
                        .file_name("sample.png")
                        .mime_str("image/png")
                        .unwrap(),
                ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::OK);
    let body = upload.text().await.unwrap();
    assert!(body.contains("Open link"));
    assert!(body.contains("Raw file"));
    assert!(!body.contains("class=\"file-preview-media\""));
    assert!(!body.contains("alt=\"sample.png\""));
}

#[tokio::test]
async fn operational_controls_cover_upload_mime_metrics_and_rate_limits() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-ops",
        "email": "unused-ops@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut settings = state.settings().await.unwrap();
    settings.metrics.enabled = true;
    settings.metrics.access = crate::config::MetricsAccessMode::Admin;
    settings
        .security
        .content_policy
        .forced_attachment_mime_types = vec!["text/plain".to_string()];
    settings.security.rate_limit_backend = crate::config::RateLimitBackend::Database;
    state
        .db
        .set_json_setting("metrics", &settings.metrics)
        .await
        .unwrap();
    state
        .db
        .set_json_setting("security", &settings.security)
        .await
        .unwrap();

    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let (admin_state, session_token) = admin_session_state().await;
    admin_state
        .db
        .set_json_setting("metrics", &settings.metrics)
        .await
        .unwrap();
    let admin_base = spawn_http_app(admin_state).await;
    assert_eq!(
        client
            .get(format!("{admin_base}/metrics"))
            .header(header::COOKIE, format!("midden_session={session_token}"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"download me".to_vec())
                    .file_name("download.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let upload: serde_json::Value = upload.json().await.unwrap();
    let file_id = upload["id"].as_str().unwrap();
    let raw = client
        .get(format!("{base}/files/{file_id}/raw"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    assert!(
        raw.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
}

#[tokio::test]
async fn rate_limits_ignore_spoofed_real_ip_without_proxy_mode() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut settings = state.settings().await.unwrap();
    settings.security.rate_limits.insert(
        "api_upload_file".to_string(),
        crate::config::RateLimitConfig {
            requests: 1,
            window_seconds: 60,
            enabled: true,
        },
    );
    state
        .db
        .set_json_setting("security", &settings.security)
        .await
        .unwrap();
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    for (index, spoofed_ip) in ["198.51.100.10", "198.51.100.11"].into_iter().enumerate() {
        let response = client
            .post(format!("{base}/api/v1/files"))
            .header("x-real-ip", spoofed_ip)
            .multipart(
                reqwest::multipart::Form::new().part(
                    "file",
                    reqwest::multipart::Part::bytes(format!("file-{index}").into_bytes())
                        .file_name(format!("file-{index}.txt"))
                        .mime_str("text/plain")
                        .unwrap(),
                ),
            )
            .send()
            .await
            .unwrap();
        if index == 0 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}

async fn upload_once(client: &reqwest::Client, base: &str, headers: &[(&str, &str)]) -> StatusCode {
    let mut request = client.post(format!("{base}/api/v1/files"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(util::secret_token().into_bytes())
                    .file_name("file.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap()
        .status()
}

async fn state_with_upload_limit_behind_proxy(hops: usize) -> AppState {
    let state = test_state_with("http://127.0.0.1".to_string(), |config| {
        config.server.behind_proxy = true;
        config.server.trusted_proxy_hops = hops;
    })
    .await;
    let mut settings = state.settings().await.unwrap();
    settings.security.rate_limits.insert(
        "api_upload_file".to_string(),
        crate::config::RateLimitConfig {
            requests: 1,
            window_seconds: 60,
            enabled: true,
        },
    );
    state
        .db
        .set_json_setting("security", &settings.security)
        .await
        .unwrap();
    state
}

#[tokio::test]
async fn rate_limits_read_the_client_ip_from_the_trusted_proxy_hop() {
    let state = state_with_upload_limit_behind_proxy(1).await;
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    assert_eq!(
        upload_once(&client, &base, &[("x-forwarded-for", "198.51.100.10")]).await,
        StatusCode::OK
    );
    assert_eq!(
        upload_once(&client, &base, &[("x-forwarded-for", "198.51.100.10")]).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        upload_once(&client, &base, &[("x-forwarded-for", "198.51.100.11")]).await,
        StatusCode::OK,
        "a different client must get its own bucket"
    );
}

#[tokio::test]
async fn rate_limits_ignore_forwarded_hops_the_client_prepended() {
    let state = state_with_upload_limit_behind_proxy(1).await;
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    // The right-most hop is what our own proxy appended; everything left of it is caller-supplied.
    assert_eq!(
        upload_once(&client, &base, &[("x-forwarded-for", "203.0.113.1, 198.51.100.10")]).await,
        StatusCode::OK
    );
    assert_eq!(
        upload_once(&client, &base, &[("x-forwarded-for", "203.0.113.2, 198.51.100.10")]).await,
        StatusCode::TOO_MANY_REQUESTS,
        "rotating a spoofed leading hop must not mint a fresh rate-limit bucket"
    );
}

#[tokio::test]
async fn http_release_flow_covers_upload_paste_claim_reports_admin_search_and_scopes() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused",
        "email": "unused@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();
    let (_user, user_token) = user_with_api_token(
        &state,
        "api-user@example.test",
        "api-user",
        Role::User,
        &[
            "files:read",
            "pastes:read",
            "items:claim",
            "tokens:read",
            "tokens:write",
        ],
    )
    .await;
    let (_admin, admin_token) = user_with_api_token(
        &state,
        "admin@example.test",
        "admin",
        Role::Admin,
        &["admin:reports", "admin:items", "admin:search"],
    )
    .await;

    let png = hex_fixture(include_str!("../../tests/fixtures/sample.png.hex"));
    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(png)
                    .file_name("sample.png")
                    .mime_str("image/png")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let upload: serde_json::Value = upload.json().await.unwrap();
    let file_id = upload["id"].as_str().unwrap().to_string();
    let file_delete_token = upload["delete_token"].as_str().unwrap().to_string();

    let paste = client
        .post(format!("{base}/api/v1/pastes"))
        .json(&serde_json::json!({
            "title": "Fixture paste",
            "syntax": "txt",
            "content": include_str!("../../tests/fixtures/sample.txt")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(paste.status(), StatusCode::OK);
    let paste: serde_json::Value = paste.json().await.unwrap();
    let paste_id = paste["id"].as_str().unwrap().to_string();
    let paste_delete_token = paste["delete_token"].as_str().unwrap().to_string();

    let paste_delete = client
        .delete(format!("{base}/api/v1/pastes/{paste_id}"))
        .header("x-delete-token", paste_delete_token)
        .send()
        .await
        .unwrap();
    assert_eq!(paste_delete.status(), StatusCode::OK);

    let claim = client
        .post(format!("{base}/api/v1/claim/file/{file_id}"))
        .bearer_auth(&user_token)
        .json(&serde_json::json!({ "delete_token": file_delete_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), StatusCode::OK);

    let files = client
        .get(format!("{base}/api/v1/me/files?q=sample"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(files.status(), StatusCode::OK);
    let files: serde_json::Value = files.json().await.unwrap();
    assert_eq!(files["items"].as_array().unwrap().len(), 1);

    let report = client
        .post(format!("{base}/api/v1/reports"))
        .json(&serde_json::json!({
            "kind": "file",
            "id": file_id,
            "reason": "abuse",
            "details": "release-flow"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), StatusCode::OK);

    let reports = client
        .get(format!("{base}/api/v1/admin/reports?state=open"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(reports.status(), StatusCode::OK);
    let reports: serde_json::Value = reports.json().await.unwrap();
    let report_id = reports["items"][0]["id"].as_str().unwrap();

    let report_update = client
        .patch(format!("{base}/api/v1/admin/reports/{report_id}"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({ "action": "resolve", "note": "handled" }))
        .send()
        .await
        .unwrap();
    assert_eq!(report_update.status(), StatusCode::OK);

    let search = client
        .get(format!("{base}/api/v1/admin/search?q=sample"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(search.status(), StatusCode::OK);
    let search: serde_json::Value = search.json().await.unwrap();
    assert_eq!(search["files"].as_array().unwrap().len(), 1);

    let created_token = client
        .post(format!("{base}/api/v1/tokens"))
        .bearer_auth(&user_token)
        .json(&serde_json::json!({ "name": "limited", "scopes": ["files:read"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(created_token.status(), StatusCode::OK);
    let created_token: serde_json::Value = created_token.json().await.unwrap();
    let limited_token = created_token["token"].as_str().unwrap();

    assert_eq!(
        client
            .get(format!("{base}/api/v1/me/files"))
            .bearer_auth(limited_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/me/pastes"))
            .bearer_auth(limited_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn invite_only_registration_with_invalid_token_does_not_create_user() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut policy = state.settings().await.unwrap().policy;
    policy.signup = crate::config::SignupMode::InviteOnly;
    state.db.set_json_setting("policy", &policy).await.unwrap();
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("midden_csrf={csrf}"))
                .body(Body::from(format!(
                    "email=invite-bypass%40example.test&username=invite-bypass&password=correct%20horse&invite_token=bad-token&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .db
            .user_by_email("invite-bypass@example.test")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invite_only_registration_without_a_token_does_not_create_user() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut policy = state.settings().await.unwrap().policy;
    policy.signup = crate::config::SignupMode::InviteOnly;
    state.db.set_json_setting("policy", &policy).await.unwrap();
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("midden_csrf={csrf}"))
                .body(Body::from(format!(
                    "email=no-invite%40example.test&username=no-invite&password=correct%20horse&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state.db.user_by_email("no-invite@example.test").await.is_err(),
        "omitting invite_token must not smuggle an account past invite-only signup"
    );
}

#[tokio::test]
async fn invite_only_registration_consumes_the_invite_and_applies_its_role() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut policy = state.settings().await.unwrap().policy;
    policy.signup = crate::config::SignupMode::InviteOnly;
    state.db.set_json_setting("policy", &policy).await.unwrap();
    let invite = util::secret_token();
    state
        .db
        .create_invite_token(&util::hash_token(&invite), "admin-user", Role::Moderator, None)
        .await
        .unwrap();
    let csrf = util::secret_token();

    let register = |body: String| {
        let state = state.clone();
        let csrf = csrf.clone();
        async move {
            state
                .router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/register")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .header(header::COOKIE, format!("midden_csrf={csrf}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    let accepted = register(format!(
        "email=invited%40example.test&username=invited&password=correct%20horse&invite_token={invite}&csrf_token={csrf}"
    ))
    .await;
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
    let user = state.db.user_by_email("invited@example.test").await.unwrap();
    assert_eq!(user.role, Role::Moderator);

    let replayed = register(format!(
        "email=replay%40example.test&username=replay&password=correct%20horse&invite_token={invite}&csrf_token={csrf}"
    ))
    .await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert!(
        state.db.user_by_email("replay@example.test").await.is_err(),
        "a consumed invite must not admit a second account"
    );
}

#[tokio::test]
async fn scoped_api_token_cannot_mint_broader_token() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();
    let (_user, token) = user_with_api_token(
        &state,
        "scope-user@example.test",
        "scope-user",
        Role::User,
        &["tokens:write"],
    )
    .await;

    let response = client
        .post(format!("{base}/api/v1/tokens"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": "escalated", "scopes": ["*"] }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_disabled_blocks_admin_api_routes() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut features = state.settings().await.unwrap().features;
    features.api = false;
    state
        .db
        .set_json_setting("features", &features)
        .await
        .unwrap();
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();
    let (_admin, token) = user_with_api_token(
        &state,
        "disabled-api-admin@example.test",
        "disabled-api-admin",
        Role::Admin,
        &["admin:reports", "admin:search"],
    )
    .await;

    for path in ["/api/v1/admin/reports", "/api/v1/admin/search?q=test"] {
        let response = client
            .get(format!("{base}{path}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn admins_cannot_mutate_owner_accounts() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let owner = state
        .db
        .create_user(
            "owner@example.test",
            "owner-user",
            Some("hash"),
            Role::Owner,
        )
        .await
        .unwrap();
    let admin = state
        .db
        .create_user(
            "actor@example.test",
            "actor-admin",
            Some("hash"),
            Role::Admin,
        )
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &admin.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    let csrf = util::secret_token();
    let router = state.clone().router();

    let role_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{}/role", owner.id))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .body(Body::from(format!("role=admin&csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(role_response.status(), StatusCode::FORBIDDEN);

    let disable_response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{}/disable", owner.id))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .body(Body::from(format!("csrf_token={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disable_response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn loopback_metrics_requires_real_loopback_client() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut metrics = state.settings().await.unwrap().metrics;
    metrics.enabled = true;
    metrics.access = crate::config::MetricsAccessMode::Loopback;
    state
        .db
        .set_json_setting("metrics", &metrics)
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn secure_cookie_runtime_setting_applies_to_all_auth_cookies() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut security = state.settings().await.unwrap().security;
    security.secure_cookies = true;
    state
        .db
        .set_json_setting("security", &security)
        .await
        .unwrap();

    let csrf_response = state
        .clone()
        .router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(
        csrf_response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|cookie| cookie.starts_with("midden_csrf=") && cookie.contains("Secure"))
    );

    let user = state
        .db
        .create_user(
            "secure-cookie@example.test",
            "secure-cookie",
            Some(&util::hash_password("correct horse").await.unwrap()),
            Role::User,
        )
        .await
        .unwrap();
    let session = create_session_response(&state, CookieJar::new(), &user)
        .await
        .unwrap();
    assert!(
        session
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|cookie| cookie.starts_with("midden_session=") && cookie.contains("Secure"))
    );
}

#[tokio::test]
async fn oidc_login_uses_secure_runtime_setting_for_transient_cookies() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "secure-transient",
        "email": "secure-transient@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut security = state.settings().await.unwrap().security;
    security.secure_cookies = true;
    state
        .db
        .set_json_setting("security", &security)
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    for name in [
        "midden_oidc_state",
        "midden_oidc_nonce",
        "midden_oidc_purpose",
    ] {
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with(&format!("{name}=")) && cookie.contains("Secure")),
            "{name} cookie should be Secure"
        );
    }
}

#[tokio::test]
async fn private_raw_files_are_not_public_cacheable() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let user = state
        .db
        .create_user(
            "private-cache@example.test",
            "private-cache",
            Some("hash"),
            Role::User,
        )
        .await
        .unwrap();
    let bytes = Bytes::from_static(b"private cache");
    let hash = util::sha256_hex_bytes(&bytes);
    state
        .db
        .create_blob_if_missing(&hash, bytes.len() as i64, Some("text/plain"))
        .await
        .unwrap();
    state.storage.put_blob(&hash, bytes).await.unwrap();
    state
        .db
        .create_file_item(NewFileItem {
            id: &uuid::Uuid::new_v4().to_string(),
            public_id: "private-cache-file",
            blob_hash: &hash,
            original_filename: Some("private.txt"),
            extension: Some("txt"),
            content_type: Some("text/plain"),
            size_bytes: 13,
            image_width: None,
            image_height: None,
            owner_user_id: Some(&user.id),
            delete_token_hash: None,
            expires_at: None,
            visibility: "private",
            metadata_json: None,
            thumbnail_hash: None,
            state: "active",
        })
        .await
        .unwrap();
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &user.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(
            Request::builder()
                .uri("/files/private-cache-file/raw")
                .header(header::COOKIE, format!("midden_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(
        response.headers()[header::CACHE_CONTROL].to_str().unwrap(),
        "public, max-age=31536000"
    );
    assert!(
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("private")
    );
}

#[tokio::test]
async fn account_bulk_delete_dedupes_file_ids_before_releasing_blobs() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let user = state
        .db
        .create_user(
            "bulk-owner@example.test",
            "bulk-owner",
            Some("hash"),
            Role::User,
        )
        .await
        .unwrap();
    let bytes = Bytes::from_static(b"shared bytes");
    let hash = util::sha256_hex_bytes(&bytes);
    state
        .db
        .create_blob_if_missing(&hash, bytes.len() as i64, Some("text/plain"))
        .await
        .unwrap();
    state.storage.put_blob(&hash, bytes).await.unwrap();
    for public_id in ["bulk-one", "bulk-two"] {
        state
            .db
            .create_file_item(NewFileItem {
                id: &uuid::Uuid::new_v4().to_string(),
                public_id,
                blob_hash: &hash,
                original_filename: Some("bulk.txt"),
                extension: Some("txt"),
                content_type: Some("text/plain"),
                size_bytes: 12,
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
    }
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &user.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/items/bulk")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("midden_session={session_token}; midden_csrf={csrf}"),
                )
                .body(Body::from(format!(
                    "bulk_action=delete&file_ids=bulk-one&file_ids=bulk-one&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(state.db.blob_ref_count(&hash).await.unwrap(), 1);
    assert!(state.storage.exists(&hash).await.unwrap());
    assert!(
        state
            .db
            .active_file_by_public_id("bulk-two")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn account_token_jobs_and_thumbnail_surfaces_are_available() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-surfaces",
        "email": "unused-surfaces@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut processing = state.settings().await.unwrap().processing;
    processing.thumbnails = true;
    processing.thumbnail_max_dimension = 12;
    state
        .db
        .set_json_setting("processing", &processing)
        .await
        .unwrap();

    let (admin, admin_token) = user_with_api_token(
        &state,
        "surface-admin@example.test",
        "surface-admin",
        Role::Admin,
        &["files:write", "files:read", "tokens:write", "tokens:read"],
    )
    .await;
    let session_token = util::secret_token();
    state
        .db
        .create_session(
            &admin.id,
            &util::hash_token(&session_token),
            util::now_ts() + 60,
        )
        .await
        .unwrap();
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let account = client
        .get(format!("{base}/account"))
        .header(header::COOKIE, format!("midden_session={session_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(account.status(), StatusCode::OK);
    let account = account.text().await.unwrap();
    assert!(account.contains("name=\"bulk_action\""));
    assert!(account.contains("Delete selected items?"));
    assert!(account.contains("class=\"settings-tabs\""));
    assert!(!account.contains("role=\"tablist\""));
    assert!(!account.contains("aria-selected"));
    assert!(account.contains("name=\"expires_in_seconds\""));

    let jobs = client
        .get(format!("{base}/admin/jobs"))
        .header(header::COOKIE, format!("midden_session={session_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(jobs.status(), StatusCode::OK);
    let jobs = jobs.text().await.unwrap();
    assert!(jobs.contains("Background jobs"));
    assert!(jobs.contains("Run once"));

    let token = client
        .post(format!("{base}/api/v1/tokens"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "short-lived",
            "scopes": ["files:read"],
            "expires_in_seconds": 1
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let token: serde_json::Value = token.json().await.unwrap();
    assert!(token["expires_at"].as_i64().is_some());

    let png = hex_fixture(include_str!("../../tests/fixtures/sample.png.hex"));
    let upload = client
        .post(format!("{base}/api/v1/files"))
        .bearer_auth(&admin_token)
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(png)
                    .file_name("thumb.png")
                    .mime_str("image/png")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let upload: serde_json::Value = upload.json().await.unwrap();
    let file_id = upload["id"].as_str().unwrap().to_string();
    jobs::run_once(&state, &state.settings().await.unwrap())
        .await
        .unwrap();
    let file = state.db.file_by_public_id(&file_id).await.unwrap();
    assert!(file.thumbnail_hash.is_some());
    assert_ne!(
        file.thumbnail_hash.as_deref(),
        Some(file.blob_hash.as_str())
    );

    let files = client
        .get(format!("{base}/api/v1/me/files"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(files.status(), StatusCode::OK);
    let files: serde_json::Value = files.json().await.unwrap();
    let item = files["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"].as_str() == Some(file_id.as_str()))
        .unwrap();
    let raw_url = item["raw_url"].as_str().unwrap();
    let thumbnail_url = item["thumbnail_url"].as_str().unwrap();
    assert_ne!(thumbnail_url, raw_url);

    let thumbnail_path = url::Url::parse(thumbnail_url).unwrap().path().to_string();
    let thumbnail = client
        .get(format!("{base}{thumbnail_path}"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(thumbnail.status(), StatusCode::OK);
    assert_eq!(
        thumbnail.headers()[header::CONTENT_TYPE].to_str().unwrap(),
        "image/png"
    );
}

#[tokio::test]
async fn quarantined_uploads_count_toward_usage_and_expire() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut settings = state.settings().await.unwrap();
    settings.scanning.enabled = true;
    #[cfg(windows)]
    let (program, args) = (
        "cmd".to_string(),
        vec!["/C".to_string(), "exit 10".to_string()],
    );
    #[cfg(not(windows))]
    let (program, args) = (
        "sh".to_string(),
        vec!["-c".to_string(), "exit 10".to_string()],
    );
    settings.scanning.adapters =
        vec![crate::config::ScannerAdapterConfig::Command { program, args }];
    state
        .db
        .set_json_setting("scanning", &settings.scanning)
        .await
        .unwrap();
    let (user, token) = user_with_api_token(
        &state,
        "quarantine-owner@example.test",
        "quarantine-owner",
        Role::User,
        &["files:write"],
    )
    .await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .bearer_auth(&token)
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"quarantine me".to_vec())
                    .file_name("quarantine-me.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::BAD_REQUEST);

    let files = state.db.admin_search_files("quarantine-me").await.unwrap();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert_eq!(file.state, "quarantined");
    assert_eq!(
        state
            .db
            .file_usage_for_user(Some(&user.id))
            .await
            .unwrap()
            .storage_bytes,
        file.size_bytes
    );

    state
        .db
        .apply_account_bulk(&crate::domain::AccountBulkPlan {
            owner_user_id: user.id.clone(),
            file_ids: vec![file.public_id.clone()],
            paste_ids: Vec::new(),
            action: crate::domain::AccountBulkAction::SetExpiry {
                file_expires_at: Some(util::now_ts() - 1),
                paste_expires_at: Some(util::now_ts() - 1),
            },
            allow_delete_any_owner: false,
        })
        .await
        .unwrap()
        .unwrap();
    let summary = jobs::cleanup_expired(&state).await.unwrap();
    assert_eq!(summary.expired_files, 1);
    assert!(!state.storage.exists(&file.blob_hash).await.unwrap());
}

#[tokio::test]
async fn background_cleanup_retries_retained_zero_ref_blobs() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let bytes = Bytes::from_static(b"retained zero ref");
    let hash = util::sha256_hex_bytes(&bytes);
    state
        .db
        .create_blob_if_missing(&hash, 17, Some("text/plain"))
        .await
        .unwrap();
    state.storage.put_blob(&hash, bytes).await.unwrap();

    let summary = jobs::cleanup_expired(&state).await.unwrap();
    assert_eq!(summary.deleted_blobs, 1);
    assert!(!state.storage.exists(&hash).await.unwrap());
    assert!(
        !state
            .db
            .zero_ref_blob_hashes()
            .await
            .unwrap()
            .contains(&hash)
    );
}

#[tokio::test]
async fn failed_publication_compensation_removes_storage_only_orphans() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let bytes = Bytes::from_static(b"unpublished orphan");
    let hash = util::sha256_hex_bytes(&bytes);
    state.storage.put_blob(&hash, bytes).await.unwrap();
    assert!(state.storage.exists(&hash).await.unwrap());

    assert!(crate::commands::cleanup_zero_ref_blob(&state.db, &state.storage, &hash).await);
    assert!(!state.storage.exists(&hash).await.unwrap());
}

#[tokio::test]
async fn failed_upload_publication_compensates_the_new_storage_object() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    state
        .db
        .install_file_insert_failure_for_test()
        .await
        .unwrap();
    let bytes = b"publication must fail";
    let hash = util::sha256_hex(bytes);
    let base = spawn_http_app(state.clone()).await;

    let response = reqwest::Client::new()
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(bytes.to_vec())
                    .file_name("failed.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!state.storage.exists(&hash).await.unwrap());
    assert!(state.db.blob_ref_count(&hash).await.is_err());
}

#[tokio::test]
async fn moderation_delete_releases_storage_and_terminal_files_cannot_reactivate() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let file = create_test_file(
        &state,
        "moderation-delete-file",
        "moderation-delete.txt",
        "text/plain",
        b"moderation deletion",
    )
    .await;
    assert_eq!(state.db.blob_ref_count(&file.blob_hash).await.unwrap(), 1);

    let mut delete_plan = crate::domain::ItemModerationPlan::new(
        crate::domain::ItemKind::File,
        file.public_id.clone(),
    );
    delete_plan.state = Some(crate::domain::ItemState::Deleted);
    crate::commands::moderate_item(
        &state,
        &state.settings().await.unwrap(),
        None,
        delete_plan,
        "moderation delete regression",
    )
    .await
    .unwrap();

    assert_eq!(
        state
            .db
            .file_by_public_id(&file.public_id)
            .await
            .unwrap()
            .state,
        "deleted"
    );
    assert!(!state.storage.exists(&file.blob_hash).await.unwrap());
    assert!(state.db.blob_ref_count(&file.blob_hash).await.is_err());
    let audit_count = state
        .db
        .audit_events_for_target(&file.public_id)
        .await
        .unwrap()
        .len();

    let mut reactivate_plan = crate::domain::ItemModerationPlan::new(
        crate::domain::ItemKind::File,
        file.public_id.clone(),
    );
    reactivate_plan.state = Some(crate::domain::ItemState::Active);
    reactivate_plan.visibility = Some(crate::domain::ItemVisibility::Private);
    reactivate_plan.note = Some("must roll back with terminal transition".to_string());
    let result = crate::commands::moderate_item(
        &state,
        &state.settings().await.unwrap(),
        None,
        reactivate_plan,
        "invalid resurrection regression",
    )
    .await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    assert_eq!(
        state
            .db
            .file_by_public_id(&file.public_id)
            .await
            .unwrap()
            .state,
        "deleted"
    );
    assert_eq!(
        state
            .db
            .file_by_public_id(&file.public_id)
            .await
            .unwrap()
            .visibility,
        file.visibility
    );
    assert_eq!(
        state
            .db
            .audit_events_for_target(&file.public_id)
            .await
            .unwrap()
            .len(),
        audit_count
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("file", &file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn report_actions_cannot_resurrect_terminal_files_or_partially_resolve_reports() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let file = create_test_file(
        &state,
        "terminal-report-file",
        "terminal-report.txt",
        "text/plain",
        b"terminal report",
    )
    .await;
    state
        .db
        .create_report("file", &file.public_id, None, "abuse", "terminal race")
        .await
        .unwrap();
    let report = state
        .db
        .reports_for_item("file", &file.public_id)
        .await
        .unwrap()
        .pop()
        .unwrap();

    let mut delete_plan = crate::domain::ItemModerationPlan::new(
        crate::domain::ItemKind::File,
        file.public_id.clone(),
    );
    delete_plan.state = Some(crate::domain::ItemState::Deleted);
    crate::commands::moderate_item(
        &state,
        &state.settings().await.unwrap(),
        None,
        delete_plan,
        "terminal report setup",
    )
    .await
    .unwrap();

    let result = crate::commands::moderate_reports(
        &state,
        std::slice::from_ref(&report.id),
        crate::domain::ReportAction::Quarantine,
        None,
        Some("must not persist"),
    )
    .await;
    assert!(matches!(result, Err(AppError::NotFound)));
    assert_eq!(
        state
            .db
            .file_by_public_id(&file.public_id)
            .await
            .unwrap()
            .state,
        "deleted"
    );
    assert_eq!(
        state
            .db
            .reports_for_item("file", &file.public_id)
            .await
            .unwrap()[0]
            .state,
        "open"
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("file", &file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn missing_report_in_bulk_action_rolls_back_every_side_effect() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let file = create_test_file(
        &state,
        "report-rollback-file",
        "rollback.txt",
        "text/plain",
        b"rollback report",
    )
    .await;
    state
        .db
        .create_report("file", &file.public_id, None, "abuse", "rollback")
        .await
        .unwrap();
    let report = state
        .db
        .reports_for_item("file", &file.public_id)
        .await
        .unwrap()
        .pop()
        .unwrap();

    let result = crate::commands::moderate_reports(
        &state,
        &[report.id.clone(), "missing-report".to_string()],
        crate::domain::ReportAction::Quarantine,
        None,
        Some("must not persist"),
    )
    .await;
    assert!(matches!(result, Err(AppError::NotFound)));

    assert_eq!(
        state
            .db
            .reports_for_item("file", &file.public_id)
            .await
            .unwrap()[0]
            .state,
        "open"
    );
    assert_eq!(
        state
            .db
            .file_by_public_id(&file.public_id)
            .await
            .unwrap()
            .state,
        "active"
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("file", &file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        state
            .db
            .audit_events_for_target(&file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn handled_report_in_bulk_action_rejects_and_rolls_back_open_reports() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let first_file = create_test_file(
        &state,
        "handled-report-file",
        "handled.txt",
        "text/plain",
        b"handled report",
    )
    .await;
    let second_file = create_test_file(
        &state,
        "still-open-report-file",
        "open.txt",
        "text/plain",
        b"still open report",
    )
    .await;
    for file in [&first_file, &second_file] {
        state
            .db
            .create_report("file", &file.public_id, None, "abuse", "bulk race")
            .await
            .unwrap();
    }
    let first_report = state
        .db
        .reports_for_item("file", &first_file.public_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let second_report = state
        .db
        .reports_for_item("file", &second_file.public_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    crate::commands::moderate_reports(
        &state,
        std::slice::from_ref(&first_report.id),
        crate::domain::ReportAction::Resolve,
        None,
        None,
    )
    .await
    .unwrap();

    let result = crate::commands::moderate_reports(
        &state,
        &[first_report.id, second_report.id],
        crate::domain::ReportAction::Quarantine,
        None,
        Some("must roll back"),
    )
    .await;
    assert!(matches!(result, Err(AppError::NotFound)));
    assert_eq!(
        state
            .db
            .reports_for_item("file", &second_file.public_id)
            .await
            .unwrap()[0]
            .state,
        "open"
    );
    assert_eq!(
        state
            .db
            .file_by_public_id(&second_file.public_id)
            .await
            .unwrap()
            .state,
        "active"
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("file", &second_file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn invalid_admin_mutations_do_not_apply_earlier_fields_or_notes() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let (_admin, token) = user_with_api_token(
        &state,
        "rollback-admin@example.test",
        "rollback-admin",
        Role::Admin,
        &["admin:reports", "admin:items"],
    )
    .await;
    let file = create_test_file(
        &state,
        "invalid-report-action-file",
        "invalid.txt",
        "text/plain",
        b"invalid report action",
    )
    .await;
    state
        .db
        .create_report("file", &file.public_id, None, "abuse", "invalid action")
        .await
        .unwrap();
    let report = state
        .db
        .reports_for_item("file", &file.public_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let paste = state
        .db
        .create_paste(crate::db::NewPaste {
            id: &uuid::Uuid::new_v4().to_string(),
            public_id: "combined-invalid-paste",
            title: Some("Combined invalid mutation"),
            content: "do not mutate",
            syntax: Some("text"),
            owner_user_id: None,
            delete_token_hash: None,
            expires_at: None,
            visibility: "unlisted",
        })
        .await
        .unwrap();
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let invalid_report = client
        .patch(format!("{base}/api/v1/admin/reports/{}", report.id))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "action": "not-an-action",
            "note": "must not persist"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_report.status(), StatusCode::BAD_REQUEST);

    let invalid_item = client
        .patch(format!(
            "{base}/api/v1/admin/items/paste/{}",
            paste.public_id
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "state": "quarantined",
            "note": "must also roll back",
            "block_hash": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_item.status(), StatusCode::BAD_REQUEST);

    assert_eq!(
        state
            .db
            .reports_for_item("file", &file.public_id)
            .await
            .unwrap()[0]
            .state,
        "open"
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("file", &file.public_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        state
            .db
            .paste_by_public_id_any(&paste.public_id)
            .await
            .unwrap()
            .state,
        "active"
    );
    assert!(
        state
            .db
            .moderation_notes_for_item("paste", &paste.public_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn concurrent_uploads_cannot_race_past_storage_quota() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let (user, token) = user_with_api_token(
        &state,
        "quota-race@example.test",
        "quota-race",
        Role::User,
        &["files:write"],
    )
    .await;
    let mut limits = state.settings().await.unwrap().limits;
    limits.role_quotas.insert(
        "user".to_string(),
        crate::config::QuotaConfig {
            storage_bytes: Some(11),
            ..Default::default()
        },
    );
    state.db.set_json_setting("limits", &limits).await.unwrap();
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let upload_a = client
        .post(format!("{base}/api/v1/files"))
        .bearer_auth(&token)
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"aaaaaa".to_vec())
                    .file_name("a.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send();
    let upload_b = client
        .post(format!("{base}/api/v1/files"))
        .bearer_auth(&token)
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"bbbbbb".to_vec())
                    .file_name("b.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send();

    let (response_a, response_b) = tokio::join!(upload_a, upload_b);
    let mut statuses = vec![response_a.unwrap().status(), response_b.unwrap().status()];
    statuses.sort();
    assert_eq!(
        statuses,
        vec![StatusCode::OK, StatusCode::PAYLOAD_TOO_LARGE]
    );

    let usage = state.db.file_usage_for_user(Some(&user.id)).await.unwrap();
    assert_eq!(usage.storage_bytes, 6);
    assert_eq!(usage.item_count, 1);
}

#[tokio::test]
async fn url_upload_stops_streaming_after_response_byte_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let chunks_written = Arc::new(AtomicUsize::new(0));
    let chunks_for_task = chunks_written.clone();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        let headers = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n";
        if stream.write_all(headers.as_bytes()).await.is_err() {
            return;
        }
        for _ in 0..10 {
            if stream.write_all(b"abcd").await.is_err() {
                return;
            }
            chunks_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });

    let mut settings = RuntimeSettings::from_config(&crate::config::AppConfig::default());
    settings.security.url_upload.block_private_ips = false;
    settings.security.url_upload.max_response_bytes = Some(8);
    let result = fetch_url_upload(
        &settings,
        url::Url::parse(&format!("http://{addr}/")).unwrap(),
    )
    .await;

    assert!(matches!(result, Err(AppError::PayloadTooLarge)));
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert!(chunks_written.load(Ordering::SeqCst) < 10);
}

#[tokio::test]
async fn public_browse_only_lists_items_marked_public() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-browse",
        "email": "unused-browse@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut features = state.settings().await.unwrap().features;
    features.public_browse = true;
    state
        .db
        .set_json_setting("features", &features)
        .await
        .unwrap();
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    for (name, visibility) in [("listed.txt", "public"), ("hidden.txt", "unlisted")] {
        let upload = client
            .post(format!("{base}/api/v1/files"))
            .multipart(
                reqwest::multipart::Form::new()
                    .text("visibility", visibility.to_string())
                    .part(
                        "file",
                        reqwest::multipart::Part::bytes(format!("{name} body").into_bytes())
                            .file_name(name.to_string())
                            .mime_str("text/plain")
                            .unwrap(),
                    ),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(upload.status(), StatusCode::OK);
    }

    let browse = client
        .get(format!("{base}/browse"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(browse.contains("listed.txt"));
    assert!(!browse.contains("hidden.txt"));
}

#[tokio::test]
async fn signed_internal_urls_and_cache_headers_are_served_when_enabled() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-signed",
        "email": "unused-signed@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut delivery = state.settings().await.unwrap().delivery;
    delivery.public_cache_seconds = 42;
    delivery.static_cache_seconds = 84;
    delivery.signed_internal_urls = true;
    delivery.internal_url_secret = Some("test-secret".to_string());
    delivery.internal_url_ttl_seconds = 60;
    state
        .db
        .set_json_setting("delivery", &delivery)
        .await
        .unwrap();
    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"cache me".to_vec())
                    .file_name("cache.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let upload: serde_json::Value = upload.json().await.unwrap();
    let file_id = upload["id"].as_str().unwrap();
    let internal_url = upload["internal_url"].as_str().unwrap();
    let internal = url::Url::parse(internal_url).unwrap();
    let internal_path = match internal.query() {
        Some(query) => format!("{}?{query}", internal.path()),
        None => internal.path().to_string(),
    };

    let raw = client
        .get(format!("{base}/files/{file_id}/raw"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    assert_eq!(
        raw.headers()["cache-control"].to_str().unwrap(),
        "public, max-age=42"
    );

    let internal = client
        .get(format!("{base}{internal_path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(internal.status(), StatusCode::OK);
    assert_eq!(internal.bytes().await.unwrap().as_ref(), b"cache me");

    let static_asset = client
        .get(format!("{base}/static/midden.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(static_asset.status(), StatusCode::OK);
    assert_eq!(
        static_asset.headers()["cache-control"].to_str().unwrap(),
        "public, max-age=84"
    );
}

#[tokio::test]
async fn oidc_callback_provisions_with_allowed_claims_and_role_mapping() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-1",
        "email": "oidc@example.test",
        "preferred_username": "oidc-user",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer.clone()).await;
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/callback?code=abc&state=state-1")
                .header(
                    header::COOKIE,
                    "midden_oidc_state=state-1; midden_oidc_purpose=login",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let user = state.db.user_by_email("oidc@example.test").await.unwrap();
    assert_eq!(user.role, Role::Admin);
    assert!(
        state
            .db
            .user_by_oidc_identity(&issuer, "subject-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn oidc_callback_requires_explicit_link_for_existing_local_user() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-2",
        "email": "local@example.test",
        "preferred_username": "local",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer.clone()).await;
    state
        .db
        .create_user(
            "local@example.test",
            "local",
            Some("password-hash"),
            Role::User,
        )
        .await
        .unwrap();
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/callback?code=abc&state=state-2")
                .header(
                    header::COOKIE,
                    "midden_oidc_state=state-2; midden_oidc_purpose=login",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .db
            .user_by_oidc_identity(&issuer, "subject-2")
            .await
            .unwrap()
            .is_none()
    );
}

async fn session_token_for(state: &AppState, user: &crate::db::User) -> String {
    let token = util::secret_token();
    state
        .db
        .create_session(&user.id, &util::hash_token(&token), util::now_ts() + 3600)
        .await
        .unwrap();
    token
}

async fn session_is_live(state: &AppState, token: &str) -> bool {
    state
        .db
        .user_by_session_token(&util::hash_token(token))
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn password_reset_revokes_sessions_opened_before_it() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let user = state
        .db
        .create_user(
            "reset-sessions@example.test",
            "reset-sessions",
            Some(&util::hash_password("old password").await.unwrap()),
            Role::User,
        )
        .await
        .unwrap();
    let stolen = session_token_for(&state, &user).await;
    let reset = util::secret_token();
    state
        .db
        .create_password_reset_token(&user.id, &util::hash_token(&reset), util::now_ts() + 3600)
        .await
        .unwrap();
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/auth/password-reset/{reset}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("midden_csrf={csrf}"))
                .body(Body::from(format!(
                    "password=brand%20new%20password&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        !session_is_live(&state, &stolen).await,
        "resetting a password must not leave earlier sessions usable"
    );
}

#[tokio::test]
async fn password_change_revokes_other_sessions_but_keeps_the_current_one() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let user = state
        .db
        .create_user(
            "change-sessions@example.test",
            "change-sessions",
            Some(&util::hash_password("old password").await.unwrap()),
            Role::User,
        )
        .await
        .unwrap();
    let stolen = session_token_for(&state, &user).await;
    let current = session_token_for(&state, &user).await;
    let csrf = util::secret_token();

    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("midden_csrf={csrf}; midden_session={current}"),
                )
                .body(Body::from(format!(
                    "current_password=old%20password&new_password=brand%20new%20password&csrf_token={csrf}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        !session_is_live(&state, &stolen).await,
        "changing a password must revoke other sessions"
    );
    assert!(
        session_is_live(&state, &current).await,
        "the session performing the change should stay signed in"
    );
}

#[tokio::test]
async fn password_reset_requests_look_identical_for_known_and_unknown_emails() {
    let state = test_state_with("http://127.0.0.1".to_string(), |config| {
        // Enabled but unreachable: delivery failures must not become an existence oracle.
        config.smtp.enabled = true;
        config.smtp.host = Some("127.0.0.1".to_string());
        config.smtp.port = Some(1);
        config.smtp.from = Some("midden@example.test".to_string());
    })
    .await;
    state
        .db
        .create_user(
            "known@example.test",
            "known",
            Some("password-hash"),
            Role::User,
        )
        .await
        .unwrap();
    let csrf = util::secret_token();

    let mut statuses = Vec::new();
    for email in ["known%40example.test", "missing%40example.test"] {
        let response = state
            .clone()
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/password-reset")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, format!("midden_csrf={csrf}"))
                    .body(Body::from(format!("email={email}&csrf_token={csrf}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        statuses.push(response.status());
    }

    assert_eq!(
        statuses[0], statuses[1],
        "a failing mail send for a real account must not be distinguishable"
    );
    assert_eq!(statuses[0], StatusCode::OK);
}

async fn oidc_callback(state: &AppState, cookie_state: &str) -> Response {
    state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/oidc/callback?code=abc&state={cookie_state}"))
                .header(
                    header::COOKIE,
                    format!("midden_oidc_state={cookie_state}; midden_oidc_purpose=login"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn oidc_login_keeps_roles_that_have_no_claim_mapping() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-keep-role",
        "email": "moderator@example.test",
        "preferred_username": "moderator",
        // Carries no group that appears in role_mappings.
        "groups": ["staff"]
    }))
    .await;
    let state = test_state_with(issuer.clone(), |config| {
        config.oidc.allowed_groups.push("staff".to_string());
    })
    .await;
    let user = state
        .db
        .create_user("moderator@example.test", "moderator", None, Role::Moderator)
        .await
        .unwrap();
    state
        .db
        .link_oidc_identity(&user.id, &issuer, "subject-keep-role", "moderator@example.test")
        .await
        .unwrap();

    assert_eq!(
        oidc_callback(&state, "state-keep-role").await.status(),
        StatusCode::SEE_OTHER
    );

    let user = state
        .db
        .user_by_email("moderator@example.test")
        .await
        .unwrap();
    assert_eq!(
        user.role,
        Role::Moderator,
        "an unmapped OIDC login must not silently demote a privileged account"
    );
}

#[tokio::test]
async fn oidc_login_still_applies_a_matching_role_mapping() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-apply-role",
        "email": "promoted@example.test",
        "preferred_username": "promoted",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer.clone()).await;
    let user = state
        .db
        .create_user("promoted@example.test", "promoted", None, Role::User)
        .await
        .unwrap();
    state
        .db
        .link_oidc_identity(&user.id, &issuer, "subject-apply-role", "promoted@example.test")
        .await
        .unwrap();

    assert_eq!(
        oidc_callback(&state, "state-apply-role").await.status(),
        StatusCode::SEE_OTHER
    );

    assert_eq!(
        state
            .db
            .user_by_email("promoted@example.test")
            .await
            .unwrap()
            .role,
        Role::Admin
    );
}

#[tokio::test]
async fn oidc_login_refuses_to_adopt_an_account_on_an_unverified_email() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-unverified",
        "email": "owner@example.test",
        "email_verified": false,
        "preferred_username": "owner",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer.clone()).await;
    // A passwordless owner, as `midden owner create` leaves one when no password is given.
    state
        .db
        .upsert_owner("owner@example.test", "owner", None)
        .await
        .unwrap();

    assert_eq!(
        oidc_callback(&state, "state-unverified").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        state
            .db
            .user_by_oidc_identity(&issuer, "subject-unverified")
            .await
            .unwrap()
            .is_none(),
        "an unverified provider email must not take over an existing account"
    );
}

#[tokio::test]
async fn oidc_login_adopts_a_passwordless_account_on_a_verified_email() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "subject-verified",
        "email": "verified@example.test",
        "email_verified": true,
        "preferred_username": "verified",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer.clone()).await;
    state
        .db
        .create_user("verified@example.test", "verified", None, Role::User)
        .await
        .unwrap();

    assert_eq!(
        oidc_callback(&state, "state-verified").await.status(),
        StatusCode::SEE_OTHER
    );
    assert!(
        state
            .db
            .user_by_oidc_identity(&issuer, "subject-verified")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn base_template_renders_custom_expiry_presets() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-presets",
        "email": "unused-presets@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let mut settings = state.settings().await.unwrap();
    settings.limits.expiry.allowed_presets = vec!["3h".to_string(), "9d".to_string()];
    settings.limits.expiry.allow_never = false;
    state
        .db
        .set_json_setting("limits", &settings.limits)
        .await
        .unwrap();

    let response = state
        .router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(!body.contains("<option value=\"never\">"));
    assert!(body.contains("<option value=\"3h\">"));
    assert!(body.contains("<option value=\"9d\">"));
}

async fn spawn_webhook_provider() -> (String, tokio::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0_u8; 4096];
            if let Ok(read) = stream.read(&mut buffer).await {
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let _ = tx.send(request).await;
                let response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    });
    (format!("http://{addr}"), rx)
}

#[tokio::test]
async fn moderation_webhook_notifies_external_service() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-webhook",
        "email": "unused-webhook@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let (webhook_url, mut rx) = spawn_webhook_provider().await;
    let mut settings = state.settings().await.unwrap();
    settings.moderation.notify_webhook_url = Some(webhook_url);
    settings.moderation.notify_webhook_secret = Some("my-secret".to_string());
    state
        .db
        .set_json_setting("moderation", &settings.moderation)
        .await
        .unwrap();

    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let upload: serde_json::Value = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"reportable".to_vec())
                    .file_name("reportable.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let file_id = upload["id"].as_str().unwrap().to_string();

    let response = client
        .post(format!("{base}/api/v1/reports"))
        .json(&serde_json::json!({
            "kind": "file",
            "id": file_id,
            "reason": "abuse",
            "details": "webhook test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let request_str = rx.recv().await.expect("webhook not received");
    assert!(request_str.contains("x-midden-moderation-secret: my-secret"));
    assert!(request_str.contains("\"kind\":\"file\""));
    assert!(request_str.contains(&format!("\"id\":\"{file_id}\"")));
    assert!(request_str.contains("\"reason\":\"abuse\""));
    assert!(request_str.contains("\"details\":\"webhook test\""));
}

#[tokio::test]
async fn reports_for_unknown_items_are_rejected() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let base = spawn_http_app(state).await;

    assert_eq!(
        reqwest::Client::new()
            .post(format!("{base}/api/v1/reports"))
            .json(&serde_json::json!({
                "kind": "file",
                "id": "never-existed",
                "reason": "abuse",
                "details": ""
            }))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "reports must name a real item so the moderation queue stays actionable"
    );
}

#[tokio::test]
async fn uploads_uses_configured_temp_dir() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-temp-dir",
        "email": "unused-temp-dir@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let custom_temp =
        std::env::temp_dir().join(format!("midden-custom-temp-{}", util::public_id()));
    let mut settings = state.settings().await.unwrap();
    settings.uploads.temp_dir = Some(custom_temp.clone());
    state
        .db
        .set_json_setting("uploads", &settings.uploads)
        .await
        .unwrap();

    let _ = tokio::fs::remove_dir_all(&custom_temp).await;

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(b"hello world".to_vec())
                    .file_name("hello.txt")
                    .mime_str("text/plain")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    assert!(custom_temp.exists());
    let _ = tokio::fs::remove_dir_all(&custom_temp).await;
}

#[tokio::test]
async fn upload_large_file() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-large-file",
        "email": "unused-large-file@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;
    let base = spawn_http_app(state.clone()).await;
    let client = reqwest::Client::new();

    let large_data = vec![0u8; 2_621_440]; // 2.5 MB

    let upload = client
        .post(format!("{base}/api/v1/files"))
        .multipart(
            reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(large_data)
                    .file_name("large.bin")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            ),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_upload_shows_notice() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-notice-upload",
        "email": "unused-notice-upload@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;

    // Set policy to require authenticated users for file uploads and enable upload_by_url
    let mut settings = state.settings().await.unwrap();
    settings.policy.upload_file = ActionRule::Authenticated;
    settings.features.upload_by_url = true;
    state
        .db
        .set_json_setting("policy", &settings.policy)
        .await
        .unwrap();
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();

    let router = state.router();

    // GET / (index page) should return OK but contain the notice and not the form help
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("An account is required to upload files on this instance."));
    assert!(!body.contains("Choose a file, then keep this tab open"));

    // GET /url-upload should return OK but contain the notice and not the fetch form
    let response_url = router
        .oneshot(
            Request::builder()
                .uri("/url-upload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_url.status(), StatusCode::OK);
    let body_url = response_body(response_url).await;
    assert!(body_url.contains("An account is required to upload files on this instance."));
    assert!(!body_url.contains("Fetch and upload"));
}

#[tokio::test]
async fn unauthenticated_paste_shows_notice() {
    let issuer = spawn_oidc_provider(serde_json::json!({
        "sub": "unused-notice-paste",
        "email": "unused-notice-paste@example.test",
        "groups": ["admins"]
    }))
    .await;
    let state = test_state(issuer).await;

    // Set policy to require authenticated users for paste creation
    let mut policy = state.settings().await.unwrap().policy;
    policy.create_paste = ActionRule::Authenticated;
    state.db.set_json_setting("policy", &policy).await.unwrap();

    let router = state.router();

    // GET /p/new should return OK (not FORBIDDEN) and contain the notice
    let response = router
        .oneshot(
            Request::builder()
                .uri("/p/new")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert!(body.contains("An account is required to create pastes on this instance."));
    assert!(!body.contains("Create paste"));
}

#[tokio::test]
async fn test_local_login_disabled_blocks_endpoints() {
    let state = test_state("http://127.0.0.1".to_string()).await;
    let mut settings = state.settings().await.unwrap();
    settings.features.local_login = false;
    state
        .db
        .set_json_setting("features", &settings.features)
        .await
        .unwrap();

    let base = spawn_http_app(state).await;
    let client = reqwest::Client::new();

    // 1. POST /auth/login returns 403 Forbidden
    let login_res = client
        .post(format!("{base}/auth/login"))
        .form(&[("email", "test@example.com"), ("password", "password")])
        .send()
        .await
        .unwrap();
    assert_eq!(login_res.status(), StatusCode::FORBIDDEN);

    // 2. GET /register returns 403 Forbidden
    let reg_form_res = client.get(format!("{base}/register")).send().await.unwrap();
    assert_eq!(reg_form_res.status(), StatusCode::FORBIDDEN);

    // 3. POST /register returns 403 Forbidden
    let reg_res = client
        .post(format!("{base}/register"))
        .form(&[
            ("email", "test@example.com"),
            ("username", "test"),
            ("password", "password"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(reg_res.status(), StatusCode::FORBIDDEN);

    // 4. GET /auth/password-reset returns 403 Forbidden
    let reset_req_form_res = client
        .get(format!("{base}/auth/password-reset"))
        .send()
        .await
        .unwrap();
    assert_eq!(reset_req_form_res.status(), StatusCode::FORBIDDEN);

    // 5. POST /auth/password-reset returns 403 Forbidden
    let reset_req_res = client
        .post(format!("{base}/auth/password-reset"))
        .form(&[("email", "test@example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(reset_req_res.status(), StatusCode::FORBIDDEN);

    // 6. GET /auth/password-reset/token returns 403 Forbidden
    let reset_form_res = client
        .get(format!("{base}/auth/password-reset/mock-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(reset_form_res.status(), StatusCode::FORBIDDEN);

    // 7. POST /auth/password-reset/token returns 403 Forbidden
    let reset_submit_res = client
        .post(format!("{base}/auth/password-reset/mock-token"))
        .form(&[("password", "new-password")])
        .send()
        .await
        .unwrap();
    assert_eq!(reset_submit_res.status(), StatusCode::FORBIDDEN);
}
