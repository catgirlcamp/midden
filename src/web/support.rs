use super::*;

pub(super) enum CacheScope {
    Public,
    Private,
}

pub(super) fn insert_cache_control(response: &mut Response, seconds: u64, scope: CacheScope) {
    let value = match scope {
        CacheScope::Private => HeaderValue::from_static("private, no-store"),
        CacheScope::Public if seconds == 0 => HeaderValue::from_static("no-store"),
        CacheScope::Public => HeaderValue::from_str(&format!("public, max-age={seconds}"))
            .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=3600")),
    };
    response.headers_mut().insert(header::CACHE_CONTROL, value);
}

pub(super) fn app_base_url(state: &AppState) -> String {
    state
        .config
        .server
        .public_base_url
        .trim_end_matches('/')
        .to_string()
}

pub(super) fn file_base_url(state: &AppState, settings: &RuntimeSettings) -> String {
    settings
        .delivery
        .public_file_base_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or(&state.config.server.public_base_url)
        .trim_end_matches('/')
        .to_string()
}

/// Whether viewing this file requires a signed-in caller.
///
/// A separate file domain is a separate origin, so the browser never sends it the session cookie
/// and no request arriving there can be authorised. Anything that needs a session therefore has to
/// stay on the application origin.
pub(super) fn file_needs_app_origin(settings: &RuntimeSettings, file: &FileItem) -> bool {
    file.visibility == "private" || !matches!(settings.policy.view_item, ActionRule::Anonymous)
}

/// The origin that is actually able to serve this file's bytes.
pub(super) fn file_origin(state: &AppState, settings: &RuntimeSettings, file: &FileItem) -> String {
    if file_needs_app_origin(settings, file) {
        app_base_url(state)
    } else {
        file_base_url(state, settings)
    }
}

/// The canonical link for a file: the preview page when there is one, the bytes otherwise.
pub(super) fn file_url(state: &AppState, settings: &RuntimeSettings, file: &FileItem) -> String {
    let slug = util::slug_with_extension(&file.public_id, file.extension.as_deref());
    // A preview page is application chrome, not file content, so it belongs on the app origin
    // where its stylesheet, scripts and session are reachable.
    let base = if settings.features.preview_pages {
        app_base_url(state)
    } else {
        file_origin(state, settings, file)
    };
    format!("{base}/{slug}")
}

pub(super) fn raw_file_url(
    state: &AppState,
    settings: &RuntimeSettings,
    file: &FileItem,
) -> String {
    format!(
        "{}/files/{}/raw",
        file_origin(state, settings, file),
        file.public_id
    )
}

pub(super) fn thumbnail_file_url(
    state: &AppState,
    settings: &RuntimeSettings,
    file: &FileItem,
) -> String {
    format!(
        "{}/files/{}/thumbnail",
        file_origin(state, settings, file),
        file.public_id
    )
}

/// Serialises files for templates together with the URL each one should be linked by.
///
/// Templates cannot build these paths themselves: which origin serves a file depends on the
/// delivery settings and on the file's own visibility, so a relative link silently breaks as soon
/// as files move to their own domain.
pub(super) fn linked_files(
    state: &AppState,
    settings: &RuntimeSettings,
    files: &[FileItem],
) -> AppResult<Vec<serde_json::Value>> {
    files
        .iter()
        .map(|file| {
            let mut value = serde_json::to_value(file).map_err(|err| {
                AppError::Other(anyhow::anyhow!("failed to serialise file: {err}"))
            })?;
            if let Some(object) = value.as_object_mut() {
                object.insert("url".to_string(), file_url(state, settings, file).into());
            }
            Ok(value)
        })
        .collect()
}

/// The host and port a request was addressed to, normalised for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOrigin {
    pub host: String,
    pub port: Option<u16>,
}

impl RequestOrigin {
    /// Resolves the origin from the URI authority first and the `Host` header second.
    ///
    /// HTTP/2 has no `Host` header — the authority arrives as the `:authority` pseudo-header,
    /// which hyper puts on the URI. Reading only the header map takes the file origin offline for
    /// any deployment whose proxy speaks h2c upstream.
    pub(super) fn from_request(uri: &Uri, headers: &HeaderMap) -> Option<Self> {
        if let Some(authority) = uri.authority() {
            return Some(Self {
                host: normalize_host(authority.host()),
                port: authority.port_u16(),
            });
        }
        Self::parse(headers.get(header::HOST)?.to_str().ok()?)
    }

    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        if let Some((host, rest)) = value
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
        {
            return Some(Self {
                host: format!("[{}]", normalize_host(host)),
                port: parse_authority_port(rest)?,
            });
        }
        match value.rsplit_once(':') {
            Some(("", _)) => None,
            Some((host, port)) => Some(Self {
                host: normalize_host(host),
                port: Some(port.parse().ok()?),
            }),
            None => Some(Self {
                host: normalize_host(value),
                port: None,
            }),
        }
    }
}

/// Hostnames are case-insensitive and may carry the root label's trailing dot.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Reads the `:port` tail of an authority, where an absent port is valid and a malformed one is not.
fn parse_authority_port(rest: &str) -> Option<Option<u16>> {
    if rest.is_empty() {
        return Some(None);
    }
    Some(Some(rest.strip_prefix(':')?.parse().ok()?))
}

pub(super) fn configured_file_origin(settings: &RuntimeSettings) -> Option<RequestOrigin> {
    let url = settings.delivery.public_file_base_url.as_deref()?;
    let parsed = url::Url::parse(url.trim()).ok()?;
    Some(RequestOrigin {
        host: normalize_host(parsed.host_str()?),
        port: parsed.port_or_known_default(),
    })
}

pub(super) fn matches_file_host(
    settings: &RuntimeSettings,
    origin: Option<&RequestOrigin>,
) -> bool {
    if !settings.delivery.isolated_file_origin {
        return false;
    }
    let (Some(configured), Some(origin)) = (configured_file_origin(settings), origin) else {
        return false;
    };
    // Proxies disagree about whether to forward the scheme's default port, so an absent port
    // matches whatever was configured. Only a port that was forwarded *and* differs is a mismatch.
    configured.host == origin.host && origin.port.is_none_or(|port| Some(port) == configured.port)
}

pub(super) fn is_isolated_file_host(settings: &RuntimeSettings, headers: &HeaderMap) -> bool {
    let origin = REQUEST_CONTEXT
        .try_with(|ctx| ctx.request_origin.clone())
        .ok()
        .flatten()
        .or_else(|| RequestOrigin::from_request(&Uri::default(), headers));
    matches_file_host(settings, origin.as_ref())
}

pub(super) fn signed_internal_raw_url(
    state: &AppState,
    settings: &RuntimeSettings,
    file: &FileItem,
) -> Option<String> {
    if !settings.delivery.signed_internal_urls {
        return None;
    }
    let secret = settings
        .delivery
        .internal_url_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())?;
    let expires = util::now_ts() + settings.delivery.internal_url_ttl_seconds.max(1);
    let signature = sign_internal_file_url(secret, &file.public_id, expires);
    let base = app_base_url(state);
    Some(format!(
        "{base}/internal/files/{}/raw?expires={expires}&signature={signature}",
        file.public_id
    ))
}

pub(super) fn sign_internal_file_url(secret: &str, public_id: &str, expires: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update([0]);
    hasher.update(public_id.as_bytes());
    hasher.update([0]);
    hasher.update(expires.to_string().as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

pub(super) fn render<S: Serialize>(
    state: &AppState,
    name: &str,
    settings: &RuntimeSettings,
    current_user: Option<&User>,
    page: S,
) -> AppResult<Html<String>> {
    let csrf_token = REQUEST_CONTEXT
        .try_with(|ctx| ctx.csrf_token.clone())
        .ok()
        .flatten();
    Ok(Html(state.templates.render(
        name,
        settings,
        current_user,
        csrf_token.as_deref(),
        page,
    )?))
}

pub(super) fn htmx_request(headers: &HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

pub(super) async fn current_user(state: &AppState, jar: &CookieJar) -> AppResult<Option<User>> {
    if let Ok(user) = REQUEST_CONTEXT.try_with(|ctx| ctx.current_user.clone()) {
        return Ok(user);
    }
    let Some(cookie) = jar.get(&state.config.security.session_cookie_name) else {
        return Ok(None);
    };
    Ok(state
        .db
        .user_by_session_token(&util::hash_token(cookie.value()))
        .await?)
}

pub(super) fn ensure_accounts_enabled(settings: &RuntimeSettings) -> AppResult<()> {
    if settings.features.accounts {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) fn ensure_local_accounts_enabled(settings: &RuntimeSettings) -> AppResult<()> {
    if settings.features.accounts && settings.features.local_login {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) fn validate_csrf(jar: &CookieJar, submitted: Option<&str>) -> AppResult<()> {
    let expected = jar
        .get(CSRF_COOKIE)
        .map(|cookie| cookie.value())
        .ok_or_else(|| AppError::BadRequest("missing CSRF cookie".to_string()))?;
    let submitted = submitted
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::BadRequest("missing CSRF token".to_string()))?;
    if submitted == expected {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct CsrfForm {
    pub(super) csrf_token: Option<String>,
}

pub(super) async fn enforce_rate_limit(
    state: &AppState,
    settings: &RuntimeSettings,
    action: &str,
    headers: &HeaderMap,
    user: Option<&User>,
) -> AppResult<()> {
    let identity = rate_limit_identity(state, headers, user);
    let result = match settings.security.rate_limit_backend {
        RateLimitBackend::Memory => {
            state
                .rate_limiter
                .check(action, &identity, settings.security.rate_limits.get(action))
                .await
        }
        RateLimitBackend::Database => {
            if state
                .db
                .check_rate_limit(action, &identity, settings.security.rate_limits.get(action))
                .await?
            {
                Ok(())
            } else {
                Err(AppError::TooManyRequests)
            }
        }
    };
    if matches!(result, Err(AppError::TooManyRequests)) {
        state.metrics.rate_limit_rejections.inc();
    }
    result
}

fn rate_limit_identity(state: &AppState, headers: &HeaderMap, user: Option<&User>) -> String {
    if let Some(user) = user {
        return format!("user:{}", user.id);
    }
    match client_ip(&state.config.server, headers, request_peer_ip()) {
        Some(ip) => format!("ip:{ip}"),
        // Only reachable when the server runs without connection info, which `serve` always
        // supplies. Sharing one bucket is the safe direction to fail: it throttles rather than
        // exempts.
        None => "anonymous".to_string(),
    }
}

/// Resolves the caller's IP address, honouring forwarding headers only in proxy deployments.
pub(super) fn client_ip(
    server: &crate::config::ServerConfig,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    if !server.behind_proxy {
        // Without a proxy in front, forwarding headers come straight from the caller.
        return peer;
    }
    forwarded_client_ip(headers, server.trusted_proxy_hops)
        .or_else(|| header_ip(headers, "x-real-ip"))
        .or(peer)
}

/// Reads the hop `trusted_proxy_hops` from the right of `X-Forwarded-For`.
///
/// Our own proxies append to the right, so those entries are trustworthy while everything to
/// their left was supplied by the caller. Returns `None` when the header carries fewer hops than
/// configured, which means the request did not traverse the expected proxy chain.
fn forwarded_client_ip(headers: &HeaderMap, trusted_hops: usize) -> Option<IpAddr> {
    let hops = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
        .collect::<Vec<_>>();
    let index = hops.len().checked_sub(trusted_hops.max(1))?;
    parse_forwarded_ip(hops.get(index)?)
}

fn header_ip(headers: &HeaderMap, name: &'static str) -> Option<IpAddr> {
    parse_forwarded_ip(headers.get(name)?.to_str().ok()?)
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    value.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

fn request_peer_ip() -> Option<IpAddr> {
    REQUEST_CONTEXT.try_with(|ctx| ctx.peer_ip).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    fn isolated(file_base_url: &str) -> RuntimeSettings {
        let mut settings = RuntimeSettings::from_config(&crate::config::AppConfig::default());
        settings.delivery.public_file_base_url = Some(file_base_url.to_string());
        settings.delivery.isolated_file_origin = true;
        settings
    }

    fn origin(value: &str) -> Option<RequestOrigin> {
        RequestOrigin::parse(value)
    }

    #[test]
    fn file_host_matching_ignores_case_and_a_trailing_root_dot() {
        let settings = isolated("https://files.example.test");
        assert!(matches_file_host(
            &settings,
            origin("Files.Example.Test").as_ref()
        ));
        assert!(matches_file_host(
            &settings,
            origin("files.example.test.").as_ref()
        ));
        assert!(!matches_file_host(
            &settings,
            origin("app.example.test").as_ref()
        ));
    }

    /// Some proxies forward the scheme's default port in `Host`. Rejecting that would take every
    /// file route offline, so an explicit default port has to compare equal to an implicit one.
    #[test]
    fn file_host_matching_accepts_an_explicit_default_port() {
        assert!(matches_file_host(
            &isolated("https://files.example.test"),
            origin("files.example.test:443").as_ref()
        ));
        assert!(matches_file_host(
            &isolated("http://files.example.test"),
            origin("files.example.test:80").as_ref()
        ));
        assert!(matches_file_host(
            &isolated("http://localhost:8080"),
            origin("localhost:8080").as_ref()
        ));
    }

    #[test]
    fn file_host_matching_rejects_a_different_port() {
        assert!(!matches_file_host(
            &isolated("https://files.example.test"),
            origin("files.example.test:8443").as_ref()
        ));
        assert!(!matches_file_host(
            &isolated("http://localhost:8080"),
            origin("localhost:9090").as_ref()
        ));
    }

    #[test]
    fn file_host_matching_is_off_without_the_isolation_flag_or_a_base_url() {
        let mut settings = isolated("https://files.example.test");
        settings.delivery.isolated_file_origin = false;
        assert!(!matches_file_host(
            &settings,
            origin("files.example.test").as_ref()
        ));

        let mut settings = isolated("https://files.example.test");
        settings.delivery.public_file_base_url = None;
        assert!(!matches_file_host(
            &settings,
            origin("files.example.test").as_ref()
        ));
        assert!(!matches_file_host(
            &isolated("https://files.example.test"),
            None
        ));
    }

    /// HTTP/2 carries the authority as a pseudo-header rather than `Host`, so hyper surfaces it on
    /// the URI. Reading only the header map would take the file origin offline over h2c.
    #[test]
    fn request_origin_prefers_the_uri_authority_and_falls_back_to_the_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("app.example.test"));

        let from_uri = RequestOrigin::from_request(
            &"https://files.example.test/abc.png".parse().unwrap(),
            &headers,
        );
        assert_eq!(from_uri, origin("files.example.test"));

        let from_header = RequestOrigin::from_request(&"/abc.png".parse().unwrap(), &headers);
        assert_eq!(from_header, origin("app.example.test"));

        assert_eq!(
            RequestOrigin::from_request(&"/abc.png".parse().unwrap(), &HeaderMap::new()),
            None
        );
    }

    #[test]
    fn request_origin_parses_ipv6_literals_and_rejects_junk() {
        assert_eq!(
            origin("[2001:db8::5]:8080"),
            Some(RequestOrigin {
                host: "[2001:db8::5]".to_string(),
                port: Some(8080)
            })
        );
        assert_eq!(
            origin("[2001:db8::5]"),
            Some(RequestOrigin {
                host: "[2001:db8::5]".to_string(),
                port: None
            })
        );
        assert_eq!(origin(""), None);
        assert_eq!(origin("files.example.test:not-a-port"), None);
    }

    fn proxied(hops: usize) -> ServerConfig {
        ServerConfig {
            behind_proxy: true,
            trusted_proxy_hops: hops,
            ..ServerConfig::default()
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn peer() -> Option<IpAddr> {
        Some("192.0.2.1".parse().unwrap())
    }

    #[test]
    fn direct_deployments_ignore_forwarding_headers() {
        let resolved = client_ip(
            &ServerConfig::default(),
            &headers(&[
                ("x-forwarded-for", "203.0.113.9"),
                ("x-real-ip", "203.0.113.9"),
            ]),
            peer(),
        );
        assert_eq!(resolved, peer());
    }

    #[test]
    fn proxied_deployments_use_the_configured_hop_from_the_right() {
        let chain = headers(&[("x-forwarded-for", "203.0.113.1, 198.51.100.7, 198.51.100.8")]);
        assert_eq!(
            client_ip(&proxied(1), &chain, peer()),
            Some("198.51.100.8".parse().unwrap())
        );
        assert_eq!(
            client_ip(&proxied(2), &chain, peer()),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn spoofed_leading_hops_do_not_change_the_resolved_client() {
        let first = client_ip(
            &proxied(1),
            &headers(&[("x-forwarded-for", "203.0.113.1, 198.51.100.8")]),
            peer(),
        );
        let second = client_ip(
            &proxied(1),
            &headers(&[("x-forwarded-for", "203.0.113.2, 198.51.100.8")]),
            peer(),
        );
        assert_eq!(first, second);
        assert_eq!(first, Some("198.51.100.8".parse().unwrap()));
    }

    #[test]
    fn a_short_forwarded_chain_falls_back_instead_of_trusting_the_caller() {
        // Two proxies are configured but the caller only supplied one hop, so the header did not
        // come through the expected chain and must not be believed.
        assert_eq!(
            client_ip(
                &proxied(2),
                &headers(&[("x-forwarded-for", "127.0.0.1")]),
                peer()
            ),
            peer()
        );
    }

    #[test]
    fn split_forwarded_headers_and_ports_are_understood() {
        assert_eq!(
            client_ip(
                &proxied(1),
                &headers(&[
                    ("x-forwarded-for", "203.0.113.1"),
                    ("x-forwarded-for", "198.51.100.8:4444"),
                ]),
                peer()
            ),
            Some("198.51.100.8".parse().unwrap())
        );
        assert_eq!(
            client_ip(
                &proxied(1),
                &headers(&[("x-forwarded-for", "[2001:db8::5]")]),
                peer()
            ),
            Some("2001:db8::5".parse().unwrap())
        );
    }
}

pub(super) async fn api_user(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> AppResult<Option<User>> {
    let Some(actor) = api_authenticated_user(state, headers, required_scope).await? else {
        return Ok(None);
    };
    Ok(Some(actor.user))
}

#[derive(Debug)]
pub(super) struct ApiAuthenticatedUser {
    pub user: User,
    pub scopes: Vec<String>,
}

pub(super) async fn api_authenticated_user(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> AppResult<Option<ApiAuthenticatedUser>> {
    let settings = state.settings().await?;
    if !settings.features.api {
        return Err(AppError::Forbidden);
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if let Some(token) = bearer {
        let Some((user, scopes)) = state
            .db
            .user_by_api_token_with_scopes(&util::hash_token(token), required_scope)
            .await?
        else {
            return Err(AppError::Unauthorized);
        };
        if policy::can_use_api(&settings, Some(&user)) {
            return Ok(Some(ApiAuthenticatedUser { user, scopes }));
        }
        return Err(AppError::Forbidden);
    }
    if policy::can_use_api(&settings, None) {
        Ok(None)
    } else {
        Err(AppError::Unauthorized)
    }
}

pub(super) async fn api_role_user(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    minimum_role: Role,
) -> AppResult<User> {
    let user = api_user(state, headers, required_scope)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if user.role >= minimum_role {
        Ok(user)
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) fn session_cookie(
    state: &AppState,
    token: String,
    max_age_seconds: Option<i64>,
    secure: bool,
) -> Cookie<'static> {
    let mut cookie = Cookie::new(state.config.security.session_cookie_name.clone(), token);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    if let Some(seconds) = max_age_seconds {
        cookie.set_max_age(time::Duration::seconds(seconds));
    }
    cookie
}

pub(super) fn transient_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_max_age(time::Duration::minutes(10));
    cookie
}

pub(super) fn parse_scopes(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn requested_visibility(
    settings: &RuntimeSettings,
    value: Option<&str>,
) -> AppResult<&'static str> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("unlisted") => Ok("unlisted"),
        Some("public") if settings.features.public_browse => Ok("public"),
        Some("public") => Err(AppError::BadRequest(
            "public visibility requires public browse to be enabled".to_string(),
        )),
        Some("private") => Ok("private"),
        _ => Err(AppError::BadRequest("invalid visibility".to_string())),
    }
}

pub(super) fn parse_expiry_or_default_checked(
    settings: &RuntimeSettings,
    user: Option<&User>,
    kind: &str,
    input: Option<&str>,
    default_input: Option<&str>,
) -> AppResult<Option<i64>> {
    let selected = input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            default_input
                .map(str::trim)
                .filter(|value| !value.is_empty())
        });
    let expiry = util::parse_expiry(selected)
        .map_err(|err| AppError::BadRequest(format!("invalid expiry: {err}")))?;
    if expiry.is_none() && !settings.limits.expiry.allow_never {
        return Err(AppError::BadRequest(
            "never-expiring items are disabled".to_string(),
        ));
    }
    let Some(expiry) = expiry else {
        return Ok(None);
    };
    let max_input = match (kind, user.is_some()) {
        ("file", false) => settings.limits.expiry.anonymous_max_file_expiry.as_deref(),
        ("file", true) => settings.limits.expiry.user_max_file_expiry.as_deref(),
        ("paste", false) => settings.limits.expiry.anonymous_max_paste_expiry.as_deref(),
        ("paste", true) => settings.limits.expiry.user_max_paste_expiry.as_deref(),
        _ => None,
    };
    if let Some(max_input) = max_input {
        let now = util::now_ts();
        let max_expiry = util::parse_expiry(Some(max_input))
            .map_err(|err| AppError::BadRequest(format!("invalid max expiry config: {err}")))?
            .ok_or_else(|| AppError::BadRequest("max expiry cannot be never".to_string()))?;
        if expiry.saturating_sub(now) > max_expiry.saturating_sub(now) {
            return Err(AppError::BadRequest(
                "expiry exceeds configured maximum".to_string(),
            ));
        }
    }
    Ok(Some(expiry))
}

pub(super) fn authorize_item_view(
    settings: &RuntimeSettings,
    user: Option<&User>,
    owner_user_id: Option<&str>,
    visibility: &str,
) -> AppResult<()> {
    if user.is_some_and(|user| user.role >= Role::Admin) {
        return Ok(());
    }
    if visibility == "private" {
        let Some(user) = user else {
            return Err(AppError::Forbidden);
        };
        if owner_user_id == Some(user.id.as_str()) {
            return Ok(());
        }
        return Err(AppError::Forbidden);
    }
    if policy::allowed(settings.policy.view_item, user) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}
