use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app::{AppError, AppResult, AppState},
    config::{OidcConfig, RuntimeSettings},
    db::{Role, User},
    util,
};

use super::{
    auth::create_session_response,
    support::{current_user, transient_cookie},
};

pub(super) async fn login(State(state): State<AppState>, jar: CookieJar) -> AppResult<Response> {
    start(state, jar, "login").await
}

async fn start(state: AppState, jar: CookieJar, purpose: &'static str) -> AppResult<Response> {
    let settings = state.settings().await?;
    if !enabled(&state, &settings) {
        return Err(AppError::NotFound);
    }
    let oidc = &state.config.oidc;
    let discovery = discovery(&state).await?;
    let state_token = util::secret_token();
    let nonce = util::secret_token();
    let redirect_url = redirect_url(&state);
    let mut url = url::Url::parse(&discovery.authorization_endpoint).map_err(|err| {
        AppError::Other(anyhow::anyhow!(
            "invalid OIDC authorization endpoint: {err}"
        ))
    })?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", oidc.client_id.as_deref().unwrap_or_default())
        .append_pair("redirect_uri", &redirect_url)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state_token)
        .append_pair("nonce", &nonce);

    let secure_cookies = settings.security.secure_cookies;
    let state_cookie = transient_cookie("midden_oidc_state", state_token, secure_cookies);
    let nonce_cookie = transient_cookie("midden_oidc_nonce", nonce, secure_cookies);
    let purpose_cookie =
        transient_cookie("midden_oidc_purpose", purpose.to_string(), secure_cookies);
    Ok((
        jar.add(state_cookie).add(nonce_cookie).add(purpose_cookie),
        Redirect::to(url.as_str()),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(super) async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    if !enabled(&state, &settings) {
        return Err(AppError::NotFound);
    }
    if let Some(error) = query.error {
        return Err(AppError::BadRequest(format!(
            "OIDC provider returned {error}"
        )));
    }
    let expected_state = jar
        .get("midden_oidc_state")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::BadRequest("missing OIDC state cookie".to_string()))?;
    if query.state.as_deref() != Some(expected_state.as_str()) {
        return Err(AppError::BadRequest("OIDC state mismatch".to_string()));
    }
    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("missing OIDC code".to_string()))?;
    let token = exchange_code(&state, &code).await?;
    let userinfo = userinfo(&state, &token.access_token).await?;
    let email = userinfo
        .email
        .clone()
        .ok_or_else(|| AppError::BadRequest("OIDC userinfo did not include email".to_string()))?;
    let subject = userinfo
        .sub
        .clone()
        .ok_or_else(|| AppError::BadRequest("OIDC userinfo did not include subject".to_string()))?;
    validate_userinfo(&state.config.oidc, &userinfo, &email)?;
    let issuer = issuer(&state)?;
    let mapped_role = mapped_role(&state.config.oidc, &userinfo)?;
    let purpose = jar
        .get("midden_oidc_purpose")
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_else(|| "login".to_string());
    let jar = clear_cookies(jar, settings.security.secure_cookies);
    if purpose == "link" {
        let user = current_user(&state, &jar)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if let Some(existing) = state.db.user_by_oidc_identity(&issuer, &subject).await?
            && existing.id != user.id
        {
            return Err(AppError::BadRequest(
                "that OIDC identity is already linked to another account".to_string(),
            ));
        }
        state
            .db
            .link_oidc_identity(&user.id, &issuer, &subject, &email)
            .await
            .map_err(|_| {
                AppError::BadRequest("that OIDC identity could not be linked".to_string())
            })?;
        state
            .db
            .audit(Some(&user.id), "oidc.linked", &user.id, &issuer)
            .await?;
        return Ok((jar, Redirect::to("/account")).into_response());
    }

    let user =
        resolve_login_user(&state, &issuer, &subject, &email, &userinfo, mapped_role).await?;
    state
        .db
        .audit(Some(&user.id), "auth.login", &user.id, "oidc")
        .await?;
    create_session_response(&state, jar, &user).await
}

fn clear_cookies(jar: CookieJar, secure_cookies: bool) -> CookieJar {
    jar.remove(transient_cookie(
        "midden_oidc_state",
        String::new(),
        secure_cookies,
    ))
    .remove(transient_cookie(
        "midden_oidc_nonce",
        String::new(),
        secure_cookies,
    ))
    .remove(transient_cookie(
        "midden_oidc_purpose",
        String::new(),
        secure_cookies,
    ))
}

async fn resolve_login_user(
    state: &AppState,
    issuer: &str,
    subject: &str,
    email: &str,
    userinfo: &UserInfo,
    mapped_role: Option<Role>,
) -> AppResult<User> {
    if let Some(user) = state.db.user_by_oidc_identity(issuer, subject).await? {
        state.db.touch_oidc_identity(issuer, subject, email).await?;
        apply_role(state, &user, mapped_role).await?;
        return state.db.user_by_id(&user.id).await.map_err(AppError::Other);
    }

    if let Ok(existing) = state.db.user_by_email(email).await {
        if existing.password_hash.is_some() {
            return Err(AppError::BadRequest(
                "existing local accounts must link OIDC from the account page before OIDC login"
                    .to_string(),
            ));
        }
        // Adopting an account we did not provision is only safe if the provider vouches for the
        // address. Without this, anyone who can assert an arbitrary email at the issuer takes over
        // matching passwordless accounts, including an owner created without a password.
        if userinfo.email_verified != Some(true) {
            return Err(AppError::BadRequest(
                "the identity provider did not report this email address as verified".to_string(),
            ));
        }
        state
            .db
            .link_oidc_identity(&existing.id, issuer, subject, email)
            .await?;
        apply_role(state, &existing, mapped_role).await?;
        return state
            .db
            .user_by_id(&existing.id)
            .await
            .map_err(AppError::Other);
    }

    // Provisioning a brand-new account is bound to issuer+subject and puts no existing account at
    // risk, so an absent email_verified claim is tolerated here.
    let username = username(userinfo, email);
    let user = create_user(state, email, &username, mapped_role.unwrap_or(Role::User)).await?;
    state
        .db
        .link_oidc_identity(&user.id, issuer, subject, email)
        .await?;
    Ok(user)
}

async fn create_user(state: &AppState, email: &str, username: &str, role: Role) -> AppResult<User> {
    let mut candidate = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();
    if candidate.is_empty() {
        candidate = email
            .split('@')
            .next()
            .unwrap_or("user")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
    }
    for attempt in 0..10 {
        let username = if attempt == 0 {
            candidate.clone()
        } else {
            format!("{candidate}-{attempt}")
        };
        match state.db.create_user(email, &username, None, role).await {
            Ok(user) => return Ok(user),
            Err(err)
                if err.to_string().contains("UNIQUE") || err.to_string().contains("unique") =>
            {
                continue;
            }
            Err(err) => return Err(AppError::Other(err)),
        }
    }
    Ok(state
        .db
        .create_user(email, &format!("user-{}", util::public_id()), None, role)
        .await?)
}

async fn apply_role(state: &AppState, user: &User, mapped_role: Option<Role>) -> AppResult<()> {
    // No claim matched a configured mapping, so the provider is not asserting anything about this
    // user's role. Leave whatever the instance has on record rather than resetting it: treating
    // "no opinion" as "demote to user" silently strips admins and moderators on every login.
    let Some(mapped_role) = mapped_role else {
        return Ok(());
    };
    if user.role != mapped_role && (user.role != Role::Owner || mapped_role == Role::Owner) {
        state.db.set_user_role(&user.id, mapped_role).await?;
        state
            .db
            .audit(
                Some(&user.id),
                "user.role_updated",
                &user.id,
                "oidc role mapping",
            )
            .await?;
    }
    Ok(())
}

fn username(userinfo: &UserInfo, email: &str) -> String {
    userinfo
        .preferred_username
        .clone()
        .or_else(|| userinfo.name.clone())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string())
}

pub(super) async fn account_link(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    if !enabled(&state, &settings) {
        return Err(AppError::NotFound);
    }
    current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    start(state, jar, "link").await
}

fn issuer(state: &AppState) -> AppResult<String> {
    Ok(state
        .config
        .oidc
        .issuer_url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("OIDC issuer_url is missing".to_string()))?
        .trim_end_matches('/')
        .to_string())
}

fn validate_userinfo(oidc: &OidcConfig, userinfo: &UserInfo, email: &str) -> AppResult<()> {
    if !oidc.allowed_domains.is_empty() {
        let domain = email
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .ok_or_else(|| {
                AppError::BadRequest("OIDC email did not include a domain".to_string())
            })?;
        let allowed = oidc
            .allowed_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&domain));
        if !allowed {
            return Err(AppError::Forbidden);
        }
    }

    if !oidc.allowed_groups.is_empty() {
        let groups = claim_values(userinfo, oidc.groups_claim.as_deref().unwrap_or("groups"));
        let allowed = groups
            .iter()
            .any(|group| oidc.allowed_groups.iter().any(|allowed| allowed == group));
        if !allowed {
            return Err(AppError::Forbidden);
        }
    }
    Ok(())
}

/// Resolves the highest role the provider's claims map to, or `None` when no claim matched.
fn mapped_role(oidc: &OidcConfig, userinfo: &UserInfo) -> AppResult<Option<Role>> {
    let mut role: Option<Role> = None;
    for value in claim_values(userinfo, oidc.role_claim.as_deref().unwrap_or("role"))
        .into_iter()
        .chain(claim_values(
            userinfo,
            oidc.groups_claim.as_deref().unwrap_or("groups"),
        ))
    {
        if let Some(mapped) = oidc.role_mappings.get(&value) {
            let mapped_role = Role::parse_form(mapped)
                .map_err(|err| AppError::BadRequest(format!("invalid OIDC role mapping: {err}")))?;
            role = Some(role.map_or(mapped_role, |current| current.max(mapped_role)));
        }
    }
    Ok(role)
}

fn claim_values(userinfo: &UserInfo, claim: &str) -> Vec<String> {
    let Some(value) = userinfo.extra.get(claim) else {
        return Vec::new();
    };
    match value {
        serde_json::Value::String(value) => value
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn enabled(state: &AppState, settings: &RuntimeSettings) -> bool {
    settings.features.accounts
        && settings.features.oidc_login
        && state.config.oidc.enabled
        && state.config.oidc.issuer_url.is_some()
        && state.config.oidc.client_id.is_some()
}

fn redirect_url(state: &AppState) -> String {
    state.config.oidc.redirect_url.clone().unwrap_or_else(|| {
        format!(
            "{}/auth/oidc/callback",
            state.config.server.public_base_url.trim_end_matches('/')
        )
    })
}

#[derive(Debug, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: Option<String>,
    email: Option<String>,
    #[serde(default, deserialize_with = "bool_claim")]
    email_verified: Option<bool>,
    preferred_username: Option<String>,
    name: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Reads a boolean claim, tolerating providers that encode it as a string.
fn bool_claim<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        match Option::<serde_json::Value>::deserialize(deserializer)? {
            Some(serde_json::Value::Bool(value)) => Some(value),
            Some(serde_json::Value::String(value)) => value.parse().ok(),
            _ => None,
        },
    )
}

async fn discovery(state: &AppState) -> AppResult<Discovery> {
    let issuer = state
        .config
        .oidc
        .issuer_url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("OIDC issuer_url is missing".to_string()))?
        .trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    Ok(reqwest::get(url).await?.error_for_status()?.json().await?)
}

async fn exchange_code(state: &AppState, code: &str) -> AppResult<TokenResponse> {
    let discovery = discovery(state).await?;
    let oidc = &state.config.oidc;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", oidc.client_id.clone().unwrap_or_default()),
        ("redirect_uri", redirect_url(state)),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    Ok(reqwest::Client::new()
        .post(discovery.token_endpoint)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn userinfo(state: &AppState, access_token: &str) -> AppResult<UserInfo> {
    let discovery = discovery(state).await?;
    let endpoint = discovery.userinfo_endpoint.ok_or_else(|| {
        AppError::BadRequest("OIDC provider did not advertise userinfo_endpoint".to_string())
    })?;
    Ok(reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
