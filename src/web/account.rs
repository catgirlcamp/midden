use super::*;
use crate::{
    commands,
    domain::{AccountBulkAction, ItemVisibility},
};
use axum_extra::extract::Form as HtmlForm;

#[derive(Debug, Deserialize)]
pub(super) struct AccountQuery {
    q: Option<String>,
}

pub(super) async fn account(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<AccountQuery>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let oidc_link_enabled = oidc::enabled(&state, &settings);
    let q = query.q.unwrap_or_default();
    let (files, pastes) = user_items_for_query(&state, &settings, &user, &q).await?;
    let page = if htmx_request(&headers) {
        serde_json::json!({
            "q": q,
            "files": files,
            "pastes": pastes,
        })
    } else {
        let tokens = state.db.list_api_tokens(&user.id).await?;
        serde_json::json!({
            "q": q,
            "files": files,
            "pastes": pastes,
            "tokens": tokens,
            "new_token": null,
            "has_local_password": user.password_hash.is_some(),
            "email_verified": user.email_verified_at.is_some(),
            "two_factor_enabled": user.two_factor_enabled,
            "smtp_enabled": state.mailer.enabled(),
            "oidc_link_enabled": oidc_link_enabled,
        })
    };
    render(
        &state,
        if htmx_request(&headers) {
            "account_items.html"
        } else {
            "account.html"
        },
        &settings,
        Some(&user),
        page,
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountTokenForm {
    name: String,
    scopes: String,
    expires_in_seconds: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn account_create_token(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AccountTokenForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    if !settings.features.api {
        return Err(AppError::Forbidden);
    }
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let oidc_link_enabled = oidc::enabled(&state, &settings);
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let scopes = parse_scopes(&form.scopes);
    let requested_ttl_seconds = form
        .expires_in_seconds
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|err| AppError::BadRequest(format!("invalid token TTL seconds: {err}")))
        })
        .transpose()?;
    let created = commands::create_token(
        &state,
        &settings,
        &user,
        &form.name,
        &scopes,
        requested_ttl_seconds,
    )
    .await?;
    let token = created.token;
    let tokens = state.db.list_api_tokens(&user.id).await?;
    if htmx_request(&headers) {
        return Ok(render(
            &state,
            "account_tokens.html",
            &settings,
            Some(&user),
            serde_json::json!({
                "tokens": tokens,
                "new_token": token,
            }),
        )?
        .into_response());
    }
    let files = state.db.recent_user_files(&user.id).await?;
    let pastes = state.db.recent_user_pastes(&user.id).await?;
    Ok(render(
        &state,
        "account.html",
        &settings,
        Some(&user),
        serde_json::json!({
            "q": "",
            "files": files,
            "pastes": pastes,
            "tokens": tokens,
            "new_token": token,
            "has_local_password": user.password_hash.is_some(),
            "email_verified": user.email_verified_at.is_some(),
            "two_factor_enabled": user.two_factor_enabled,
            "smtp_enabled": state.mailer.enabled(),
            "oidc_link_enabled": oidc_link_enabled,
        }),
    )?
    .into_response())
}

pub(super) async fn account_revoke_token(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    if !settings.features.api {
        return Err(AppError::Forbidden);
    }
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    commands::revoke_token(&state, &user, &id).await?;
    if htmx_request(&headers) {
        let tokens = state.db.list_api_tokens(&user.id).await?;
        Ok(render(
            &state,
            "account_tokens.html",
            &settings,
            Some(&user),
            serde_json::json!({
                "tokens": tokens,
                "new_token": null,
            }),
        )?
        .into_response())
    } else {
        Ok(Redirect::to("/account").into_response())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountBulkItemsForm {
    bulk_action: String,
    file_ids: Option<Vec<String>>,
    paste_ids: Option<Vec<String>>,
    visibility: Option<String>,
    expires: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn account_bulk_items(
    State(state): State<AppState>,
    jar: CookieJar,
    HtmlForm(form): HtmlForm<AccountBulkItemsForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let action = match form.bulk_action.as_str() {
        "delete" => AccountBulkAction::Delete,
        "set_visibility" => {
            let visibility = requested_visibility(&settings, form.visibility.as_deref())?;
            AccountBulkAction::SetVisibility(ItemVisibility::parse(&settings, visibility)?)
        }
        "set_expiry" => {
            let file_expires_at = parse_expiry_or_default_checked(
                &settings,
                Some(&user),
                "file",
                form.expires.as_deref(),
                None,
            )?;
            let paste_expires_at = parse_expiry_or_default_checked(
                &settings,
                Some(&user),
                "paste",
                form.expires.as_deref(),
                None,
            )?;
            AccountBulkAction::SetExpiry {
                file_expires_at,
                paste_expires_at,
            }
        }
        _ => return Err(AppError::BadRequest("unknown bulk action".to_string())),
    };
    commands::apply_account_bulk(
        &state,
        &user,
        form.file_ids.unwrap_or_default(),
        form.paste_ids.unwrap_or_default(),
        action,
    )
    .await?;
    Ok(Redirect::to("/account"))
}

pub(super) async fn account_send_email_verification(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    if user.email_verified_at.is_some() {
        return Ok(Redirect::to("/account"));
    }
    send_email_verification(&state, &user).await?;
    state
        .db
        .audit(
            Some(&user.id),
            "user.email_verification_sent",
            &user.id,
            "account UI",
        )
        .await?;
    Ok(Redirect::to("/account"))
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountPasswordForm {
    current_password: String,
    new_password: String,
    csrf_token: Option<String>,
}

pub(super) async fn account_change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<AccountPasswordForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let Some(password_hash) = &user.password_hash else {
        return Err(AppError::BadRequest(
            "OIDC-only accounts do not have a local password".to_string(),
        ));
    };
    if !util::verify_password(&form.current_password, password_hash).await {
        return Err(AppError::Unauthorized);
    }
    let new_hash = util::hash_password(&form.new_password).await?;
    state.db.update_user_password(&user.id, &new_hash).await?;
    // Sign out anyone else holding a session for this account, but keep the caller signed in.
    let current_session = jar
        .get(&state.config.security.session_cookie_name)
        .map(|cookie| util::hash_token(cookie.value()));
    state
        .db
        .delete_sessions_for_user(&user.id, current_session.as_deref())
        .await?;
    state
        .db
        .audit(
            Some(&user.id),
            "user.password_changed",
            &user.id,
            "account UI",
        )
        .await?;
    Ok(Redirect::to("/account"))
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountTwoFactorForm {
    current_password: String,
    csrf_token: Option<String>,
}

pub(super) async fn account_enable_two_factor(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<AccountTwoFactorForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    if !state.mailer.enabled() {
        return Err(AppError::BadRequest(
            "two-factor authentication requires SMTP".to_string(),
        ));
    }
    if user.email_verified_at.is_none() {
        return Err(AppError::BadRequest(
            "verify your email before enabling two-factor authentication".to_string(),
        ));
    }
    verify_current_password(&user, &form.current_password).await?;
    state.db.set_user_two_factor_enabled(&user.id, true).await?;
    state
        .db
        .audit(
            Some(&user.id),
            "user.two_factor_enabled",
            &user.id,
            "account UI",
        )
        .await?;
    Ok(Redirect::to("/account"))
}

pub(super) async fn account_disable_two_factor(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<AccountTwoFactorForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    verify_current_password(&user, &form.current_password).await?;
    state
        .db
        .set_user_two_factor_enabled(&user.id, false)
        .await?;
    state
        .db
        .audit(
            Some(&user.id),
            "user.two_factor_disabled",
            &user.id,
            "account UI",
        )
        .await?;
    Ok(Redirect::to("/account"))
}

async fn verify_current_password(user: &User, password: &str) -> AppResult<()> {
    let Some(password_hash) = &user.password_hash else {
        return Err(AppError::BadRequest(
            "OIDC-only accounts do not have a local password".to_string(),
        ));
    };
    if !util::verify_password(password, password_hash).await {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

pub(super) async fn account_deactivate(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    state.db.set_user_disabled(&user.id, true).await?;
    state
        .db
        .audit(Some(&user.id), "user.deactivated", &user.id, "account UI")
        .await?;
    let secure_cookies = settings.security.secure_cookies;
    let cookie = session_cookie(&state, String::new(), Some(0), secure_cookies);
    Ok((jar.remove(cookie), Redirect::to("/")).into_response())
}

async fn user_items_for_query(
    state: &AppState,
    settings: &RuntimeSettings,
    user: &User,
    query: &str,
) -> AppResult<(Vec<FileItem>, Vec<Paste>)> {
    if query.trim().is_empty() {
        Ok((
            state.db.recent_user_files(&user.id).await?,
            state.db.recent_user_pastes(&user.id).await?,
        ))
    } else {
        Ok((
            state.db.search_user_files(&user.id, query).await?,
            state
                .db
                .search_user_pastes(&user.id, query, settings.features.paste_content_search)
                .await?,
        ))
    }
}
