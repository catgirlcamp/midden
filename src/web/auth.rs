use super::*;

pub(super) async fn login_form(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    let oidc_enabled = oidc::enabled(&state, &settings);
    render(
        &state,
        "login.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "oidc_enabled": oidc_enabled }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginForm {
    email: String,
    password: String,
    csrf_token: Option<String>,
}

pub(super) async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    enforce_rate_limit(&state, &settings, "login", &headers, None).await?;
    let user = match state.db.user_by_email(&form.email).await {
        Ok(user) => user,
        Err(_) => {
            state
                .db
                .audit(None, "auth.login_failed", &form.email, "unknown email")
                .await?;
            return Err(AppError::Unauthorized);
        }
    };
    let Some(password_hash) = &user.password_hash else {
        state
            .db
            .audit(
                Some(&user.id),
                "auth.login_failed",
                &user.id,
                "local password unavailable",
            )
            .await?;
        return Err(AppError::Unauthorized);
    };
    if !util::verify_password(&form.password, password_hash) {
        state
            .db
            .audit(
                Some(&user.id),
                "auth.login_failed",
                &user.id,
                "bad password",
            )
            .await?;
        return Err(AppError::Unauthorized);
    }
    if user.email_verified_at.is_none() {
        state
            .db
            .audit(
                Some(&user.id),
                "auth.login_failed",
                &user.id,
                "email unverified",
            )
            .await?;
        return Err(AppError::BadRequest(
            "email verification is required before login".to_string(),
        ));
    }
    if user.two_factor_enabled {
        return start_two_factor_challenge(&state, jar, &user).await;
    }
    state
        .db
        .audit(Some(&user.id), "auth.login", &user.id, "password")
        .await?;
    create_session_response(&state, jar, &user).await
}

async fn start_two_factor_challenge(
    state: &AppState,
    jar: CookieJar,
    user: &User,
) -> AppResult<Response> {
    if !state.mailer.enabled() {
        state
            .db
            .audit(
                Some(&user.id),
                "auth.login_failed",
                &user.id,
                "two-factor email unavailable",
            )
            .await?;
        return Err(AppError::BadRequest(
            "two-factor email is unavailable for this instance".to_string(),
        ));
    }
    let challenge = util::secret_token();
    let code = util::public_id().to_ascii_uppercase();
    state
        .db
        .create_two_factor_challenge(
            &user.id,
            &util::hash_token(&challenge),
            &util::hash_token(&code),
            util::now_ts() + 10 * 60,
        )
        .await?;
    state
        .mailer
        .send(
            &user.email,
            "Your Midden sign-in code",
            &format!(
                "Use this code to finish signing in:\n\n{code}\n\nThe code expires in 10 minutes."
            ),
        )
        .await?;
    state
        .db
        .audit(
            Some(&user.id),
            "auth.2fa_challenge_created",
            &user.id,
            "email",
        )
        .await?;
    let secure_cookies = state.settings().await?.security.secure_cookies;
    Ok((
        jar.add(transient_cookie(
            TWO_FACTOR_CHALLENGE_COOKIE,
            challenge,
            secure_cookies,
        )),
        Redirect::to("/auth/2fa"),
    )
        .into_response())
}

pub(super) async fn create_session_response(
    state: &AppState,
    jar: CookieJar,
    user: &User,
) -> AppResult<Response> {
    let token = util::secret_token();
    let token_hash = util::hash_token(&token);
    let expires = util::now_ts() + state.config.security.session_ttl_seconds;
    state
        .db
        .create_session(&user.id, &token_hash, expires)
        .await?;
    let secure_cookies = state.settings().await?.security.secure_cookies;
    let cookie = session_cookie(
        state,
        token,
        Some(state.config.security.session_ttl_seconds),
        secure_cookies,
    );
    Ok((jar.add(cookie), Redirect::to("/account")).into_response())
}

pub(super) async fn two_factor_form(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    if jar.get(TWO_FACTOR_CHALLENGE_COOKIE).is_none() {
        return Err(AppError::BadRequest(
            "missing two-factor challenge".to_string(),
        ));
    }
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    render(
        &state,
        "two_factor.html",
        &settings,
        user.as_ref(),
        serde_json::json!({}),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct TwoFactorSubmitForm {
    code: String,
    csrf_token: Option<String>,
}

pub(super) async fn two_factor_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<TwoFactorSubmitForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let challenge = jar
        .get(TWO_FACTOR_CHALLENGE_COOKIE)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::BadRequest("missing two-factor challenge".to_string()))?;
    let user = match state
        .db
        .consume_two_factor_challenge(
            &util::hash_token(&challenge),
            &util::hash_token(&form.code.trim().to_ascii_uppercase()),
        )
        .await
    {
        Ok(user) => user,
        Err(_) => {
            state
                .db
                .audit(None, "auth.2fa_failed", "two_factor_challenge", "bad code")
                .await?;
            return Err(AppError::Unauthorized);
        }
    };
    state
        .db
        .audit(Some(&user.id), "auth.login", &user.id, "two-factor")
        .await?;
    let secure_cookies = settings.security.secure_cookies;
    create_session_response(
        &state,
        jar.remove(transient_cookie(
            TWO_FACTOR_CHALLENGE_COOKIE,
            String::new(),
            secure_cookies,
        )),
        &user,
    )
    .await
}

pub(super) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    if let Some(cookie) = jar.get(&state.config.security.session_cookie_name) {
        state
            .db
            .delete_session(&util::hash_token(cookie.value()))
            .await?;
    }
    let secure_cookies = state.settings().await?.security.secure_cookies;
    let cookie = session_cookie(&state, String::new(), Some(0), secure_cookies);
    Ok((jar.remove(cookie), Redirect::to("/")).into_response())
}

pub(super) async fn password_reset_request_form(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    render(
        &state,
        "password_reset_request.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "sent": false, "smtp_enabled": state.mailer.enabled() }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct PasswordResetRequestForm {
    email: String,
    csrf_token: Option<String>,
}

pub(super) async fn password_reset_request(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<PasswordResetRequestForm>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    enforce_rate_limit(&state, &settings, "password_reset", &headers, user.as_ref()).await?;
    if state.mailer.enabled()
        && let Ok(reset_user) = state.db.user_by_email(&form.email).await
    {
        let token = util::secret_token();
        state
            .db
            .create_password_reset_token(
                &reset_user.id,
                &util::hash_token(&token),
                util::now_ts() + 60 * 60,
            )
            .await?;
        let reset_url = format!(
            "{}/auth/password-reset/{}",
            state.config.server.public_base_url.trim_end_matches('/'),
            token
        );
        // Deliver out of band. Awaiting the send here made both the latency and the failure mode
        // depend on whether the address existed, which told an unauthenticated caller exactly
        // which emails have accounts.
        let mailer = state.mailer.clone();
        let recipient = reset_user.email.clone();
        tokio::spawn(async move {
            if let Err(err) = mailer
                .send(
                    &recipient,
                    "Reset your Midden password",
                    &format!("Use this link to reset your password:\n\n{reset_url}\n\nThe link expires in one hour."),
                )
                .await
            {
                tracing::error!(error = %err, "failed to send password reset email");
            }
        });
    }
    render(
        &state,
        "password_reset_request.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "sent": true, "smtp_enabled": state.mailer.enabled() }),
    )
}

pub(super) async fn password_reset_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(token): Path<String>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    render(
        &state,
        "password_reset_form.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "token": token }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct PasswordResetSubmitForm {
    password: String,
    csrf_token: Option<String>,
}

pub(super) async fn password_reset_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(token): Path<String>,
    axum::Form(form): axum::Form<PasswordResetSubmitForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let reset_user = state
        .db
        .consume_password_reset_token(&util::hash_token(&token))
        .await
        .map_err(|_| AppError::BadRequest("invalid or expired password reset token".to_string()))?;
    let password_hash = util::hash_password(&form.password)?;
    state
        .db
        .update_user_password(&reset_user.id, &password_hash)
        .await?;
    state
        .db
        .set_user_email_verified_at(&reset_user.id, Some(util::now_ts()))
        .await?;
    // Recovery flow: assume the account may be compromised and cut off everything the previous
    // holder of the password could still be using.
    state
        .db
        .delete_sessions_for_user(&reset_user.id, None)
        .await?;
    state.db.revoke_api_tokens_for_user(&reset_user.id).await?;
    state
        .db
        .audit(
            Some(&reset_user.id),
            "user.password_reset",
            &reset_user.id,
            "email token",
        )
        .await?;
    create_session_response(&state, jar, &reset_user).await
}

pub(super) async fn verify_email(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(token): Path<String>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_accounts_enabled(&settings)?;
    let current = current_user(&state, &jar).await?;
    let verified = state
        .db
        .consume_email_verification_token(&util::hash_token(&token))
        .await
        .map_err(|_| {
            AppError::BadRequest("invalid or expired email verification token".to_string())
        })?;
    state
        .db
        .audit(
            Some(&verified.id),
            "user.email_verified",
            &verified.id,
            "email token",
        )
        .await?;
    render(
        &state,
        "email_verified.html",
        &settings,
        current.as_ref(),
        serde_json::json!({ "email": verified.email }),
    )
}

pub(super) async fn register_form(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    if !matches!(
        settings.policy.signup,
        crate::config::SignupMode::Open | crate::config::SignupMode::InviteOnly
    ) {
        return Err(AppError::Forbidden);
    }
    let invite_required = matches!(
        settings.policy.signup,
        crate::config::SignupMode::InviteOnly
    );
    render(
        &state,
        "register.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "invite_required": invite_required }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct RegisterForm {
    email: String,
    username: String,
    password: String,
    invite_token: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<RegisterForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    ensure_local_accounts_enabled(&settings)?;
    let user = current_user(&state, &jar).await?;
    if !matches!(
        settings.policy.signup,
        crate::config::SignupMode::Open | crate::config::SignupMode::InviteOnly
    ) {
        return Err(AppError::Forbidden);
    }
    if user.is_some() {
        return Ok(Redirect::to("/account"));
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let password_hash = util::hash_password(&form.password)?;
    let requires_email_verification =
        matches!(settings.policy.signup, crate::config::SignupMode::Open) && state.mailer.enabled();
    let created = if matches!(
        settings.policy.signup,
        crate::config::SignupMode::InviteOnly
    ) {
        let token = form
            .invite_token
            .as_deref()
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AppError::BadRequest("invite token is required".to_string()))?;
        state
            .db
            .create_user_with_invite(
                &form.email,
                &form.username,
                Some(&password_hash),
                &util::hash_token(token),
            )
            .await?
            .ok_or_else(|| AppError::BadRequest("invalid invite token".to_string()))?
    } else {
        state
            .db
            .create_user(
                &form.email,
                &form.username,
                Some(&password_hash),
                Role::User,
            )
            .await?
    };
    state
        .db
        .audit(Some(&created.id), "user.created", &created.id, "signup")
        .await?;
    if requires_email_verification {
        state
            .db
            .set_user_email_verified_at(&created.id, None)
            .await?;
        send_email_verification(&state, &created).await?;
        state
            .db
            .audit(
                Some(&created.id),
                "user.email_verification_sent",
                &created.id,
                "signup",
            )
            .await?;
    }
    Ok(Redirect::to("/auth/login"))
}

pub(super) async fn send_email_verification(state: &AppState, user: &User) -> AppResult<()> {
    if !state.mailer.enabled() {
        return Err(AppError::BadRequest(
            "email verification requires SMTP".to_string(),
        ));
    }
    let token = util::secret_token();
    state
        .db
        .create_email_verification_token(
            &user.id,
            &util::hash_token(&token),
            util::now_ts() + 24 * 60 * 60,
        )
        .await?;
    let verify_url = format!(
        "{}/auth/verify-email/{}",
        state.config.server.public_base_url.trim_end_matches('/'),
        token
    );
    state
        .mailer
        .send(
            &user.email,
            "Verify your Midden email",
            &format!("Use this link to verify your email address:\n\n{verify_url}\n\nThe link expires in 24 hours."),
        )
        .await?;
    Ok(())
}
