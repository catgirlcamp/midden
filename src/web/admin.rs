use super::*;
use crate::{
    commands,
    domain::{ItemKind, ItemModerationPlan, ItemState, ItemVisibility, ReportAction},
};

pub(super) async fn admin(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let homepage_blocks_json = homepage_blocks_for_form(&settings.branding.homepage_blocks)?;
    let scanner_adapters_json = scanner_adapters_for_form(&settings.scanning.adapters)?;
    let user_quota = settings
        .limits
        .role_quotas
        .get("user")
        .cloned()
        .unwrap_or_default();
    render(
        &state,
        "admin.html",
        &settings,
        user.as_ref(),
        serde_json::json!({
            "blocked_hashes": settings.scanning.blocked_hashes.join("\n"),
            "blocked_mime_types": settings.scanning.blocked_mime_types.join("\n"),
            "homepage_blocks_json": homepage_blocks_json,
            "scanner_adapters_json": scanner_adapters_json,
            "user_quota": user_quota,
        }),
    )
}

pub(super) async fn admin_jobs(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    render(
        &state,
        "admin_jobs.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "summary": null }),
    )
}

pub(super) async fn admin_jobs_run_once(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let summary = crate::jobs::run_once(&state, &settings).await?;
    state
        .db
        .audit(
            user.as_ref().map(|user| user.id.as_str()),
            "jobs.run_once",
            "jobs",
            "admin UI",
        )
        .await?;
    render(
        &state,
        "admin_jobs.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "summary": summary }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminSearchQuery {
    pub(super) q: Option<String>,
    pub(super) paste_content: Option<bool>,
}

pub(super) async fn admin_search(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<AdminSearchQuery>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let q = query.q.unwrap_or_default();
    let (files, pastes) = if q.trim().is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (
            state.db.admin_search_files(&q).await?,
            state
                .db
                .admin_search_pastes(&q, query.paste_content.unwrap_or(false))
                .await?,
        )
    };
    render(
        &state,
        if htmx_request(&headers) {
            "admin_search_results.html"
        } else {
            "admin_search.html"
        },
        &settings,
        user.as_ref(),
        serde_json::json!({
            "q": q,
            "paste_content": query.paste_content.unwrap_or(false),
            "files": files,
            "pastes": pastes,
        }),
    )
}

pub(super) async fn admin_users(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let users = state.db.list_users().await?;
    let invites = state.db.list_invite_tokens().await?;
    render(
        &state,
        "admin_users.html",
        &settings,
        user.as_ref(),
        serde_json::json!({ "users": users, "invites": invites, "invite_token": null }),
    )
}

async fn render_admin_users_page(
    state: &AppState,
    settings: &RuntimeSettings,
    user: Option<&User>,
    invite_token: Option<String>,
    template: &str,
) -> AppResult<Html<String>> {
    let users = state.db.list_users().await?;
    let invites = state.db.list_invite_tokens().await?;
    render(
        state,
        template,
        settings,
        user,
        serde_json::json!({ "users": users, "invites": invites, "invite_token": invite_token }),
    )
}

fn role_requires_owner_actor(role: Role, user: Option<&User>) -> bool {
    role == Role::Owner && user.is_none_or(|user| user.role != Role::Owner)
}

async fn ensure_owner_account_mutation_allowed(
    state: &AppState,
    actor: Option<&User>,
    target: &User,
    next_role: Option<Role>,
    disabling: bool,
) -> AppResult<()> {
    if target.role != Role::Owner {
        return Ok(());
    }
    if actor.is_none_or(|user| user.role != Role::Owner) {
        return Err(AppError::Forbidden);
    }
    let removes_enabled_owner =
        !target.is_disabled && (disabling || next_role.is_some_and(|role| role != Role::Owner));
    if removes_enabled_owner && state.db.enabled_owner_count().await? <= 1 {
        return Err(AppError::BadRequest(
            "cannot remove the last enabled owner".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminCreateUserForm {
    email: String,
    username: String,
    password: String,
    role: String,
    csrf_token: Option<String>,
}

pub(super) async fn admin_create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AdminCreateUserForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let role = Role::parse_form(&form.role)
        .map_err(|err| AppError::BadRequest(format!("invalid role: {err}")))?;
    if role_requires_owner_actor(role, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let password_hash = util::hash_password(&form.password).await?;
    let created = state
        .db
        .create_user(&form.email, &form.username, Some(&password_hash), role)
        .await?;
    state
        .db
        .audit(
            user.as_ref().map(|user| user.id.as_str()),
            "user.created",
            &created.id,
            "admin UI",
        )
        .await?;
    if htmx_request(&headers) {
        Ok(render_admin_users_page(
            &state,
            &settings,
            user.as_ref(),
            None,
            "admin_users_lists.html",
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/users").into_response())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminRoleForm {
    role: String,
    csrf_token: Option<String>,
}

pub(super) async fn admin_set_user_role(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<AdminRoleForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let role = Role::parse_form(&form.role)
        .map_err(|err| AppError::BadRequest(format!("invalid role: {err}")))?;
    if role_requires_owner_actor(role, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let target = state.db.user_by_id(&id).await?;
    ensure_owner_account_mutation_allowed(&state, user.as_ref(), &target, Some(role), false)
        .await?;
    state.db.set_user_role(&id, role).await?;
    state
        .db
        .audit(
            user.as_ref().map(|user| user.id.as_str()),
            "user.role_updated",
            &id,
            role.as_str(),
        )
        .await?;
    if htmx_request(&headers) {
        Ok(render_admin_users_page(
            &state,
            &settings,
            user.as_ref(),
            None,
            "admin_users_lists.html",
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/users").into_response())
    }
}

pub(super) async fn admin_disable_user(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    set_user_disabled_from_admin(state, jar, headers, id, true, form.csrf_token).await
}

pub(super) async fn admin_enable_user(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    set_user_disabled_from_admin(state, jar, headers, id, false, form.csrf_token).await
}

async fn set_user_disabled_from_admin(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    id: String,
    disabled: bool,
    csrf_token: Option<String>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, csrf_token.as_deref())?;
    if user.as_ref().is_some_and(|user| user.id == id) && disabled {
        return Err(AppError::BadRequest(
            "admins cannot disable themselves".to_string(),
        ));
    }
    let target = state.db.user_by_id(&id).await?;
    ensure_owner_account_mutation_allowed(&state, user.as_ref(), &target, None, disabled).await?;
    state.db.set_user_disabled(&id, disabled).await?;
    state
        .db
        .audit(
            user.as_ref().map(|user| user.id.as_str()),
            if disabled {
                "user.disabled"
            } else {
                "user.enabled"
            },
            &id,
            "admin UI",
        )
        .await?;
    if htmx_request(&headers) {
        Ok(render_admin_users_page(
            &state,
            &settings,
            user.as_ref(),
            None,
            "admin_users_lists.html",
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/users").into_response())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminInviteForm {
    role: String,
    expires_hours: Option<i64>,
    csrf_token: Option<String>,
}

pub(super) async fn admin_create_invite(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AdminInviteForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let role = Role::parse_form(&form.role)
        .map_err(|err| AppError::BadRequest(format!("invalid role: {err}")))?;
    if role_requires_owner_actor(role, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let token = util::secret_token();
    let expires_at = form
        .expires_hours
        .filter(|hours| *hours > 0)
        .map(|hours| util::now_ts() + hours * 60 * 60);
    state
        .db
        .create_invite_token(
            &util::hash_token(&token),
            user.as_ref()
                .map(|user| user.id.as_str())
                .unwrap_or_default(),
            role,
            expires_at,
        )
        .await?;
    Ok(render_admin_users_page(
        &state,
        &settings,
        user.as_ref(),
        Some(token),
        if htmx_request(&headers) {
            "admin_users_lists.html"
        } else {
            "admin_users.html"
        },
    )
    .await?
    .into_response())
}

pub(super) async fn admin_revoke_invite(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<CsrfForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    state
        .db
        .revoke_invite_token(&id, user.as_ref().map(|user| user.id.as_str()))
        .await?;
    if htmx_request(&headers) {
        Ok(render_admin_users_page(
            &state,
            &settings,
            user.as_ref(),
            None,
            "admin_users_lists.html",
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/users").into_response())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminSettingsForm {
    feature_files: Option<String>,
    feature_pastes: Option<String>,
    feature_accounts: Option<String>,
    feature_api: Option<String>,
    feature_reports: Option<String>,
    feature_upload_by_url: Option<String>,
    feature_preview_pages: Option<String>,
    feature_public_browse: Option<String>,
    feature_oidc_login: Option<String>,
    feature_local_login: Option<String>,
    feature_paste_content_search: Option<String>,
    feature_paste_editing: Option<String>,
    max_upload_bytes: Option<String>,
    max_paste_bytes: Option<String>,
    default_file_expiry: Option<String>,
    default_paste_expiry: Option<String>,
    anonymous_storage_bytes: Option<String>,
    anonymous_daily_upload_bytes: Option<String>,
    anonymous_monthly_upload_bytes: Option<String>,
    anonymous_item_count: Option<String>,
    user_storage_bytes: Option<String>,
    user_daily_upload_bytes: Option<String>,
    user_monthly_upload_bytes: Option<String>,
    user_item_count: Option<String>,
    signup: String,
    policy_upload_file: String,
    policy_create_paste: String,
    policy_use_api: String,
    policy_view_item: String,
    policy_delete_own_item: String,
    policy_claim_anonymous_item: String,
    policy_create_account: String,
    delete_policy: String,
    instance_name: String,
    tagline: String,
    logo_url: Option<String>,
    favicon_url: Option<String>,
    accent_color: String,
    dark_mode: String,
    opengraph_description: String,
    opengraph_files: Option<String>,
    opengraph_pastes: Option<String>,
    takedown_page_text: String,
    homepage_blocks_json: Option<String>,
    abuse_email: Option<String>,
    contact_url: Option<String>,
    secure_cookies: Option<String>,
    content_disposition: String,
    reject_mime_mismatch: Option<String>,
    delivery_public_cache_seconds: Option<String>,
    delivery_static_cache_seconds: Option<String>,
    delivery_public_file_base_url: Option<String>,
    delivery_isolated_file_origin: Option<String>,
    delivery_signed_internal_urls: Option<String>,
    delivery_internal_url_secret: Option<String>,
    delivery_internal_url_ttl_seconds: Option<String>,
    processing_metadata_extraction: Option<String>,
    processing_metadata_stripping: Option<String>,
    processing_thumbnails: Option<String>,
    discovery_robots_index: Option<String>,
    discovery_page_size: Option<String>,
    jobs_enabled: Option<String>,
    jobs_interval_seconds: Option<String>,
    jobs_metadata_limit: Option<String>,
    jobs_scanner_retry_limit: Option<String>,
    jobs_storage_verify_interval_seconds: Option<String>,
    upload_temp_dir: Option<String>,
    metrics_enabled: Option<String>,
    metrics_access: String,
    metrics_bearer_token: Option<String>,
    rate_limit_backend: String,
    forced_attachment_mime_types: Option<String>,
    risky_mime_mode: String,
    allowed_mime_types: Option<String>,
    max_filename_bytes: Option<String>,
    expiry_allow_never: Option<String>,
    anonymous_max_file_expiry: Option<String>,
    user_max_file_expiry: Option<String>,
    anonymous_max_paste_expiry: Option<String>,
    user_max_paste_expiry: Option<String>,
    expiry_allowed_presets: Option<String>,
    token_default_ttl_seconds: Option<String>,
    token_max_ttl_seconds: Option<String>,
    thumbnail_max_dimension: Option<String>,
    thumbnail_jpeg_quality: Option<String>,
    moderation_notify_webhook_url: Option<String>,
    moderation_notify_webhook_secret: Option<String>,
    url_block_private_ips: Option<String>,
    url_max_redirects: Option<String>,
    url_connect_timeout_seconds: Option<String>,
    url_request_timeout_seconds: Option<String>,
    url_max_response_bytes: Option<String>,
    url_allowed_ports: Option<String>,
    url_blocked_ports: Option<String>,
    url_user_agent: Option<String>,
    url_allowed_hosts: Option<String>,
    url_blocked_hosts: Option<String>,
    rl_upload_file_enabled: Option<String>,
    rl_upload_file_requests: Option<String>,
    rl_upload_file_window: Option<String>,
    rl_upload_by_url_enabled: Option<String>,
    rl_upload_by_url_requests: Option<String>,
    rl_upload_by_url_window: Option<String>,
    rl_login_enabled: Option<String>,
    rl_login_requests: Option<String>,
    rl_login_window: Option<String>,
    rl_password_reset_enabled: Option<String>,
    rl_password_reset_requests: Option<String>,
    rl_password_reset_window: Option<String>,
    rl_report_enabled: Option<String>,
    rl_report_requests: Option<String>,
    rl_report_window: Option<String>,
    scanning_enabled: Option<String>,
    blocked_hashes: Option<String>,
    blocked_mime_types: Option<String>,
    default_on_error: String,
    scanner_adapters_json: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn admin_update_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<AdminSettingsForm>,
) -> AppResult<Redirect> {
    let user = current_user(&state, &jar).await?;
    if !policy::can_admin(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let settings = state.settings().await?;
    let persisted_settings = state.db.persisted_runtime_settings(&state.config).await?;
    let features = FeatureConfig {
        files: form.feature_files.is_some(),
        pastes: form.feature_pastes.is_some(),
        accounts: form.feature_accounts.is_some(),
        api: form.feature_api.is_some(),
        reports: form.feature_reports.is_some(),
        upload_by_url: form.feature_upload_by_url.is_some(),
        preview_pages: form.feature_preview_pages.is_some(),
        public_browse: form.feature_public_browse.is_some(),
        oidc_login: form.feature_oidc_login.is_some(),
        local_login: form.feature_local_login.is_some(),
        paste_content_search: form.feature_paste_content_search.is_some(),
        paste_editing: form.feature_paste_editing.is_some(),
    };
    let mut limits = settings.limits.clone();
    limits.max_upload_bytes =
        parse_required_i64("max_upload_bytes", form.max_upload_bytes.as_deref())?;
    limits.max_paste_bytes =
        parse_required_i64("max_paste_bytes", form.max_paste_bytes.as_deref())?;
    limits.default_file_expiry = nonempty(form.default_file_expiry.as_deref());
    limits.default_paste_expiry = nonempty(form.default_paste_expiry.as_deref());
    limits.anonymous_quota.storage_bytes =
        parse_optional_i64(form.anonymous_storage_bytes.as_deref())?;
    limits.anonymous_quota.daily_upload_bytes =
        parse_optional_i64(form.anonymous_daily_upload_bytes.as_deref())?;
    limits.anonymous_quota.monthly_upload_bytes =
        parse_optional_i64(form.anonymous_monthly_upload_bytes.as_deref())?;
    limits.anonymous_quota.item_count = parse_optional_i64(form.anonymous_item_count.as_deref())?;
    let mut user_quota = settings
        .limits
        .role_quotas
        .get("user")
        .cloned()
        .unwrap_or_default();
    user_quota.storage_bytes = parse_optional_i64(form.user_storage_bytes.as_deref())?;
    user_quota.daily_upload_bytes = parse_optional_i64(form.user_daily_upload_bytes.as_deref())?;
    user_quota.monthly_upload_bytes =
        parse_optional_i64(form.user_monthly_upload_bytes.as_deref())?;
    user_quota.item_count = parse_optional_i64(form.user_item_count.as_deref())?;
    if quota_is_empty(&user_quota) {
        limits.role_quotas.remove("user");
    } else {
        limits.role_quotas.insert("user".to_string(), user_quota);
    }

    let policy = PolicyConfig {
        signup: parse_signup_mode(&form.signup)?,
        upload_file: parse_action_rule(&form.policy_upload_file)?,
        create_paste: parse_action_rule(&form.policy_create_paste)?,
        use_api: parse_action_rule(&form.policy_use_api)?,
        view_item: parse_action_rule(&form.policy_view_item)?,
        delete_own_item: parse_action_rule(&form.policy_delete_own_item)?,
        delete_policy: parse_delete_policy(&form.delete_policy)?,
        claim_anonymous_item: parse_action_rule(&form.policy_claim_anonymous_item)?,
        create_account: parse_action_rule(&form.policy_create_account)?,
    };

    let mut security = settings.security.clone();
    security.secure_cookies = form.secure_cookies.is_some();
    security.content_disposition = match form.content_disposition.as_str() {
        "attachment" => ContentDispositionMode::Attachment,
        "inline" => ContentDispositionMode::Inline,
        _ => {
            return Err(AppError::BadRequest(
                "invalid content disposition".to_string(),
            ));
        }
    };
    security.reject_mime_mismatch = form.reject_mime_mismatch.is_some();
    security.rate_limit_backend = parse_rate_limit_backend(&form.rate_limit_backend)?;
    security.content_policy.allowed_mime_types = lines(form.allowed_mime_types.as_deref());
    security.content_policy.forced_attachment_mime_types =
        lines(form.forced_attachment_mime_types.as_deref());
    security.content_policy.risky_mime_mode = match form.risky_mime_mode.as_str() {
        "attachment" => RiskyMimeMode::Attachment,
        "inline_on_isolated_origin" => RiskyMimeMode::InlineOnIsolatedOrigin,
        "plaintext" => RiskyMimeMode::Plaintext,
        _ => return Err(AppError::BadRequest("invalid risky MIME mode".to_string())),
    };
    security.content_policy.max_filename_bytes =
        parse_optional_usize(form.max_filename_bytes.as_deref())?
            .unwrap_or(security.content_policy.max_filename_bytes)
            .max(1);
    security.url_upload.block_private_ips = form.url_block_private_ips.is_some();
    security.url_upload.max_redirects = parse_optional_usize(form.url_max_redirects.as_deref())?
        .unwrap_or(security.url_upload.max_redirects);
    security.url_upload.connect_timeout_seconds =
        parse_optional_u64(form.url_connect_timeout_seconds.as_deref())?
            .unwrap_or(security.url_upload.connect_timeout_seconds)
            .max(1);
    security.url_upload.request_timeout_seconds =
        parse_optional_u64(form.url_request_timeout_seconds.as_deref())?
            .unwrap_or(security.url_upload.request_timeout_seconds)
            .max(1);
    security.url_upload.max_response_bytes =
        parse_optional_i64(form.url_max_response_bytes.as_deref())?;
    security.url_upload.allowed_ports = parse_u16_lines(form.url_allowed_ports.as_deref())?;
    security.url_upload.blocked_ports = parse_u16_lines(form.url_blocked_ports.as_deref())?;
    security.url_upload.user_agent = nonempty(form.url_user_agent.as_deref());
    security.url_upload.allowed_hosts = lines(form.url_allowed_hosts.as_deref());
    security.url_upload.blocked_hosts = lines(form.url_blocked_hosts.as_deref());
    apply_rate_limit_form(
        &mut security.rate_limits,
        "upload_file",
        form.rl_upload_file_enabled.is_some(),
        form.rl_upload_file_requests.as_deref(),
        form.rl_upload_file_window.as_deref(),
    )?;
    apply_rate_limit_form(
        &mut security.rate_limits,
        "upload_by_url",
        form.rl_upload_by_url_enabled.is_some(),
        form.rl_upload_by_url_requests.as_deref(),
        form.rl_upload_by_url_window.as_deref(),
    )?;
    apply_rate_limit_form(
        &mut security.rate_limits,
        "login",
        form.rl_login_enabled.is_some(),
        form.rl_login_requests.as_deref(),
        form.rl_login_window.as_deref(),
    )?;
    apply_rate_limit_form(
        &mut security.rate_limits,
        "password_reset",
        form.rl_password_reset_enabled.is_some(),
        form.rl_password_reset_requests.as_deref(),
        form.rl_password_reset_window.as_deref(),
    )?;
    apply_rate_limit_form(
        &mut security.rate_limits,
        "report",
        form.rl_report_enabled.is_some(),
        form.rl_report_requests.as_deref(),
        form.rl_report_window.as_deref(),
    )?;

    let mut delivery = settings.delivery.clone();
    delivery.public_cache_seconds =
        parse_optional_u64(form.delivery_public_cache_seconds.as_deref())?
            .unwrap_or(delivery.public_cache_seconds);
    delivery.static_cache_seconds =
        parse_optional_u64(form.delivery_static_cache_seconds.as_deref())?
            .unwrap_or(delivery.static_cache_seconds);
    delivery.public_file_base_url = nonempty(form.delivery_public_file_base_url.as_deref());
    delivery.isolated_file_origin = form.delivery_isolated_file_origin.is_some();
    delivery.signed_internal_urls = form.delivery_signed_internal_urls.is_some();
    delivery.internal_url_secret = nonempty(form.delivery_internal_url_secret.as_deref());
    delivery.internal_url_ttl_seconds =
        parse_optional_i64(form.delivery_internal_url_ttl_seconds.as_deref())?
            .unwrap_or(delivery.internal_url_ttl_seconds)
            .max(1);
    if delivery.isolated_file_origin && delivery.public_file_base_url.is_none() {
        return Err(AppError::BadRequest(
            "isolated file origin requires a public file base URL".to_string(),
        ));
    }
    if delivery.signed_internal_urls && delivery.internal_url_secret.is_none() {
        return Err(AppError::BadRequest(
            "signed internal URLs require a secret".to_string(),
        ));
    }

    let mut processing = settings.processing.clone();
    processing.metadata_extraction = form.processing_metadata_extraction.is_some();
    processing.metadata_stripping = form.processing_metadata_stripping.is_some();
    processing.thumbnails = form.processing_thumbnails.is_some();
    processing.thumbnail_max_dimension =
        parse_optional_u32(form.thumbnail_max_dimension.as_deref())?
            .unwrap_or(processing.thumbnail_max_dimension)
            .max(1);
    processing.thumbnail_jpeg_quality = parse_optional_u8(form.thumbnail_jpeg_quality.as_deref())?
        .unwrap_or(processing.thumbnail_jpeg_quality)
        .clamp(1, 100);

    let mut discovery = settings.discovery.clone();
    discovery.robots_index = form.discovery_robots_index.is_some();
    discovery.page_size = parse_optional_u32(form.discovery_page_size.as_deref())?
        .unwrap_or(discovery.page_size)
        .clamp(1, 1000);

    let mut jobs = settings.jobs.clone();
    jobs.enabled = form.jobs_enabled.is_some();
    jobs.interval_seconds = parse_optional_u64(form.jobs_interval_seconds.as_deref())?
        .unwrap_or(jobs.interval_seconds)
        .max(30);
    jobs.metadata_limit = parse_optional_u32(form.jobs_metadata_limit.as_deref())?
        .unwrap_or(jobs.metadata_limit)
        .max(1);
    jobs.scanner_retry_limit = parse_optional_u32(form.jobs_scanner_retry_limit.as_deref())?
        .unwrap_or(jobs.scanner_retry_limit)
        .max(1);
    jobs.storage_verify_interval_seconds =
        parse_optional_u64(form.jobs_storage_verify_interval_seconds.as_deref())?
            .unwrap_or(jobs.storage_verify_interval_seconds)
            .max(60);

    let mut uploads = settings.uploads.clone();
    uploads.temp_dir = nonempty(form.upload_temp_dir.as_deref()).map(PathBuf::from);

    let mut metrics = settings.metrics.clone();
    metrics.enabled = form.metrics_enabled.is_some();
    metrics.access = parse_metrics_access(&form.metrics_access)?;
    metrics.bearer_token = nonempty(form.metrics_bearer_token.as_deref());
    if matches!(metrics.access, crate::config::MetricsAccessMode::Token)
        && metrics.bearer_token.is_none()
    {
        return Err(AppError::BadRequest(
            "token-protected metrics require a bearer token".to_string(),
        ));
    }

    let mut tokens = settings.tokens.clone();
    tokens.default_ttl_seconds = parse_optional_i64(form.token_default_ttl_seconds.as_deref())?;
    tokens.max_ttl_seconds = parse_optional_i64(form.token_max_ttl_seconds.as_deref())?;
    if let (Some(default), Some(max)) = (tokens.default_ttl_seconds, tokens.max_ttl_seconds)
        && default > max
    {
        return Err(AppError::BadRequest(
            "default token TTL cannot exceed max token TTL".to_string(),
        ));
    }

    let mut moderation = settings.moderation.clone();
    moderation.notify_webhook_url = nonempty(form.moderation_notify_webhook_url.as_deref());
    moderation.notify_webhook_secret = nonempty(form.moderation_notify_webhook_secret.as_deref());

    limits.expiry.allow_never = form.expiry_allow_never.is_some();
    limits.expiry.anonymous_max_file_expiry = nonempty(form.anonymous_max_file_expiry.as_deref());
    limits.expiry.user_max_file_expiry = nonempty(form.user_max_file_expiry.as_deref());
    limits.expiry.anonymous_max_paste_expiry = nonempty(form.anonymous_max_paste_expiry.as_deref());
    limits.expiry.user_max_paste_expiry = nonempty(form.user_max_paste_expiry.as_deref());
    limits.expiry.allowed_presets =
        expiry_presets_from_form(form.expiry_allowed_presets.as_deref());

    let mut branding = settings.branding.clone();
    branding.instance_name = form.instance_name.trim().to_string();
    branding.tagline = form.tagline.trim().to_string();
    branding.logo_url = nonempty(form.logo_url.as_deref());
    branding.favicon_url = nonempty(form.favicon_url.as_deref());
    branding.accent_color = form.accent_color.trim().to_string();
    branding.dark_mode = match form.dark_mode.as_str() {
        "auto" | "light" | "dark" => form.dark_mode.clone(),
        _ => {
            return Err(AppError::BadRequest(
                "invalid dark mode behavior".to_string(),
            ));
        }
    };
    branding.opengraph_description = form.opengraph_description.trim().to_string();
    branding.opengraph_files = form.opengraph_files.is_some();
    branding.opengraph_pastes = form.opengraph_pastes.is_some();
    branding.takedown_page_text = form.takedown_page_text.trim().to_string();
    branding.homepage_blocks = parse_homepage_blocks_json(form.homepage_blocks_json.as_deref())?;
    branding.abuse_email = nonempty(form.abuse_email.as_deref());
    branding.contact_url = nonempty(form.contact_url.as_deref());

    let mut scanning = settings.scanning.clone();
    scanning.enabled = form.scanning_enabled.is_some();
    scanning.blocked_hashes = lines(form.blocked_hashes.as_deref());
    scanning.blocked_mime_types = lines(form.blocked_mime_types.as_deref());
    scanning.default_on_error = parse_scan_decision(&form.default_on_error)?;
    scanning.adapters = parse_scanner_adapters_json(form.scanner_adapters_json.as_deref())?;
    let mut candidate_settings = RuntimeSettings {
        features,
        limits,
        branding,
        policy,
        security,
        delivery,
        scanning,
        processing,
        discovery,
        jobs,
        uploads,
        metrics,
        tokens,
        moderation,
    };
    state.db.restore_environment_owned_fields(
        &mut candidate_settings,
        &persisted_settings,
        &state.config,
    )?;
    let mut effective_candidate = candidate_settings.clone();
    state
        .db
        .apply_runtime_environment(&mut effective_candidate, &state.config)?;
    if !effective_candidate.features.local_login && !oidc::enabled(&state, &effective_candidate) {
        return Err(AppError::BadRequest(
            "at least one sign-in method must remain enabled".to_string(),
        ));
    }
    state
        .config
        .validate_runtime_settings(&effective_candidate)
        .map_err(|err| AppError::BadRequest(format!("invalid runtime settings: {err}")))?;
    state
        .db
        .replace_runtime_settings(
            &candidate_settings,
            user.as_ref().map(|u| u.id.as_str()),
            "admin UI",
        )
        .await?;
    Ok(Redirect::to("/admin"))
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminReportsQuery {
    pub(super) state: Option<String>,
    pub(super) kind: Option<String>,
    pub(super) reason: Option<String>,
    pub(super) days: Option<i64>,
}

pub(super) async fn admin_reports(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<AdminReportsQuery>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    if !settings.features.reports {
        return Err(AppError::NotFound);
    }
    let state_filter = query.state.as_deref().filter(|value| !value.is_empty());
    let kind_filter = query.kind.as_deref().filter(|value| !value.is_empty());
    let reason_filter = query
        .reason
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let created_after = query
        .days
        .filter(|days| *days > 0)
        .map(|days| util::now_ts() - days * 60 * 60 * 24);
    let reports = state
        .db
        .list_reports_filtered(state_filter, kind_filter, reason_filter, created_after)
        .await?;
    render(
        &state,
        if htmx_request(&headers) {
            "reports_table.html"
        } else {
            "reports.html"
        },
        &settings,
        user.as_ref(),
        serde_json::json!({
            "reports": reports,
            "filters": {
                "state": query.state.unwrap_or_default(),
                "kind": query.kind.unwrap_or_default(),
                "reason": query.reason.unwrap_or_default(),
                "days": query.days,
            },
        }),
    )
}

#[allow(clippy::too_many_arguments)]
async fn render_reports_table(
    state: &AppState,
    settings: &RuntimeSettings,
    user: Option<&User>,
    state_value: Option<String>,
    kind_value: Option<String>,
    reason_value: Option<String>,
    days_value: Option<i64>,
) -> AppResult<Html<String>> {
    let state_text = state_value.unwrap_or_default();
    let kind_text = kind_value.unwrap_or_default();
    let reason_text = reason_value.unwrap_or_default();
    let state_filter = state_text.as_str().trim();
    let kind_filter = kind_text.as_str().trim();
    let reason_filter = reason_text.as_str().trim();
    let created_after = days_value
        .filter(|days| *days > 0)
        .map(|days| util::now_ts() - days * 60 * 60 * 24);
    let reports = state
        .db
        .list_reports_filtered(
            if state_filter.is_empty() {
                None
            } else {
                Some(state_filter)
            },
            if kind_filter.is_empty() {
                None
            } else {
                Some(kind_filter)
            },
            if reason_filter.is_empty() {
                None
            } else {
                Some(reason_filter)
            },
            created_after,
        )
        .await?;
    render(
        state,
        "reports_table.html",
        settings,
        user,
        serde_json::json!({
            "reports": reports,
            "filters": {
                "state": state_text,
                "kind": kind_text,
                "reason": reason_text,
                "days": days_value,
            },
        }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminReportActionForm {
    pub(super) action: String,
    pub(super) note: Option<String>,
    filter_state: Option<String>,
    filter_kind: Option<String>,
    filter_reason: Option<String>,
    filter_days: Option<i64>,
    csrf_token: Option<String>,
}

pub(super) async fn admin_update_report(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<AdminReportActionForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    if !settings.features.reports {
        return Err(AppError::NotFound);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    commands::moderate_reports(
        &state,
        std::slice::from_ref(&id),
        ReportAction::parse(&form.action)?,
        user.as_ref().map(|user| user.id.as_str()),
        form.note.as_deref(),
    )
    .await?;
    if htmx_request(&headers) {
        Ok(render_reports_table(
            &state,
            &settings,
            user.as_ref(),
            form.filter_state,
            form.filter_kind,
            form.filter_reason,
            form.filter_days,
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/reports").into_response())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminBulkReportActionForm {
    action: String,
    note: Option<String>,
    #[serde(default)]
    report_ids: Vec<String>,
    filter_state: Option<String>,
    filter_kind: Option<String>,
    filter_reason: Option<String>,
    filter_days: Option<i64>,
    csrf_token: Option<String>,
}

pub(super) async fn admin_bulk_update_reports(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AdminBulkReportActionForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    if !settings.features.reports {
        return Err(AppError::NotFound);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    commands::moderate_reports(
        &state,
        &form.report_ids,
        ReportAction::parse(&form.action)?,
        user.as_ref().map(|user| user.id.as_str()),
        form.note.as_deref(),
    )
    .await?;
    if htmx_request(&headers) {
        Ok(render_reports_table(
            &state,
            &settings,
            user.as_ref(),
            form.filter_state,
            form.filter_kind,
            form.filter_reason,
            form.filter_days,
        )
        .await?
        .into_response())
    } else {
        Ok(Redirect::to("/admin/reports").into_response())
    }
}

pub(super) async fn admin_item(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((kind, id)): Path<(String, String)>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let item = moderation_item_json(&state, &kind, &id).await?;
    let reports = state.db.reports_for_item(&kind, &id).await?;
    let scans = state.db.scan_results_for_item(&kind, &id).await?;
    let audits = state.db.audit_events_for_target(&id).await?;
    let notes = state.db.moderation_notes_for_item(&kind, &id).await?;
    render(
        &state,
        "admin_item.html",
        &settings,
        user.as_ref(),
        serde_json::json!({
            "kind": kind,
            "id": id,
            "item": item,
            "reports": reports,
            "scans": scans,
            "audits": audits,
            "notes": notes,
        }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminItemActionForm {
    action: String,
    state: Option<String>,
    visibility: Option<String>,
    note: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn admin_update_item(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((kind, id)): Path<(String, String)>,
    axum::Form(form): axum::Form<AdminItemActionForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_moderate(user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let item_kind = ItemKind::parse(&kind)?;
    let mut plan = ItemModerationPlan::new(item_kind, id.clone());
    match form.action.as_str() {
        "set_state" => {
            let state_value = form
                .state
                .as_deref()
                .ok_or_else(|| AppError::BadRequest("invalid item state".to_string()))?;
            plan.state = Some(ItemState::parse(state_value)?);
        }
        "set_visibility" => {
            let visibility = requested_visibility(&settings, form.visibility.as_deref())?;
            plan.visibility = Some(ItemVisibility::parse(&settings, visibility)?);
        }
        "add_note" => {
            let note = form
                .note
                .as_deref()
                .map(str::trim)
                .filter(|note| !note.is_empty())
                .ok_or_else(|| AppError::BadRequest("note is required".to_string()))?;
            plan.note = Some(note.to_string());
        }
        "block_hash" => {
            plan.block_hash = true;
        }
        _ => return Err(AppError::BadRequest("unknown item action".to_string())),
    }
    commands::moderate_item(
        &state,
        &settings,
        user.as_ref().map(|user| user.id.as_str()),
        plan,
        "item moderation",
    )
    .await?;
    Ok(Redirect::to(&format!("/admin/items/{kind}/{id}")))
}

async fn moderation_item_json(
    state: &AppState,
    kind: &str,
    id: &str,
) -> AppResult<serde_json::Value> {
    match kind {
        "file" => {
            let file = state
                .db
                .file_by_public_id(id)
                .await
                .map_err(|_| AppError::NotFound)?;
            Ok(serde_json::json!({
                "public_id": file.public_id,
                "filename": file.original_filename,
                "content_type": file.content_type,
                "size_bytes": file.size_bytes,
                "image_width": file.image_width,
                "image_height": file.image_height,
                "blob_hash": file.blob_hash,
                "visibility": file.visibility,
                "metadata": file.metadata_json.as_deref().and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok()),
                "thumbnail_hash": file.thumbnail_hash,
                "state": file.state,
                "created_at": file.created_at,
                "expires_at": file.expires_at,
            }))
        }
        "paste" => {
            let paste = state
                .db
                .paste_by_public_id_any(id)
                .await
                .map_err(|_| AppError::NotFound)?;
            Ok(serde_json::json!({
                "public_id": paste.public_id,
                "title": paste.title,
                "syntax": paste.syntax,
                "size_bytes": paste.content.len(),
                "visibility": paste.visibility,
                "state": paste.state,
                "created_at": paste.created_at,
                "expires_at": paste.expires_at,
            }))
        }
        _ => Err(AppError::NotFound),
    }
}

fn scanner_adapters_for_form(adapters: &[ScannerAdapterConfig]) -> AppResult<String> {
    serde_json::to_string_pretty(adapters).map_err(|err| AppError::Other(err.into()))
}

fn parse_scanner_adapters_json(value: Option<&str>) -> AppResult<Vec<ScannerAdapterConfig>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    serde_json::from_str(value)
        .map_err(|err| AppError::BadRequest(format!("invalid scanner adapters JSON: {err}")))
}

fn parse_required_i64(name: &str, value: Option<&str>) -> AppResult<i64> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest(format!("{name} is required")))?;
    value
        .parse::<i64>()
        .map_err(|err| AppError::BadRequest(format!("{name}: {err}")))
}

fn parse_optional_i64(value: Option<&str>) -> AppResult<Option<i64>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(value.parse::<i64>().map_err(|err| {
        AppError::BadRequest(format!("invalid integer: {err}"))
    })?))
}

fn parse_optional_usize(value: Option<&str>) -> AppResult<Option<usize>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(value.parse::<usize>().map_err(|err| {
        AppError::BadRequest(format!("invalid integer: {err}"))
    })?))
}

fn parse_optional_u32(value: Option<&str>) -> AppResult<Option<u32>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(value.parse::<u32>().map_err(|err| {
        AppError::BadRequest(format!("invalid integer: {err}"))
    })?))
}

fn parse_optional_u64(value: Option<&str>) -> AppResult<Option<u64>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(value.parse::<u64>().map_err(|err| {
        AppError::BadRequest(format!("invalid integer: {err}"))
    })?))
}

fn parse_optional_u8(value: Option<&str>) -> AppResult<Option<u8>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(value.parse::<u8>().map_err(|err| {
        AppError::BadRequest(format!("invalid integer: {err}"))
    })?))
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn lines(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_u16_lines(value: Option<&str>) -> AppResult<Vec<u16>> {
    lines(value)
        .into_iter()
        .map(|line| {
            line.parse::<u16>()
                .map_err(|err| AppError::BadRequest(format!("invalid port {line}: {err}")))
        })
        .collect()
}

fn quota_is_empty(quota: &crate::config::QuotaConfig) -> bool {
    quota.storage_bytes.is_none()
        && quota.daily_upload_bytes.is_none()
        && quota.monthly_upload_bytes.is_none()
        && quota.item_count.is_none()
}

fn parse_rate_limit_backend(value: &str) -> AppResult<crate::config::RateLimitBackend> {
    match value {
        "memory" => Ok(crate::config::RateLimitBackend::Memory),
        "database" => Ok(crate::config::RateLimitBackend::Database),
        _ => Err(AppError::BadRequest(
            "invalid rate limit backend".to_string(),
        )),
    }
}

fn parse_metrics_access(value: &str) -> AppResult<crate::config::MetricsAccessMode> {
    match value {
        "public" => Ok(crate::config::MetricsAccessMode::Public),
        "admin" => Ok(crate::config::MetricsAccessMode::Admin),
        "token" => Ok(crate::config::MetricsAccessMode::Token),
        "loopback" => Ok(crate::config::MetricsAccessMode::Loopback),
        _ => Err(AppError::BadRequest("invalid metrics access".to_string())),
    }
}

fn parse_signup_mode(value: &str) -> AppResult<SignupMode> {
    match value {
        "disabled" => Ok(SignupMode::Disabled),
        "open" => Ok(SignupMode::Open),
        "invite_only" => Ok(SignupMode::InviteOnly),
        "admin_created" => Ok(SignupMode::AdminCreated),
        _ => Err(AppError::BadRequest("invalid signup mode".to_string())),
    }
}

fn parse_action_rule(value: &str) -> AppResult<ActionRule> {
    match value {
        "disabled" => Ok(ActionRule::Disabled),
        "anonymous" => Ok(ActionRule::Anonymous),
        "authenticated" => Ok(ActionRule::Authenticated),
        "moderator" => Ok(ActionRule::Moderator),
        "admin" => Ok(ActionRule::Admin),
        "owner" => Ok(ActionRule::Owner),
        _ => Err(AppError::BadRequest("invalid action rule".to_string())),
    }
}

fn parse_delete_policy(value: &str) -> AppResult<DeletePolicy> {
    match value {
        "disabled" => Ok(DeletePolicy::Disabled),
        "delete_tokens" => Ok(DeletePolicy::DeleteTokens),
        "no_anonymous_delete" => Ok(DeletePolicy::NoAnonymousDelete),
        "claim_later" => Ok(DeletePolicy::ClaimLater),
        _ => Err(AppError::BadRequest("invalid delete policy".to_string())),
    }
}

fn parse_scan_decision(value: &str) -> AppResult<ScanDecision> {
    match value {
        "allow" => Ok(ScanDecision::Allow),
        "quarantine" => Ok(ScanDecision::Quarantine),
        "reject" => Ok(ScanDecision::Reject),
        _ => Err(AppError::BadRequest(
            "invalid scanner failure behavior".to_string(),
        )),
    }
}

fn apply_rate_limit_form(
    rate_limits: &mut BTreeMap<String, RateLimitConfig>,
    action: &str,
    enabled: bool,
    requests: Option<&str>,
    window_seconds: Option<&str>,
) -> AppResult<()> {
    if !enabled {
        rate_limits.remove(action);
        return Ok(());
    }
    rate_limits.insert(
        action.to_string(),
        RateLimitConfig {
            requests: parse_optional_u32(requests)?.unwrap_or(10),
            window_seconds: parse_optional_u64(window_seconds)?.unwrap_or(60),
            enabled: true,
        },
    );
    Ok(())
}

fn homepage_blocks_for_form(blocks: &[HomepageBlock]) -> AppResult<String> {
    serde_json::to_string_pretty(blocks).map_err(|err| AppError::Other(err.into()))
}

fn parse_homepage_blocks_json(input: Option<&str>) -> AppResult<Vec<HomepageBlock>> {
    let Some(input) = input.map(str::trim).filter(|input| !input.is_empty()) else {
        return Ok(Vec::new());
    };
    let blocks: Vec<HomepageBlock> = serde_json::from_str(input)
        .map_err(|err| AppError::BadRequest(format!("invalid homepage blocks JSON: {err}")))?;
    if blocks
        .iter()
        .any(|block| block.title.trim().is_empty() || block.body.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "homepage blocks require title and body".to_string(),
        ));
    }
    Ok(blocks)
}

fn expiry_presets_from_form(input: Option<&str>) -> Vec<String> {
    lines(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_adapter_editor_round_trips_arbitrary_vectors_and_argv() {
        let adapters = vec![
            ScannerAdapterConfig::Command {
                program: "scanner one".to_string(),
                args: vec![
                    "--label".to_string(),
                    "value with spaces".to_string(),
                    "quoted=\"value\"".to_string(),
                ],
            },
            ScannerAdapterConfig::Command {
                program: "scanner-two".to_string(),
                args: vec!["--stdin".to_string()],
            },
            ScannerAdapterConfig::Webhook {
                url: "https://scanner-one.example.test/check".to_string(),
                secret: Some("first secret".to_string()),
            },
            ScannerAdapterConfig::Webhook {
                url: "https://scanner-two.example.test/check".to_string(),
                secret: None,
            },
            ScannerAdapterConfig::ClamAv {
                socket: "tcp://127.0.0.1:3310".to_string(),
            },
        ];

        let encoded = scanner_adapters_for_form(&adapters).unwrap();
        let decoded = parse_scanner_adapters_json(Some(&encoded)).unwrap();

        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(adapters).unwrap()
        );
    }

    #[test]
    fn empty_scanner_adapter_editor_round_trips_as_empty_vector() {
        let encoded = scanner_adapters_for_form(&[]).unwrap();
        let decoded = parse_scanner_adapters_json(Some(&encoded)).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn homepage_block_editor_round_trips_pipes_and_newlines() {
        let blocks = vec![
            HomepageBlock {
                title: "Title | with a pipe".to_string(),
                body: "First line\nSecond | line".to_string(),
                href: Some("https://example.test/a|b?next=line%0Abreak".to_string()),
                link_label: Some("Read | more\nnow".to_string()),
            },
            HomepageBlock {
                title: "Another\nblock".to_string(),
                body: "Body".to_string(),
                href: None,
                link_label: None,
            },
        ];

        let encoded = homepage_blocks_for_form(&blocks).unwrap();
        let decoded = parse_homepage_blocks_json(Some(&encoded)).unwrap();

        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(blocks).unwrap()
        );
    }

    #[test]
    fn empty_homepage_block_editor_round_trips_as_empty_vector() {
        let encoded = homepage_blocks_for_form(&[]).unwrap();
        let decoded = parse_homepage_blocks_json(Some(&encoded)).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn empty_expiry_preset_editor_clears_existing_presets() {
        let mut expiry = crate::config::ExpiryGuardrailsConfig::default();
        assert!(!expiry.allowed_presets.is_empty());

        expiry.allowed_presets = expiry_presets_from_form(Some(" \r\n \n"));

        assert!(expiry.allowed_presets.is_empty());
    }
}
