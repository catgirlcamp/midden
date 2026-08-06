use super::*;
use crate::commands;

pub(super) async fn new_paste(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    if !policy::can_create_paste(&settings, user.as_ref()) {
        let account_required = user.is_none()
            && settings.policy.create_paste != ActionRule::Anonymous
            && settings.policy.create_paste != ActionRule::Disabled;
        if !account_required {
            return Err(AppError::Forbidden);
        }
    }
    render(
        &state,
        "paste_new.html",
        &settings,
        user.as_ref(),
        serde_json::json!({}),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct PasteForm {
    title: Option<String>,
    syntax: Option<String>,
    expires: Option<String>,
    visibility: Option<String>,
    content: String,
    csrf_token: Option<String>,
}

pub(super) async fn create_paste(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<PasteForm>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    enforce_rate_limit(&state, &settings, "create_paste", &headers, user.as_ref()).await?;
    if !policy::can_create_paste(&settings, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let expires_at = parse_expiry_or_default_checked(
        &settings,
        user.as_ref(),
        "paste",
        form.expires.as_deref(),
        settings.limits.default_paste_expiry.as_deref(),
    )?;
    let visibility = requested_visibility(&settings, form.visibility.as_deref())?;
    let created = commands::create_paste(
        &state,
        &settings,
        user.as_ref(),
        commands::CreatePasteInput {
            title: form.title.as_deref(),
            syntax: form.syntax.as_deref(),
            content: &form.content,
            expires_at,
            visibility,
        },
    )
    .await?;
    render(
        &state,
        "paste_result.html",
        &settings,
        user.as_ref(),
        serde_json::json!({
            "paste": created.paste,
            "url": created.url,
            "raw_url": created.raw_url,
            "delete_token": created.delete_token,
        }),
    )
}

pub(super) async fn show_paste(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    let paste = match state.db.paste_by_public_id(&id).await {
        Ok(paste) => paste,
        Err(_) => {
            let existing = state
                .db
                .paste_by_public_id_any(&id)
                .await
                .map_err(|_| AppError::NotFound)?;
            return render_unavailable_item(
                &state,
                &settings,
                user.as_ref(),
                "paste",
                &id,
                &existing.state,
            );
        }
    };
    authorize_item_view(
        &settings,
        user.as_ref(),
        paste.owner_user_id.as_deref(),
        &paste.visibility,
    )?;
    let rendered = {
        let content = paste.content.clone();
        let syntax = paste.syntax.clone();
        tokio::task::spawn_blocking(move || render_paste_content(&content, syntax.as_deref()))
            .await
            .map_err(|err| AppError::Other(anyhow::anyhow!("paste rendering failed: {err}")))?
    };
    let can_edit = can_edit_paste(&settings, user.as_ref(), &paste);
    let revision_count = state.db.paste_revision_count(&paste.id).await.unwrap_or(0);
    let base = state.config.server.public_base_url.trim_end_matches('/');
    let page = serde_json::json!({
        "paste": paste,
        "rendered": rendered,
        "can_edit": can_edit,
        "revision_count": revision_count,
        "absolute_url": format!("{base}/p/{id}"),
        "absolute_raw_url": format!("{base}/p/{id}/raw"),
    });
    render(&state, "paste_show.html", &settings, user.as_ref(), page)
}

pub(super) async fn edit_paste_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let paste = state
        .db
        .paste_by_public_id(&id)
        .await
        .map_err(|_| AppError::NotFound)?;
    if !can_edit_paste(&settings, Some(&user), &paste) {
        return Err(AppError::Forbidden);
    }
    render(
        &state,
        "paste_edit.html",
        &settings,
        Some(&user),
        serde_json::json!({ "paste": paste }),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct PasteEditForm {
    title: Option<String>,
    syntax: Option<String>,
    content: String,
    csrf_token: Option<String>,
}

pub(super) async fn update_paste(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<PasteEditForm>,
) -> AppResult<Redirect> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar)
        .await?
        .ok_or(AppError::Unauthorized)?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    if form.content.len() as i64 > settings.limits.max_paste_bytes {
        return Err(AppError::PayloadTooLarge);
    }
    let paste = state
        .db
        .paste_by_public_id(&id)
        .await
        .map_err(|_| AppError::NotFound)?;
    if !can_edit_paste(&settings, Some(&user), &paste) {
        return Err(AppError::Forbidden);
    }
    let syntax = commands::normalize_syntax(form.syntax.as_deref());
    state
        .db
        .update_paste(
            &paste.id,
            form.title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            &form.content,
            syntax.as_deref(),
            Some(&user.id),
        )
        .await?;
    Ok(Redirect::to(&format!("/p/{id}")))
}

pub(super) async fn raw_paste(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    let paste = state
        .db
        .paste_by_public_id(&id)
        .await
        .map_err(|_| AppError::NotFound)?;
    authorize_item_view(
        &settings,
        user.as_ref(),
        paste.owner_user_id.as_deref(),
        &paste.visibility,
    )?;
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        paste.content,
    )
        .into_response())
}

fn can_edit_paste(settings: &RuntimeSettings, user: Option<&User>, paste: &Paste) -> bool {
    if !settings.features.paste_editing {
        return false;
    }
    let Some(user) = user else {
        return false;
    };
    user.role >= Role::Admin || paste.owner_user_id.as_deref() == Some(user.id.as_str())
}

/// Syntect's bundled definitions deserialize several megabytes each. Building them per request
/// made every view of a highlighted paste an unauthenticated CPU sink.
static HIGHLIGHTING: std::sync::LazyLock<Highlighting> =
    std::sync::LazyLock::new(|| Highlighting {
        syntaxes: syntect::parsing::SyntaxSet::load_defaults_newlines(),
        themes: syntect::highlighting::ThemeSet::load_defaults(),
    });

struct Highlighting {
    syntaxes: syntect::parsing::SyntaxSet,
    themes: syntect::highlighting::ThemeSet,
}

fn plain_paste_body(content: &str) -> String {
    format!(
        "<pre class=\"paste-body\"><code>{}</code></pre>",
        html_escape::encode_text(content)
    )
}

/// Highlights paste content. Blocking and CPU-bound for large pastes; call from `spawn_blocking`.
fn render_paste_content(content: &str, syntax: Option<&str>) -> String {
    let Some(syntax) = syntax.filter(|value| !value.trim().is_empty()) else {
        return plain_paste_body(content);
    };
    let Some(theme) = HIGHLIGHTING.themes.themes.get("base16-ocean.dark") else {
        return plain_paste_body(content);
    };
    let syntax_ref = HIGHLIGHTING
        .syntaxes
        .find_syntax_by_token(syntax)
        .unwrap_or_else(|| HIGHLIGHTING.syntaxes.find_syntax_plain_text());
    match syntect::html::highlighted_html_for_string(
        content,
        &HIGHLIGHTING.syntaxes,
        syntax_ref,
        theme,
    ) {
        Ok(html) => html,
        Err(_) => plain_paste_body(content),
    }
}
