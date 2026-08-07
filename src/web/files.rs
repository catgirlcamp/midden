use super::*;

pub(super) async fn index(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    let page = serde_json::json!({
        "max_upload": util::human_bytes(settings.limits.max_upload_bytes),
        "delete_policy": format!("{:?}", settings.policy.delete_policy),
    });
    render(&state, "index.html", &settings, user.as_ref(), page)
}

pub(super) async fn upload_form_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    multipart: Multipart,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    enforce_rate_limit(&state, &settings, "upload_file", &headers, user.as_ref()).await?;
    if !policy::can_upload_file(&settings, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let form = read_upload_form(&settings, multipart, settings.limits.max_upload_bytes).await?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    let result = persist_file_upload(
        &state,
        &settings,
        user.as_ref(),
        form.file,
        parse_expiry_or_default_checked(
            &settings,
            user.as_ref(),
            "file",
            form.expires.as_deref(),
            settings.limits.default_file_expiry.as_deref(),
        )?,
        requested_visibility(&settings, form.visibility.as_deref())?,
    )
    .await?;
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));
    if wants_json {
        Ok(axum::Json(serde_json::json!({
            "finalUrl": result.url,
            "rawUrl": result.raw_url,
            "deleteUrl": format!("/delete/file/{}", result.file.public_id),
            "deleteToken": result.delete_token
        }))
        .into_response())
    } else {
        let page = serde_json::json!({
            "url": result.url,
            "raw_url": result.raw_url,
            "delete_token": result.delete_token,
            "file": result.file,
        });
        Ok(render(&state, "upload_result.html", &settings, user.as_ref(), page)?.into_response())
    }
}

pub(super) async fn url_upload_form(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Html<String>> {
    let settings = state.settings().await?;
    if !settings.features.upload_by_url {
        return Err(AppError::NotFound);
    }
    let user = current_user(&state, &jar).await?;
    render(
        &state,
        "url_upload.html",
        &settings,
        user.as_ref(),
        serde_json::json!({}),
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct UrlUploadForm {
    url: String,
    expires: Option<String>,
    visibility: Option<String>,
    csrf_token: Option<String>,
}

pub(super) async fn url_upload(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<UrlUploadForm>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    if !settings.features.upload_by_url {
        return Err(AppError::NotFound);
    }
    let user = current_user(&state, &jar).await?;
    validate_csrf(&jar, form.csrf_token.as_deref())?;
    enforce_rate_limit(&state, &settings, "upload_by_url", &headers, user.as_ref()).await?;
    if !policy::can_upload_file(&settings, user.as_ref()) {
        return Err(AppError::Forbidden);
    }
    let url = url::Url::parse(&form.url)
        .map_err(|err| AppError::BadRequest(format!("invalid URL: {err}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "only http and https URLs are supported".to_string(),
        ));
    }
    let mut fetched = fetch_url_upload(&settings, url.clone()).await?;
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned);
    fetched.file.filename = filename;
    let result = persist_file_upload(
        &state,
        &settings,
        user.as_ref(),
        fetched.file,
        parse_expiry_or_default_checked(
            &settings,
            user.as_ref(),
            "file",
            form.expires.as_deref(),
            settings.limits.default_file_expiry.as_deref(),
        )?,
        requested_visibility(&settings, form.visibility.as_deref())?,
    )
    .await?;
    let page = serde_json::json!({
        "url": result.url,
        "raw_url": result.raw_url,
        "delete_token": result.delete_token,
        "file": result.file,
    });
    Ok(render(&state, "upload_result.html", &settings, user.as_ref(), page)?.into_response())
}

pub(super) async fn file_slug(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> AppResult<Response> {
    let Some((public_id, _extension)) = util::split_slug(&slug) else {
        return Err(AppError::NotFound);
    };
    let settings = state.settings().await?;
    let isolated_file_host = is_isolated_file_host(&settings, &headers);
    // A preview page is application chrome, so it only exists on the application origin.
    if settings.features.preview_pages && isolated_file_host {
        return Err(AppError::NotFound);
    }
    let user = current_user(&state, &jar).await?;
    let file = match state.db.active_file_by_public_id(public_id).await? {
        Some(file) => file,
        None => {
            let existing = state
                .db
                .file_by_public_id(public_id)
                .await
                .map_err(|_| AppError::NotFound)?;
            // Whether an item exists, and what it was taken down for, is only the viewer's
            // business if they could have viewed it in the first place.
            authorize_item_view(
                &settings,
                user.as_ref(),
                existing.owner_user_id.as_deref(),
                &existing.visibility,
            )
            .map_err(|_| AppError::NotFound)?;
            return render_unavailable_item(
                &state,
                &settings,
                user.as_ref(),
                "file",
                public_id,
                &existing.state,
            )
            .map(IntoResponse::into_response);
        }
    };
    if !settings.features.preview_pages {
        enforce_file_origin(&settings, isolated_file_host, &file)?;
    }
    authorize_item_view(
        &settings,
        user.as_ref(),
        file.owner_user_id.as_deref(),
        &file.visibility,
    )?;
    if settings.features.preview_pages {
        let preview = file_preview_context(&state, &file).await?;
        let raw_url = raw_file_url(&state, &settings, &file);
        let page = serde_json::json!({
            "file": file,
            "absolute_url": file_url(&state, &settings, &file),
            // The preview embeds and links the bytes by absolute URL: under an isolated origin the
            // application host does not serve them at all.
            "raw_url": raw_url,
            "absolute_raw_url": raw_url,
            "human_size": util::human_bytes(file.size_bytes),
            "preview": preview,
        });
        Ok(render(&state, "file_preview.html", &settings, user.as_ref(), page)?.into_response())
    } else {
        let cache_scope = file_cache_scope(&settings, &file);
        serve_file(&state, &settings, &headers, file, cache_scope).await
    }
}

/// Enforces which origin may serve a file's bytes.
///
/// With an isolated file origin, public bytes are only available through the file host so that
/// user-controlled content never shares the application origin. Files that need a session are the
/// exception in both directions: the file host cannot authorise them, so they stay on the
/// application origin rather than becoming unreachable from either host.
fn enforce_file_origin(
    settings: &RuntimeSettings,
    isolated_file_host: bool,
    file: &FileItem,
) -> AppResult<()> {
    if !settings.delivery.isolated_file_origin {
        return Ok(());
    }
    if file_needs_app_origin(settings, file) {
        if isolated_file_host {
            return Err(AppError::NotFound);
        }
        return Ok(());
    }
    if isolated_file_host {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

async fn file_preview_context(state: &AppState, file: &FileItem) -> AppResult<serde_json::Value> {
    let content_type = file.content_type.as_deref().unwrap_or_default();
    let is_image = matches!(content_type, "image/png" | "image/gif" | "image/jpeg");
    let is_text = content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json" | "application/xml" | "application/javascript"
        );
    let text = if is_text && file.size_bytes <= 128 * 1024 {
        let bytes = state.storage.get_blob(&file.blob_hash).await?;
        Some(
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(8000)
                .collect::<String>(),
        )
    } else {
        None
    };
    Ok(serde_json::json!({
        "is_image": is_image,
        "is_text": is_text,
        "text": text,
    }))
}

fn render_unavailable_item(
    state: &AppState,
    settings: &RuntimeSettings,
    user: Option<&User>,
    kind: &str,
    id: &str,
    item_state: &str,
) -> AppResult<Html<String>> {
    render(
        state,
        "takedown.html",
        settings,
        user,
        serde_json::json!({ "kind": kind, "id": id, "state": item_state }),
    )
}

pub(super) async fn raw_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    let file = state
        .db
        .active_file_by_public_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    enforce_file_origin(&settings, is_isolated_file_host(&settings, &headers), &file)?;
    authorize_item_view(
        &settings,
        user.as_ref(),
        file.owner_user_id.as_deref(),
        &file.visibility,
    )?;
    let cache_scope = file_cache_scope(&settings, &file);
    serve_file(&state, &settings, &headers, file, cache_scope).await
}

pub(super) async fn thumbnail_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    let user = current_user(&state, &jar).await?;
    let file = state
        .db
        .active_file_by_public_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Thumbnails are file content and must follow the same origin rules as the raw bytes.
    let isolated_file_host = is_isolated_file_host(&settings, &headers);
    enforce_file_origin(&settings, isolated_file_host, &file)?;
    authorize_item_view(
        &settings,
        user.as_ref(),
        file.owner_user_id.as_deref(),
        &file.visibility,
    )?;
    let thumbnail_hash = file.thumbnail_hash.as_deref().ok_or(AppError::NotFound)?;
    let bytes = state.storage.get_blob(thumbnail_hash).await?;
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    insert_file_security_headers(&mut response, isolated_file_host);
    insert_cache_control(
        &mut response,
        settings.delivery.public_cache_seconds,
        file_cache_scope(&settings, &file),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub(super) struct InternalFileQuery {
    expires: i64,
    signature: String,
}

pub(super) async fn internal_raw_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<InternalFileQuery>,
) -> AppResult<Response> {
    let settings = state.settings().await?;
    if !settings.delivery.signed_internal_urls {
        return Err(AppError::NotFound);
    }
    let secret = settings
        .delivery
        .internal_url_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
        .ok_or(AppError::NotFound)?;
    if query.expires < util::now_ts() {
        return Err(AppError::Forbidden);
    }
    let expected = sign_internal_file_url(secret, &id, query.expires);
    if !constant_time_eq(expected.as_bytes(), query.signature.as_bytes()) {
        return Err(AppError::Forbidden);
    }
    let file = state
        .db
        .active_file_by_public_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    serve_file(&state, &settings, &headers, file, CacheScope::Public).await
}

async fn serve_file(
    state: &AppState,
    settings: &RuntimeSettings,
    headers: &HeaderMap,
    file: FileItem,
    cache_scope: CacheScope,
) -> AppResult<Response> {
    use futures_util::StreamExt;
    use headers::HeaderMapExt;

    // `file.size_bytes` is metadata and can drift from what was actually stored. Range arithmetic
    // and `Content-Length` have to describe the bytes the response will really carry, so both come
    // from the object store instead.
    let blob = match headers.typed_get::<headers::Range>() {
        Some(requested) => {
            let total_len = state.storage.blob_size(&file.blob_hash).await?;
            let Some(range) = first_satisfiable_range(&requested, total_len) else {
                return Ok(range_not_satisfiable(total_len));
            };
            state
                .storage
                .get_blob_range_stream(&file.blob_hash, object_store::GetRange::Bounded(range))
                .await?
        }
        None => state.storage.get_blob_stream(&file.blob_hash).await?,
    };

    let is_partial = blob.range.start != 0 || blob.range.end != blob.size;
    let content_length_val = blob.range.end.saturating_sub(blob.range.start);
    let content_range_val = is_partial.then(|| {
        format!(
            "bytes {}-{}/{}",
            blob.range.start,
            blob.range.end.saturating_sub(1),
            blob.size
        )
    });
    let body =
        axum::body::Body::from_stream(blob.stream.map(|result| result.map_err(axum::Error::new)));

    let stored_content_type = file
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let risky_type = is_risky_mime(settings, stored_content_type);
    let isolated_file_host = is_isolated_file_host(settings, headers);
    let plaintext = risky_type
        && matches!(
            settings.security.content_policy.risky_mime_mode,
            RiskyMimeMode::Plaintext
        );
    let response_content_type = if plaintext {
        "text/plain; charset=utf-8"
    } else {
        stored_content_type
    };
    let content_type = response_content_type
        .parse::<HeaderValue>()
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let mut response = body.into_response();
    if is_partial {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        if let Some(cr) = content_range_val
            && let Ok(val) = HeaderValue::from_str(&cr)
        {
            response.headers_mut().insert(header::CONTENT_RANGE, val);
        }
    }
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(content_length_val),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    let filename = file
        .original_filename
        .as_deref()
        .unwrap_or(&file.public_id)
        .replace('"', "");
    let disposition_kind = file_disposition_kind(settings, risky_type, isolated_file_host);
    let disposition = format!("{disposition_kind}; filename=\"{filename}\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    // Every response here is user-controlled content, so it always gets the sniffing and referrer
    // protections. Only the sandbox policy is specific to the isolated origin.
    insert_file_security_headers(&mut response, isolated_file_host);
    insert_cache_control(
        &mut response,
        settings.delivery.public_cache_seconds,
        cache_scope,
    );
    state.metrics.served_files.inc();
    Ok(response)
}

/// Resolves the first range the client asked for that the object can actually satisfy.
fn first_satisfiable_range(
    requested: &headers::Range,
    total_len: u64,
) -> Option<std::ops::Range<u64>> {
    let (start_bound, end_bound) = requested.satisfiable_ranges(total_len).next()?;
    let start = match start_bound {
        std::ops::Bound::Included(n) => n,
        std::ops::Bound::Excluded(n) => n.saturating_add(1),
        std::ops::Bound::Unbounded => 0,
    };
    let end = match end_bound {
        std::ops::Bound::Included(n) => n,
        std::ops::Bound::Excluded(n) => n.saturating_sub(1),
        std::ops::Bound::Unbounded => total_len.saturating_sub(1),
    };
    (start <= end && end < total_len).then(|| start..end + 1)
}

fn range_not_satisfiable(total_len: u64) -> Response {
    let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total_len}")) {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
}

/// A response a shared cache may keep has to be one that any caller was entitled to.
fn file_cache_scope(settings: &RuntimeSettings, file: &FileItem) -> CacheScope {
    if file_needs_app_origin(settings, file) {
        CacheScope::Private
    } else {
        CacheScope::Public
    }
}

fn is_risky_mime(settings: &RuntimeSettings, content_type: &str) -> bool {
    settings
        .security
        .content_policy
        .forced_attachment_mime_types
        .iter()
        .any(|forced| forced.eq_ignore_ascii_case(content_type))
}

fn file_disposition_kind(
    settings: &RuntimeSettings,
    risky_type: bool,
    isolated_file_host: bool,
) -> &'static str {
    if risky_type {
        return match settings.security.content_policy.risky_mime_mode {
            RiskyMimeMode::Attachment => "attachment",
            RiskyMimeMode::InlineOnIsolatedOrigin if isolated_file_host => "inline",
            RiskyMimeMode::InlineOnIsolatedOrigin => "attachment",
            RiskyMimeMode::Plaintext => "inline",
        };
    }
    match settings.security.content_disposition {
        ContentDispositionMode::Inline => "inline",
        ContentDispositionMode::Attachment => "attachment",
    }
}

fn insert_file_security_headers(response: &mut Response, isolated_file_host: bool) {
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    if isolated_file_host {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; sandbox; style-src 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-ancestors 'none'",
            ),
        );
    }
}
