use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    app::{AppError, AppResult, AppState},
    config::{DeletePolicy, RuntimeSettings},
    db::{Database, FileItem, NewPaste, Paste, Role, User},
    domain::{
        AccountBulkAction, AccountBulkPlan, ItemKind, ItemModerationOutcome, ItemModerationPlan,
        ItemState, ReportAction,
    },
    storage::BlobStorage,
    util,
};

pub async fn moderate_item(
    state: &AppState,
    settings: &RuntimeSettings,
    actor_user_id: Option<&str>,
    mut plan: ItemModerationPlan,
    detail: &str,
) -> AppResult<()> {
    plan.note = plan
        .note
        .take()
        .map(|note| note.trim().to_string())
        .filter(|note| !note.is_empty());
    if !plan.has_mutation() {
        return Err(AppError::BadRequest(
            "at least one item update is required".to_string(),
        ));
    }
    if plan.block_hash && plan.kind != ItemKind::File {
        return Err(AppError::BadRequest(
            "blocked hashes can only be created from files".to_string(),
        ));
    }
    if plan.block_hash {
        plan.scanning_fallback = Some(settings.scanning.clone());
    }

    let releases_file = plan.kind == ItemKind::File && plan.state == Some(ItemState::Deleted);
    // Keep the established local lock order (quota, then blob) for deletions. The database-backed
    // blob lock in cleanup supplies the cross-process guarantee.
    let _upload_guard = if releases_file {
        Some(state.upload_quota_lock.lock().await)
    } else {
        None
    };
    match state
        .db
        .apply_item_moderation(&plan, actor_user_id, detail)
        .await?
    {
        ItemModerationOutcome::Applied { zero_ref_blob_hash } => {
            if let Some(blob_hash) = zero_ref_blob_hash {
                cleanup_zero_ref_blob(&state.db, &state.storage, &blob_hash).await;
            }
            Ok(())
        }
        ItemModerationOutcome::NotFound => Err(AppError::NotFound),
        ItemModerationOutcome::TerminalFileTransition => Err(AppError::BadRequest(
            "deleted or expired files cannot be reactivated".to_string(),
        )),
    }
}

pub async fn moderate_reports(
    state: &AppState,
    report_ids: &[String],
    action: ReportAction,
    actor_user_id: Option<&str>,
    note: Option<&str>,
) -> AppResult<()> {
    let report_ids = report_ids.iter().cloned().collect::<BTreeSet<_>>();
    if report_ids.is_empty() {
        return Err(AppError::BadRequest(
            "select at least one report".to_string(),
        ));
    }
    let note = note.map(str::trim).filter(|note| !note.is_empty());
    let report_ids = report_ids.into_iter().collect::<Vec<_>>();
    if state
        .db
        .apply_report_actions(&report_ids, action, actor_user_id, note)
        .await?
    {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

pub async fn apply_account_bulk(
    state: &AppState,
    user: &User,
    file_ids: Vec<String>,
    paste_ids: Vec<String>,
    action: AccountBulkAction,
) -> AppResult<()> {
    // Blob release and storage deletion must be serialized with content-addressed uploads.
    let _upload_guard = state.upload_quota_lock.lock().await;
    let plan = AccountBulkPlan {
        owner_user_id: user.id.clone(),
        file_ids: file_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        paste_ids: paste_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        action,
        allow_delete_any_owner: user.role >= Role::Admin,
    };
    if plan.file_ids.is_empty() && plan.paste_ids.is_empty() {
        return Err(AppError::BadRequest("select at least one item".to_string()));
    }
    let result = state
        .db
        .apply_account_bulk(&plan)
        .await?
        .ok_or(AppError::Forbidden)?;
    for blob_hash in result.zero_ref_blob_hashes {
        cleanup_zero_ref_blob(&state.db, &state.storage, &blob_hash).await;
    }
    Ok(())
}

pub struct CreatePasteInput<'a> {
    pub title: Option<&'a str>,
    pub syntax: Option<&'a str>,
    pub content: &'a str,
    pub expires_at: Option<i64>,
    pub visibility: &'a str,
}

pub struct CreatedPaste {
    pub paste: Paste,
    pub url: String,
    pub raw_url: String,
    pub delete_token: Option<String>,
}

pub async fn create_paste(
    state: &AppState,
    settings: &RuntimeSettings,
    user: Option<&User>,
    input: CreatePasteInput<'_>,
) -> AppResult<CreatedPaste> {
    if input.content.len() as i64 > settings.limits.max_paste_bytes {
        return Err(AppError::PayloadTooLarge);
    }
    let public_id = util::public_id();
    let delete_token = if user.is_none()
        && matches!(
            settings.policy.delete_policy,
            DeletePolicy::DeleteTokens | DeletePolicy::ClaimLater
        ) {
        Some(util::secret_token())
    } else {
        None
    };
    let delete_hash = delete_token.as_deref().map(util::hash_token);
    let syntax = normalize_syntax(input.syntax);
    let paste = state
        .db
        .create_paste(NewPaste {
            id: &uuid::Uuid::new_v4().to_string(),
            public_id: &public_id,
            title: input.title.map(str::trim).filter(|value| !value.is_empty()),
            content: input.content,
            syntax: syntax.as_deref(),
            owner_user_id: user.map(|user| user.id.as_str()),
            delete_token_hash: delete_hash.as_deref(),
            expires_at: input.expires_at,
            visibility: input.visibility,
        })
        .await?;
    state.metrics.pastes.inc();
    let base = state.config.server.public_base_url.trim_end_matches('/');
    Ok(CreatedPaste {
        paste,
        url: format!("{base}/p/{public_id}"),
        raw_url: format!("{base}/p/{public_id}/raw"),
        delete_token,
    })
}

pub async fn claim_item(
    state: &AppState,
    kind: ItemKind,
    public_id: &str,
    user_id: &str,
    delete_token: &str,
) -> AppResult<()> {
    let token = delete_token.trim();
    if token.is_empty() {
        return Err(AppError::BadRequest("claim token is required".to_string()));
    }
    let token_hash = util::hash_token(token);
    let claimed = match kind {
        ItemKind::File => {
            state
                .db
                .claim_file_by_public_id(public_id, user_id, &token_hash)
                .await?
        }
        ItemKind::Paste => {
            state
                .db
                .claim_paste_by_public_id(public_id, user_id, &token_hash)
                .await?
        }
    };
    if claimed {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "invalid token or item is not claimable".to_string(),
        ))
    }
}

pub async fn delete_file(
    state: &AppState,
    file: &FileItem,
    actor_user_id: Option<&str>,
    reason: &str,
) -> AppResult<()> {
    // Prevent a hash from being reused between the ref-count update and object deletion.
    let _upload_guard = state.upload_quota_lock.lock().await;
    if let Some(blob_hash) = state
        .db
        .delete_file_and_release_blob(&file.id, actor_user_id, reason)
        .await?
    {
        cleanup_zero_ref_blob(&state.db, &state.storage, &blob_hash).await;
    }
    Ok(())
}

pub(crate) async fn cleanup_zero_ref_blob(
    db: &Database,
    storage: &BlobStorage,
    blob_hash: &str,
) -> bool {
    let cleanup = async {
        let mut mutation = db.begin_blob_mutation(blob_hash).await?;
        if !mutation.is_unreferenced().await? {
            mutation.commit().await?;
            return Ok(false);
        }
        storage.delete_blob(blob_hash).await?;
        mutation.delete_if_unreferenced().await?;
        mutation.commit().await?;
        Ok::<_, anyhow::Error>(true)
    }
    .await;
    match cleanup {
        Ok(deleted) => deleted,
        Err(err) => {
            tracing::warn!(
                error = %err,
                blob_hash,
                "zero-reference blob cleanup failed; database record retained for retry"
            );
            false
        }
    }
}

pub async fn cleanup_zero_ref_blobs(db: &Database, storage: &BlobStorage) -> anyhow::Result<u64> {
    let hashes = db.zero_ref_blob_hashes().await?;
    let mut deleted = 0;
    for hash in hashes {
        deleted += u64::from(cleanup_zero_ref_blob(db, storage, &hash).await);
    }
    Ok(deleted)
}

pub async fn delete_paste(
    state: &AppState,
    paste: &Paste,
    actor_user_id: Option<&str>,
    reason: &str,
) -> AppResult<()> {
    state
        .db
        .delete_paste(&paste.id, actor_user_id, reason)
        .await?;
    Ok(())
}

pub fn normalize_syntax(input: Option<&str>) -> Option<String> {
    let syntax = input?.trim().to_ascii_lowercase();
    if syntax.is_empty() {
        return None;
    }
    Some(
        match syntax.as_str() {
            "txt" | "plain" => "text",
            "js" | "mjs" | "cjs" => "javascript",
            "ts" => "typescript",
            "py" => "python",
            "rb" => "ruby",
            "rs" => "rust",
            "sh" | "shell" => "bash",
            "yml" => "yaml",
            "md" => "markdown",
            "htm" => "html",
            other => other,
        }
        .to_string(),
    )
}

pub struct CreatedToken {
    pub token: String,
    pub expires_at: Option<i64>,
}

pub fn token_expires_at(
    settings: &RuntimeSettings,
    requested_ttl_seconds: Option<i64>,
) -> AppResult<Option<i64>> {
    let ttl = requested_ttl_seconds.or(settings.tokens.default_ttl_seconds);
    let Some(ttl) = ttl else {
        return Ok(None);
    };
    if ttl <= 0 {
        return Err(AppError::BadRequest(
            "token TTL must be positive".to_string(),
        ));
    }
    if let Some(max) = settings.tokens.max_ttl_seconds
        && ttl > max
    {
        return Err(AppError::BadRequest(
            "token TTL exceeds configured maximum".to_string(),
        ));
    }
    Ok(Some(util::now_ts().saturating_add(ttl)))
}

pub async fn create_token(
    state: &AppState,
    settings: &RuntimeSettings,
    user: &User,
    name: &str,
    scopes: &[String],
    requested_ttl_seconds: Option<i64>,
) -> AppResult<CreatedToken> {
    if scopes.is_empty() {
        return Err(AppError::BadRequest(
            "at least one scope is required".to_string(),
        ));
    }
    let expires_at = token_expires_at(settings, requested_ttl_seconds)?;
    let token = format!("mdd_{}", util::secret_token());
    state
        .db
        .create_api_token_with_expiry(
            &user.id,
            name,
            &util::hash_token(&token),
            scopes,
            expires_at,
        )
        .await?;
    state
        .db
        .audit(Some(&user.id), "api_token.created", &user.id, name)
        .await?;
    Ok(CreatedToken { token, expires_at })
}

pub async fn revoke_token(state: &AppState, user: &User, token_id: &str) -> AppResult<()> {
    state.db.revoke_api_token(&user.id, token_id).await?;
    state
        .db
        .audit(Some(&user.id), "api_token.revoked", &user.id, token_id)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ReportCreated {
    pub reported: bool,
}

pub async fn create_report(
    state: &AppState,
    settings: &RuntimeSettings,
    kind: ItemKind,
    id: &str,
    reporter_user_id: Option<&str>,
    reason: &str,
    details: &str,
) -> AppResult<ReportCreated> {
    // Reports on items that never existed only cost moderators time. Items in any state are
    // reportable, since someone may be reporting something they saw before a takedown.
    let exists = match kind {
        ItemKind::File => state.db.file_by_public_id(id).await.is_ok(),
        ItemKind::Paste => state.db.paste_by_public_id_any(id).await.is_ok(),
    };
    if !exists {
        return Err(AppError::NotFound);
    }
    state
        .db
        .create_report(kind.as_str(), id, reporter_user_id, reason, details)
        .await?;
    state.metrics.reports.inc();

    if let Some(url) = settings
        .moderation
        .notify_webhook_url
        .as_deref()
        .filter(|url| !url.is_empty())
    {
        let mut request = reqwest::Client::new().post(url).json(&serde_json::json!({
            "kind": kind.as_str(),
            "id": id,
            "reporter_user_id": reporter_user_id,
            "reason": reason,
            "details": details,
        }));
        if let Some(secret) = settings
            .moderation
            .notify_webhook_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
        {
            request = request.header("x-midden-moderation-secret", secret);
        }
        if let Err(err) = async { request.send().await?.error_for_status() }.await {
            tracing::error!(error = %err, "failed to trigger moderation webhook");
        }
    }

    if let Some(abuse_email) = &settings.branding.abuse_email {
        state
            .mailer
            .send(
                abuse_email,
                "New Midden report",
                &format!(
                    "A report was submitted for {} {}.\n\nReason: {reason}\n\nDetails:\n{details}",
                    kind.as_str(),
                    id
                ),
            )
            .await?;
    }

    Ok(ReportCreated { reported: true })
}
