use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Moderator,
    Admin,
    Owner,
}

impl Role {
    pub fn from_str(value: &str) -> Self {
        match value {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "moderator" => Self::Moderator,
            _ => Self::User,
        }
    }

    pub fn parse_form(value: &str) -> anyhow::Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "moderator" => Ok(Self::Moderator),
            "admin" => Ok(Self::Admin),
            "owner" => Ok(Self::Owner),
            _ => anyhow::bail!("unknown role: {value}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Moderator => "moderator",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub role: Role,
    pub is_disabled: bool,
    pub email_verified_at: Option<i64>,
    pub two_factor_enabled: bool,
    pub created_at: i64,
}

impl User {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            role: Role::from_str(&row.try_get::<String, _>("role")?),
            is_disabled: row.try_get::<i64, _>("is_disabled")? != 0,
            email_verified_at: row.try_get("email_verified_at")?,
            two_factor_enabled: row.try_get::<i64, _>("two_factor_enabled")? != 0,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileItem {
    pub id: String,
    pub public_id: String,
    pub blob_hash: String,
    pub original_filename: Option<String>,
    pub extension: Option<String>,
    pub content_type: Option<String>,
    pub size_bytes: i64,
    pub image_width: Option<i64>,
    pub image_height: Option<i64>,
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing)]
    pub delete_token_hash: Option<String>,
    pub expires_at: Option<i64>,
    pub visibility: String,
    pub metadata_json: Option<String>,
    pub thumbnail_hash: Option<String>,
    pub state: String,
    pub created_at: i64,
}

impl FileItem {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            public_id: row.try_get("public_id")?,
            blob_hash: row.try_get("blob_hash")?,
            original_filename: row.try_get("original_filename")?,
            extension: row.try_get("extension")?,
            content_type: row.try_get("content_type")?,
            size_bytes: row.try_get("size_bytes")?,
            image_width: row.try_get("image_width")?,
            image_height: row.try_get("image_height")?,
            owner_user_id: row.try_get("owner_user_id")?,
            delete_token_hash: row.try_get("delete_token_hash")?,
            expires_at: row.try_get("expires_at")?,
            visibility: row.try_get("visibility")?,
            metadata_json: row.try_get("metadata_json")?,
            thumbnail_hash: row.try_get("thumbnail_hash")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

pub struct NewFileItem<'a> {
    pub id: &'a str,
    pub public_id: &'a str,
    pub blob_hash: &'a str,
    pub original_filename: Option<&'a str>,
    pub extension: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub size_bytes: i64,
    pub image_width: Option<i64>,
    pub image_height: Option<i64>,
    pub owner_user_id: Option<&'a str>,
    pub delete_token_hash: Option<&'a str>,
    pub expires_at: Option<i64>,
    pub visibility: &'a str,
    pub metadata_json: Option<&'a str>,
    pub thumbnail_hash: Option<&'a str>,
    pub state: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Paste {
    pub id: String,
    pub public_id: String,
    pub title: Option<String>,
    pub content: String,
    pub syntax: Option<String>,
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing)]
    pub delete_token_hash: Option<String>,
    pub expires_at: Option<i64>,
    pub visibility: String,
    pub state: String,
    pub created_at: i64,
}

impl Paste {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            public_id: row.try_get("public_id")?,
            title: row.try_get("title")?,
            content: row.try_get("content")?,
            syntax: row.try_get("syntax")?,
            owner_user_id: row.try_get("owner_user_id")?,
            delete_token_hash: row.try_get("delete_token_hash")?,
            expires_at: row.try_get("expires_at")?,
            visibility: row.try_get("visibility")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

pub struct NewPaste<'a> {
    pub id: &'a str,
    pub public_id: &'a str,
    pub title: Option<&'a str>,
    pub content: &'a str,
    pub syntax: Option<&'a str>,
    pub owner_user_id: Option<&'a str>,
    pub delete_token_hash: Option<&'a str>,
    pub expires_at: Option<i64>,
    pub visibility: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub id: String,
    pub item_kind: String,
    pub item_public_id: String,
    pub reporter_user_id: Option<String>,
    pub reason: String,
    pub details: String,
    pub state: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenSummary {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

impl ApiTokenSummary {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        let scopes_json: String = row.try_get("scopes_json")?;
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            scopes: serde_json::from_str(&scopes_json).unwrap_or_default(),
            expires_at: row.try_get("expires_at")?,
            last_used_at: row.try_get("last_used_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InviteTokenSummary {
    pub id: String,
    pub created_by_user_id: String,
    pub role: String,
    pub expires_at: Option<i64>,
    pub used_by_user_id: Option<String>,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

impl InviteTokenSummary {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            created_by_user_id: row.try_get("created_by_user_id")?,
            role: row.try_get("role")?,
            expires_at: row.try_get("expires_at")?,
            used_by_user_id: row.try_get("used_by_user_id")?,
            used_at: row.try_get("used_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl Report {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            item_kind: row.try_get("item_kind")?,
            item_public_id: row.try_get("item_public_id")?,
            reporter_user_id: row.try_get("reporter_user_id")?,
            reason: row.try_get("reason")?,
            details: row.try_get("details")?,
            state: row.try_get("state")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannerResult {
    pub id: String,
    pub item_kind: String,
    pub item_public_id: String,
    pub adapter: String,
    pub decision: String,
    pub detail: String,
    pub created_at: i64,
}

impl ScannerResult {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            item_kind: row.try_get("item_kind")?,
            item_public_id: row.try_get("item_public_id")?,
            adapter: row.try_get("adapter")?,
            decision: row.try_get("decision")?,
            detail: row.try_get("detail")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: i64,
}

impl AuditEvent {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            actor_user_id: row.try_get("actor_user_id")?,
            action: row.try_get("action")?,
            target: row.try_get("target")?,
            detail: row.try_get("detail")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModerationNote {
    pub id: String,
    pub item_kind: String,
    pub item_public_id: String,
    pub report_id: Option<String>,
    pub actor_user_id: Option<String>,
    pub note: String,
    pub created_at: i64,
}

impl ModerationNote {
    pub(super) fn from_row(row: &sqlx::any::AnyRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            item_kind: row.try_get("item_kind")?,
            item_public_id: row.try_get("item_public_id")?,
            report_id: row.try_get("report_id")?,
            actor_user_id: row.try_get("actor_user_id")?,
            note: row.try_get("note")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// Keyset pagination cursor for the public listings.
///
/// Ordering on `created_at` alone is not stable: uploads routinely share a second, and a cursor
/// that only remembers the timestamp skips every tied row on the next page. Pair it with the
/// `public_id` tiebreaker that the queries also sort on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    pub created_at: i64,
    pub public_id: String,
}

impl std::fmt::Display for PageCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `public_id` uses nanoid's URL-safe alphabet, which has no '.', so this round-trips.
        write!(formatter, "{}.{}", self.created_at, self.public_id)
    }
}

impl std::str::FromStr for PageCursor {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (created_at, public_id) = value.split_once('.').ok_or(())?;
        if public_id.is_empty() {
            return Err(());
        }
        Ok(Self {
            created_at: created_at.parse().map_err(|_| ())?,
            public_id: public_id.to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct FileUsage {
    pub storage_bytes: i64,
    pub daily_upload_bytes: i64,
    pub monthly_upload_bytes: i64,
    pub item_count: i64,
}
