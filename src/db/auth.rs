use super::*;

/// Retention for rate-limit rows, generous enough to outlive any sane configured window so the
/// cleanup job never drops a bucket that is still counting.
const RATE_LIMIT_BUCKET_RETENTION_SECONDS: i64 = 24 * 60 * 60;

impl Database {
    pub async fn create_user(
        &self,
        email: &str,
        username: &str,
        password_hash: Option<&str>,
        role: Role,
    ) -> anyhow::Result<User> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        self.query(
            "INSERT INTO users (id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at)
             VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?)",
        )
        .bind(&id)
        .bind(email)
        .bind(username)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        self.user_by_id(&id).await
    }

    pub async fn user_by_oidc_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<Option<User>> {
        let row = self
            .query(
                "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at
             FROM oidc_identities i
             JOIN users u ON u.id = i.user_id
             WHERE i.issuer = ? AND i.subject = ? AND u.is_disabled = 0",
            )
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| User::from_row(&row)).transpose()
    }

    pub async fn link_oidc_identity(
        &self,
        user_id: &str,
        issuer: &str,
        subject: &str,
        email: &str,
    ) -> anyhow::Result<()> {
        let now = util::now_ts();
        self.query(
            "INSERT INTO oidc_identities (id, user_id, issuer, subject, email, created_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(issuer, subject) DO UPDATE SET email = excluded.email,
                                                         last_seen_at = excluded.last_seen_at
             WHERE oidc_identities.user_id = excluded.user_id",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(issuer)
        .bind(subject)
        .bind(email)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .and_then(|result| {
            if result.rows_affected() == 0 {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(result)
            }
        })?;
        Ok(())
    }

    pub async fn touch_oidc_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
    ) -> anyhow::Result<()> {
        self.query(
            "UPDATE oidc_identities SET email = ?, last_seen_at = ? WHERE issuer = ? AND subject = ?",
        )
        .bind(email)
        .bind(util::now_ts())
        .bind(issuer)
        .bind(subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        let rows = self
            .query(
                "SELECT id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at
             FROM users ORDER BY created_at DESC LIMIT 200",
            )
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(User::from_row).collect()
    }

    pub async fn set_user_role(&self, user_id: &str, role: Role) -> anyhow::Result<()> {
        self.query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_user_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<()> {
        self.query("UPDATE users SET is_disabled = ? WHERE id = ?")
            .bind(if disabled { 1_i64 } else { 0_i64 })
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn enabled_owner_count(&self) -> anyhow::Result<i64> {
        let row = self
            .query("SELECT COUNT(*) AS count FROM users WHERE role = 'owner' AND is_disabled = 0")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("count")?)
    }

    pub async fn set_user_email_verified_at(
        &self,
        user_id: &str,
        verified_at: Option<i64>,
    ) -> anyhow::Result<()> {
        self.query("UPDATE users SET email_verified_at = ? WHERE id = ?")
            .bind(verified_at)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_user_two_factor_enabled(
        &self,
        user_id: &str,
        enabled: bool,
    ) -> anyhow::Result<()> {
        self.query("UPDATE users SET two_factor_enabled = ? WHERE id = ?")
            .bind(if enabled { 1_i64 } else { 0_i64 })
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_invite_token(
        &self,
        token_hash: &str,
        created_by_user_id: &str,
        role: Role,
        expires_at: Option<i64>,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO invite_tokens (
                id, token_hash, created_by_user_id, role, expires_at, used_by_user_id, used_at, revoked_at, created_at
             ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(token_hash)
        .bind(created_by_user_id)
        .bind(role.as_str())
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates a user and claims an invite token in one transaction.
    ///
    /// Returns `Ok(None)` when the invite is unknown, already used, revoked, or expired. Creating
    /// the account and consuming the invite must stay atomic: a two-step version leaves a usable
    /// account behind whenever the second step is skipped or fails.
    pub async fn create_user_with_invite(
        &self,
        email: &str,
        username: &str,
        password_hash: Option<&str>,
        token_hash: &str,
    ) -> anyhow::Result<Option<User>> {
        let select = if self.kind == DatabaseKind::Postgres {
            "SELECT id, role, expires_at
             FROM invite_tokens
             WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
             FOR UPDATE"
        } else {
            "SELECT id, role, expires_at
             FROM invite_tokens
             WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL"
        };
        let mut transaction = self.pool.begin().await?;
        let row = self
            .query(select)
            .bind(token_hash)
            .fetch_optional(&mut *transaction)
            .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let now = util::now_ts();
        let expires_at: Option<i64> = row.try_get("expires_at")?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            transaction.rollback().await?;
            return Ok(None);
        }
        let invite_id: String = row.try_get("id")?;
        let role = Role::from_str(&row.try_get::<String, _>("role")?);

        let id = uuid::Uuid::new_v4().to_string();
        self.query(
            "INSERT INTO users (id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at)
             VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?)",
        )
        .bind(&id)
        .bind(email)
        .bind(username)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        let claimed = self
            .query(
                "UPDATE invite_tokens SET used_by_user_id = ?, used_at = ?
                 WHERE id = ? AND used_at IS NULL",
            )
            .bind(&id)
            .bind(now)
            .bind(invite_id)
            .execute(&mut *transaction)
            .await?;
        if claimed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }

        let row = self
            .query(
                "SELECT id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at
                 FROM users WHERE id = ?",
            )
            .bind(&id)
            .fetch_one(&mut *transaction)
            .await?;
        let user = User::from_row(&row)?;
        transaction.commit().await?;
        Ok(Some(user))
    }

    pub async fn list_invite_tokens(&self) -> anyhow::Result<Vec<InviteTokenSummary>> {
        let rows = self
            .query(
                "SELECT id, created_by_user_id, role, expires_at, used_by_user_id, used_at, revoked_at, created_at
             FROM invite_tokens ORDER BY created_at DESC LIMIT 100",
            )
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(InviteTokenSummary::from_row).collect()
    }

    pub async fn revoke_invite_token(
        &self,
        invite_id: &str,
        actor_user_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.query("UPDATE invite_tokens SET revoked_at = ? WHERE id = ? AND used_at IS NULL")
            .bind(util::now_ts())
            .bind(invite_id)
            .execute(&self.pool)
            .await?;
        self.audit(actor_user_id, "invite.revoked", invite_id, "admin UI")
            .await?;
        Ok(())
    }

    pub async fn upsert_owner(
        &self,
        email: &str,
        username: &str,
        password_hash: Option<&str>,
    ) -> anyhow::Result<User> {
        self.query(
            "INSERT INTO users (id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at)
             VALUES (?, ?, ?, ?, 'owner', 0, ?, 0, ?)
             ON CONFLICT(email) DO UPDATE SET username = excluded.username,
                                             password_hash = excluded.password_hash,
                                             role = 'owner',
                                             is_disabled = 0,
                                             email_verified_at = excluded.email_verified_at",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(email)
        .bind(username)
        .bind(password_hash)
        .bind(util::now_ts())
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        self.user_by_email(email).await
    }

    pub async fn user_by_email(&self, email: &str) -> anyhow::Result<User> {
        let row = self
            .query(
                "SELECT id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at
             FROM users WHERE email = ?",
            )
            .bind(email)
            .fetch_one(&self.pool)
            .await?;
        User::from_row(&row)
    }

    pub async fn user_by_id(&self, id: &str) -> anyhow::Result<User> {
        let row = self
            .query(
                "SELECT id, email, username, password_hash, role, is_disabled, email_verified_at, two_factor_enabled, created_at
             FROM users WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        User::from_row(&row)
    }

    pub async fn create_session(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn user_by_session_token(&self, token_hash: &str) -> anyhow::Result<Option<User>> {
        let row = self.query(
            "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_disabled = 0",
        )
        .bind(token_hash)
        .bind(util::now_ts())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| User::from_row(&row)).transpose()
    }

    pub async fn delete_session(&self, token_hash: &str) -> anyhow::Result<()> {
        self.query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_password_reset_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
             VALUES (?, ?, ?, ?, NULL, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_email_verification_token(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
             VALUES (?, ?, ?, ?, NULL, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_email_verification_token(&self, token_hash: &str) -> anyhow::Result<User> {
        let row = self.query(
            "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at,
                    t.id AS verification_id
             FROM email_verification_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ? AND u.is_disabled = 0",
        )
        .bind(token_hash)
        .bind(util::now_ts())
        .fetch_one(&self.pool)
        .await?;
        let verification_id: String = row.try_get("verification_id")?;
        let user_id: String = row.try_get("id")?;
        let now = util::now_ts();
        self.query("UPDATE email_verification_tokens SET used_at = ? WHERE id = ?")
            .bind(now)
            .bind(verification_id)
            .execute(&self.pool)
            .await?;
        self.set_user_email_verified_at(&user_id, Some(now)).await?;
        self.user_by_id(&user_id).await
    }

    pub async fn create_two_factor_challenge(
        &self,
        user_id: &str,
        challenge_hash: &str,
        code_hash: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO two_factor_challenges (id, user_id, challenge_hash, code_hash, expires_at, used_at, created_at)
             VALUES (?, ?, ?, ?, ?, NULL, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(challenge_hash)
        .bind(code_hash)
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_two_factor_challenge(
        &self,
        challenge_hash: &str,
        code_hash: &str,
    ) -> anyhow::Result<User> {
        let row = self.query(
            "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at,
                    c.id AS challenge_id
             FROM two_factor_challenges c
             JOIN users u ON u.id = c.user_id
             WHERE c.challenge_hash = ? AND c.code_hash = ? AND c.used_at IS NULL AND c.expires_at > ? AND u.is_disabled = 0",
        )
        .bind(challenge_hash)
        .bind(code_hash)
        .bind(util::now_ts())
        .fetch_one(&self.pool)
        .await?;
        let challenge_id: String = row.try_get("challenge_id")?;
        let user = User::from_row(&row)?;
        self.query("UPDATE two_factor_challenges SET used_at = ? WHERE id = ?")
            .bind(util::now_ts())
            .bind(challenge_id)
            .execute(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn consume_password_reset_token(&self, token_hash: &str) -> anyhow::Result<User> {
        let row = self.query(
            "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at,
                    t.id AS reset_id
             FROM password_reset_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ? AND u.is_disabled = 0",
        )
        .bind(token_hash)
        .bind(util::now_ts())
        .fetch_one(&self.pool)
        .await?;
        let reset_id: String = row.try_get("reset_id")?;
        self.query("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?")
            .bind(util::now_ts())
            .bind(reset_id)
            .execute(&self.pool)
            .await?;
        User::from_row(&row)
    }

    pub async fn update_user_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> anyhow::Result<()> {
        self.query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_api_token_with_expiry(
        &self,
        user_id: &str,
        name: &str,
        token_hash: &str,
        scopes: &[String],
        expires_at: Option<i64>,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, scopes_json, expires_at, last_used_at, revoked_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(serde_json::to_string(scopes)?)
        .bind(expires_at)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_api_tokens(&self, user_id: &str) -> anyhow::Result<Vec<ApiTokenSummary>> {
        let rows = self
            .query(
                "SELECT id, name, scopes_json, expires_at, last_used_at, revoked_at, created_at
             FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(ApiTokenSummary::from_row).collect()
    }

    pub async fn revoke_api_token(&self, user_id: &str, token_id: &str) -> anyhow::Result<()> {
        self.query("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?")
            .bind(util::now_ts())
            .bind(token_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn user_by_api_token_with_scopes(
        &self,
        token_hash: &str,
        required_scope: &str,
    ) -> anyhow::Result<Option<(User, Vec<String>)>> {
        let row = self.query(
            "SELECT u.id, u.email, u.username, u.password_hash, u.role, u.is_disabled, u.email_verified_at, u.two_factor_enabled, u.created_at,
                    t.id AS token_id, t.scopes_json
             FROM api_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?) AND u.is_disabled = 0",
        )
        .bind(token_hash)
        .bind(util::now_ts())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scopes_json: String = row.try_get("scopes_json")?;
        let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();
        if scopes
            .iter()
            .any(|scope| scope == "*" || scope == required_scope)
        {
            let token_id: String = row.try_get("token_id")?;
            self.query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
                .bind(util::now_ts())
                .bind(token_id)
                .execute(&self.pool)
                .await?;
            return Ok(Some((User::from_row(&row)?, scopes)));
        }
        Ok(None)
    }

    pub async fn cleanup_expired_auth_state(&self) -> anyhow::Result<u64> {
        let now = util::now_ts();
        let mut deleted = 0;
        deleted += self
            .query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        deleted += self
            .query("DELETE FROM password_reset_tokens WHERE expires_at <= ? OR used_at IS NOT NULL")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        deleted += self
            .query("DELETE FROM email_verification_tokens WHERE expires_at <= ? OR used_at IS NOT NULL")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        deleted += self
            .query("DELETE FROM two_factor_challenges WHERE expires_at <= ? OR used_at IS NOT NULL")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        deleted += self
            .query("DELETE FROM invite_tokens WHERE used_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // Bucket keys include the client IP, so finished windows have to be reclaimed.
        deleted += self
            .query("DELETE FROM rate_limit_buckets WHERE window_start <= ?")
            .bind(now.saturating_sub(RATE_LIMIT_BUCKET_RETENTION_SECONDS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(deleted)
    }
}
