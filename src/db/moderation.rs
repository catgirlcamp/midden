use super::*;
use crate::domain::ReportAction;
use std::collections::BTreeSet;

impl Database {
    pub async fn apply_report_actions(
        &self,
        report_ids: &[String],
        action: ReportAction,
        actor_user_id: Option<&str>,
        note: Option<&str>,
    ) -> anyhow::Result<bool> {
        let report_ids = report_ids.iter().collect::<BTreeSet<_>>();
        if report_ids.is_empty() {
            return Ok(false);
        }
        let mut transaction = self.pool.begin().await?;
        let mut reports = Vec::with_capacity(report_ids.len());
        for report_id in report_ids {
            let report_sql = if self.kind == DatabaseKind::Postgres {
                "SELECT id, item_kind, item_public_id, reporter_user_id, reason, details, state, created_at
                 FROM reports WHERE id = ? FOR UPDATE"
            } else {
                "SELECT id, item_kind, item_public_id, reporter_user_id, reason, details, state, created_at
                 FROM reports WHERE id = ?"
            };
            let row = self
                .query(report_sql)
                .bind(report_id)
                .fetch_optional(&mut *transaction)
                .await?;
            let Some(row) = row else {
                transaction.rollback().await?;
                return Ok(false);
            };
            let report = Report::from_row(&row)?;
            if report.state != "open" {
                transaction.rollback().await?;
                return Ok(false);
            }
            reports.push(report);
        }

        let affected_items = reports
            .iter()
            .map(|report| (report.item_kind.as_str(), report.item_public_id.as_str()))
            .collect::<BTreeSet<_>>();
        for (item_kind, public_id) in affected_items {
            let base_sql = match item_kind {
                "file" => "SELECT id, state FROM files WHERE public_id = ?",
                "paste" => "SELECT id FROM pastes WHERE public_id = ?",
                _ => {
                    transaction.rollback().await?;
                    return Ok(false);
                }
            };
            let item_sql = if self.kind == DatabaseKind::Postgres {
                match item_kind {
                    "file" => "SELECT id, state FROM files WHERE public_id = ? FOR UPDATE",
                    "paste" => "SELECT id FROM pastes WHERE public_id = ? FOR UPDATE",
                    _ => unreachable!(),
                }
            } else {
                base_sql
            };
            let item = self
                .query(item_sql)
                .bind(public_id)
                .fetch_optional(&mut *transaction)
                .await?;
            let Some(item) = item else {
                transaction.rollback().await?;
                return Ok(false);
            };
            if item_kind == "file"
                && action.item_state().is_some()
                && matches!(
                    item.try_get::<String, _>("state")?.as_str(),
                    "deleted" | "expired"
                )
            {
                transaction.rollback().await?;
                return Ok(false);
            }
        }

        for report in &reports {
            if let Some(note) = note {
                self.query(
                    "INSERT INTO moderation_notes (
                        id, item_kind, item_public_id, report_id, actor_user_id, note, created_at
                     ) VALUES (?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(&report.item_kind)
                .bind(&report.item_public_id)
                .bind(&report.id)
                .bind(actor_user_id)
                .bind(note)
                .bind(util::now_ts())
                .execute(&mut *transaction)
                .await?;
            }

            if let Some(item_state) = action.item_state() {
                let result = match report.item_kind.as_str() {
                    "file" => {
                        self.query("UPDATE files SET state = ? WHERE public_id = ?")
                            .bind(item_state.as_str())
                            .bind(&report.item_public_id)
                            .execute(&mut *transaction)
                            .await?
                    }
                    "paste" => {
                        self.query("UPDATE pastes SET state = ? WHERE public_id = ?")
                            .bind(item_state.as_str())
                            .bind(&report.item_public_id)
                            .execute(&mut *transaction)
                            .await?
                    }
                    _ => {
                        transaction.rollback().await?;
                        return Ok(false);
                    }
                };
                if result.rows_affected() == 0 {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                insert_audit(
                    self,
                    &mut transaction,
                    actor_user_id,
                    if report.item_kind == "file" {
                        "file.state_updated"
                    } else {
                        "paste.state_updated"
                    },
                    &report.item_public_id,
                    &format!("report {}", report.id),
                )
                .await?;
            }

            let updated = self
                .query("UPDATE reports SET state = ? WHERE id = ? AND state = 'open'")
                .bind(action.report_state())
                .bind(&report.id)
                .execute(&mut *transaction)
                .await?;
            if updated.rows_affected() != 1 {
                transaction.rollback().await?;
                return Ok(false);
            }
            let detail = match action.item_state() {
                Some(item_state) => format!("moderator set item state {}", item_state.as_str()),
                None if action == ReportAction::Dismiss => "moderator dismissed".to_string(),
                None => "moderator resolved".to_string(),
            };
            insert_audit(
                self,
                &mut transaction,
                actor_user_id,
                "report.updated",
                &report.id,
                &detail,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn create_report(
        &self,
        item_kind: &str,
        item_public_id: &str,
        reporter_user_id: Option<&str>,
        reason: &str,
        details: &str,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO reports (id, item_kind, item_public_id, reporter_user_id, reason, details, state, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(item_kind)
        .bind(item_public_id)
        .bind(reporter_user_id)
        .bind(reason)
        .bind(details)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists the newest reports matching every supplied filter.
    ///
    /// Filtering happens in the query. Fetching a fixed window and filtering afterwards hid open
    /// reports behind newer resolved ones as soon as the table outgrew that window.
    pub async fn list_reports_filtered(
        &self,
        state: Option<&str>,
        item_kind: Option<&str>,
        reason: Option<&str>,
        created_after: Option<i64>,
    ) -> anyhow::Result<Vec<Report>> {
        let reason_pattern = reason.map(|reason| format!("%{}%", reason.to_lowercase()));
        let rows = self.query(
            "SELECT id, item_kind, item_public_id, reporter_user_id, reason, details, state, created_at
             FROM reports
             WHERE (CAST(? AS TEXT) IS NULL OR state = ?)
               AND (CAST(? AS TEXT) IS NULL OR item_kind = ?)
               AND (CAST(? AS TEXT) IS NULL OR lower(reason) LIKE ?)
               AND (CAST(? AS BIGINT) IS NULL OR created_at >= ?)
             ORDER BY created_at DESC LIMIT 100",
        )
        .bind(state)
        .bind(state)
        .bind(item_kind)
        .bind(item_kind)
        .bind(reason_pattern.as_deref())
        .bind(reason_pattern.as_deref())
        .bind(created_after)
        .bind(created_after)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Report::from_row).collect()
    }

    pub async fn reports_for_item(
        &self,
        item_kind: &str,
        item_public_id: &str,
    ) -> anyhow::Result<Vec<Report>> {
        let rows = self
            .query(
                "SELECT id, item_kind, item_public_id, reporter_user_id, reason, details, state, created_at
             FROM reports
             WHERE item_kind = ? AND item_public_id = ?
             ORDER BY created_at DESC LIMIT 100",
            )
            .bind(item_kind)
            .bind(item_public_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(Report::from_row).collect()
    }

    pub async fn update_file_state_by_public_id(
        &self,
        public_id: &str,
        state: &str,
        actor_user_id: Option<&str>,
        detail: &str,
    ) -> anyhow::Result<bool> {
        let mut transaction = self.pool.begin().await?;
        let result = self
            .query(
                "UPDATE files SET state = ?
                 WHERE public_id = ? AND state NOT IN ('deleted', 'expired')",
            )
            .bind(state)
            .bind(public_id)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() > 0 {
            insert_audit(
                self,
                &mut transaction,
                actor_user_id,
                "file.state_updated",
                public_id,
                detail,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(result.rows_affected() > 0)
    }
}

async fn insert_audit(
    db: &Database,
    transaction: &mut sqlx::Transaction<'_, sqlx::Any>,
    actor_user_id: Option<&str>,
    action: &str,
    target: &str,
    detail: &str,
) -> anyhow::Result<()> {
    db.query(
        "INSERT INTO audit_events (id, actor_user_id, action, target, detail, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(actor_user_id)
    .bind(action)
    .bind(target)
    .bind(detail)
    .bind(util::now_ts())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

impl Database {
    pub async fn record_scan_result(
        &self,
        item_kind: &str,
        item_public_id: &str,
        adapter: &str,
        decision: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        self.query(
            "INSERT INTO scanner_results (
                id, item_kind, item_public_id, adapter, decision, detail, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(item_kind)
        .bind(item_public_id)
        .bind(adapter)
        .bind(decision)
        .bind(detail)
        .bind(util::now_ts())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn scan_results_for_item(
        &self,
        item_kind: &str,
        item_public_id: &str,
    ) -> anyhow::Result<Vec<ScannerResult>> {
        let rows = self
            .query(
                "SELECT id, item_kind, item_public_id, adapter, decision, detail, created_at
             FROM scanner_results
             WHERE item_kind = ? AND item_public_id = ?
             ORDER BY created_at DESC LIMIT 100",
            )
            .bind(item_kind)
            .bind(item_public_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(ScannerResult::from_row).collect()
    }

    pub async fn audit_events_for_target(&self, target: &str) -> anyhow::Result<Vec<AuditEvent>> {
        let rows = self
            .query(
                "SELECT id, actor_user_id, action, target, detail, created_at
             FROM audit_events
             WHERE target = ?
             ORDER BY created_at DESC LIMIT 100",
            )
            .bind(target)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(AuditEvent::from_row).collect()
    }

    pub async fn moderation_notes_for_item(
        &self,
        item_kind: &str,
        item_public_id: &str,
    ) -> anyhow::Result<Vec<ModerationNote>> {
        let rows = self
            .query(
                "SELECT id, item_kind, item_public_id, report_id, actor_user_id, note, created_at
             FROM moderation_notes
             WHERE item_kind = ? AND item_public_id = ?
             ORDER BY created_at DESC LIMIT 100",
            )
            .bind(item_kind)
            .bind(item_public_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(ModerationNote::from_row).collect()
    }
}
