use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::AuditRepository;
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::{AuditEvent, Id};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqliteAuditRepository {
    pool: SqlitePool,
}

impl SqliteAuditRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for SqliteAuditRepository {
    async fn record(
        &self,
        actor_user_id: Option<Id<UserMarker>>,
        actor_ip: Option<&str>,
        action: AuditAction,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> CoreResult<()> {
        sqlx::query(
            r#"INSERT INTO audit_events
               (actor_user_id, actor_ip, action, resource_type, resource_id, metadata, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        )
        .bind(actor_user_id.map(|i| i.to_string()))
        .bind(actor_ip)
        .bind(action.as_str())
        .bind(resource_type)
        .bind(resource_id)
        .bind(metadata.map(|m| m.to_string()))
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list(&self, limit: u32) -> CoreResult<Vec<AuditEvent>> {
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter().map(AuditRow::into_domain).collect()
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    actor_user_id: Option<String>,
    actor_ip: Option<String>,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
    metadata: Option<String>,
    created_at: DateTime<Utc>,
}

impl AuditRow {
    fn into_domain(self) -> CoreResult<AuditEvent> {
        let actor = self
            .actor_user_id
            .map(|s| Uuid::parse_str(&s).map(Id::<UserMarker>::from_uuid))
            .transpose()
            .map_err(|e| CoreError::Persistence(format!("audit uuid: {e}")))?;
        let action = parse_action(&self.action)?;
        let metadata = self
            .metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| CoreError::Persistence(format!("audit metadata: {e}")))?;
        Ok(AuditEvent {
            id: self.id,
            actor_user_id: actor,
            actor_ip: self.actor_ip,
            action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            metadata,
            created_at: self.created_at,
        })
    }
}

fn parse_action(s: &str) -> CoreResult<AuditAction> {
    use AuditAction::*;
    Ok(match s {
        "user.login" => UserLogin,
        "user.logout" => UserLogout,
        "user.login_failed" => UserLoginFailed,
        "user.created" => UserCreated,
        "user.deleted" => UserDeleted,
        "user.role_changed" => UserRoleChanged,
        "totp.enabled" => TotpEnabled,
        "totp.disabled" => TotpDisabled,
        "interface.created" => InterfaceCreated,
        "interface.updated" => InterfaceUpdated,
        "interface.deleted" => InterfaceDeleted,
        "interface.started" => InterfaceStarted,
        "interface.stopped" => InterfaceStopped,
        "peer.created" => PeerCreated,
        "peer.updated" => PeerUpdated,
        "peer.deleted" => PeerDeleted,
        "peer.enabled" => PeerEnabled,
        "peer.disabled" => PeerDisabled,
        "backup.created" => BackupCreated,
        "backup.restored" => BackupRestored,
        "settings.updated" => SettingsUpdated,
        other => return Err(CoreError::Persistence(format!("unknown action: {other}"))),
    })
}
