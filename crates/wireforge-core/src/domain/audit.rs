use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserMarker;
use super::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    UserLogin,
    UserLogout,
    UserLoginFailed,
    UserCreated,
    UserDeleted,
    UserRoleChanged,
    TotpEnabled,
    TotpDisabled,
    InterfaceCreated,
    InterfaceUpdated,
    InterfaceDeleted,
    InterfaceStarted,
    InterfaceStopped,
    PeerCreated,
    PeerUpdated,
    PeerDeleted,
    PeerEnabled,
    PeerDisabled,
    BackupCreated,
    BackupRestored,
    SettingsUpdated,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserLogin => "user.login",
            Self::UserLogout => "user.logout",
            Self::UserLoginFailed => "user.login_failed",
            Self::UserCreated => "user.created",
            Self::UserDeleted => "user.deleted",
            Self::UserRoleChanged => "user.role_changed",
            Self::TotpEnabled => "totp.enabled",
            Self::TotpDisabled => "totp.disabled",
            Self::InterfaceCreated => "interface.created",
            Self::InterfaceUpdated => "interface.updated",
            Self::InterfaceDeleted => "interface.deleted",
            Self::InterfaceStarted => "interface.started",
            Self::InterfaceStopped => "interface.stopped",
            Self::PeerCreated => "peer.created",
            Self::PeerUpdated => "peer.updated",
            Self::PeerDeleted => "peer.deleted",
            Self::PeerEnabled => "peer.enabled",
            Self::PeerDisabled => "peer.disabled",
            Self::BackupCreated => "backup.created",
            Self::BackupRestored => "backup.restored",
            Self::SettingsUpdated => "settings.updated",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub actor_user_id: Option<Id<UserMarker>>,
    pub actor_ip: Option<String>,
    pub action: AuditAction,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}
