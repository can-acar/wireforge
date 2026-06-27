use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::domain::api_token::ApiTokenMarker;
use crate::domain::audit::AuditAction;
use crate::domain::interface::InterfaceMarker;
use crate::domain::peer::PeerMarker;
use crate::domain::user::UserMarker;
use crate::domain::webhook::WebhookMarker;
use crate::domain::{
    ApiToken, AuditEvent, Id, Interface, IpBan, NewApiToken, NewInterface, NewPeer, NewUser,
    NewWebhook, Peer, Role, User, Webhook,
};
use crate::CoreResult;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn count(&self) -> CoreResult<u64>;
    async fn create(&self, new: NewUser) -> CoreResult<User>;
    async fn find_by_id(&self, id: Id<UserMarker>) -> CoreResult<Option<User>>;
    async fn find_by_username(&self, username: &str) -> CoreResult<Option<User>>;
    async fn list(&self) -> CoreResult<Vec<User>>;
    async fn update_password(&self, id: Id<UserMarker>, hash: &str) -> CoreResult<()>;
    async fn update_role(&self, id: Id<UserMarker>, role: Role) -> CoreResult<()>;
    async fn update_totp(
        &self,
        id: Id<UserMarker>,
        enabled: bool,
        secret_encrypted: Option<&[u8]>,
    ) -> CoreResult<()>;
    async fn touch_last_login(&self, id: Id<UserMarker>) -> CoreResult<()>;
    async fn delete(&self, id: Id<UserMarker>) -> CoreResult<()>;
}

#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(&self, new: NewApiToken) -> CoreResult<ApiToken>;
    /// Look up a non-revoked token by its SHA-256 hash. Expiry is enforced by
    /// the caller via [`ApiToken::is_active`].
    async fn find_active_by_hash(&self, token_hash: &str) -> CoreResult<Option<ApiToken>>;
    async fn list_for_user(&self, user_id: Id<UserMarker>) -> CoreResult<Vec<ApiToken>>;
    /// Revoke a token owned by `owner`. Errors with `NotFound` if it does not
    /// exist, is already revoked, or belongs to a different user.
    async fn revoke(&self, id: Id<ApiTokenMarker>, owner: Id<UserMarker>) -> CoreResult<()>;
}

#[async_trait]
pub trait InterfaceRepository: Send + Sync {
    async fn create(&self, new: NewInterface, private_key_sealed: Vec<u8>) -> CoreResult<Interface>;
    async fn find_by_id(&self, id: Id<InterfaceMarker>) -> CoreResult<Option<Interface>>;
    async fn find_by_name(&self, name: &str) -> CoreResult<Option<Interface>>;
    async fn list(&self) -> CoreResult<Vec<Interface>>;
    async fn update(&self, iface: &Interface) -> CoreResult<()>;
    async fn delete(&self, id: Id<InterfaceMarker>) -> CoreResult<()>;
}

#[async_trait]
pub trait PeerRepository: Send + Sync {
    async fn create(&self, new: NewPeer, preshared_sealed: Option<Vec<u8>>) -> CoreResult<Peer>;
    async fn find_by_id(&self, id: Id<PeerMarker>) -> CoreResult<Option<Peer>>;
    async fn list_for_interface(&self, iface_id: Id<InterfaceMarker>) -> CoreResult<Vec<Peer>>;
    async fn list_all(&self) -> CoreResult<Vec<Peer>>;
    async fn update(&self, peer: &Peer) -> CoreResult<()>;
    async fn delete(&self, id: Id<PeerMarker>) -> CoreResult<()>;
    async fn record_bandwidth(&self, id: Id<PeerMarker>, bytes: u64) -> CoreResult<()>;
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn record(
        &self,
        actor_user_id: Option<Id<UserMarker>>,
        actor_ip: Option<&str>,
        action: AuditAction,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> CoreResult<()>;
    async fn list(&self, limit: u32) -> CoreResult<Vec<AuditEvent>>;
}

#[async_trait]
pub trait BanRepository: Send + Sync {
    async fn find(&self, ip: &str) -> CoreResult<Option<IpBan>>;
    async fn record_failure(
        &self,
        ip: &str,
        max_attempts: u32,
        lockout: std::time::Duration,
    ) -> CoreResult<IpBan>;
    async fn clear(&self, ip: &str) -> CoreResult<()>;
}

#[async_trait]
pub trait WebhookRepository: Send + Sync {
    async fn list_enabled(&self) -> CoreResult<Vec<Webhook>>;
    async fn list(&self) -> CoreResult<Vec<Webhook>>;
    async fn create(&self, new: NewWebhook) -> CoreResult<Webhook>;
    async fn delete(&self, id: Id<WebhookMarker>) -> CoreResult<()>;
}

/// Latest recorded traffic counters for a single peer.
#[derive(Debug, Clone)]
pub struct PeerTrafficRow {
    pub peer_id: Id<PeerMarker>,
    pub tx: u64,
    pub rx: u64,
    pub last_handshake: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait TrafficRepository: Send + Sync {
    async fn snapshot(
        &self,
        peer_id: Id<PeerMarker>,
        tx: u64,
        rx: u64,
        last_handshake: Option<DateTime<Utc>>,
    ) -> CoreResult<()>;

    async fn series_for_peer(
        &self,
        peer_id: Id<PeerMarker>,
        since: DateTime<Utc>,
    ) -> CoreResult<Vec<(DateTime<Utc>, u64, u64)>>;

    /// Most recent snapshot per peer — feeds the dashboard summary cards and
    /// the per-peer bar chart.
    async fn latest_per_peer(&self) -> CoreResult<Vec<PeerTrafficRow>>;

    /// Minute-bucketed total tx/rx across all peers since `since` — feeds the
    /// dashboard time-series line chart.
    async fn series_totals(
        &self,
        since: DateTime<Utc>,
    ) -> CoreResult<Vec<(DateTime<Utc>, u64, u64)>>;
}

/// Runtime-mutable key/value configuration. Each value is stored as a JSON
/// scalar (string / number / bool) so that consumers can decode it as needed.
#[async_trait]
pub trait SettingsRepository: Send + Sync {
    /// All persisted overrides (may be empty on a fresh install).
    async fn all(&self) -> CoreResult<HashMap<String, String>>;

    /// Insert or replace a single setting. `actor` is recorded for audit.
    async fn upsert(
        &self,
        key: &str,
        value: &str,
        actor: Option<Id<UserMarker>>,
    ) -> CoreResult<()>;
}
