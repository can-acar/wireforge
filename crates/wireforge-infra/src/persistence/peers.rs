use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::PeerRepository;
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::{Id, NewPeer, Peer, WgPublicKey};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqlitePeerRepository {
    pool: SqlitePool,
}

impl SqlitePeerRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PeerRepository for SqlitePeerRepository {
    async fn create(
        &self,
        new: NewPeer,
        preshared_sealed: Option<Vec<u8>>,
    ) -> CoreResult<Peer> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let allowed_json = serde_json::to_string(
            &new.allowed_ips
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into());

        sqlx::query(
            r#"INSERT INTO peers
               (id, interface_id, name, public_key, private_key_sealed, preshared_key_sealed,
                allowed_ips, endpoint, persistent_keepalive, bandwidth_quota_bytes,
                bandwidth_used_bytes, expires_at, schedule, enabled, owner_user_id,
                created_at, updated_at, primary_dns, secondary_dns, nat)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, NULL, 1, ?12, ?13, ?13, ?14, ?15, ?16)"#,
        )
        .bind(id.to_string())
        .bind(new.interface_id.to_string())
        .bind(&new.name)
        .bind(new.public_key.as_str())
        .bind(&new.private_key_sealed)
        .bind(&preshared_sealed)
        .bind(allowed_json)
        .bind(&new.endpoint)
        .bind(new.persistent_keepalive.map(|k| k as i64))
        .bind(new.bandwidth_quota_bytes.map(|b| b as i64))
        .bind(new.expires_at)
        .bind(new.owner_user_id.map(|u| u.to_string()))
        .bind(now)
        .bind(&new.primary_dns)
        .bind(&new.secondary_dns)
        .bind(new.nat as i64)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(Peer {
            id: Id::from_uuid(id),
            interface_id: new.interface_id,
            name: new.name,
            public_key: new.public_key,
            private_key_sealed: new.private_key_sealed,
            preshared_key_sealed: preshared_sealed,
            allowed_ips: new.allowed_ips,
            primary_dns: new.primary_dns,
            secondary_dns: new.secondary_dns,
            nat: new.nat,
            endpoint: new.endpoint,
            persistent_keepalive: new.persistent_keepalive,
            bandwidth_quota_bytes: new.bandwidth_quota_bytes,
            bandwidth_used_bytes: 0,
            expires_at: new.expires_at,
            schedule: None,
            enabled: true,
            owner_user_id: new.owner_user_id,
            created_at: now,
            updated_at: now,
        })
    }

    async fn find_by_id(&self, id: Id<PeerMarker>) -> CoreResult<Option<Peer>> {
        let row: Option<PeerRow> =
            sqlx::query_as("SELECT * FROM peers WHERE id = ?1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        row.map(PeerRow::into_domain).transpose()
    }

    async fn list_for_interface(&self, iface_id: Id<InterfaceMarker>) -> CoreResult<Vec<Peer>> {
        let rows: Vec<PeerRow> = sqlx::query_as(
            "SELECT * FROM peers WHERE interface_id = ?1 ORDER BY created_at ASC",
        )
        .bind(iface_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter().map(PeerRow::into_domain).collect()
    }

    async fn list_all(&self) -> CoreResult<Vec<Peer>> {
        let rows: Vec<PeerRow> =
            sqlx::query_as("SELECT * FROM peers ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        rows.into_iter().map(PeerRow::into_domain).collect()
    }

    async fn update(&self, peer: &Peer) -> CoreResult<()> {
        let allowed_json = serde_json::to_string(
            &peer
                .allowed_ips
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into());
        sqlx::query(
            r#"UPDATE peers SET
               name=?1, interface_id=?2, public_key=?3, private_key_sealed=?4,
               allowed_ips=?5, primary_dns=?6, secondary_dns=?7, nat=?8, endpoint=?9,
               persistent_keepalive=?10, bandwidth_quota_bytes=?11, expires_at=?12,
               schedule=?13, enabled=?14, updated_at=?15 WHERE id=?16"#,
        )
        .bind(&peer.name)
        .bind(peer.interface_id.to_string())
        .bind(peer.public_key.as_str())
        .bind(&peer.private_key_sealed)
        .bind(allowed_json)
        .bind(&peer.primary_dns)
        .bind(&peer.secondary_dns)
        .bind(peer.nat as i64)
        .bind(&peer.endpoint)
        .bind(peer.persistent_keepalive.map(|k| k as i64))
        .bind(peer.bandwidth_quota_bytes.map(|b| b as i64))
        .bind(peer.expires_at)
        .bind(&peer.schedule)
        .bind(peer.enabled as i64)
        .bind(Utc::now())
        .bind(peer.id.to_string())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete(&self, id: Id<PeerMarker>) -> CoreResult<()> {
        sqlx::query("DELETE FROM peers WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn record_bandwidth(&self, id: Id<PeerMarker>, bytes: u64) -> CoreResult<()> {
        sqlx::query("UPDATE peers SET bandwidth_used_bytes = ?1 WHERE id = ?2")
            .bind(bytes as i64)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct PeerRow {
    id: String,
    interface_id: String,
    name: String,
    public_key: String,
    private_key_sealed: Option<Vec<u8>>,
    preshared_key_sealed: Option<Vec<u8>>,
    allowed_ips: Option<String>,
    primary_dns: Option<String>,
    secondary_dns: Option<String>,
    nat: i64,
    endpoint: Option<String>,
    persistent_keepalive: Option<i64>,
    bandwidth_quota_bytes: Option<i64>,
    bandwidth_used_bytes: i64,
    expires_at: Option<DateTime<Utc>>,
    schedule: Option<String>,
    enabled: i64,
    owner_user_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl PeerRow {
    fn into_domain(self) -> CoreResult<Peer> {
        let allowed: Vec<String> = self
            .allowed_ips
            .as_deref()
            .map(|s| serde_json::from_str(s).unwrap_or_default())
            .unwrap_or_default();
        let allowed_ips = allowed
            .iter()
            .map(|s| s.parse::<IpNet>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Persistence(format!("allowed_ip: {e}")))?;

        let owner = self
            .owner_user_id
            .map(|s| Uuid::parse_str(&s).map(Id::<UserMarker>::from_uuid))
            .transpose()
            .map_err(|e| CoreError::Persistence(format!("owner uuid: {e}")))?;

        Ok(Peer {
            id: Id::from_uuid(
                Uuid::parse_str(&self.id)
                    .map_err(|e| CoreError::Persistence(format!("peer uuid: {e}")))?,
            ),
            interface_id: Id::from_uuid(
                Uuid::parse_str(&self.interface_id)
                    .map_err(|e| CoreError::Persistence(format!("iface uuid: {e}")))?,
            ),
            name: self.name,
            public_key: WgPublicKey::from_base64(self.public_key)?,
            private_key_sealed: self.private_key_sealed,
            preshared_key_sealed: self.preshared_key_sealed,
            allowed_ips,
            primary_dns: self.primary_dns,
            secondary_dns: self.secondary_dns,
            nat: self.nat != 0,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive.map(|k| k as u16),
            bandwidth_quota_bytes: self.bandwidth_quota_bytes.map(|b| b as u64),
            bandwidth_used_bytes: self.bandwidth_used_bytes as u64,
            expires_at: self.expires_at,
            schedule: self.schedule,
            enabled: self.enabled != 0,
            owner_user_id: owner,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
