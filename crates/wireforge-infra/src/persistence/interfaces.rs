use async_trait::async_trait;
use chrono::Utc;
use ipnet::IpNet;
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::InterfaceRepository;
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::{Id, Interface, InterfaceStatus, NewInterface, WgPublicKey};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqliteInterfaceRepository {
    pool: SqlitePool,
}

impl SqliteInterfaceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InterfaceRepository for SqliteInterfaceRepository {
    async fn create(
        &self,
        new: NewInterface,
        private_key_sealed: Vec<u8>,
    ) -> CoreResult<Interface> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let dns_json = serde_json::to_string(&new.dns).unwrap_or_else(|_| "[]".into());

        sqlx::query(
            r#"INSERT INTO interfaces
               (id, name, public_key, private_key_sealed, listen_port, endpoint,
                gateway, ipv4_cidr, ipv6_cidr, mtu, dns, on_up, on_down, status,
                created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'down', ?14, ?14)"#,
        )
        .bind(id.to_string())
        .bind(&new.name)
        .bind(new.public_key.as_str())
        .bind(&private_key_sealed)
        .bind(new.listen_port as i64)
        .bind(&new.endpoint)
        .bind(&new.gateway)
        .bind(new.ipv4_cidr.map(|n| n.to_string()))
        .bind(new.ipv6_cidr.map(|n| n.to_string()))
        .bind(new.mtu.map(|m| m as i64))
        .bind(dns_json)
        .bind(&new.on_up)
        .bind(&new.on_down)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(Interface {
            id: Id::from_uuid(id),
            name: new.name,
            public_key: new.public_key,
            private_key_sealed,
            listen_port: new.listen_port,
            endpoint: new.endpoint,
            gateway: new.gateway,
            ipv4_cidr: new.ipv4_cidr,
            ipv6_cidr: new.ipv6_cidr,
            mtu: new.mtu,
            dns: new.dns,
            on_up: new.on_up,
            on_down: new.on_down,
            status: InterfaceStatus::Down,
            created_at: now,
            updated_at: now,
        })
    }

    async fn find_by_id(&self, id: Id<InterfaceMarker>) -> CoreResult<Option<Interface>> {
        let row: Option<IfaceRow> =
            sqlx::query_as("SELECT * FROM interfaces WHERE id = ?1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        row.map(IfaceRow::into_domain).transpose()
    }

    async fn find_by_name(&self, name: &str) -> CoreResult<Option<Interface>> {
        let row: Option<IfaceRow> =
            sqlx::query_as("SELECT * FROM interfaces WHERE name = ?1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        row.map(IfaceRow::into_domain).transpose()
    }

    async fn list(&self) -> CoreResult<Vec<Interface>> {
        let rows: Vec<IfaceRow> =
            sqlx::query_as("SELECT * FROM interfaces ORDER BY name ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        rows.into_iter().map(IfaceRow::into_domain).collect()
    }

    async fn update(&self, iface: &Interface) -> CoreResult<()> {
        let dns_json = serde_json::to_string(&iface.dns).unwrap_or_else(|_| "[]".into());
        sqlx::query(
            r#"UPDATE interfaces SET
               listen_port=?1, endpoint=?2, gateway=?3, ipv4_cidr=?4, ipv6_cidr=?5,
               mtu=?6, dns=?7, on_up=?8, on_down=?9, public_key=?10,
               private_key_sealed=?11, status=?12, updated_at=?13
               WHERE id=?14"#,
        )
        .bind(iface.listen_port as i64)
        .bind(&iface.endpoint)
        .bind(&iface.gateway)
        .bind(iface.ipv4_cidr.map(|n| n.to_string()))
        .bind(iface.ipv6_cidr.map(|n| n.to_string()))
        .bind(iface.mtu.map(|m| m as i64))
        .bind(dns_json)
        .bind(&iface.on_up)
        .bind(&iface.on_down)
        .bind(iface.public_key.as_str())
        .bind(&iface.private_key_sealed)
        .bind(iface.status.as_str())
        .bind(Utc::now())
        .bind(iface.id.to_string())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete(&self, id: Id<InterfaceMarker>) -> CoreResult<()> {
        sqlx::query("DELETE FROM interfaces WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct IfaceRow {
    id: String,
    name: String,
    public_key: String,
    private_key_sealed: Vec<u8>,
    listen_port: i64,
    endpoint: Option<String>,
    gateway: Option<String>,
    ipv4_cidr: Option<String>,
    ipv6_cidr: Option<String>,
    mtu: Option<i64>,
    dns: Option<String>,
    on_up: Option<String>,
    on_down: Option<String>,
    status: String,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl IfaceRow {
    fn into_domain(self) -> CoreResult<Interface> {
        let dns: Vec<String> = self
            .dns
            .as_deref()
            .map(|s| serde_json::from_str(s).unwrap_or_default())
            .unwrap_or_default();
        let parse_cidr = |s: Option<String>| -> CoreResult<Option<IpNet>> {
            match s {
                None => Ok(None),
                Some(s) => s
                    .parse::<IpNet>()
                    .map(Some)
                    .map_err(|e| CoreError::Persistence(format!("cidr: {e}"))),
            }
        };
        let status = match self.status.as_str() {
            "up" => InterfaceStatus::Up,
            "error" => InterfaceStatus::Error,
            _ => InterfaceStatus::Down,
        };
        Ok(Interface {
            id: Id::from_uuid(
                Uuid::parse_str(&self.id)
                    .map_err(|e| CoreError::Persistence(format!("iface uuid: {e}")))?,
            ),
            name: self.name,
            public_key: WgPublicKey::from_base64(self.public_key)?,
            private_key_sealed: self.private_key_sealed,
            listen_port: self.listen_port as u16,
            endpoint: self.endpoint,
            gateway: self.gateway,
            ipv4_cidr: parse_cidr(self.ipv4_cidr)?,
            ipv6_cidr: parse_cidr(self.ipv6_cidr)?,
            mtu: self.mtu.map(|m| m as u16),
            dns,
            on_up: self.on_up,
            on_down: self.on_down,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
