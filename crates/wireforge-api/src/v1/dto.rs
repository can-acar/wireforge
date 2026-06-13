use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use wireforge_core::domain::{Interface, Peer};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InterfaceDto {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub listen_port: u16,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Interface> for InterfaceDto {
    fn from(i: Interface) -> Self {
        Self {
            id: i.id.to_string(),
            name: i.name,
            public_key: i.public_key.into_inner(),
            listen_port: i.listen_port,
            ipv4_cidr: i.ipv4_cidr.map(|n| n.to_string()),
            ipv6_cidr: i.ipv6_cidr.map(|n| n.to_string()),
            mtu: i.mtu,
            dns: i.dns,
            status: i.status.as_str().to_string(),
            created_at: i.created_at.to_rfc3339(),
            updated_at: i.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerDto {
    pub id: String,
    pub interface_id: String,
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    pub nat: bool,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub bandwidth_used_bytes: u64,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Peer> for PeerDto {
    fn from(p: Peer) -> Self {
        Self {
            id: p.id.to_string(),
            interface_id: p.interface_id.to_string(),
            name: p.name,
            public_key: p.public_key.into_inner(),
            allowed_ips: p.allowed_ips.iter().map(|n| n.to_string()).collect(),
            primary_dns: p.primary_dns,
            secondary_dns: p.secondary_dns,
            nat: p.nat,
            endpoint: p.endpoint,
            persistent_keepalive: p.persistent_keepalive,
            bandwidth_used_bytes: p.bandwidth_used_bytes,
            enabled: p.enabled,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthDto {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiError {
    pub error: String,
    pub status: u16,
}
