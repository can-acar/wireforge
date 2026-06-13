use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{interface::InterfaceMarker, user::UserMarker, Id, WgPublicKey};

#[derive(Debug)]
pub struct PeerMarker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: Id<PeerMarker>,
    pub interface_id: Id<InterfaceMarker>,
    pub name: String,
    pub public_key: WgPublicKey,
    /// Optional: sealed peer private key when the server generated the
    /// keypair on the user's behalf (Linguard-compatible flow).
    pub private_key_sealed: Option<Vec<u8>>,
    pub preshared_key_sealed: Option<Vec<u8>>,
    pub allowed_ips: Vec<IpNet>,
    /// Client-side DNS servers written into the generated `.conf`. When set,
    /// they override the interface-level DNS. `secondary_dns` is only emitted
    /// when `primary_dns` is also present.
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    /// Full-tunnel toggle. `true` → client routes all traffic through this
    /// server (`AllowedIPs = 0.0.0.0/0, ::/0`); `false` → split tunnel
    /// (only the interface's own subnet).
    pub nat: bool,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub bandwidth_quota_bytes: Option<u64>,
    pub bandwidth_used_bytes: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub schedule: Option<String>,
    pub enabled: bool,
    pub owner_user_id: Option<Id<UserMarker>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Peer {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if exp < now)
    }

    pub fn over_quota(&self) -> bool {
        matches!(self.bandwidth_quota_bytes, Some(q) if self.bandwidth_used_bytes >= q)
    }
}

#[derive(Debug, Clone)]
pub struct NewPeer {
    pub interface_id: Id<InterfaceMarker>,
    pub name: String,
    pub public_key: WgPublicKey,
    pub allowed_ips: Vec<IpNet>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    pub nat: bool,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub bandwidth_quota_bytes: Option<u64>,
    pub expires_at: Option<DateTime<Utc>>,
    pub owner_user_id: Option<Id<UserMarker>>,
    pub private_key_sealed: Option<Vec<u8>>,
}
