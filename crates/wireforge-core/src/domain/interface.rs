use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{Id, WgPrivateKey, WgPublicKey};

#[derive(Debug)]
pub struct InterfaceMarker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceStatus {
    Down,
    Up,
    Error,
}

impl InterfaceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Up => "up",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub id: Id<InterfaceMarker>,
    pub name: String,
    pub public_key: WgPublicKey,
    /// Stored sealed (age-encrypted) at rest; only decrypted when applying to WG.
    pub private_key_sealed: Vec<u8>,
    pub listen_port: u16,
    pub endpoint: Option<String>,
    /// Host egress interface for NAT/masquerade (e.g. `eth0`). `None` = no NAT.
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<IpNet>,
    pub ipv6_cidr: Option<IpNet>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
    pub status: InterfaceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewInterface {
    pub name: String,
    pub private_key: WgPrivateKey,
    pub public_key: WgPublicKey,
    pub listen_port: u16,
    pub endpoint: Option<String>,
    /// Host egress interface for NAT/masquerade (e.g. `eth0`). `None` = no NAT.
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<IpNet>,
    pub ipv6_cidr: Option<IpNet>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
}
