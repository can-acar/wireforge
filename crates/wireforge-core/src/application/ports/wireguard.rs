use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::domain::{Interface, Peer, WgPrivateKey, WgPublicKey};
use crate::CoreResult;

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub public_key: WgPublicKey,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub endpoint: Option<String>,
}

/// Port that adapters implement to manage WireGuard at the OS level.
///
/// The reference implementation lives in `wireforge-infra::wireguard` and
/// wraps `defguard_wireguard_rs`. **Never** shell out with `shell=true`.
#[async_trait]
pub trait WireGuardPort: Send + Sync {
    /// Derive the public key for a freshly generated private key.
    /// Implemented by the adapter via x25519 — keeps core crate slim.
    async fn derive_public_key(&self, private: &WgPrivateKey) -> CoreResult<WgPublicKey>;

    /// Generate a fresh (private, public) keypair using the OS CSPRNG.
    async fn generate_keypair(&self) -> CoreResult<(WgPrivateKey, WgPublicKey)>;

    /// Create the interface in the kernel/userspace (does not bring it up).
    async fn create_interface(&self, iface: &Interface) -> CoreResult<()>;

    /// Bring an interface up (configures addresses, listen port, peers, routes).
    async fn interface_up(&self, iface: &Interface, peers: &[Peer]) -> CoreResult<()>;

    /// Bring an interface down (without removing config from the DB).
    async fn interface_down(&self, iface: &Interface) -> CoreResult<()>;

    /// Remove the interface entirely.
    async fn delete_interface(&self, iface: &Interface) -> CoreResult<()>;

    /// Apply a peer config (add or update) to a running interface.
    async fn apply_peer(&self, iface: &Interface, peer: &Peer) -> CoreResult<()>;

    /// Remove a peer from a running interface.
    async fn remove_peer(&self, iface: &Interface, peer_pubkey: &WgPublicKey) -> CoreResult<()>;

    /// Query live peer statistics from the kernel.
    async fn peer_stats(&self, iface: &Interface) -> CoreResult<Vec<PeerStats>>;
}
