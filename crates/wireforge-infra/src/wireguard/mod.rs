//! WireGuard adapter backed by `defguard_wireguard_rs`.
//!
//! - On **Linux** the adapter prefers the kernel module (netlink).
//! - On **macOS / Windows / *BSD** it uses the userspace boringtun backend.
//!
//! All I/O is performed through the published API — **no shell-out is ever
//! used**. Blocking calls are dispatched to a Tokio blocking worker.

use std::convert::TryFrom;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use defguard_wireguard_rs::host::Peer as WgPeer;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
#[cfg(target_os = "linux")]
use defguard_wireguard_rs::Kernel;
use defguard_wireguard_rs::{InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::task;
use tracing::{debug, info, instrument, warn};
use wireforge_core::application::ports::{PeerStats, WireGuardPort};
use wireforge_core::crypto::{unseal, SealKey};
use wireforge_core::domain::{Interface, Peer, WgPrivateKey, WgPublicKey};
use wireforge_core::{CoreError, CoreResult};

#[cfg(target_os = "linux")]
type ApiBackend = Kernel;
#[cfg(not(target_os = "linux"))]
type ApiBackend = Userspace;

pub struct DefguardAdapter {
    seal_key: SealKey,
    /// When `dry_run` is true the adapter only logs operations without
    /// touching the OS. Enabled automatically on macOS dev hosts when no
    /// TUN driver is configured, or via `WIREFORGE_WG_DRY_RUN=1`.
    dry_run: bool,
}

impl DefguardAdapter {
    pub fn new(seal_key: SealKey) -> Self {
        let dry_run = std::env::var("WIREFORGE_WG_DRY_RUN")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self { seal_key, dry_run }
    }

    pub fn with_dry_run(seal_key: SealKey, dry_run: bool) -> Self {
        Self { seal_key, dry_run }
    }

    fn open(name: &str) -> CoreResult<WGApi<ApiBackend>> {
        WGApi::<ApiBackend>::new(name.to_string())
            .map_err(|e| CoreError::WireGuard(format!("wgapi open '{name}': {e}")))
    }

    fn unseal_private(&self, iface: &Interface) -> CoreResult<WgPrivateKey> {
        let bytes = unseal(&iface.private_key_sealed, &self.seal_key)?;
        let s = String::from_utf8(bytes)
            .map_err(|e| CoreError::Crypto(format!("private key utf8: {e}")))?;
        WgPrivateKey::from_base64(s)
    }

    fn to_wg_peer(peer: &Peer) -> CoreResult<WgPeer> {
        let key = decode_b64_key(peer.public_key.as_str())?;
        let mut wg_peer = WgPeer::new(key);
        for cidr in &peer.allowed_ips {
            wg_peer
                .allowed_ips
                .push(IpAddrMask::new(cidr.network(), cidr.prefix_len()));
        }
        if let Some(ep) = &peer.endpoint {
            wg_peer.endpoint = ep.parse().ok();
        }
        wg_peer.persistent_keepalive_interval = peer.persistent_keepalive;
        Ok(wg_peer)
    }
}

#[async_trait]
impl WireGuardPort for DefguardAdapter {
    async fn derive_public_key(&self, private: &WgPrivateKey) -> CoreResult<WgPublicKey> {
        let priv_s = private.as_str().to_string();
        task::spawn_blocking(move || {
            let priv_bytes = STANDARD
                .decode(&priv_s)
                .map_err(|e| CoreError::Crypto(format!("priv b64: {e}")))?;
            let priv_key = Key::try_from(priv_bytes.as_slice())
                .map_err(|e| CoreError::Crypto(format!("priv key: {e}")))?;
            let pub_key = priv_key.public_key();
            WgPublicKey::from_base64(STANDARD.encode(pub_key.as_array()))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    async fn generate_keypair(&self) -> CoreResult<(WgPrivateKey, WgPublicKey)> {
        task::spawn_blocking(|| {
            let private = Key::generate();
            let public = private.public_key();
            Ok::<_, CoreError>((
                WgPrivateKey::from_base64(STANDARD.encode(private.as_array()))?,
                WgPublicKey::from_base64(STANDARD.encode(public.as_array()))?,
            ))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    #[instrument(skip(self, iface), fields(iface = %iface.name))]
    async fn create_interface(&self, iface: &Interface) -> CoreResult<()> {
        if self.dry_run {
            info!("dry-run: create_interface");
            return Ok(());
        }
        let name = iface.name.clone();
        task::spawn_blocking(move || {
            let mut api = Self::open(&name)?;
            api.create_interface()
                .map_err(|e| CoreError::WireGuard(format!("create {name}: {e}")))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    #[instrument(skip(self, iface, peers), fields(iface = %iface.name, peer_count = peers.len()))]
    async fn interface_up(&self, iface: &Interface, peers: &[Peer]) -> CoreResult<()> {
        if self.dry_run {
            debug!(peers = peers.len(), "dry-run: interface_up");
            return Ok(());
        }
        let private = self.unseal_private(iface)?;
        let mut addresses = Vec::new();
        if let Some(c) = iface.ipv4_cidr {
            addresses.push(IpAddrMask::new(c.network(), c.prefix_len()));
        }
        if let Some(c) = iface.ipv6_cidr {
            addresses.push(IpAddrMask::new(c.network(), c.prefix_len()));
        }
        let cfg = InterfaceConfiguration {
            name: iface.name.clone(),
            prvkey: private.into_inner(),
            addresses,
            port: iface.listen_port,
            peers: peers
                .iter()
                .filter(|p| p.enabled)
                .map(Self::to_wg_peer)
                .collect::<Result<Vec<_>, _>>()?,
            mtu: iface.mtu.map(|m| m as u32),
        };
        let name = iface.name.clone();
        task::spawn_blocking(move || {
            let api = Self::open(&name)?;
            api.configure_interface(&cfg)
                .map_err(|e| CoreError::WireGuard(format!("configure {name}: {e}")))?;
            api.configure_peer_routing(&cfg.peers)
                .map_err(|e| CoreError::WireGuard(format!("routing {name}: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    #[instrument(skip(self, iface), fields(iface = %iface.name))]
    async fn interface_down(&self, iface: &Interface) -> CoreResult<()> {
        if self.dry_run {
            debug!("dry-run: interface_down");
            return Ok(());
        }
        let name = iface.name.clone();
        task::spawn_blocking(move || {
            #[cfg(not(target_os = "windows"))]
            {
                let api = Self::open(&name)?;
                api.remove_interface()
                    .map_err(|e| CoreError::WireGuard(format!("down {name}: {e}")))
            }
            #[cfg(target_os = "windows")]
            {
                let mut api = Self::open(&name)?;
                api.remove_interface()
                    .map_err(|e| CoreError::WireGuard(format!("down {name}: {e}")))
            }
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    async fn delete_interface(&self, iface: &Interface) -> CoreResult<()> {
        // For WireGuard "delete" is functionally identical to "down":
        // the kernel/userspace driver removes the interface entirely.
        if let Err(e) = self.interface_down(iface).await {
            warn!(error = %e, "delete_interface: interface_down failed (continuing)");
        }
        Ok(())
    }

    #[instrument(skip(self, iface, peer), fields(iface = %iface.name, peer = %peer.name))]
    async fn apply_peer(&self, iface: &Interface, peer: &Peer) -> CoreResult<()> {
        if self.dry_run {
            debug!("dry-run: apply_peer");
            return Ok(());
        }
        let wg_peer = Self::to_wg_peer(peer)?;
        let name = iface.name.clone();
        task::spawn_blocking(move || {
            let api = Self::open(&name)?;
            api.configure_peer(&wg_peer)
                .map_err(|e| CoreError::WireGuard(format!("apply peer {name}: {e}")))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    async fn remove_peer(
        &self,
        iface: &Interface,
        peer_pubkey: &WgPublicKey,
    ) -> CoreResult<()> {
        if self.dry_run {
            debug!(iface = %iface.name, "dry-run: remove_peer");
            return Ok(());
        }
        let key = decode_b64_key(peer_pubkey.as_str())?;
        let name = iface.name.clone();
        task::spawn_blocking(move || {
            let api = Self::open(&name)?;
            api.remove_peer(&key)
                .map_err(|e| CoreError::WireGuard(format!("remove peer {name}: {e}")))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    async fn peer_stats(&self, iface: &Interface) -> CoreResult<Vec<PeerStats>> {
        if self.dry_run {
            return Ok(Vec::new());
        }
        let name = iface.name.clone();
        let host = task::spawn_blocking(move || {
            let api = Self::open(&name)?;
            api.read_interface_data()
                .map_err(|e| CoreError::WireGuard(format!("read {name}: {e}")))
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))??;

        let mut out = Vec::with_capacity(host.peers.len());
        for (_pubkey, p) in host.peers {
            let pubkey = WgPublicKey::from_base64(STANDARD.encode(p.public_key.as_array()))?;
            let last_handshake = p.last_handshake.and_then(|t| {
                let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
            });
            out.push(PeerStats {
                public_key: pubkey,
                last_handshake,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                endpoint: p.endpoint.map(|ep| ep.to_string()),
            });
        }
        Ok(out)
    }
}

/// Decode a base64 WireGuard key (32 bytes) into the defguard `Key` type.
fn decode_b64_key(s: &str) -> CoreResult<Key> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|e| CoreError::Crypto(format!("key b64: {e}")))?;
    Key::try_from(bytes.as_slice()).map_err(|e| CoreError::Crypto(format!("key bytes: {e}")))
}

/// Stateless local CSPRNG keypair generator used by tests and the optional
/// `wireforge keygen` CLI command.
#[allow(dead_code)]
pub fn generate_keypair_local() -> CoreResult<(WgPrivateKey, WgPublicKey)> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let priv_key = Key::new(bytes);
    let pub_key = priv_key.public_key();
    Ok((
        WgPrivateKey::from_base64(STANDARD.encode(priv_key.as_array()))?,
        WgPublicKey::from_base64(STANDARD.encode(pub_key.as_array()))?,
    ))
}
