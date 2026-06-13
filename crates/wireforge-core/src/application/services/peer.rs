use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::application::ports::{InterfaceRepository, PeerRepository, WireGuardPort};
use crate::crypto::{seal, unseal, SealKey};
use crate::domain::interface::InterfaceMarker;
use crate::domain::peer::PeerMarker;
use crate::domain::user::UserMarker;
use crate::domain::{Id, NewPeer, Peer, WgPrivateKey, WgPublicKey};
use crate::{CoreError, CoreResult};

pub struct PeerService<R: PeerRepository, I: InterfaceRepository, W: WireGuardPort> {
    peers: Arc<R>,
    ifaces: Arc<I>,
    wg: Arc<W>,
    seal_key: SealKey,
}

#[derive(Debug, Clone)]
pub struct CreatePeerInput {
    pub interface_id: Id<InterfaceMarker>,
    pub name: String,
    pub allowed_ips: Option<Vec<IpNet>>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    pub nat: bool,
    pub persistent_keepalive: Option<u16>,
    pub owner_user_id: Option<Id<UserMarker>>,
    /// BYOK key fields from the form. A non-empty `private_key` is authoritative
    /// (its public key is derived); a `public_key` alone stores no server-side
    /// private key; both empty → a fresh keypair is generated server-side.
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone)]
pub struct UpdatePeerInput {
    pub name: String,
    /// Target interface — may differ from the peer's current interface
    /// (moving a peer between interfaces).
    pub interface_id: Id<InterfaceMarker>,
    pub allowed_ips: Vec<IpNet>,
    pub primary_dns: Option<String>,
    pub secondary_dns: Option<String>,
    pub nat: bool,
    pub persistent_keepalive: Option<u16>,
    pub enabled: bool,
    /// Raw BYOK key inputs from the form (may equal the current values). The
    /// service validates, derives, seals and detects whether they really
    /// changed — see [`PeerService::update`].
    pub public_key: String,
    pub private_key: String,
}

impl<R: PeerRepository, I: InterfaceRepository, W: WireGuardPort> PeerService<R, I, W> {
    pub fn new(peers: Arc<R>, ifaces: Arc<I>, wg: Arc<W>, seal_key: SealKey) -> Self {
        Self {
            peers,
            ifaces,
            wg,
            seal_key,
        }
    }

    /// Create a peer, resolving its keypair via BYOK: a supplied private key
    /// (public derived), a public-only key (no server private), or — when both
    /// are blank — a fresh server-side keypair sealed at rest so the user can
    /// download the `.conf` (Linguard-compatible UX).
    pub async fn create_with_server_keypair(&self, input: CreatePeerInput) -> CoreResult<Peer> {
        if input.name.trim().is_empty() {
            return Err(CoreError::Validation("peer name is required".into()));
        }
        let iface = self
            .ifaces
            .find_by_id(input.interface_id)
            .await?
            .ok_or_else(|| {
                CoreError::NotFound(format!("interface {}", input.interface_id))
            })?;

        // Determine allowed_ips: explicit or auto-allocate from pool.
        let existing = self.peers.list_for_interface(iface.id).await?;
        let allowed = match input.allowed_ips {
            Some(v) if !v.is_empty() => {
                ensure_no_conflict(&v, &existing)?;
                v
            }
            _ => {
                let cidr = iface
                    .ipv4_cidr
                    .ok_or_else(|| CoreError::Validation("interface has no IPv4 CIDR".into()))?;
                let ip = next_free_ipv4(cidr, &existing)
                    .ok_or_else(|| CoreError::IpPoolExhausted(cidr.to_string()))?;
                let host_cidr = IpNet::new(ip, max_prefix(cidr)).map_err(|e| {
                    CoreError::Validation(format!("host net: {e}"))
                })?;
                vec![host_cidr]
            }
        };

        // BYOK: a supplied private key is authoritative (derive its public key);
        // a public-only key is stored without a server-side private key;
        // otherwise generate a fresh keypair server-side (default flow).
        let new_private = input.private_key.trim();
        let new_public = input.public_key.trim();
        let (public_key, private_sealed) = if !new_private.is_empty() {
            let pk = WgPrivateKey::from_base64(new_private)?;
            let derived = self.wg.derive_public_key(&pk).await?;
            (derived, Some(seal(pk.as_str().as_bytes(), &self.seal_key)?))
        } else if !new_public.is_empty() {
            (WgPublicKey::from_base64(new_public)?, None)
        } else {
            let (private_key, public_key) = self.wg.generate_keypair().await?;
            (public_key, Some(seal(private_key.as_str().as_bytes(), &self.seal_key)?))
        };

        let new = NewPeer {
            interface_id: iface.id,
            name: input.name,
            public_key,
            allowed_ips: allowed,
            primary_dns: input.primary_dns,
            secondary_dns: input.secondary_dns,
            nat: input.nat,
            endpoint: None,
            persistent_keepalive: input.persistent_keepalive,
            bandwidth_quota_bytes: None,
            expires_at: None,
            owner_user_id: input.owner_user_id,
            private_key_sealed: private_sealed,
        };
        let peer = self.peers.create(new, None).await?;
        let _ = self.wg.apply_peer(&iface, &peer).await;
        Ok(peer)
    }

    pub async fn list(&self, iface_id: Id<InterfaceMarker>) -> CoreResult<Vec<Peer>> {
        self.peers.list_for_interface(iface_id).await
    }

    pub async fn list_all(&self) -> CoreResult<Vec<Peer>> {
        self.peers.list_all().await
    }

    pub async fn get(&self, id: Id<PeerMarker>) -> CoreResult<Peer> {
        self.peers
            .find_by_id(id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("peer {id}")))
    }

    pub async fn update(&self, id: Id<PeerMarker>, input: UpdatePeerInput) -> CoreResult<Peer> {
        if input.name.trim().is_empty() {
            return Err(CoreError::Validation("peer name is required".into()));
        }
        let mut peer = self.get(id).await?;
        let old_interface_id = peer.interface_id;
        let moving = input.interface_id != old_interface_id;

        // Validate the target interface exists.
        let target_iface = self
            .ifaces
            .find_by_id(input.interface_id)
            .await?
            .ok_or_else(|| {
                CoreError::NotFound(format!("interface {}", input.interface_id))
            })?;

        // Detect IP conflicts against *other* peers on the TARGET interface.
        let others: Vec<Peer> = self
            .peers
            .list_for_interface(input.interface_id)
            .await?
            .into_iter()
            .filter(|p| p.id != peer.id)
            .collect();
        ensure_no_conflict(&input.allowed_ips, &others)?;

        peer.interface_id = input.interface_id;
        peer.name = input.name;
        peer.allowed_ips = input.allowed_ips;
        peer.primary_dns = input.primary_dns;
        peer.secondary_dns = input.secondary_dns;
        peer.nat = input.nat;
        peer.persistent_keepalive = input.persistent_keepalive;
        peer.enabled = input.enabled;

        // BYOK key resolution. A changed private key is authoritative — we
        // derive the matching public key from it. Otherwise an explicitly
        // changed public key replaces the stored one and clears the
        // server-side private key (the client then holds it alone).
        let old_public = peer.public_key.clone();
        let current_private = peer
            .private_key_sealed
            .as_deref()
            .and_then(|blob| unseal(blob, &self.seal_key).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
        let new_private = input.private_key.trim();
        let new_public = input.public_key.trim();
        if !new_private.is_empty() && new_private != current_private {
            let priv_key = WgPrivateKey::from_base64(new_private)?;
            let derived = self.wg.derive_public_key(&priv_key).await?;
            peer.private_key_sealed = Some(seal(priv_key.as_str().as_bytes(), &self.seal_key)?);
            peer.public_key = derived;
        } else if new_private.is_empty()
            && !new_public.is_empty()
            && new_public != old_public.as_str()
        {
            peer.public_key = WgPublicKey::from_base64(new_public)?;
            peer.private_key_sealed = None;
        }
        let key_changed = peer.public_key.as_str() != old_public.as_str();

        self.peers.update(&peer).await?;

        // Remove the peer's stale kernel entry when it moved interfaces or its
        // public key changed (kernel peers are keyed by their public key).
        if moving {
            if let Ok(Some(old_iface)) = self.ifaces.find_by_id(old_interface_id).await {
                let _ = self.wg.remove_peer(&old_iface, &old_public).await;
            }
        } else if key_changed {
            let _ = self.wg.remove_peer(&target_iface, &old_public).await;
        }

        // Best-effort: push the change to the (target) running interface.
        if peer.enabled {
            let _ = self.wg.apply_peer(&target_iface, &peer).await;
        } else {
            let _ = self.wg.remove_peer(&target_iface, &peer.public_key).await;
        }
        Ok(peer)
    }

    /// Toggle the `enabled` flag and re-apply to the WG interface.
    pub async fn set_enabled(&self, id: Id<PeerMarker>, enabled: bool) -> CoreResult<Peer> {
        let mut peer = self.get(id).await?;
        peer.enabled = enabled;
        self.peers.update(&peer).await?;
        let iface = self
            .ifaces
            .find_by_id(peer.interface_id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("interface {}", peer.interface_id)))?;
        if enabled {
            let _ = self.wg.apply_peer(&iface, &peer).await;
        } else {
            let _ = self.wg.remove_peer(&iface, &peer.public_key).await;
        }
        Ok(peer)
    }

    pub async fn delete(&self, id: Id<PeerMarker>) -> CoreResult<()> {
        let peer = self.get(id).await?;
        let iface = self
            .ifaces
            .find_by_id(peer.interface_id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("interface {}", peer.interface_id)))?;
        let _ = self.wg.remove_peer(&iface, &peer.public_key).await;
        self.peers.delete(id).await
    }
}

fn ensure_no_conflict(want: &[IpNet], existing: &[Peer]) -> CoreResult<()> {
    let used: HashSet<IpNet> = existing
        .iter()
        .flat_map(|p| p.allowed_ips.iter().copied())
        .collect();
    for ip in want {
        if used.contains(ip) {
            return Err(CoreError::Conflict(format!("ip {ip} already assigned")));
        }
    }
    Ok(())
}

fn max_prefix(cidr: IpNet) -> u8 {
    match cidr {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    }
}

fn next_free_ipv4(cidr: IpNet, existing: &[Peer]) -> Option<IpAddr> {
    let used: HashSet<IpAddr> = existing
        .iter()
        .flat_map(|p| p.allowed_ips.iter().map(|n| n.network()))
        .collect();
    // Skip the network address and the server's own address (.1 by convention).
    cidr.hosts()
        .skip(1)
        .find(|host| !used.contains(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allocates_next_free_ipv4() {
        let cidr: IpNet = "10.7.0.0/24".parse().unwrap();
        let peers: Vec<Peer> = Vec::new();
        let first = next_free_ipv4(cidr, &peers).unwrap();
        assert_eq!(first, IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)));
    }

    #[test]
    fn skips_used_ips() {
        let cidr: IpNet = "10.7.0.0/24".parse().unwrap();
        let used: IpNet = "10.7.0.2/32".parse().unwrap();
        let stub_peer = Peer {
            id: Id::new(),
            interface_id: Id::new(),
            name: "p".into(),
            public_key: crate::domain::WgPublicKey::from_base64(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .unwrap(),
            private_key_sealed: None,
            preshared_key_sealed: None,
            allowed_ips: vec![used],
            primary_dns: None,
            secondary_dns: None,
            nat: true,
            endpoint: None,
            persistent_keepalive: None,
            bandwidth_quota_bytes: None,
            bandwidth_used_bytes: 0,
            expires_at: None,
            schedule: None,
            enabled: true,
            owner_user_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let next = next_free_ipv4(cidr, &[stub_peer]).unwrap();
        assert_eq!(next, IpAddr::V4(Ipv4Addr::new(10, 7, 0, 3)));
    }
}
