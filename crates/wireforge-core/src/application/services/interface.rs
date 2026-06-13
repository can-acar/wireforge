use std::sync::Arc;

use ipnet::IpNet;

use crate::application::ports::{
    InterfaceRepository, NatPort, PeerRepository, SysNetPort, WireGuardPort,
};
use crate::crypto::{seal, unseal, SealKey};
use crate::domain::interface::InterfaceMarker;
use crate::domain::{Id, Interface, InterfaceStatus, NewInterface, WgPrivateKey};
use crate::{CoreError, CoreResult};

pub struct InterfaceService<
    R: InterfaceRepository,
    P: PeerRepository,
    W: WireGuardPort,
    N: NatPort,
    S: SysNetPort,
> {
    ifaces: Arc<R>,
    peers: Arc<P>,
    wg: Arc<W>,
    nat: Arc<N>,
    sysnet: Arc<S>,
    seal_key: SealKey,
}

#[derive(Debug, Clone)]
pub struct CreateInterfaceInput {
    pub name: String,
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
    /// BYOK: a base64 private key supplied by the user. Empty → auto-generate
    /// a fresh keypair. The public key is always derived from this.
    pub private_key: String,
}

#[derive(Debug, Clone)]
pub struct UpdateInterfaceInput {
    pub listen_port: u16,
    pub endpoint: Option<String>,
    pub gateway: Option<String>,
    pub ipv4_cidr: Option<IpNet>,
    pub ipv6_cidr: Option<IpNet>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
    /// BYOK: a changed base64 private key re-derives the public key. Empty or
    /// unchanged → keep the current keypair.
    pub private_key: String,
}

impl<R, P, W, N, S> InterfaceService<R, P, W, N, S>
where
    R: InterfaceRepository,
    P: PeerRepository,
    W: WireGuardPort,
    N: NatPort,
    S: SysNetPort,
{
    pub fn new(
        ifaces: Arc<R>,
        peers: Arc<P>,
        wg: Arc<W>,
        nat: Arc<N>,
        sysnet: Arc<S>,
        seal_key: SealKey,
    ) -> Self {
        Self {
            ifaces,
            peers,
            wg,
            nat,
            sysnet,
            seal_key,
        }
    }

    /// Generate a fresh (private, public) base64 keypair to pre-fill the create
    /// form. The user may keep it or replace the private key (BYOK).
    pub async fn fresh_keypair(&self) -> CoreResult<(String, String)> {
        let (private_key, public_key) = self.wg.generate_keypair().await?;
        Ok((private_key.into_inner(), public_key.into_inner()))
    }

    /// Create the interface row, resolving the keypair via BYOK (supplied
    /// private key) or fresh generation through the WireGuard adapter.
    pub async fn create(&self, input: CreateInterfaceInput) -> CoreResult<Interface> {
        validate_iface_name(&input.name)?;
        if let Some(gw) = input.gateway.as_deref() {
            self.validate_gateway(gw)?;
        }
        if self.ifaces.find_by_name(&input.name).await?.is_some() {
            return Err(CoreError::Conflict(format!(
                "interface '{}' already exists",
                input.name
            )));
        }
        let (private_key, public_key) = {
            let supplied = input.private_key.trim();
            if supplied.is_empty() {
                self.wg.generate_keypair().await?
            } else {
                let pk = WgPrivateKey::from_base64(supplied)?;
                let pubk = self.wg.derive_public_key(&pk).await?;
                (pk, pubk)
            }
        };
        let new = NewInterface {
            name: input.name.clone(),
            private_key: private_key.clone(),
            public_key,
            listen_port: input.listen_port,
            endpoint: input.endpoint,
            gateway: input.gateway,
            ipv4_cidr: input.ipv4_cidr,
            ipv6_cidr: input.ipv6_cidr,
            mtu: input.mtu,
            dns: input.dns,
            on_up: input.on_up,
            on_down: input.on_down,
        };
        let sealed = seal(private_key.as_str().as_bytes(), &self.seal_key)?;
        let iface = self.ifaces.create(new, sealed).await?;
        // Best-effort: create the kernel/userspace iface (idempotent under
        // dry-run; harmless under real adapter as configure_interface in
        // `start` will re-establish it).
        let _ = self.wg.create_interface(&iface).await;
        Ok(iface)
    }

    pub async fn list(&self) -> CoreResult<Vec<Interface>> {
        self.ifaces.list().await
    }

    pub async fn get(&self, id: Id<InterfaceMarker>) -> CoreResult<Interface> {
        self.ifaces
            .find_by_id(id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("interface {id}")))
    }

    pub async fn start(&self, id: Id<InterfaceMarker>) -> CoreResult<Interface> {
        let mut iface = self.get(id).await?;
        let peers = self.peers.list_for_interface(iface.id).await?;
        self.wg.interface_up(&iface, &peers).await?;

        // Run the user's on_up hook commands (best-effort, no shell).
        if let Some(script) = iface.on_up.as_deref() {
            let _ = self.nat.run_hook(script).await;
        }

        // Apply structured NAT/masquerade if a gateway is configured. On any
        // failure roll the tunnel back down so we never leave it up but
        // unmasqueraded (which would silently break peer internet egress).
        if let Some(gw) = iface.gateway.as_deref() {
            let result = match self.validate_gateway(gw) {
                Ok(()) => self.nat.apply(&iface, gw).await,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                let _ = self.wg.interface_down(&iface).await;
                return Err(e);
            }
        }

        iface.status = InterfaceStatus::Up;
        self.ifaces.update(&iface).await?;
        Ok(iface)
    }

    pub async fn stop(&self, id: Id<InterfaceMarker>) -> CoreResult<Interface> {
        let mut iface = self.get(id).await?;
        // Tear NAT down first (best-effort; the adapter logs failures), then
        // run on_down, then bring wg down — symmetric with `start`.
        if let Some(gw) = iface.gateway.as_deref() {
            let _ = self.nat.remove(&iface, gw).await;
        }
        if let Some(script) = iface.on_down.as_deref() {
            let _ = self.nat.run_hook(script).await;
        }
        self.wg.interface_down(&iface).await?;
        iface.status = InterfaceStatus::Down;
        self.ifaces.update(&iface).await?;
        Ok(iface)
    }

    pub async fn update(
        &self,
        id: Id<InterfaceMarker>,
        input: UpdateInterfaceInput,
    ) -> CoreResult<Interface> {
        let mut iface = self.get(id).await?;
        if let Some(gw) = input.gateway.as_deref() {
            self.validate_gateway(gw)?;
        }
        let old_gateway = iface.gateway.clone();
        iface.listen_port = input.listen_port;
        iface.endpoint = input.endpoint;
        iface.gateway = input.gateway;
        iface.ipv4_cidr = input.ipv4_cidr;
        iface.ipv6_cidr = input.ipv6_cidr;
        iface.mtu = input.mtu;
        iface.dns = input.dns;
        iface.on_up = input.on_up;
        iface.on_down = input.on_down;

        // BYOK: a changed private key is authoritative — derive the matching
        // public key from it. An interface must always retain its private key
        // (needed to bring the tunnel up), so there is no "public-key-only"
        // branch here, unlike peers.
        let current_private = unseal(&iface.private_key_sealed, &self.seal_key)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let new_private = input.private_key.trim();
        if !new_private.is_empty() && new_private != current_private {
            let priv_key = WgPrivateKey::from_base64(new_private)?;
            let derived = self.wg.derive_public_key(&priv_key).await?;
            iface.private_key_sealed = seal(priv_key.as_str().as_bytes(), &self.seal_key)?;
            iface.public_key = derived;
        }

        self.ifaces.update(&iface).await?;

        // If the interface is currently up, re-apply the configuration (DNS,
        // MTU, address, key) and NAT so changes take effect without a restart.
        if matches!(iface.status, InterfaceStatus::Up) {
            let peers = self.peers.list_for_interface(iface.id).await?;
            let _ = self.wg.interface_up(&iface, &peers).await;
            // Re-apply NAT idempotently, handling a changed gateway.
            if let Some(old_gw) = old_gateway.as_deref() {
                let _ = self.nat.remove(&iface, old_gw).await;
            }
            if let Some(gw) = iface.gateway.as_deref() {
                let _ = self.nat.apply(&iface, gw).await;
            }
        }
        Ok(iface)
    }

    pub async fn delete(&self, id: Id<InterfaceMarker>) -> CoreResult<()> {
        let iface = self.get(id).await?;
        // Best-effort: pull NAT rules before destroying the interface.
        if let Some(gw) = iface.gateway.as_deref() {
            let _ = self.nat.remove(&iface, gw).await;
        }
        let _ = self.wg.interface_down(&iface).await;
        let _ = self.wg.delete_interface(&iface).await;
        self.ifaces.delete(id).await
    }

    /// Validate a gateway interface name: charset/length plus existence as a
    /// real host interface (rejecting loopback). Used at create/update/start.
    fn validate_gateway(&self, gw: &str) -> CoreResult<()> {
        if !gateway_charset_ok(gw) {
            return Err(CoreError::Validation(
                "invalid gateway interface name".into(),
            ));
        }
        let exists = self.sysnet.list()?.iter().any(|i| i.name == gw);
        if !exists {
            return Err(CoreError::Validation(format!(
                "gateway '{gw}' is not a host interface"
            )));
        }
        Ok(())
    }
}

fn validate_iface_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(CoreError::Validation(
            "interface name must be 1-15 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CoreError::Validation(
            "interface name may only contain a-z, 0-9, '-', '_'".into(),
        ));
    }
    Ok(())
}

/// Charset/length check for a gateway (host) interface name. Loopback is
/// rejected outright. Existence is verified separately against `SysNetPort`.
fn gateway_charset_ok(gw: &str) -> bool {
    !gw.is_empty()
        && gw.len() <= 15
        && gw != "lo"
        && gw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_name_validation() {
        assert!(validate_iface_name("wg0").is_ok());
        assert!(validate_iface_name("vpn-prod_1").is_ok());
        assert!(validate_iface_name("").is_err());
        assert!(validate_iface_name("interfacenametoolong").is_err());
        assert!(validate_iface_name("wg with space").is_err());
        assert!(validate_iface_name("wg/0").is_err());
    }

    #[test]
    fn gateway_charset_validation() {
        assert!(gateway_charset_ok("eth0"));
        assert!(gateway_charset_ok("enp0s31f6"));
        assert!(gateway_charset_ok("br-lan"));
        assert!(!gateway_charset_ok("")); // empty
        assert!(!gateway_charset_ok("lo")); // loopback rejected
        assert!(!gateway_charset_ok("eth0; rm -rf /")); // injection chars
        assert!(!gateway_charset_ok("waytoolonginterface")); // > 15 chars
    }
}
