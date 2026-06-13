//! Build a WireGuard `.conf` file for a peer.
//!
//! The generated config is in the standard `wg-quick` format and works with
//! every WireGuard client (Linux, Windows, macOS, iOS, Android).

use crate::crypto::{unseal, SealKey};
use crate::domain::{Interface, Peer};
use crate::CoreResult;

/// Render the `[Interface]` + `[Peer]` config a downstream user needs to
/// connect through `iface` as `peer`.
///
/// `server_endpoint` is the public reachable host (or host:port) advertised
/// to the peer. If a port is omitted the interface's `listen_port` is
/// appended.
pub fn render_peer_conf(
    iface: &Interface,
    peer: &Peer,
    server_endpoint: &str,
    seal_key: &SealKey,
) -> CoreResult<String> {
    let private_key_b64 = match peer.private_key_sealed.as_ref() {
        Some(blob) => {
            let bytes = unseal(blob, seal_key)?;
            String::from_utf8(bytes).map_err(|e| {
                crate::CoreError::Crypto(format!("peer privkey utf8: {e}"))
            })?
        }
        None => return Err(crate::CoreError::Validation(
            "peer has no server-side private key; provide one or regenerate".into(),
        )),
    };

    // Pick the first peer-allocated address as the interface Address. The
    // remainder fall through as additional addresses if any.
    let address_line = peer
        .allowed_ips
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let endpoint = if server_endpoint.contains(':') {
        server_endpoint.to_string()
    } else {
        format!("{server_endpoint}:{}", iface.listen_port)
    };

    // DNS: a per-peer primary/secondary overrides the interface default;
    // fall back to the interface DNS when the peer sets none.
    let mut dns: Vec<String> = Vec::new();
    if let Some(d) = peer.primary_dns.as_deref().filter(|s| !s.is_empty()) {
        dns.push(d.to_string());
    }
    if let Some(d) = peer.secondary_dns.as_deref().filter(|s| !s.is_empty()) {
        dns.push(d.to_string());
    }
    if dns.is_empty() {
        dns = iface.dns.clone();
    }
    let dns_line = if dns.is_empty() {
        String::new()
    } else {
        format!("DNS = {}\n", dns.join(", "))
    };

    let keepalive = peer
        .persistent_keepalive
        .map(|k| format!("PersistentKeepalive = {k}\n"))
        .unwrap_or_default();

    // Client-side AllowedIPs. NAT on → full tunnel (route everything through
    // this server, which NATs it out). NAT off → split tunnel, restricted to
    // the interface's own subnet(s). Falls back to full tunnel when the
    // interface has no configured CIDR.
    let client_allowed_ips = if peer.nat {
        "0.0.0.0/0, ::/0".to_string()
    } else {
        let mut nets: Vec<String> = Vec::new();
        if let Some(c) = iface.ipv4_cidr {
            nets.push(c.trunc().to_string());
        }
        if let Some(c) = iface.ipv6_cidr {
            nets.push(c.trunc().to_string());
        }
        if nets.is_empty() {
            "0.0.0.0/0, ::/0".to_string()
        } else {
            nets.join(", ")
        }
    };

    let mtu_line = iface
        .mtu
        .map(|m| format!("MTU = {m}\n"))
        .unwrap_or_default();

    Ok(format!(
        "[Interface]\n\
         # {peer_name} ({iface_name})\n\
         PrivateKey = {private_key_b64}\n\
         Address = {address_line}\n\
         {dns_line}{mtu_line}\
         \n\
         [Peer]\n\
         PublicKey = {server_pub}\n\
         AllowedIPs = {client_allowed_ips}\n\
         Endpoint = {endpoint}\n\
         {keepalive}",
        peer_name = peer.name,
        iface_name = iface.name,
        server_pub = iface.public_key.as_str(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seal;
    use crate::domain::{Id, InterfaceStatus, WgPublicKey};

    const VALID_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn key() -> SealKey {
        SealKey::from_passphrase("unit-test-key")
    }

    fn iface() -> Interface {
        Interface {
            id: Id::new(),
            name: "wg0".into(),
            public_key: WgPublicKey::from_base64(VALID_KEY).unwrap(),
            private_key_sealed: Vec::new(),
            listen_port: 51820,
            endpoint: None,
            gateway: None,
            ipv4_cidr: Some("10.0.0.1/24".parse().unwrap()),
            ipv6_cidr: None,
            mtu: None,
            dns: vec!["1.1.1.1".into()],
            on_up: None,
            on_down: None,
            status: InterfaceStatus::Up,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn peer(k: &SealKey, primary: Option<&str>, secondary: Option<&str>, nat: bool) -> Peer {
        Peer {
            id: Id::new(),
            interface_id: Id::new(),
            name: "laptop".into(),
            public_key: WgPublicKey::from_base64(VALID_KEY).unwrap(),
            private_key_sealed: Some(seal(b"cGVlci1wcml2YXRl", k).unwrap()),
            preshared_key_sealed: None,
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            primary_dns: primary.map(str::to_string),
            secondary_dns: secondary.map(str::to_string),
            nat,
            endpoint: None,
            persistent_keepalive: Some(25),
            bandwidth_quota_bytes: None,
            bandwidth_used_bytes: 0,
            expires_at: None,
            schedule: None,
            enabled: true,
            owner_user_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn peer_dns_overrides_interface_dns() {
        let k = key();
        let p = peer(&k, Some("8.8.8.8"), Some("8.8.4.4"), true);
        let conf = render_peer_conf(&iface(), &p, "vpn.example.com", &k).unwrap();
        assert!(conf.contains("DNS = 8.8.8.8, 8.8.4.4"), "{conf}");
    }

    #[test]
    fn dns_falls_back_to_interface_when_peer_has_none() {
        let k = key();
        let p = peer(&k, None, None, true);
        let conf = render_peer_conf(&iface(), &p, "vpn.example.com", &k).unwrap();
        assert!(conf.contains("DNS = 1.1.1.1"), "{conf}");
    }

    #[test]
    fn nat_on_routes_full_tunnel() {
        let k = key();
        let p = peer(&k, None, None, true);
        let conf = render_peer_conf(&iface(), &p, "vpn.example.com", &k).unwrap();
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0, ::/0"), "{conf}");
    }

    #[test]
    fn nat_off_restricts_to_interface_subnet() {
        let k = key();
        let p = peer(&k, None, None, false);
        let conf = render_peer_conf(&iface(), &p, "vpn.example.com", &k).unwrap();
        assert!(conf.contains("AllowedIPs = 10.0.0.0/24"), "{conf}");
        assert!(!conf.contains("0.0.0.0/0"), "{conf}");
    }
}
