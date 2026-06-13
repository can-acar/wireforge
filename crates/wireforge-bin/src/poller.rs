//! Background traffic poller.
//!
//! Periodically reads peer stats from the WireGuard kernel/userspace layer
//! and:
//!   1. snapshots the totals into `traffic_snapshots` for charting,
//!   2. updates `peers.bandwidth_used_bytes` cumulative counter,
//!   3. enforces `bandwidth_quota_bytes` by auto-disabling peers that
//!      crossed their quota (Faz 6 — bandwidth quota enforcement).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info, warn};
use wireforge_core::application::ports::{
    InterfaceRepository, PeerRepository, TrafficRepository, WireGuardPort,
};
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::{Id, InterfaceStatus, RuntimeSettings};
use wireforge_infra::{
    DefguardAdapter, SqliteInterfaceRepository, SqlitePeerRepository, SqliteTrafficRepository,
};

pub struct PollerHandles {
    pub interfaces: Arc<SqliteInterfaceRepository>,
    pub peers: Arc<SqlitePeerRepository>,
    pub traffic: Arc<SqliteTrafficRepository>,
    pub wg: Arc<DefguardAdapter>,
    /// Live settings — the poller re-reads `traffic_poller_interval_secs` and
    /// `traffic_enabled` on every iteration so changes apply without restart.
    pub settings: Arc<RwLock<RuntimeSettings>>,
}

/// Spawn the poller. Returns immediately; the task runs until shutdown.
pub fn spawn(h: PollerHandles) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("traffic poller started");
        loop {
            // Read interval + enabled fresh each loop.
            let (interval_secs, enabled) = {
                let s = h.settings.read();
                (s.traffic_poller_interval_secs.max(1), s.traffic_enabled)
            };
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            if !enabled {
                debug!("traffic poll skipped: disabled via settings");
                continue;
            }
            if let Err(e) = poll_once(&h).await {
                warn!(error = %e, "poller iteration failed");
            }
        }
    })
}

async fn poll_once(h: &PollerHandles) -> anyhow::Result<()> {
    let ifaces = h.interfaces.list().await?;
    for iface in ifaces {
        if !matches!(iface.status, InterfaceStatus::Up) {
            continue;
        }
        let stats = match h.wg.peer_stats(&iface).await {
            Ok(v) => v,
            Err(e) => {
                debug!(iface = %iface.name, error = %e, "peer_stats skipped");
                continue;
            }
        };

        // Build a lookup of peer public_key -> Peer entity.
        let peers = h.peers.list_for_interface(iface.id).await?;
        let by_pubkey: HashMap<String, &wireforge_core::domain::Peer> = peers
            .iter()
            .map(|p| (p.public_key.as_str().to_string(), p))
            .collect();

        for s in stats {
            let Some(peer) = by_pubkey.get(s.public_key.as_str()) else {
                continue;
            };
            let total = s.rx_bytes.saturating_add(s.tx_bytes);
            // Persist snapshot (charting + audit).
            if let Err(e) = h
                .traffic
                .snapshot(peer.id, s.tx_bytes, s.rx_bytes, s.last_handshake)
                .await
            {
                warn!(peer = %peer.id, error = %e, "traffic snapshot failed");
            }
            if let Err(e) = h.peers.record_bandwidth(peer.id, total).await {
                warn!(peer = %peer.id, error = %e, "bandwidth update failed");
            }

            // Bandwidth quota enforcement.
            if let Some(quota) = peer.bandwidth_quota_bytes {
                if total >= quota && peer.enabled {
                    info!(
                        peer = %peer.name,
                        used = total,
                        quota,
                        "peer over quota — disabling"
                    );
                    let _ = disable_peer(h, peer.id).await;
                }
            }
        }
    }
    Ok(())
}

async fn disable_peer(h: &PollerHandles, peer_id: Id<PeerMarker>) -> anyhow::Result<()> {
    let mut peer = h
        .peers
        .find_by_id(peer_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("peer vanished"))?;
    let iface = h
        .interfaces
        .find_by_id(peer.interface_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("iface vanished"))?;
    peer.enabled = false;
    h.peers.update(&peer).await?;
    let _ = h.wg.remove_peer(&iface, &peer.public_key).await;
    Ok(())
}
