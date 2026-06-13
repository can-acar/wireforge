use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use askama::Template;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use chrono::{Duration as ChronoDuration, Utc};
use futures::stream::Stream;
use serde::Serialize;
use tower_sessions::Session;
use wireforge_core::application::ports::{
    InterfaceRepository, PeerRepository, SysNetPort, TrafficRepository,
};
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::{Id, InterfaceStatus};

use crate::extractors::AuthUser;
use crate::flash::take_flash;
use crate::templates::DashboardPage;
use crate::{AppState, WebError};

/// Serializable traffic payload — rendered once into the page for the initial
/// paint and pushed over SSE thereafter. The browser updates cards + charts in
/// place; the server never re-renders HTML for live updates.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSnapshot {
    pub interfaces: Vec<IfaceTraffic>,
    pub peers: Vec<PeerTraffic>,
    pub total_tx_h: String,
    pub total_rx_h: String,
    pub has_data: bool,
    pub labels: Vec<String>,
    pub tx: Vec<u64>,
    pub rx: Vec<u64>,
    pub peer_labels: Vec<String>,
    pub peer_totals: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IfaceTraffic {
    pub name: String,
    pub status: String,
    pub tx_h: String,
    pub rx_h: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerTraffic {
    pub name: String,
    pub iface: String,
    pub tx_h: String,
    pub rx_h: String,
}

pub async fn index(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let interfaces = state.interfaces.list().await?;
    let peers = state.peers.list_all().await?;
    let up = interfaces
        .iter()
        .filter(|i| matches!(i.status, InterfaceStatus::Up))
        .count();

    // Host (system) interfaces summary — degrades to zero on a sampling error.
    let host = state.sysnet.list().unwrap_or_default();
    let host_iface_count = host.len();
    let host_iface_up = host.iter().filter(|i| i.up).count();

    let snapshot = build_traffic_snapshot(&state).await?;
    let traffic_json =
        serde_json::to_string(&snapshot).map_err(|e| WebError::Internal(format!("json: {e}")))?;

    let flash = take_flash(&session).await;
    let page = DashboardPage {
        user: &user,
        flash: flash.as_ref(),
        interface_count: interfaces.len(),
        peer_count: peers.len(),
        up_interface_count: up,
        host_iface_count,
        host_iface_up,
        traffic_json,
    };
    page.render()
        .map(Html)
        .map_err(|e| WebError::Internal(format!("render: {e}")))
}

/// Server-Sent Events stream of traffic snapshots. The browser keeps one open
/// connection and patches the dashboard in place — no polling, no re-render.
pub async fn traffic_stream(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Push cadence for the UI. Independent of the DB poller; sending the same
    // snapshot twice is cheap and keeps the client responsive.
    const TICK: Duration = Duration::from_secs(5);

    let stream = futures::stream::unfold(state, |state| async move {
        tokio::time::sleep(TICK).await;
        let event = match build_traffic_snapshot(&state).await {
            Ok(snap) => match serde_json::to_string(&snap) {
                Ok(json) => Event::default().data(json),
                Err(_) => Event::default().comment("serialize error"),
            },
            Err(_) => Event::default().comment("snapshot error"),
        };
        Some((Ok(event), state))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn build_traffic_snapshot(state: &AppState) -> Result<TrafficSnapshot, WebError> {
    let latest = state.traffic.latest_per_peer().await?;
    let peers = state.peers.list_all().await?;
    let interfaces = state.interfaces.list().await?;

    // peer_id -> (tx, rx) from the most recent snapshot.
    let by_peer: HashMap<Id<PeerMarker>, (u64, u64)> =
        latest.iter().map(|r| (r.peer_id, (r.tx, r.rx))).collect();

    // Aggregate per interface.
    let mut iface_totals: HashMap<Id<InterfaceMarker>, (u64, u64)> = HashMap::new();
    for p in &peers {
        let (tx, rx) = by_peer.get(&p.id).copied().unwrap_or((0, 0));
        let entry = iface_totals.entry(p.interface_id).or_insert((0, 0));
        entry.0 += tx;
        entry.1 += rx;
    }

    let interface_rows: Vec<IfaceTraffic> = interfaces
        .iter()
        .map(|i| {
            let (tx, rx) = iface_totals.get(&i.id).copied().unwrap_or((0, 0));
            IfaceTraffic {
                name: i.name.clone(),
                status: i.status.as_str().to_string(),
                tx_h: human_bytes(tx),
                rx_h: human_bytes(rx),
            }
        })
        .collect();

    let total_tx: u64 = iface_totals.values().map(|(t, _)| *t).sum();
    let total_rx: u64 = iface_totals.values().map(|(_, r)| *r).sum();

    let iface_name: HashMap<Id<InterfaceMarker>, String> =
        interfaces.iter().map(|i| (i.id, i.name.clone())).collect();

    // Top 5 peers by total (tx + rx), skipping peers with no traffic.
    let mut ranked: Vec<(u64, PeerTraffic)> = peers
        .iter()
        .filter_map(|p| {
            let (tx, rx) = by_peer.get(&p.id).copied().unwrap_or((0, 0));
            let total = tx + rx;
            if total == 0 {
                return None;
            }
            Some((
                total,
                PeerTraffic {
                    name: p.name.clone(),
                    iface: iface_name.get(&p.interface_id).cloned().unwrap_or_default(),
                    tx_h: human_bytes(tx),
                    rx_h: human_bytes(rx),
                },
            ))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0));
    let top: Vec<(u64, PeerTraffic)> = ranked.into_iter().take(5).collect();
    let peer_labels: Vec<String> = top.iter().map(|(_, r)| r.name.clone()).collect();
    let peer_totals: Vec<u64> = top.iter().map(|(t, _)| *t).collect();
    let peer_rows: Vec<PeerTraffic> = top.into_iter().map(|(_, r)| r).collect();

    // Time-series for the line chart (last 24h, minute buckets).
    let since = Utc::now() - ChronoDuration::hours(24);
    let series = state.traffic.series_totals(since).await?;
    let labels: Vec<String> = series
        .iter()
        .map(|(t, _, _)| t.format("%H:%M").to_string())
        .collect();
    let tx_series: Vec<u64> = series.iter().map(|(_, tx, _)| *tx).collect();
    let rx_series: Vec<u64> = series.iter().map(|(_, _, rx)| *rx).collect();

    let has_data = !by_peer.is_empty() || !series.is_empty();

    Ok(TrafficSnapshot {
        interfaces: interface_rows,
        peers: peer_rows,
        total_tx_h: human_bytes(total_tx),
        total_rx_h: human_bytes(total_rx),
        has_data,
        labels,
        tx: tx_series,
        rx: rx_series,
        peer_labels,
        peer_totals,
    })
}

/// Render a byte count as a compact human-readable string (e.g. "4.8 GiB").
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx < UNITS.len() - 1 {
        value /= 1024.0;
        idx += 1;
    }
    format!("{value:.1} {}", UNITS[idx])
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn formats_bytes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
