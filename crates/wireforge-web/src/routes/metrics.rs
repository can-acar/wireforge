use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use wireforge_core::application::ports::{InterfaceRepository, PeerRepository};
use wireforge_core::domain::InterfaceStatus;

use crate::{AppState, WebError};

/// Prometheus text-format `/metrics` endpoint.
///
/// We hand-roll the format rather than holding a global Prometheus registry —
/// this keeps the metrics surface tied to current DB state and avoids drift.
pub async fn handler(State(state): State<AppState>) -> Result<Response, WebError> {
    let interfaces = state.interfaces.list().await?;
    let peers = state.peers.list_all().await?;

    let iface_total = interfaces.len();
    let iface_up = interfaces
        .iter()
        .filter(|i| matches!(i.status, InterfaceStatus::Up))
        .count();
    let peer_total = peers.len();
    let peer_enabled = peers.iter().filter(|p| p.enabled).count();
    let bandwidth_total: u64 = peers.iter().map(|p| p.bandwidth_used_bytes).sum();

    let mut body = String::with_capacity(1024);
    body.push_str("# HELP wireforge_build_info Wireforge build information.\n");
    body.push_str("# TYPE wireforge_build_info gauge\n");
    body.push_str(&format!(
        "wireforge_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    body.push_str("# HELP wireforge_interfaces_total Number of configured WireGuard interfaces.\n");
    body.push_str("# TYPE wireforge_interfaces_total gauge\n");
    body.push_str(&format!("wireforge_interfaces_total {iface_total}\n"));

    body.push_str("# HELP wireforge_interfaces_up Number of interfaces currently up.\n");
    body.push_str("# TYPE wireforge_interfaces_up gauge\n");
    body.push_str(&format!("wireforge_interfaces_up {iface_up}\n"));

    body.push_str("# HELP wireforge_peers_total Number of configured peers.\n");
    body.push_str("# TYPE wireforge_peers_total gauge\n");
    body.push_str(&format!("wireforge_peers_total {peer_total}\n"));

    body.push_str("# HELP wireforge_peers_enabled Peers with enabled=true.\n");
    body.push_str("# TYPE wireforge_peers_enabled gauge\n");
    body.push_str(&format!("wireforge_peers_enabled {peer_enabled}\n"));

    body.push_str("# HELP wireforge_bandwidth_used_bytes_total Lifetime bandwidth consumed across all peers.\n");
    body.push_str("# TYPE wireforge_bandwidth_used_bytes_total counter\n");
    body.push_str(&format!(
        "wireforge_bandwidth_used_bytes_total {bandwidth_total}\n"
    ));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok((StatusCode::OK, headers, body).into_response())
}
