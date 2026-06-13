//! WebSocket endpoint for real-time peer status events.
//!
//! Faz 4 ships a minimal heartbeat + on-demand snapshot. A background poller
//! task in `wireforge-bin` periodically reads `wg show` style stats via
//! `WireGuardPort::peer_stats` and broadcasts deltas; we keep the channel
//! plumbing in `AppState::events` (added later) — for now the endpoint pushes
//! a periodic ping so frontend code can wire reconnect/UI without waiting on
//! the poller.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio::time::interval;

use crate::extractors::AuthUser;
use crate::AppState;

pub async fn events(
    State(_state): State<AppState>,
    _user: AuthUser,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    let mut tick = interval(Duration::from_secs(15));
    // Drop the first immediate tick.
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Heartbeat ping. Real event broadcasting wires in once the
                // background traffic poller (Faz 5) lands.
                let payload = serde_json::json!({
                    "type": "heartbeat",
                    "ts": chrono::Utc::now().to_rfc3339(),
                });
                if socket.send(Message::Text(payload.to_string().into())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
