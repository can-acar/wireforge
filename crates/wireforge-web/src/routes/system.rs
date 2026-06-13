//! Host (system) network interfaces page.
//!
//! Read-only view of the OS network stack (`lo`, `eth0`, `docker0`, …). Mirrors
//! the dashboard's live pattern: the initial state is embedded as JSON for the
//! first paint, then patched in place over SSE — the browser renders the cards,
//! the server never re-renders HTML for live updates.

use std::convert::Infallible;
use std::time::Duration;

use askama::Template;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use futures::stream::Stream;
use serde::Serialize;
use tower_sessions::Session;
use wireforge_core::application::ports::SysNetPort;
use wireforge_core::domain::SysInterface;

use crate::extractors::AuthUser;
use crate::flash::take_flash;
use crate::templates::SystemPage;
use crate::{AppState, WebError};

/// Serializable payload rendered into the page and pushed over SSE.
#[derive(Debug, Clone, Serialize)]
pub struct SystemSnapshot {
    pub interfaces: Vec<SysInterface>,
}

/// Sample the host interfaces. A `getifaddrs` failure degrades to an empty
/// list rather than erroring the whole page.
fn snapshot(state: &AppState) -> SystemSnapshot {
    let interfaces = state.sysnet.list().unwrap_or_default();
    SystemSnapshot { interfaces }
}

pub async fn index(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    let sysnet_json = serde_json::to_string(&snapshot(&state))
        .map_err(|e| WebError::Internal(format!("json: {e}")))?;

    let flash = take_flash(&session).await;
    let page = SystemPage {
        user: &user,
        flash: flash.as_ref(),
        sysnet_json,
    };
    page.render()
        .map(Html)
        .map_err(|e| WebError::Internal(format!("render: {e}")))
}

/// Server-Sent Events stream of host-interface snapshots. The browser keeps one
/// connection open and re-renders the cards in place — `docker0` going up/down
/// is reflected within one tick.
pub async fn stream(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    const TICK: Duration = Duration::from_secs(5);

    let stream = futures::stream::unfold(state, |state| async move {
        tokio::time::sleep(TICK).await;
        let event = match serde_json::to_string(&snapshot(&state)) {
            Ok(json) => Event::default().data(json),
            Err(_) => Event::default().comment("serialize error"),
        };
        Some((Ok(event), state))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
