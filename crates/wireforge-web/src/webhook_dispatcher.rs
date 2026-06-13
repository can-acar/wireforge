//! Async webhook dispatcher.
//!
//! Loads enabled webhooks from the DB, filters by event type, signs the
//! payload with HMAC-SHA256 (if a secret is configured) and POSTs.
//! Best-effort: failures are logged but never break the originating request.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use tracing::warn;
use wireforge_core::application::ports::WebhookRepository;
use wireforge_infra::SqliteWebhookRepository;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    event: &'a str,
    ts: String,
    data: &'a T,
}

/// Spawn a background task that fires the given event to all matching
/// webhooks. Returns immediately.
pub fn fire_and_forget<T: Serialize + Send + Sync + 'static>(
    repo: Arc<SqliteWebhookRepository>,
    event: &'static str,
    payload: T,
) {
    tokio::spawn(async move {
        let hooks = match repo.list_enabled().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "webhook list failed");
                return;
            }
        };
        if hooks.is_empty() {
            return;
        }
        let body = match serde_json::to_vec(&Envelope {
            event,
            ts: chrono::Utc::now().to_rfc3339(),
            data: &payload,
        }) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "webhook payload serialize failed");
                return;
            }
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        for hook in hooks {
            if !hook.events.iter().any(|e| e == event || e == "*") {
                continue;
            }
            let mut req = client.post(&hook.url);
            req = req.header("content-type", "application/json");
            req = req.header("x-wireforge-event", event);
            if let Some(secret) = &hook.secret {
                if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                    mac.update(&body);
                    let sig = mac.finalize().into_bytes();
                    let hex = sig.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    req = req.header("x-wireforge-signature", format!("sha256={hex}"));
                }
            }
            match req.body(body.clone()).send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => warn!(url = %hook.url, status = %resp.status(), "webhook non-2xx"),
                Err(e) => warn!(url = %hook.url, error = %e, "webhook POST failed"),
            }
        }
    });
}
