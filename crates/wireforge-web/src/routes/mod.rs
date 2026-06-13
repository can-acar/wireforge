use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::AppState;

pub mod audit;
pub mod auth;
pub mod dashboard;
pub mod health;
pub mod interfaces;
pub mod metrics;
pub mod peers;
pub mod profile;
pub mod settings;
pub mod system;
pub mod ws;

/// Build the session layer separately so the binary can wrap it around the
/// fully-composed router (web + API + Swagger), guaranteeing that session
/// state reaches *every* nested route — not just the web-layer ones.
pub fn build_session_layer(
    state: &AppState,
    session_store: MemoryStore,
) -> SessionManagerLayer<MemoryStore> {
    let secure = state.config.session_secure;
    SessionManagerLayer::new(session_store)
        .with_name("wireforge.sid")
        .with_secure(secure)
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(time::Duration::hours(12)))
}

/// Build the web router (no session layer here — applied at the outer level).
pub fn router(state: AppState) -> Router {
    Router::new()
        // Public
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/login/totp", post(auth::totp_submit))
        .route("/logout", post(auth::logout))
        .route("/setup", get(auth::setup_page).post(auth::setup_submit))
        // Authenticated — dashboard
        .route("/", get(dashboard::index))
        .route("/dashboard/traffic/stream", get(dashboard::traffic_stream))
        // Interfaces
        .route("/interfaces", get(interfaces::list))
        .route(
            "/interfaces/new",
            get(interfaces::new_page).post(interfaces::create),
        )
        .route(
            "/interfaces/{id}/edit",
            get(interfaces::edit_page).post(interfaces::edit),
        )
        .route("/interfaces/{id}/start", post(interfaces::start))
        .route("/interfaces/{id}/stop", post(interfaces::stop))
        .route("/interfaces/{id}/delete", post(interfaces::delete))
        // System (host) network interfaces — read-only, live over SSE
        .route("/system", get(system::index))
        .route("/system/interfaces/stream", get(system::stream))
        // Peers
        .route("/peers", get(peers::list))
        .route("/peers/new", get(peers::new_page).post(peers::create))
        .route(
            "/peers/{id}/edit",
            get(peers::edit_page).post(peers::edit),
        )
        .route("/peers/{id}/toggle", post(peers::toggle))
        .route("/peers/{id}/delete", post(peers::delete))
        .route("/peers/{id}/download", get(peers::download))
        .route("/peers/{id}/qr", get(peers::qr))
        // Profile + 2FA
        .route("/profile", get(profile::index))
        .route(
            "/profile/2fa",
            get(profile::totp_setup_page).post(profile::totp_confirm),
        )
        .route("/profile/2fa/disable", post(profile::totp_disable))
        // Audit log
        .route("/audit", get(audit::list))
        // System settings (admin-only)
        .route("/settings", get(settings::index).post(settings::save))
        // Prometheus metrics + real-time events
        .route("/metrics", get(metrics::handler))
        .route("/ws/events", get(ws::events))
        // Static
        .nest_service("/static", ServeDir::new("crates/wireforge-web/static"))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .on_response(tower_http::trace::DefaultOnResponse::new().latency_unit(
                    tower_http::LatencyUnit::Millis,
                )),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(30),
        ))
}
