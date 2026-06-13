use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::AppState;

/// Liveness probe: cheap, no DB touch.
pub async fn healthz() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

/// Readiness probe: confirms DB is reachable.
pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    use wireforge_core::application::ports::UserRepository;
    match state.users.count().await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ready"})),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded", "error": e.to_string()})),
        ),
    }
}
