//! Wireforge REST API v1.
//!
//! Endpoints live under `/api/v1/*` and return JSON. OpenAPI schema is
//! generated at compile time via `utoipa` and served at
//! `/api/v1/openapi.json` (and `/swagger-ui` by the binary).
//!
//! Authentication: bearer JWT in `Authorization: Bearer <token>` header, OR
//! a session cookie (the same one used by the web UI).

use axum::routing::get;
use axum::Router;
use utoipa::OpenApi;
use wireforge_web::AppState;

pub mod auth;
pub mod v1;

pub use auth::ApiAuthUser;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Wireforge API",
        version = "0.1.0",
        description = "Next-generation WireGuard management platform — REST API v1",
        license(name = "MIT OR Apache-2.0")
    ),
    paths(
        v1::interfaces::list,
        v1::interfaces::get_one,
        v1::peers::list,
        v1::peers::get_one,
        v1::health::healthz,
    ),
    components(schemas(
        v1::dto::InterfaceDto,
        v1::dto::PeerDto,
        v1::dto::HealthDto,
        v1::dto::ApiError,
    )),
    tags(
        (name = "interfaces", description = "WireGuard interfaces"),
        (name = "peers", description = "WireGuard peers"),
        (name = "system", description = "Health, version and meta endpoints"),
    )
)]
pub struct ApiDoc;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(v1::health::healthz))
        .route("/interfaces", get(v1::interfaces::list))
        .route("/interfaces/{id}", get(v1::interfaces::get_one))
        .route("/peers", get(v1::peers::list))
        .route("/peers/{id}", get(v1::peers::get_one))
}
