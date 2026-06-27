//! Wireforge REST API v1.
//!
//! Endpoints live under `/api/v1/*` and return JSON. OpenAPI schema is
//! generated at compile time via `utoipa` and served at
//! `/api/v1/openapi.json` (and `/swagger-ui` by the binary).
//!
//! Authentication: an opaque API bearer token in `Authorization: Bearer
//! <token>` (create one via `POST /api/v1/tokens`), OR a session cookie (the
//! same one used by the web UI). Read endpoints accept any authenticated role;
//! write/lifecycle endpoints require a role that may mutate state.

use axum::routing::{delete, get, post};
use axum::Router;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use wireforge_web::AppState;

pub mod auth;
pub mod v1;

pub use auth::ApiAuthUser;

/// Adds the `bearer_auth` security scheme so Swagger UI shows an "Authorize"
/// button and the spec advertises bearer-token auth.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Wireforge API",
        version = "0.1.0",
        description = "Next-generation WireGuard management platform — REST API v1",
        license(name = "MIT OR Apache-2.0")
    ),
    modifiers(&SecurityAddon),
    paths(
        v1::health::healthz,
        v1::interfaces::list,
        v1::interfaces::get_one,
        v1::interfaces::create,
        v1::interfaces::update,
        v1::interfaces::delete,
        v1::interfaces::start,
        v1::interfaces::stop,
        v1::peers::list,
        v1::peers::get_one,
        v1::peers::create,
        v1::peers::update,
        v1::peers::set_enabled,
        v1::peers::delete,
        v1::peers::config,
        v1::peers::qr,
        v1::tokens::list,
        v1::tokens::create,
        v1::tokens::revoke,
    ),
    components(schemas(
        v1::dto::InterfaceDto,
        v1::dto::CreateInterfaceRequest,
        v1::dto::UpdateInterfaceRequest,
        v1::dto::PeerDto,
        v1::dto::CreatePeerRequest,
        v1::dto::UpdatePeerRequest,
        v1::dto::SetEnabledRequest,
        v1::dto::TokenDto,
        v1::dto::CreatedTokenDto,
        v1::dto::CreateTokenRequest,
        v1::dto::HealthDto,
        v1::dto::ApiError,
    )),
    tags(
        (name = "interfaces", description = "WireGuard interfaces — CRUD + lifecycle"),
        (name = "peers", description = "WireGuard peers — CRUD, config + QR"),
        (name = "tokens", description = "API bearer tokens (personal access tokens)"),
        (name = "system", description = "Health, version and meta endpoints"),
    )
)]
pub struct ApiDoc;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(v1::health::healthz))
        .route(
            "/interfaces",
            get(v1::interfaces::list).post(v1::interfaces::create),
        )
        .route(
            "/interfaces/{id}",
            get(v1::interfaces::get_one)
                .put(v1::interfaces::update)
                .delete(v1::interfaces::delete),
        )
        .route("/interfaces/{id}/start", post(v1::interfaces::start))
        .route("/interfaces/{id}/stop", post(v1::interfaces::stop))
        .route("/peers", get(v1::peers::list).post(v1::peers::create))
        .route(
            "/peers/{id}",
            get(v1::peers::get_one)
                .put(v1::peers::update)
                .patch(v1::peers::set_enabled)
                .delete(v1::peers::delete),
        )
        .route("/peers/{id}/config", get(v1::peers::config))
        .route("/peers/{id}/qr", get(v1::peers::qr))
        .route("/tokens", get(v1::tokens::list).post(v1::tokens::create))
        .route("/tokens/{id}", delete(v1::tokens::revoke))
}
