use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use qrcode::render::svg;
use qrcode::QrCode;
use validator::Validate;
use wireforge_core::application::ports::{InterfaceRepository, PeerRepository};
use wireforge_core::application::services::{CreatePeerInput, UpdatePeerInput};
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::peer_conf::render_peer_conf;
use wireforge_web::AppState;

use crate::ApiAuthUser;

use super::dto::{
    bad_request, from_core, not_found, ApiError, CreatePeerRequest, PeerDto, SetEnabledRequest,
    UpdatePeerRequest,
};
use super::{parse_cidrs, parse_id};

const FALLBACK_ENDPOINT: &str = "vpn.example.com";

#[utoipa::path(
    get,
    path = "/api/v1/peers",
    tag = "peers",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Vec<PeerDto>),
        (status = 401, body = ApiError),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    _user: ApiAuthUser,
) -> Result<Json<Vec<PeerDto>>, (StatusCode, Json<ApiError>)> {
    let peers = state.peers.list_all().await.map_err(from_core)?;
    Ok(Json(peers.into_iter().map(PeerDto::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/peers/{id}",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    responses(
        (status = 200, body = PeerDto),
        (status = 404, body = ApiError),
    )
)]
pub async fn get_one(
    State(state): State<AppState>,
    _user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Json<PeerDto>, (StatusCode, Json<ApiError>)> {
    let id = parse_id::<PeerMarker>(&id)?;
    let peer = state
        .peers
        .find_by_id(id)
        .await
        .map_err(from_core)?
        .ok_or_else(not_found)?;
    Ok(Json(PeerDto::from(peer)))
}

#[utoipa::path(
    post,
    path = "/api/v1/peers",
    tag = "peers",
    security(("bearer_auth" = [])),
    request_body = CreatePeerRequest,
    responses(
        (status = 200, body = PeerDto),
        (status = 400, body = ApiError),
        (status = 403, body = ApiError),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Json(req): Json<CreatePeerRequest>,
) -> Result<Json<PeerDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    req.validate().map_err(|e| bad_request(e.to_string()))?;

    let interface_id = parse_id::<InterfaceMarker>(&req.interface_id)?;
    let allowed_ips = match req.allowed_ips {
        Some(items) => Some(parse_cidrs(items, "allowed IP")?),
        None => None,
    };

    let input = CreatePeerInput {
        interface_id,
        name: req.name.trim().to_string(),
        allowed_ips,
        primary_dns: req.primary_dns,
        secondary_dns: req.secondary_dns,
        nat: req.nat,
        persistent_keepalive: req.persistent_keepalive,
        owner_user_id: None,
        public_key: req.public_key,
        private_key: req.private_key,
    };
    let peer = state
        .peer_service()
        .create_with_server_keypair(input)
        .await
        .map_err(from_core)?;
    Ok(Json(PeerDto::from(peer)))
}

#[utoipa::path(
    put,
    path = "/api/v1/peers/{id}",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    request_body = UpdatePeerRequest,
    responses(
        (status = 200, body = PeerDto),
        (status = 400, body = ApiError),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdatePeerRequest>,
) -> Result<Json<PeerDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    req.validate().map_err(|e| bad_request(e.to_string()))?;
    let id = parse_id::<PeerMarker>(&id)?;
    let interface_id = parse_id::<InterfaceMarker>(&req.interface_id)?;

    let input = UpdatePeerInput {
        name: req.name.trim().to_string(),
        interface_id,
        allowed_ips: parse_cidrs(req.allowed_ips, "allowed IP")?,
        primary_dns: req.primary_dns,
        secondary_dns: req.secondary_dns,
        nat: req.nat,
        persistent_keepalive: req.persistent_keepalive,
        enabled: req.enabled,
        public_key: req.public_key,
        private_key: req.private_key,
    };
    let peer = state
        .peer_service()
        .update(id, input)
        .await
        .map_err(from_core)?;
    Ok(Json(PeerDto::from(peer)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/peers/{id}",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    request_body = SetEnabledRequest,
    responses(
        (status = 200, body = PeerDto),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn set_enabled(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> Result<Json<PeerDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    let id = parse_id::<PeerMarker>(&id)?;
    let peer = state
        .peer_service()
        .set_enabled(id, req.enabled)
        .await
        .map_err(from_core)?;
    Ok(Json(PeerDto::from(peer)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/peers/{id}",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    responses(
        (status = 204),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    let id = parse_id::<PeerMarker>(&id)?;
    state.peer_service().delete(id).await.map_err(from_core)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/peers/{id}/config",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    responses(
        (status = 200, description = "WireGuard .conf for the peer", content_type = "text/plain", body = String),
        (status = 404, body = ApiError),
    )
)]
pub async fn config(
    State(state): State<AppState>,
    _user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let conf = peer_conf(&state, &id).await?;
    Ok((
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"))],
        conf,
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/peers/{id}/qr",
    tag = "peers",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Peer UUID")),
    responses(
        (status = 200, description = "QR code (SVG) of the peer config", content_type = "image/svg+xml", body = String),
        (status = 404, body = ApiError),
    )
)]
pub async fn qr(
    State(state): State<AppState>,
    _user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let conf = peer_conf(&state, &id).await?;
    let code = QrCode::new(conf.as_bytes())
        .map_err(|e| bad_request(format!("qr encode: {e}")))?;
    let svg_str = code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .build();
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        svg_str,
    )
        .into_response())
}

/// Shared helper: render the peer's WireGuard config text.
async fn peer_conf(state: &AppState, id: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let id = parse_id::<PeerMarker>(id)?;
    let peer = state
        .peers
        .find_by_id(id)
        .await
        .map_err(from_core)?
        .ok_or_else(not_found)?;
    let iface = state
        .interfaces
        .find_by_id(peer.interface_id)
        .await
        .map_err(from_core)?
        .ok_or_else(not_found)?;
    let endpoint = state
        .settings_snapshot()
        .endpoint
        .unwrap_or_else(|| FALLBACK_ENDPOINT.to_string());
    render_peer_conf(&iface, &peer, &endpoint, &state.seal_key).map_err(from_core)
}
