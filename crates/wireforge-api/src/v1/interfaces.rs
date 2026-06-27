use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use validator::Validate;
use wireforge_core::application::ports::InterfaceRepository;
use wireforge_core::application::services::{CreateInterfaceInput, UpdateInterfaceInput};
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_web::AppState;

use crate::ApiAuthUser;

use super::dto::{
    bad_request, from_core, not_found, ApiError, CreateInterfaceRequest, InterfaceDto,
    UpdateInterfaceRequest,
};
use super::{blank_to_none, parse_cidr_opt, parse_id};

#[utoipa::path(
    get,
    path = "/api/v1/interfaces",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Vec<InterfaceDto>),
        (status = 401, body = ApiError),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    _user: ApiAuthUser,
) -> Result<Json<Vec<InterfaceDto>>, (StatusCode, Json<ApiError>)> {
    let ifaces = state.interfaces.list().await.map_err(from_core)?;
    Ok(Json(ifaces.into_iter().map(InterfaceDto::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/interfaces/{id}",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Interface UUID")),
    responses(
        (status = 200, body = InterfaceDto),
        (status = 404, body = ApiError),
    )
)]
pub async fn get_one(
    State(state): State<AppState>,
    _user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Json<InterfaceDto>, (StatusCode, Json<ApiError>)> {
    let id = parse_id::<InterfaceMarker>(&id)?;
    let iface = state
        .interfaces
        .find_by_id(id)
        .await
        .map_err(from_core)?
        .ok_or_else(not_found)?;
    Ok(Json(InterfaceDto::from(iface)))
}

#[utoipa::path(
    post,
    path = "/api/v1/interfaces",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    request_body = CreateInterfaceRequest,
    responses(
        (status = 200, body = InterfaceDto),
        (status = 400, body = ApiError),
        (status = 401, body = ApiError),
        (status = 403, body = ApiError),
        (status = 409, body = ApiError),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Json(req): Json<CreateInterfaceRequest>,
) -> Result<Json<InterfaceDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    req.validate().map_err(|e| bad_request(e.to_string()))?;

    let input = CreateInterfaceInput {
        name: req.name.trim().to_string(),
        listen_port: req.listen_port,
        endpoint: blank_to_none(req.endpoint),
        gateway: blank_to_none(req.gateway),
        ipv4_cidr: parse_cidr_opt(req.ipv4_cidr, "IPv4 CIDR")?,
        ipv6_cidr: parse_cidr_opt(req.ipv6_cidr, "IPv6 CIDR")?,
        mtu: req.mtu,
        dns: req.dns,
        on_up: blank_to_none(req.on_up),
        on_down: blank_to_none(req.on_down),
        private_key: req.private_key.unwrap_or_default(),
    };
    let iface = state
        .interface_service()
        .create(input)
        .await
        .map_err(from_core)?;
    Ok(Json(InterfaceDto::from(iface)))
}

#[utoipa::path(
    put,
    path = "/api/v1/interfaces/{id}",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Interface UUID")),
    request_body = UpdateInterfaceRequest,
    responses(
        (status = 200, body = InterfaceDto),
        (status = 400, body = ApiError),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateInterfaceRequest>,
) -> Result<Json<InterfaceDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    req.validate().map_err(|e| bad_request(e.to_string()))?;
    let id = parse_id::<InterfaceMarker>(&id)?;

    let input = UpdateInterfaceInput {
        listen_port: req.listen_port,
        endpoint: blank_to_none(req.endpoint),
        gateway: blank_to_none(req.gateway),
        ipv4_cidr: parse_cidr_opt(req.ipv4_cidr, "IPv4 CIDR")?,
        ipv6_cidr: parse_cidr_opt(req.ipv6_cidr, "IPv6 CIDR")?,
        mtu: req.mtu,
        dns: req.dns,
        on_up: blank_to_none(req.on_up),
        on_down: blank_to_none(req.on_down),
        private_key: req.private_key.unwrap_or_default(),
    };
    let iface = state
        .interface_service()
        .update(id, input)
        .await
        .map_err(from_core)?;
    Ok(Json(InterfaceDto::from(iface)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/interfaces/{id}",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Interface UUID")),
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
    let id = parse_id::<InterfaceMarker>(&id)?;
    state
        .interface_service()
        .delete(id)
        .await
        .map_err(from_core)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/interfaces/{id}/start",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Interface UUID")),
    responses(
        (status = 200, body = InterfaceDto),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn start(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Json<InterfaceDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    let id = parse_id::<InterfaceMarker>(&id)?;
    let iface = state.interface_service().start(id).await.map_err(from_core)?;
    Ok(Json(InterfaceDto::from(iface)))
}

#[utoipa::path(
    post,
    path = "/api/v1/interfaces/{id}/stop",
    tag = "interfaces",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Interface UUID")),
    responses(
        (status = 200, body = InterfaceDto),
        (status = 403, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn stop(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<Json<InterfaceDto>, (StatusCode, Json<ApiError>)> {
    user.require_mutate()?;
    let id = parse_id::<InterfaceMarker>(&id)?;
    let iface = state.interface_service().stop(id).await.map_err(from_core)?;
    Ok(Json(InterfaceDto::from(iface)))
}
