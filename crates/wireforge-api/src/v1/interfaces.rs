use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;
use wireforge_core::application::ports::InterfaceRepository;
use wireforge_core::domain::interface::InterfaceMarker;
use wireforge_core::domain::Id;
use wireforge_web::AppState;

use crate::ApiAuthUser;

use super::dto::{ApiError, InterfaceDto};

#[utoipa::path(
    get,
    path = "/api/v1/interfaces",
    tag = "interfaces",
    responses(
        (status = 200, body = Vec<InterfaceDto>),
        (status = 401, body = ApiError),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    _user: ApiAuthUser,
) -> Result<Json<Vec<InterfaceDto>>, (StatusCode, Json<ApiError>)> {
    let ifaces = state
        .interfaces
        .list()
        .await
        .map_err(internal)?;
    Ok(Json(ifaces.into_iter().map(InterfaceDto::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/interfaces/{id}",
    tag = "interfaces",
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
    let id = Uuid::parse_str(&id)
        .map(Id::<InterfaceMarker>::from_uuid)
        .map_err(|_| not_found())?;
    let iface = state
        .interfaces
        .find_by_id(id)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    Ok(Json(InterfaceDto::from(iface)))
}

fn not_found() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            error: "not found".into(),
            status: 404,
        }),
    )
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: e.to_string(),
            status: 500,
        }),
    )
}
