use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;
use wireforge_core::application::ports::PeerRepository;
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::Id;
use wireforge_web::AppState;

use crate::ApiAuthUser;

use super::dto::{ApiError, PeerDto};

#[utoipa::path(
    get,
    path = "/api/v1/peers",
    tag = "peers",
    responses(
        (status = 200, body = Vec<PeerDto>),
        (status = 401, body = ApiError),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    _user: ApiAuthUser,
) -> Result<Json<Vec<PeerDto>>, (StatusCode, Json<ApiError>)> {
    let peers = state.peers.list_all().await.map_err(internal)?;
    Ok(Json(peers.into_iter().map(PeerDto::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/peers/{id}",
    tag = "peers",
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
    let id = Uuid::parse_str(&id)
        .map(Id::<PeerMarker>::from_uuid)
        .map_err(|_| not_found())?;
    let peer = state
        .peers
        .find_by_id(id)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    Ok(Json(PeerDto::from(peer)))
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
