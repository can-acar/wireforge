use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{Duration, Utc};
use validator::Validate;
use wireforge_core::application::ports::ApiTokenRepository;
use wireforge_core::crypto::generate_api_token;
use wireforge_core::domain::api_token::ApiTokenMarker;
use wireforge_core::domain::NewApiToken;
use wireforge_web::AppState;

use crate::ApiAuthUser;

use super::dto::{
    bad_request, from_core, ApiError, CreateTokenRequest, CreatedTokenDto, TokenDto,
};
use super::parse_id;

#[utoipa::path(
    get,
    path = "/api/v1/tokens",
    tag = "tokens",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Vec<TokenDto>),
        (status = 401, body = ApiError),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    user: ApiAuthUser,
) -> Result<Json<Vec<TokenDto>>, (StatusCode, Json<ApiError>)> {
    let tokens = state
        .api_tokens
        .list_for_user(user.0.id)
        .await
        .map_err(from_core)?;
    Ok(Json(tokens.into_iter().map(TokenDto::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/tokens",
    tag = "tokens",
    security(("bearer_auth" = [])),
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "The plaintext token is returned ONCE", body = CreatedTokenDto),
        (status = 400, body = ApiError),
        (status = 401, body = ApiError),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreatedTokenDto>, (StatusCode, Json<ApiError>)> {
    req.validate().map_err(|e| bad_request(e.to_string()))?;

    let expires_at = match req.expires_in_days {
        Some(days) if days > 0 => Some(Utc::now() + Duration::days(days)),
        Some(_) => return Err(bad_request("expires_in_days must be positive")),
        None => None,
    };

    let (plaintext, token_hash) = generate_api_token();
    let new = NewApiToken {
        user_id: user.0.id,
        name: req.name.trim().to_string(),
        token_hash,
        scopes: vec!["*".to_string()],
        expires_at,
    };
    let token = state.api_tokens.create(new).await.map_err(from_core)?;
    Ok(Json(CreatedTokenDto {
        token: plaintext,
        info: TokenDto::from(token),
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/tokens/{id}",
    tag = "tokens",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "API token UUID")),
    responses(
        (status = 204),
        (status = 401, body = ApiError),
        (status = 404, body = ApiError),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    user: ApiAuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let id = parse_id::<ApiTokenMarker>(&id)?;
    state
        .api_tokens
        .revoke(id, user.0.id)
        .await
        .map_err(from_core)?;
    Ok(StatusCode::NO_CONTENT)
}
