//! API-specific authentication extractor.
//!
//! `wireforge_web::extractors::AuthUser` rejects with `WebError`, which the
//! web layer turns into a 303 → /login redirect. That's correct for HTML
//! clients but wrong for API clients — they expect JSON 401. This wrapper
//! delegates to the same session lookup but returns a JSON ApiError on
//! failure.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use wireforge_web::extractors::AuthUser;

use crate::v1::dto::ApiError;

#[derive(Debug, Clone)]
pub struct ApiAuthUser(pub AuthUser);

impl std::ops::Deref for ApiAuthUser {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for ApiAuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ApiError>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        AuthUser::from_request_parts(parts, state).await.map(ApiAuthUser).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "unauthorized".into(),
                    status: 401,
                }),
            )
        })
    }
}
