//! API authentication extractor.
//!
//! Resolves the caller from **either** an `Authorization: Bearer <token>`
//! header (an opaque personal access token) **or** the same session cookie the
//! web UI uses. Bearer is tried first so programmatic clients (curl, CI,
//! Swagger UI's "Authorize") work without a browser session.
//!
//! Unlike `wireforge_web::extractors::AuthUser` (which rejects with a 303 →
//! /login redirect), failures here return a JSON `ApiError` with the right
//! status code, as API clients expect.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use chrono::Utc;
use wireforge_core::application::ports::{ApiTokenRepository, UserRepository};
use wireforge_core::crypto::hash_api_token;
use wireforge_web::extractors::AuthUser;
use wireforge_web::AppState;

use crate::v1::dto::{forbidden, unauthorized, ApiError};

#[derive(Debug, Clone)]
pub struct ApiAuthUser(pub AuthUser);

impl std::ops::Deref for ApiAuthUser {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ApiAuthUser {
    /// Require a role that may mutate state (write/lifecycle endpoints).
    /// Returns a 403 JSON error otherwise.
    pub fn require_mutate(&self) -> Result<(), (StatusCode, Json<ApiError>)> {
        if self.0.role.can_mutate() {
            Ok(())
        } else {
            Err(forbidden("insufficient role for this operation"))
        }
    }
}

impl<S> FromRequestParts<S> for ApiAuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, Json<ApiError>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1. Bearer token path.
        if let Ok(TypedHeader(Authorization(bearer))) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state).await
        {
            let app = AppState::from_ref(state);
            let hash = hash_api_token(bearer.token());
            let token = app
                .api_tokens
                .find_active_by_hash(&hash)
                .await
                .map_err(|_| unauthorized())?
                .filter(|t| t.is_active(Utc::now()))
                .ok_or_else(unauthorized)?;
            let user = app
                .users
                .find_by_id(token.user_id)
                .await
                .map_err(|_| unauthorized())?
                .ok_or_else(unauthorized)?;
            return Ok(ApiAuthUser(AuthUser {
                id: user.id,
                username: user.username,
                role: user.role,
            }));
        }

        // 2. Session-cookie fallback (browser / Swagger UI same-origin).
        AuthUser::from_request_parts(parts, state)
            .await
            .map(ApiAuthUser)
            .map_err(|_| unauthorized())
    }
}
