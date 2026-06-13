use std::str::FromStr;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::{Id, Role};

use crate::WebError;

const SESSION_USER_KEY: &str = "auth_user";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Id<UserMarker>,
    pub username: String,
    pub role: Role,
}

impl AuthUser {
    pub async fn store(&self, session: &Session) -> Result<(), WebError> {
        session
            .insert(SESSION_USER_KEY, self)
            .await
            .map_err(|e| WebError::Internal(format!("session insert: {e}")))?;
        Ok(())
    }

    pub async fn clear(session: &Session) -> Result<(), WebError> {
        session
            .remove::<AuthUser>(SESSION_USER_KEY)
            .await
            .map_err(|e| WebError::Internal(format!("session remove: {e}")))?;
        Ok(())
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| WebError::Unauthorized)?;
        session
            .get::<AuthUser>(SESSION_USER_KEY)
            .await
            .map_err(|e| WebError::Internal(format!("session get: {e}")))?
            .ok_or(WebError::Unauthorized)
    }
}

/// Helper used by handlers — read the auth user if present (without rejecting).
pub async fn read_session_user(session: &Session) -> Option<AuthUser> {
    session.get::<AuthUser>(SESSION_USER_KEY).await.ok().flatten()
}

#[allow(dead_code)]
pub(crate) fn parse_id(s: &str) -> Result<Id<UserMarker>, WebError> {
    Uuid::from_str(s)
        .map(Id::from_uuid)
        .map_err(|_| WebError::NotFound)
}
