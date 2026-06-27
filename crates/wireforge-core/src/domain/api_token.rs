//! API bearer tokens (personal access tokens) for programmatic clients.
//!
//! The plaintext token is shown to the user exactly once at creation; only a
//! deterministic SHA-256 hash is persisted (see [`crate::crypto::api_token`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserMarker;
use super::Id;

#[derive(Debug)]
pub struct ApiTokenMarker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Id<ApiTokenMarker>,
    pub user_id: Id<UserMarker>,
    pub name: String,
    /// SHA-256 (hex) of the plaintext token. Never reversible; used for lookup.
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    /// Active = not revoked and (no expiry, or expiry still in the future).
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.map(|e| e > now).unwrap_or(true)
    }
}

#[derive(Debug, Clone)]
pub struct NewApiToken {
    pub user_id: Id<UserMarker>,
    pub name: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}
