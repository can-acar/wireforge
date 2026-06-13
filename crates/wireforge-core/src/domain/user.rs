use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Id, Role};

/// Marker type used by `Id<User>`.
#[derive(Debug)]
pub struct UserMarker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Id<UserMarker>,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: Role,
    pub totp_enabled: bool,
    pub totp_secret_encrypted: Option<Vec<u8>>,
    pub oidc_subject: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn requires_totp(&self) -> bool {
        self.totp_enabled
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: Role,
}
