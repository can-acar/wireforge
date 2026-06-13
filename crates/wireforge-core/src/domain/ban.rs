use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Login-attempt accounting per IP. The repository stores both the rolling
/// attempt count and the timestamp until which the IP is locked out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBan {
    pub ip: String,
    pub banned_until: DateTime<Utc>,
    pub attempt_count: i64,
    pub updated_at: DateTime<Utc>,
}

impl IpBan {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.banned_until > now
    }
}
