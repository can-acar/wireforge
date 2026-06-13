use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserMarker;
use super::Id;

#[derive(Debug)]
pub struct WebhookMarker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Id<WebhookMarker>,
    pub url: String,
    /// HMAC signing secret. Sent as `X-Wireforge-Signature: sha256=<hex>`.
    pub secret: Option<String>,
    /// JSON array of subscribed event types (e.g. ["peer.created","peer.deleted"]).
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_by: Option<Id<UserMarker>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewWebhook {
    pub url: String,
    pub secret: Option<String>,
    pub events: Vec<String>,
    pub created_by: Option<Id<UserMarker>>,
}
