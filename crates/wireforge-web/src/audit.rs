//! Thin helper to emit audit events from web handlers without each call
//! having to import the repository trait + handle errors.

use serde_json::Value;
use tracing::warn;
use wireforge_core::application::ports::AuditRepository;
use wireforge_core::domain::audit::AuditAction;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::Id;

use crate::AppState;

/// Fire-and-forget audit emission. Failures are logged but not propagated —
/// missing an audit entry should never break the user-visible flow.
pub async fn record(
    state: &AppState,
    actor_user_id: Option<Id<UserMarker>>,
    actor_ip: Option<&str>,
    action: AuditAction,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    metadata: Option<Value>,
) {
    if let Err(e) = state
        .audit
        .record(
            actor_user_id,
            actor_ip,
            action,
            resource_type,
            resource_id,
            metadata,
        )
        .await
    {
        warn!(error = %e, action = action.as_str(), "audit record failed");
    }
}
