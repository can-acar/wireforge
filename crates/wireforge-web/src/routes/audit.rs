use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use tower_sessions::Session;
use wireforge_core::application::ports::AuditRepository;

use crate::extractors::AuthUser;
use crate::flash::take_flash;
use crate::templates::{AuditPage, AuditRow};
use crate::{AppState, WebError};

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    session: Session,
) -> Result<impl IntoResponse, WebError> {
    if !user.role.can_read_audit() {
        return Err(WebError::Forbidden);
    }
    let events = state.audit.list(200).await?;
    let rows: Vec<AuditRow> = events
        .into_iter()
        .map(|e| AuditRow {
            created_at: e.created_at.to_rfc3339(),
            actor: e
                .actor_user_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "—".into()),
            actor_ip: e.actor_ip.unwrap_or_default(),
            action: e.action.as_str().to_string(),
            resource: match (e.resource_type, e.resource_id) {
                (Some(t), Some(i)) => format!("{t}:{i}"),
                _ => "—".into(),
            },
            metadata: e
                .metadata
                .map(|m| serde_json::to_string(&m).unwrap_or_default())
                .unwrap_or_default(),
        })
        .collect();
    let flash = take_flash(&session).await;
    let page = AuditPage {
        user: &user,
        flash: flash.as_ref(),
        events: rows,
    };
    Ok(Html(
        page.render()
            .unwrap_or_else(|e| format!("render error: {e}")),
    ))
}
