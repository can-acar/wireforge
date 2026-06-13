use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::WebhookRepository;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::webhook::WebhookMarker;
use wireforge_core::domain::{Id, NewWebhook, Webhook};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqliteWebhookRepository {
    pool: SqlitePool,
}

impl SqliteWebhookRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WebhookRepository for SqliteWebhookRepository {
    async fn list_enabled(&self) -> CoreResult<Vec<Webhook>> {
        let rows: Vec<WebhookRow> =
            sqlx::query_as("SELECT * FROM webhooks WHERE enabled = 1")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        rows.into_iter().map(WebhookRow::into_domain).collect()
    }

    async fn list(&self) -> CoreResult<Vec<Webhook>> {
        let rows: Vec<WebhookRow> = sqlx::query_as("SELECT * FROM webhooks ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        rows.into_iter().map(WebhookRow::into_domain).collect()
    }

    async fn create(&self, new: NewWebhook) -> CoreResult<Webhook> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let events_json = serde_json::to_string(&new.events).unwrap_or_else(|_| "[]".into());
        sqlx::query(
            r#"INSERT INTO webhooks (id, url, secret, events, enabled, created_by, created_at)
               VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)"#,
        )
        .bind(id.to_string())
        .bind(&new.url)
        .bind(&new.secret)
        .bind(events_json)
        .bind(new.created_by.map(|u| u.to_string()))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(Webhook {
            id: Id::from_uuid(id),
            url: new.url,
            secret: new.secret,
            events: new.events,
            enabled: true,
            created_by: new.created_by,
            created_at: now,
        })
    }

    async fn delete(&self, id: Id<WebhookMarker>) -> CoreResult<()> {
        sqlx::query("DELETE FROM webhooks WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: String,
    url: String,
    secret: Option<String>,
    events: String,
    enabled: i64,
    created_by: Option<String>,
    created_at: DateTime<Utc>,
}

impl WebhookRow {
    fn into_domain(self) -> CoreResult<Webhook> {
        let events: Vec<String> = serde_json::from_str(&self.events).unwrap_or_default();
        let created_by = self
            .created_by
            .map(|s| Uuid::parse_str(&s).map(Id::<UserMarker>::from_uuid))
            .transpose()
            .map_err(|e| CoreError::Persistence(format!("wh user: {e}")))?;
        Ok(Webhook {
            id: Id::from_uuid(
                Uuid::parse_str(&self.id)
                    .map_err(|e| CoreError::Persistence(format!("wh id: {e}")))?,
            ),
            url: self.url,
            secret: self.secret,
            events,
            enabled: self.enabled != 0,
            created_by,
            created_at: self.created_at,
        })
    }
}
