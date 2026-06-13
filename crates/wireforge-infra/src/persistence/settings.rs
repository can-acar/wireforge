use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::SqlitePool;
use wireforge_core::application::ports::SettingsRepository;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::Id;
use wireforge_core::CoreResult;

use super::map_err;

pub struct SqliteSettingsRepository {
    pool: SqlitePool,
}

impl SqliteSettingsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SettingsRepository for SqliteSettingsRepository {
    async fn all(&self) -> CoreResult<HashMap<String, String>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        Ok(rows.into_iter().collect())
    }

    async fn upsert(
        &self,
        key: &str,
        value: &str,
        actor: Option<Id<UserMarker>>,
    ) -> CoreResult<()> {
        let now = Utc::now();
        let actor_str = actor.map(|i| i.to_string());
        sqlx::query(
            r#"INSERT INTO settings (key, value, updated_by, updated_at, created_at)
               VALUES (?1, ?2, ?3, ?4, ?4)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_by = excluded.updated_by,
                   updated_at = excluded.updated_at"#,
        )
        .bind(key)
        .bind(value)
        .bind(actor_str)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}
