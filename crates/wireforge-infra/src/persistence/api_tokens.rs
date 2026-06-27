use async_trait::async_trait;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::ApiTokenRepository;
use wireforge_core::domain::api_token::ApiTokenMarker;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::{ApiToken, Id, NewApiToken};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqliteApiTokenRepository {
    pool: SqlitePool,
}

impl SqliteApiTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for SqliteApiTokenRepository {
    async fn create(&self, new: NewApiToken) -> CoreResult<ApiToken> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let scopes_json = serde_json::to_string(&new.scopes).unwrap_or_else(|_| "[]".into());
        sqlx::query(
            r#"INSERT INTO api_tokens
               (id, user_id, name, token_hash, scopes, created_at, expires_at, revoked_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)"#,
        )
        .bind(id.to_string())
        .bind(new.user_id.to_string())
        .bind(&new.name)
        .bind(&new.token_hash)
        .bind(&scopes_json)
        .bind(now)
        .bind(new.expires_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(ApiToken {
            id: Id::from_uuid(id),
            user_id: new.user_id,
            name: new.name,
            token_hash: new.token_hash,
            scopes: new.scopes,
            created_at: now,
            expires_at: new.expires_at,
            revoked_at: None,
        })
    }

    async fn find_active_by_hash(&self, token_hash: &str) -> CoreResult<Option<ApiToken>> {
        let row: Option<ApiTokenRow> = sqlx::query_as(
            "SELECT * FROM api_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(ApiTokenRow::into_domain).transpose()
    }

    async fn list_for_user(&self, user_id: Id<UserMarker>) -> CoreResult<Vec<ApiToken>> {
        let rows: Vec<ApiTokenRow> = sqlx::query_as(
            "SELECT * FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.into_iter().map(ApiTokenRow::into_domain).collect()
    }

    async fn revoke(&self, id: Id<ApiTokenMarker>, owner: Id<UserMarker>) -> CoreResult<()> {
        let res = sqlx::query(
            "UPDATE api_tokens SET revoked_at = ?1
             WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
        )
        .bind(Utc::now())
        .bind(id.to_string())
        .bind(owner.to_string())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if res.rows_affected() == 0 {
            return Err(CoreError::NotFound(format!("api token {id}")));
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ApiTokenRow {
    id: String,
    user_id: String,
    name: String,
    token_hash: String,
    scopes: Option<String>,
    created_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
}

impl ApiTokenRow {
    fn into_domain(self) -> CoreResult<ApiToken> {
        let scopes: Vec<String> = self
            .scopes
            .as_deref()
            .map(|s| serde_json::from_str(s).unwrap_or_default())
            .unwrap_or_default();
        Ok(ApiToken {
            id: Id::from_uuid(
                Uuid::parse_str(&self.id)
                    .map_err(|e| CoreError::Persistence(format!("api token uuid: {e}")))?,
            ),
            user_id: Id::from_uuid(
                Uuid::parse_str(&self.user_id)
                    .map_err(|e| CoreError::Persistence(format!("api token user uuid: {e}")))?,
            ),
            name: self.name,
            token_hash: self.token_hash,
            scopes,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        })
    }
}
