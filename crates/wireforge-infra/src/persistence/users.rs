use async_trait::async_trait;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;
use wireforge_core::application::ports::UserRepository;
use wireforge_core::domain::user::UserMarker;
use wireforge_core::domain::{Id, NewUser, Role, User};
use wireforge_core::{CoreError, CoreResult};

use super::map_err;

pub struct SqliteUserRepository {
    pool: SqlitePool,
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn count(&self) -> CoreResult<u64> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(n as u64)
    }

    async fn create(&self, new: NewUser) -> CoreResult<User> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        sqlx::query(
            r#"INSERT INTO users
               (id, username, email, password_hash, role, totp_enabled, totp_secret_encrypted,
                oidc_subject, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL, ?6, ?6)"#,
        )
        .bind(id.to_string())
        .bind(&new.username)
        .bind(&new.email)
        .bind(&new.password_hash)
        .bind(new.role.as_str())
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(User {
            id: Id::from_uuid(id),
            username: new.username,
            email: new.email,
            password_hash: new.password_hash,
            role: new.role,
            totp_enabled: false,
            totp_secret_encrypted: None,
            oidc_subject: None,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        })
    }

    async fn find_by_id(&self, id: Id<UserMarker>) -> CoreResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE id = ?1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        row.map(UserRow::into_domain).transpose()
    }

    async fn find_by_username(&self, username: &str) -> CoreResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE username = ?1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        row.map(UserRow::into_domain).transpose()
    }

    async fn list(&self) -> CoreResult<Vec<User>> {
        let rows: Vec<UserRow> =
            sqlx::query_as("SELECT * FROM users ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(map_err)?;
        rows.into_iter().map(UserRow::into_domain).collect()
    }

    async fn update_password(&self, id: Id<UserMarker>, hash: &str) -> CoreResult<()> {
        sqlx::query("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(hash)
            .bind(Utc::now())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn update_role(&self, id: Id<UserMarker>, role: Role) -> CoreResult<()> {
        sqlx::query("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(role.as_str())
            .bind(Utc::now())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn update_totp(
        &self,
        id: Id<UserMarker>,
        enabled: bool,
        secret_encrypted: Option<&[u8]>,
    ) -> CoreResult<()> {
        sqlx::query(
            "UPDATE users SET totp_enabled = ?1, totp_secret_encrypted = ?2, updated_at = ?3 WHERE id = ?4",
        )
        .bind(enabled as i64)
        .bind(secret_encrypted)
        .bind(Utc::now())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn touch_last_login(&self, id: Id<UserMarker>) -> CoreResult<()> {
        sqlx::query("UPDATE users SET last_login_at = ?1 WHERE id = ?2")
            .bind(Utc::now())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete(&self, id: Id<UserMarker>) -> CoreResult<()> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    username: String,
    email: Option<String>,
    password_hash: String,
    role: String,
    totp_enabled: i64,
    totp_secret_encrypted: Option<Vec<u8>>,
    oidc_subject: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    last_login_at: Option<chrono::DateTime<Utc>>,
}

impl UserRow {
    fn into_domain(self) -> CoreResult<User> {
        Ok(User {
            id: Id::from_uuid(
                Uuid::parse_str(&self.id)
                    .map_err(|e| CoreError::Persistence(format!("user uuid: {e}")))?,
            ),
            username: self.username,
            email: self.email,
            password_hash: self.password_hash,
            role: self
                .role
                .parse()
                .map_err(|e| CoreError::Persistence(format!("role: {e}")))?,
            totp_enabled: self.totp_enabled != 0,
            totp_secret_encrypted: self.totp_secret_encrypted,
            oidc_subject: self.oidc_subject,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}
