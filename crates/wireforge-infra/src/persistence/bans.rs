use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use wireforge_core::application::ports::BanRepository;
use wireforge_core::domain::IpBan;
use wireforge_core::CoreResult;

use super::map_err;

pub struct SqliteBanRepository {
    pool: SqlitePool,
}

impl SqliteBanRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BanRepository for SqliteBanRepository {
    async fn find(&self, ip: &str) -> CoreResult<Option<IpBan>> {
        let row: Option<BanRow> = sqlx::query_as("SELECT * FROM ip_bans WHERE ip = ?1")
            .bind(ip)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(row.map(BanRow::into_domain))
    }

    /// Atomically increment the attempt counter for `ip`; if it reaches
    /// `max_attempts`, set `banned_until = now + lockout` and reset the count
    /// so the next round of attempts after the lockout window starts fresh.
    async fn record_failure(
        &self,
        ip: &str,
        max_attempts: u32,
        lockout: Duration,
    ) -> CoreResult<IpBan> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await.map_err(map_err)?;

        let existing: Option<BanRow> = sqlx::query_as("SELECT * FROM ip_bans WHERE ip = ?1")
            .bind(ip)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;

        let (attempt_count, banned_until) = match existing.as_ref() {
            Some(b) if b.banned_until > now => {
                // Already banned — keep extending if attempts pile on.
                (b.attempt_count + 1, b.banned_until)
            }
            Some(b) => {
                let new_count = b.attempt_count + 1;
                if new_count as u32 >= max_attempts {
                    (
                        0,
                        now + chrono::Duration::from_std(lockout)
                            .unwrap_or(chrono::Duration::seconds(60)),
                    )
                } else {
                    (new_count, b.banned_until)
                }
            }
            None => (1, now),
        };

        sqlx::query(
            r#"INSERT INTO ip_bans (ip, banned_until, attempt_count, updated_at)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(ip) DO UPDATE SET
                   banned_until = excluded.banned_until,
                   attempt_count = excluded.attempt_count,
                   updated_at = excluded.updated_at"#,
        )
        .bind(ip)
        .bind(banned_until)
        .bind(attempt_count)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

        tx.commit().await.map_err(map_err)?;
        Ok(IpBan {
            ip: ip.to_string(),
            banned_until,
            attempt_count,
            updated_at: now,
        })
    }

    async fn clear(&self, ip: &str) -> CoreResult<()> {
        sqlx::query("DELETE FROM ip_bans WHERE ip = ?1")
            .bind(ip)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct BanRow {
    ip: String,
    banned_until: DateTime<Utc>,
    attempt_count: i64,
    updated_at: DateTime<Utc>,
}

impl BanRow {
    fn into_domain(self) -> IpBan {
        IpBan {
            ip: self.ip,
            banned_until: self.banned_until,
            attempt_count: self.attempt_count,
            updated_at: self.updated_at,
        }
    }
}
