use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use wireforge_core::application::ports::{PeerTrafficRow, TrafficRepository};
use wireforge_core::domain::peer::PeerMarker;
use wireforge_core::domain::Id;
use wireforge_core::CoreResult;

use super::map_err;

pub struct SqliteTrafficRepository {
    pool: SqlitePool,
}

impl SqliteTrafficRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TrafficRepository for SqliteTrafficRepository {
    async fn snapshot(
        &self,
        peer_id: Id<PeerMarker>,
        tx: u64,
        rx: u64,
        last_handshake: Option<DateTime<Utc>>,
    ) -> CoreResult<()> {
        sqlx::query(
            r#"INSERT INTO traffic_snapshots
               (peer_id, tx_bytes, rx_bytes, last_handshake_at, recorded_at)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
        )
        .bind(peer_id.to_string())
        .bind(tx as i64)
        .bind(rx as i64)
        .bind(last_handshake)
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn series_for_peer(
        &self,
        peer_id: Id<PeerMarker>,
        since: DateTime<Utc>,
    ) -> CoreResult<Vec<(DateTime<Utc>, u64, u64)>> {
        let rows: Vec<(DateTime<Utc>, i64, i64)> = sqlx::query_as(
            r#"SELECT recorded_at, tx_bytes, rx_bytes FROM traffic_snapshots
               WHERE peer_id = ?1 AND recorded_at >= ?2
               ORDER BY recorded_at ASC"#,
        )
        .bind(peer_id.to_string())
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|(t, tx, rx)| (t, tx as u64, rx as u64))
            .collect())
    }

    async fn latest_per_peer(&self) -> CoreResult<Vec<PeerTrafficRow>> {
        let rows: Vec<(String, i64, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
            r#"SELECT peer_id, tx_bytes, rx_bytes, last_handshake_at
               FROM (
                   SELECT peer_id, tx_bytes, rx_bytes, last_handshake_at,
                          ROW_NUMBER() OVER (
                              PARTITION BY peer_id ORDER BY recorded_at DESC
                          ) AS rn
                   FROM traffic_snapshots
               )
               WHERE rn = 1"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(rows
            .into_iter()
            .map(|(pid, tx, rx, hs)| PeerTrafficRow {
                peer_id: Id::<PeerMarker>::from_str(&pid).unwrap_or_default(),
                tx: tx.max(0) as u64,
                rx: rx.max(0) as u64,
                last_handshake: hs,
            })
            .collect())
    }

    async fn series_totals(
        &self,
        since: DateTime<Utc>,
    ) -> CoreResult<Vec<(DateTime<Utc>, u64, u64)>> {
        // Bucket by minute so concurrent per-peer snapshots collapse into a
        // single point on the line chart.
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            r#"SELECT strftime('%Y-%m-%dT%H:%M:00+00:00', recorded_at) AS bucket,
                      CAST(SUM(tx_bytes) AS INTEGER) AS tx,
                      CAST(SUM(rx_bytes) AS INTEGER) AS rx
               FROM traffic_snapshots
               WHERE recorded_at >= ?1
               GROUP BY bucket
               ORDER BY bucket ASC"#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(rows
            .into_iter()
            .filter_map(|(bucket, tx, rx)| {
                DateTime::parse_from_rfc3339(&bucket)
                    .ok()
                    .map(|t| (t.with_timezone(&Utc), tx.max(0) as u64, rx.max(0) as u64))
            })
            .collect())
    }
}
