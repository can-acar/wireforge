//! Time-based access enforcement.
//!
//! Peers can carry a `schedule` field describing when they are allowed to
//! connect. Faz 5 ships a minimal cron-style enforcer: a JSON object
//! `{ "weekdays": [1,2,3,4,5], "from": "09:00", "to": "18:00", "tz": "UTC" }`.
//! If `schedule` is set and the current time falls *outside* the window, the
//! peer is auto-disabled; when it re-enters the window the peer is
//! re-enabled.

use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, NaiveTime, Timelike, Utc};
use serde::Deserialize;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};
use wireforge_core::application::ports::{InterfaceRepository, PeerRepository, WireGuardPort};
use wireforge_infra::{DefguardAdapter, SqliteInterfaceRepository, SqlitePeerRepository};

#[derive(Debug, Deserialize)]
struct Schedule {
    /// 1=Mon .. 7=Sun (ISO weekday).
    weekdays: Vec<u8>,
    /// 24h "HH:MM".
    from: String,
    to: String,
}

pub struct SchedulerHandles {
    pub interfaces: Arc<SqliteInterfaceRepository>,
    pub peers: Arc<SqlitePeerRepository>,
    pub wg: Arc<DefguardAdapter>,
}

pub fn spawn(h: SchedulerHandles) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        info!("schedule enforcer started");
        loop {
            tick.tick().await;
            if let Err(e) = run_once(&h).await {
                warn!(error = %e, "scheduler iteration failed");
            }
        }
    })
}

async fn run_once(h: &SchedulerHandles) -> anyhow::Result<()> {
    let now = Utc::now();
    let peers = h.peers.list_all().await?;
    for mut peer in peers {
        let Some(schedule_json) = peer.schedule.as_ref() else {
            continue;
        };
        let schedule: Schedule = match serde_json::from_str(schedule_json) {
            Ok(s) => s,
            Err(e) => {
                debug!(peer = %peer.id, error = %e, "invalid schedule json");
                continue;
            }
        };

        let in_window = is_in_window(&schedule, now);
        if in_window == peer.enabled {
            continue;
        }
        info!(
            peer = %peer.name,
            in_window,
            "schedule transition — toggling enabled"
        );
        peer.enabled = in_window;
        h.peers.update(&peer).await?;
        let iface = h
            .interfaces
            .find_by_id(peer.interface_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("iface vanished"))?;
        if in_window {
            let _ = h.wg.apply_peer(&iface, &peer).await;
        } else {
            let _ = h.wg.remove_peer(&iface, &peer.public_key).await;
        }
    }
    Ok(())
}

fn is_in_window(schedule: &Schedule, now: chrono::DateTime<Utc>) -> bool {
    let weekday_iso = now.weekday().number_from_monday() as u8;
    if !schedule.weekdays.contains(&weekday_iso) {
        return false;
    }
    let Ok(from) = NaiveTime::parse_from_str(&schedule.from, "%H:%M") else {
        return false;
    };
    let Ok(to) = NaiveTime::parse_from_str(&schedule.to, "%H:%M") else {
        return false;
    };
    let current = NaiveTime::from_hms_opt(now.hour(), now.minute(), 0).unwrap_or(from);
    if to >= from {
        current >= from && current <= to
    } else {
        // Wrapping window (e.g. 22:00 -> 06:00).
        current >= from || current <= to
    }
}
