//! Runtime-mutable settings — the in-memory shape of values that can be
//! changed without restarting the server. Boot loads TOML defaults then
//! overlays persisted overrides from the `settings` table.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSettings {
    // --- General ---
    pub locale_default: String,
    pub totp_issuer: String,

    // --- Security ---
    pub login_max_attempts: u32,
    pub login_lockout_secs: u64,
    pub session_timeout_hours: u32,

    // --- WireGuard ---
    pub endpoint: Option<String>,

    // --- Operational ---
    pub traffic_poller_interval_secs: u64,
    pub traffic_enabled: bool,
    pub backup_retention_days: u32,
    pub log_level: String,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            locale_default: "en".into(),
            totp_issuer: "Wireforge".into(),
            login_max_attempts: 5,
            login_lockout_secs: 300,
            session_timeout_hours: 12,
            endpoint: None,
            traffic_poller_interval_secs: 30,
            traffic_enabled: true,
            backup_retention_days: 30,
            log_level: "info".into(),
        }
    }
}

impl RuntimeSettings {
    /// Apply DB-persisted overrides on top of the current values. Unknown
    /// keys are ignored; parse failures fall back to the existing value.
    pub fn apply_overrides(&mut self, overrides: &HashMap<String, String>) {
        for (k, raw) in overrides {
            match k.as_str() {
                "locale_default" => self.locale_default = strip_quotes(raw),
                "totp_issuer" => self.totp_issuer = strip_quotes(raw),
                "login_max_attempts" => {
                    if let Ok(v) = raw.parse() {
                        self.login_max_attempts = v;
                    }
                }
                "login_lockout_secs" => {
                    if let Ok(v) = raw.parse() {
                        self.login_lockout_secs = v;
                    }
                }
                "session_timeout_hours" => {
                    if let Ok(v) = raw.parse() {
                        self.session_timeout_hours = v;
                    }
                }
                "endpoint" => {
                    let s = strip_quotes(raw);
                    self.endpoint = if s.is_empty() { None } else { Some(s) };
                }
                "traffic_poller_interval_secs" => {
                    if let Ok(v) = raw.parse() {
                        self.traffic_poller_interval_secs = v;
                    }
                }
                "traffic_enabled" => {
                    if let Ok(v) = raw.parse() {
                        self.traffic_enabled = v;
                    }
                }
                "backup_retention_days" => {
                    if let Ok(v) = raw.parse() {
                        self.backup_retention_days = v;
                    }
                }
                "log_level" => self.log_level = strip_quotes(raw),
                _ => {}
            }
        }
    }
}

/// DB values are JSON-encoded scalars, so quoted strings need trimming for
/// the simple `String` consumers above.
fn strip_quotes(raw: &str) -> String {
    let s = raw.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_toml_baseline() {
        let s = RuntimeSettings::default();
        assert_eq!(s.login_max_attempts, 5);
        assert_eq!(s.traffic_poller_interval_secs, 30);
        assert!(s.traffic_enabled);
        assert_eq!(s.log_level, "info");
    }

    #[test]
    fn overrides_replace_defaults() {
        let mut s = RuntimeSettings::default();
        let mut o = HashMap::new();
        o.insert("login_max_attempts".into(), "3".into());
        o.insert("traffic_enabled".into(), "false".into());
        o.insert("endpoint".into(), "\"vpn.example.com:51820\"".into());
        s.apply_overrides(&o);
        assert_eq!(s.login_max_attempts, 3);
        assert!(!s.traffic_enabled);
        assert_eq!(s.endpoint, Some("vpn.example.com:51820".into()));
    }

    #[test]
    fn invalid_values_are_ignored() {
        let mut s = RuntimeSettings::default();
        let mut o = HashMap::new();
        o.insert("login_max_attempts".into(), "not-a-number".into());
        s.apply_overrides(&o);
        assert_eq!(s.login_max_attempts, 5); // unchanged
    }
}
