//! NAT/masquerade adapter backed by `iptables`/`ip6tables`.
//!
//! When a WireGuard interface comes up it installs FORWARD + POSTROUTING
//! MASQUERADE rules so peer traffic egresses via a chosen host gateway, enables
//! IP forwarding (turnkey, remembering the prior value), and runs the
//! interface's `on_up`/`on_down` hook commands.
//!
//! All process execution uses **explicit argv** — never `shell=true`. Blocking
//! syscalls run on a Tokio blocking worker, mirroring the WireGuard adapter.
//!
//! On non-Linux hosts (macOS dev) and under dry-run every operation is a logged
//! no-op so `start`/`stop` keep working without a real firewall.

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::task;
use tracing::{debug, info, instrument, warn};
use wireforge_core::application::ports::NatPort;
use wireforge_core::domain::Interface;
use wireforge_core::{CoreError, CoreResult};

const V4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const V6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// Snapshot of IP-forwarding state captured when we enabled it, so `remove`
/// restores the prior value only if we were the ones who turned it on.
#[derive(Clone, Copy)]
struct ForwardSnapshot {
    v4_was_on: bool,
    v6_was_on: bool,
}

pub struct IptablesNatAdapter {
    /// When true the adapter only logs operations without touching the OS.
    /// Enabled on non-Linux hosts implicitly, or via `WIREFORGE_WG_DRY_RUN=1`.
    dry_run: bool,
    /// Per-interface forwarding snapshot, keyed by interface name. Lets
    /// `remove` restore `ip_forward` to its pre-`apply` value.
    forward_state: Arc<Mutex<HashMap<String, ForwardSnapshot>>>,
}

impl IptablesNatAdapter {
    pub fn new() -> Self {
        let dry_run = std::env::var("WIREFORGE_WG_DRY_RUN")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self::with_dry_run(dry_run)
    }

    pub fn with_dry_run(dry_run: bool) -> Self {
        Self {
            dry_run,
            forward_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// True when NAT operations must be skipped: non-Linux (no iptables) or
    /// dry-run. Kept as a method so the cfg check lives in one place.
    fn skip(&self) -> bool {
        self.dry_run || !cfg!(target_os = "linux")
    }
}

impl Default for IptablesNatAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NatPort for IptablesNatAdapter {
    #[instrument(skip(self, iface), fields(iface = %iface.name, gateway))]
    async fn apply(&self, iface: &Interface, gateway: &str) -> CoreResult<()> {
        if self.skip() {
            info!("nat: skip apply (dry-run/non-linux); no masquerade installed");
            return Ok(());
        }
        let wg = iface.name.clone();
        let gw = gateway.to_string();
        let has_v6 = iface.ipv6_cidr.is_some();
        let state = self.forward_state.clone();
        task::spawn_blocking(move || {
            // 1. Enable IP forwarding (turnkey), remembering the prior values.
            let v4_was_on = read_forward(V4_FORWARD);
            if !v4_was_on {
                write_forward(V4_FORWARD, true)?;
            }
            let v6_was_on = if has_v6 {
                let was = read_forward(V6_FORWARD);
                if !was {
                    write_forward(V6_FORWARD, true)?;
                }
                was
            } else {
                true
            };
            if let Ok(mut map) = state.lock() {
                map.insert(wg.clone(), ForwardSnapshot { v4_was_on, v6_was_on });
            }

            // 2. Install the rules idempotently (`-C` probe before `-I`).
            let rules = nat_rules(&wg, &gw);
            apply_rules("iptables", &rules)?;
            if has_v6 {
                apply_rules("ip6tables", &rules)?;
            }
            Ok::<_, CoreError>(())
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    #[instrument(skip(self, iface), fields(iface = %iface.name, gateway))]
    async fn remove(&self, iface: &Interface, gateway: &str) -> CoreResult<()> {
        if self.skip() {
            debug!("nat: skip remove (dry-run/non-linux)");
            return Ok(());
        }
        let wg = iface.name.clone();
        let gw = gateway.to_string();
        let has_v6 = iface.ipv6_cidr.is_some();
        let state = self.forward_state.clone();
        task::spawn_blocking(move || {
            // 1. Delete the rules (best-effort; a missing rule is benign).
            let rules = nat_rules(&wg, &gw);
            remove_rules("iptables", &rules);
            if has_v6 {
                remove_rules("ip6tables", &rules);
            }
            // 2. Restore IP forwarding only if we were the ones who enabled it.
            if let Ok(mut map) = state.lock() {
                if let Some(snap) = map.remove(&wg) {
                    if !snap.v4_was_on {
                        let _ = write_forward(V4_FORWARD, false);
                    }
                    if has_v6 && !snap.v6_was_on {
                        let _ = write_forward(V6_FORWARD, false);
                    }
                }
            }
            Ok::<_, CoreError>(())
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))?
    }

    async fn run_hook(&self, script: &str) -> CoreResult<()> {
        if script.trim().is_empty() {
            return Ok(());
        }
        if self.skip() {
            info!(lines = script.lines().count(), "nat: skip hook (dry-run/non-linux)");
            return Ok(());
        }
        let script = script.to_string();
        task::spawn_blocking(move || {
            for raw in script.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Whitespace-split into argv — NO shell, so `;`/`|`/`$()` are
                // passed verbatim as arguments and never interpreted.
                let mut parts = line.split_whitespace();
                let Some(cmd) = parts.next() else {
                    continue;
                };
                let args: Vec<&str> = parts.collect();
                match Command::new(cmd).args(&args).status() {
                    Ok(s) if s.success() => {}
                    Ok(s) => warn!(command = %line, code = s.code(), "hook exited non-zero"),
                    Err(e) => warn!(command = %line, error = %e, "hook failed to spawn"),
                }
            }
        })
        .await
        .map_err(|e| CoreError::WireGuard(format!("join: {e}")))
    }
}

/// A single firewall rule, modelled independently of the add/check/delete
/// action so the same spec can be checked (`-C`), inserted (`-I`) and
/// deleted (`-D`).
struct Rule {
    table: Option<&'static str>,
    body: Vec<String>,
}

impl Rule {
    /// Build the full argv for the given action, e.g. `-C` / `-I` / `-D`.
    fn argv(&self, action: &str) -> Vec<String> {
        let mut v = Vec::with_capacity(self.body.len() + 3);
        if let Some(t) = self.table {
            v.push("-t".to_string());
            v.push(t.to_string());
        }
        v.push(action.to_string());
        v.extend(self.body.iter().cloned());
        v
    }
}

/// Build the FORWARD + POSTROUTING MASQUERADE rule set for WireGuard interface
/// `wg` egressing via `gateway`. Pure (no I/O) so it can be unit-tested.
fn nat_rules(wg: &str, gateway: &str) -> Vec<Rule> {
    vec![
        Rule {
            table: None,
            body: vec![
                "FORWARD".into(),
                "-i".into(),
                wg.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        },
        Rule {
            table: None,
            body: vec![
                "FORWARD".into(),
                "-o".into(),
                wg.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        },
        Rule {
            table: Some("nat"),
            body: vec![
                "POSTROUTING".into(),
                "-o".into(),
                gateway.into(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        },
    ]
}

/// Render the rule set as human-readable iptables command lines, for read-only
/// display in the UI (`on up` block). Shows what `apply` would install.
pub fn render_nat_rules(wg: &str, gateway: &str, has_v6: bool) -> String {
    let mut out = String::new();
    for (bin, enabled) in [("iptables", true), ("ip6tables", has_v6)] {
        if !enabled {
            continue;
        }
        for rule in nat_rules(wg, gateway) {
            out.push_str(bin);
            out.push(' ');
            out.push_str(&rule.argv("-I").join(" "));
            out.push('\n');
        }
    }
    out
}

/// Run an iptables/ip6tables invocation with explicit argv. Returns whether the
/// process exited 0. A spawn failure (e.g. binary absent) is a hard error.
fn run_ipt(bin: &str, args: &[String]) -> CoreResult<bool> {
    let status = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| CoreError::WireGuard(format!("{bin}: {e} (is iptables installed?)")))?;
    Ok(status.success())
}

/// Insert each rule that is not already present (`-C` probe → `-I`).
fn apply_rules(bin: &str, rules: &[Rule]) -> CoreResult<()> {
    for rule in rules {
        let exists = run_ipt(bin, &rule.argv("-C"))?;
        if !exists {
            let inserted = run_ipt(bin, &rule.argv("-I"))?;
            if !inserted {
                return Err(CoreError::WireGuard(format!(
                    "{bin} failed to insert rule: {:?}",
                    rule.argv("-I")
                )));
            }
        }
    }
    Ok(())
}

/// Delete each rule (best-effort; a non-existent rule is not an error).
fn remove_rules(bin: &str, rules: &[Rule]) {
    for rule in rules {
        if let Err(e) = run_ipt(bin, &rule.argv("-D")) {
            debug!(%bin, error = %e, "nat: rule delete failed (ignored)");
        }
    }
}

fn read_forward(path: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn write_forward(path: &str, on: bool) -> CoreResult<()> {
    std::fs::write(path, if on { "1\n" } else { "0\n" })
        .map_err(|e| CoreError::WireGuard(format!("write {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_forward_and_masquerade_rules() {
        let rules = nat_rules("wg0", "eth0");
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0].argv("-I"),
            vec!["-I", "FORWARD", "-i", "wg0", "-j", "ACCEPT"]
        );
        assert_eq!(
            rules[1].argv("-I"),
            vec!["-I", "FORWARD", "-o", "wg0", "-j", "ACCEPT"]
        );
        assert_eq!(
            rules[2].argv("-I"),
            vec!["-t", "nat", "-I", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"]
        );
        // The delete counterpart mirrors the insert exactly.
        assert_eq!(
            rules[2].argv("-D"),
            vec!["-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"]
        );
    }

    #[test]
    fn renders_rules_for_display() {
        let text = render_nat_rules("wg0", "eth0", false);
        assert!(text.contains("iptables -I FORWARD -i wg0 -j ACCEPT"));
        assert!(text.contains("iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE"));
        assert!(!text.contains("ip6tables"));
        let text6 = render_nat_rules("wg0", "eth0", true);
        assert!(text6.contains("ip6tables -t nat -I POSTROUTING -o eth0 -j MASQUERADE"));
    }

    #[tokio::test]
    async fn hook_is_noop_when_empty_or_dry_run() {
        // Empty script is a no-op even on the real adapter.
        let real = IptablesNatAdapter::with_dry_run(false);
        assert!(real.run_hook("   \n  ").await.is_ok());
        // Under dry-run, even a populated script does nothing and succeeds.
        let dry = IptablesNatAdapter::with_dry_run(true);
        assert!(dry.run_hook("iptables -L\n# comment\nfoo bar").await.is_ok());
    }
}
