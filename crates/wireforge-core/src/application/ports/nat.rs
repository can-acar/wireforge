use async_trait::async_trait;

use crate::domain::Interface;
use crate::CoreResult;

/// Port for applying NAT/masquerade for a WireGuard interface that egresses via
/// a chosen host gateway, and for executing the interface's `on_up`/`on_down`
/// hook commands. The reference implementation lives in `wireforge-infra::nat`
/// and shells out to `iptables`/`ip6tables` with **explicit argv** (never
/// `shell=true`).
///
/// Implementations MUST be a logged no-op on platforms without iptables (e.g.
/// macOS) and under dry-run, so `start`/`stop` keep working in development.
#[async_trait]
pub trait NatPort: Send + Sync {
    /// Enable IP forwarding (turnkey, remembering the prior value) and install
    /// FORWARD + POSTROUTING MASQUERADE rules so peer traffic egresses via
    /// `gateway`. Idempotent: rules are checked (`-C`) before insertion.
    async fn apply(&self, iface: &Interface, gateway: &str) -> CoreResult<()>;

    /// Remove the rules previously installed for `iface`/`gateway` and restore
    /// IP forwarding to its prior value (only if we enabled it). Best-effort:
    /// missing rules are not an error.
    async fn remove(&self, iface: &Interface, gateway: &str) -> CoreResult<()>;

    /// Execute a multi-line hook script (`on_up`/`on_down`). Each non-empty,
    /// non-comment line is run as a single argv command WITHOUT a shell
    /// (so `;`, `|`, `&&`, `$()` are NOT interpreted). Best-effort.
    async fn run_hook(&self, script: &str) -> CoreResult<()>;
}
