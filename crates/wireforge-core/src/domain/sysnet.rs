//! Host (system) network interface snapshot — a read-only view of the OS
//! network stack (`lo`, `eth0`, `docker0`, …).
//!
//! This is **observability**, not configuration: distinct from the WireGuard
//! [`Interface`](crate::domain::Interface) entities the application creates and
//! persists. The data is sampled from the kernel on demand and never stored.

use serde::Serialize;

/// A single host network interface as observed from the operating system.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SysInterface {
    /// Kernel interface name, e.g. `eth0`, `docker0`.
    pub name: String,
    /// Operational state: `true` when the link is up and running, `false`
    /// when administratively down or carrier-less (e.g. `docker0` with no
    /// running containers).
    pub up: bool,
    /// IPv4 addresses in CIDR form, e.g. `172.17.0.1/16`. May be empty.
    pub ipv4: Vec<String>,
    /// IPv6 addresses in CIDR form, e.g. `fe80::1/64`. May be empty.
    pub ipv6: Vec<String>,
    /// MAC (hardware) address, lowercase colon-separated
    /// (e.g. `02:42:68:d5:e2:9f`). `None` for interfaces without a
    /// link-layer address.
    pub mac: Option<String>,
    /// Human-readable flag labels, e.g.
    /// `["NO-CARRIER", "BROADCAST", "MULTICAST"]`.
    pub flags: Vec<String>,
}
