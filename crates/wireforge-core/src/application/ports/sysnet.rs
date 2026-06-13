use crate::domain::SysInterface;
use crate::CoreResult;

/// Port for enumerating host (system) network interfaces.
///
/// The reference implementation lives in `wireforge-infra::sysnet` and reads
/// `getifaddrs(3)` plus `/sys/class/net` on Linux. It is **read-only** — it
/// never mutates kernel state.
pub trait SysNetPort: Send + Sync {
    /// Snapshot all host network interfaces.
    ///
    /// Synchronous on purpose: `getifaddrs` is a microsecond-scale local
    /// syscall with no blocking I/O worth offloading to a thread pool.
    fn list(&self) -> CoreResult<Vec<SysInterface>>;
}
