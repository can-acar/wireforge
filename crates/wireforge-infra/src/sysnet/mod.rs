//! Host network interface enumeration via `getifaddrs(3)`.
//!
//! Reference adapter for [`SysNetPort`]. Reads the OS network stack read-only:
//! `getifaddrs` for addresses / hardware address / kernel flags, refined on
//! Linux with `/sys/class/net/<name>/{operstate,carrier}` so the `up`/`down`
//! badge and the synthetic `NO-CARRIER` flag match what `ip link` reports
//! (e.g. `docker0` with no running containers shows `down` + `NO-CARRIER`).
//!
//! The raw `getifaddrs` walk is the only `unsafe` here; everything else is
//! pure, unit-tested helpers (`prefix_len`, `format_mac`, `flag_labels`,
//! `is_up`).

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};

use wireforge_core::application::ports::SysNetPort;
use wireforge_core::domain::SysInterface;
use wireforge_core::{CoreError, CoreResult};

/// `getifaddrs`-backed implementation of [`SysNetPort`].
#[derive(Debug, Default, Clone, Copy)]
pub struct GetifaddrsAdapter;

impl GetifaddrsAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl SysNetPort for GetifaddrsAdapter {
    fn list(&self) -> CoreResult<Vec<SysInterface>> {
        let raw = collect_raw()?;
        Ok(assemble(raw))
    }
}

/// Per-interface accumulator while walking the `getifaddrs` linked list.
/// Every entry for a given interface carries the same `ifa_flags`, so the
/// last write wins (they are identical).
#[derive(Debug, Default)]
struct Acc {
    flags: u32,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    mac: Option<String>,
}

/// Walk `getifaddrs(3)` once and group raw address data by interface name.
fn collect_raw() -> CoreResult<BTreeMap<String, Acc>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a heap-allocated linked list into `ifap` on
    // success; we free it with `freeifaddrs` before returning.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(CoreError::Internal(format!(
            "getifaddrs: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut map: BTreeMap<String, Acc> = BTreeMap::new();
    let mut cur = ifap;
    // SAFETY: we only dereference non-null nodes and follow `ifa_next` until
    // null, exactly as the C API contract specifies. Pointers stay valid until
    // `freeifaddrs`.
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        let name = match unsafe { CStr::from_ptr(ifa.ifa_name) }.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => continue,
        };
        let acc = map.entry(name).or_default();
        acc.flags = ifa.ifa_flags as u32;

        if ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        match family {
            libc::AF_INET => {
                let addr = unsafe { ipv4_addr(ifa.ifa_addr) };
                let prefix = unsafe { ipv4_prefix(ifa.ifa_netmask) };
                acc.ipv4.push(format!("{addr}/{prefix}"));
            }
            libc::AF_INET6 => {
                let addr = unsafe { ipv6_addr(ifa.ifa_addr) };
                let prefix = unsafe { ipv6_prefix(ifa.ifa_netmask) };
                acc.ipv6.push(format!("{addr}/{prefix}"));
            }
            _ => {
                if let Some(mac) = unsafe { mac_addr(ifa.ifa_addr) } {
                    acc.mac = Some(mac);
                }
            }
        }
    }

    // SAFETY: `ifap` is the list head returned by a successful `getifaddrs`.
    unsafe { libc::freeifaddrs(ifap) };
    Ok(map)
}

/// Combine raw address data with `/sys`-derived operational state.
fn assemble(map: BTreeMap<String, Acc>) -> Vec<SysInterface> {
    map.into_iter()
        .map(|(name, acc)| {
            let operstate = read_operstate(&name);
            let carrier = read_carrier(&name);
            let up = is_up(operstate.as_deref(), acc.flags);
            let flags = flag_labels(acc.flags, carrier, operstate.as_deref());
            SysInterface {
                name,
                up,
                ipv4: acc.ipv4,
                ipv6: acc.ipv6,
                mac: acc.mac,
                flags,
            }
        })
        .collect()
}

// --- Address extraction (unsafe pointer casts, value parsing only) ---

/// SAFETY: `sa` must point to a valid `sockaddr` whose family is `AF_INET`.
unsafe fn ipv4_addr(sa: *const libc::sockaddr) -> Ipv4Addr {
    let sin = sa as *const libc::sockaddr_in;
    // `s_addr` is stored in network byte order; its in-memory bytes are the
    // big-endian octets `Ipv4Addr::from([u8; 4])` expects.
    Ipv4Addr::from((*sin).sin_addr.s_addr.to_ne_bytes())
}

/// SAFETY: `nm` is either null or a valid `AF_INET` `sockaddr`.
unsafe fn ipv4_prefix(nm: *const libc::sockaddr) -> u8 {
    if nm.is_null() {
        return 32;
    }
    let sin = nm as *const libc::sockaddr_in;
    prefix_len(&(*sin).sin_addr.s_addr.to_ne_bytes())
}

/// SAFETY: `sa` must point to a valid `sockaddr` whose family is `AF_INET6`.
unsafe fn ipv6_addr(sa: *const libc::sockaddr) -> Ipv6Addr {
    let sin6 = sa as *const libc::sockaddr_in6;
    Ipv6Addr::from((*sin6).sin6_addr.s6_addr)
}

/// SAFETY: `nm` is either null or a valid `AF_INET6` `sockaddr`.
unsafe fn ipv6_prefix(nm: *const libc::sockaddr) -> u8 {
    if nm.is_null() {
        return 128;
    }
    let sin6 = nm as *const libc::sockaddr_in6;
    prefix_len(&(*sin6).sin6_addr.s6_addr)
}

/// Extract the link-layer (MAC) address. Linux exposes it via `AF_PACKET` /
/// `sockaddr_ll`; other platforms are not supported here and yield `None`.
///
/// SAFETY: `sa` must point to a valid `sockaddr`.
#[cfg(target_os = "linux")]
unsafe fn mac_addr(sa: *const libc::sockaddr) -> Option<String> {
    if (*sa).sa_family as i32 != libc::AF_PACKET {
        return None;
    }
    let sll = sa as *const libc::sockaddr_ll;
    let halen = (*sll).sll_halen as usize;
    if halen == 0 || halen > (*sll).sll_addr.len() {
        return None;
    }
    Some(format_mac(&(*sll).sll_addr[..halen]))
}

/// SAFETY: `sa` must point to a valid `sockaddr`.
#[cfg(not(target_os = "linux"))]
unsafe fn mac_addr(_sa: *const libc::sockaddr) -> Option<String> {
    None
}

// --- /sys refinement (Linux only) ---

#[cfg(target_os = "linux")]
fn read_operstate(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
        .ok()
        .map(|s| s.trim().to_owned())
}

#[cfg(target_os = "linux")]
fn read_carrier(name: &str) -> Option<bool> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/carrier"))
        .ok()
        .and_then(|s| match s.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        })
}

#[cfg(not(target_os = "linux"))]
fn read_operstate(_name: &str) -> Option<String> {
    None
}

#[cfg(not(target_os = "linux"))]
fn read_carrier(_name: &str) -> Option<bool> {
    None
}

// --- Pure helpers (unit-tested) ---

/// Count set bits across a contiguous network mask to derive its prefix length.
fn prefix_len(mask: &[u8]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

/// Format raw hardware-address bytes as lowercase, colon-separated hex.
/// Only called from the Linux `mac_addr` path; still compiled (and tested)
/// everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Decide the operational `up`/`down` state. `operstate` (from `/sys`) is
/// authoritative when present; otherwise fall back to kernel flags.
///
/// - `"up"` → up; `"unknown"` (e.g. `lo`) → up iff `IFF_UP`; any other state
///   (`"down"`, `"dormant"`, …) → down.
/// - No `operstate` (non-Linux): up iff both `IFF_UP` and `IFF_RUNNING`.
fn is_up(operstate: Option<&str>, flags: u32) -> bool {
    let iff_up = flags & libc::IFF_UP as u32 != 0;
    match operstate {
        Some("up") => true,
        Some("unknown") => iff_up,
        Some(_) => false,
        None => iff_up && flags & libc::IFF_RUNNING as u32 != 0,
    }
}

/// Build the human-readable flag list shown in the UI. Mirrors the subset
/// `ip link` surfaces: a synthetic `NO-CARRIER` (when a non-loopback link has
/// no carrier) followed by `BROADCAST`, `MULTICAST`, `LOOPBACK`,
/// `POINTOPOINT`. Administrative `UP`/`RUNNING` are intentionally omitted —
/// they are conveyed by the status badge.
fn flag_labels(flags: u32, carrier: Option<bool>, operstate: Option<&str>) -> Vec<String> {
    let is_loopback = flags & libc::IFF_LOOPBACK as u32 != 0;
    let no_carrier = !is_loopback
        && match (carrier, operstate) {
            (Some(false), _) => true,
            (None, Some(s)) => s != "up" && s != "unknown",
            _ => false,
        };

    let mut out = Vec::new();
    if no_carrier {
        out.push("NO-CARRIER".to_owned());
    }
    if flags & libc::IFF_BROADCAST as u32 != 0 {
        out.push("BROADCAST".to_owned());
    }
    if flags & libc::IFF_MULTICAST as u32 != 0 {
        out.push("MULTICAST".to_owned());
    }
    if is_loopback {
        out.push("LOOPBACK".to_owned());
    }
    if flags & libc::IFF_POINTOPOINT as u32 != 0 {
        out.push("POINTOPOINT".to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_len_counts_mask_bits() {
        assert_eq!(prefix_len(&[255, 255, 0, 0]), 16);
        assert_eq!(prefix_len(&[255, 255, 255, 0]), 24);
        assert_eq!(prefix_len(&[255, 255, 255, 255]), 32);
        assert_eq!(prefix_len(&[0, 0, 0, 0]), 0);
        // IPv6 /64.
        let mut m = [0u8; 16];
        m[..8].fill(0xff);
        assert_eq!(prefix_len(&m), 64);
    }

    #[test]
    fn format_mac_lowercase_colon_separated() {
        assert_eq!(
            format_mac(&[0x02, 0x42, 0x68, 0xd5, 0xe2, 0x9f]),
            "02:42:68:d5:e2:9f"
        );
        assert_eq!(format_mac(&[0, 0, 0, 0, 0, 0]), "00:00:00:00:00:00");
    }

    #[test]
    fn is_up_resolves_operstate_then_flags() {
        let up = libc::IFF_UP as u32;
        let running = libc::IFF_RUNNING as u32;
        // operstate authoritative
        assert!(is_up(Some("up"), 0));
        assert!(!is_up(Some("down"), up | running));
        // lo: unknown + IFF_UP
        assert!(is_up(Some("unknown"), up));
        assert!(!is_up(Some("unknown"), 0));
        // non-Linux fallback needs UP + RUNNING
        assert!(is_up(None, up | running));
        assert!(!is_up(None, up));
    }

    #[test]
    fn flag_labels_match_ip_link_subset() {
        let broadcast = libc::IFF_BROADCAST as u32;
        let multicast = libc::IFF_MULTICAST as u32;
        let loopback = libc::IFF_LOOPBACK as u32;

        // docker0 down: NO-CARRIER prepended.
        assert_eq!(
            flag_labels(broadcast | multicast, Some(false), Some("down")),
            vec!["NO-CARRIER", "BROADCAST", "MULTICAST"]
        );
        // physical NIC up: carrier present, no NO-CARRIER.
        assert_eq!(
            flag_labels(broadcast | multicast, Some(true), Some("up")),
            vec!["BROADCAST", "MULTICAST"]
        );
        // loopback: never NO-CARRIER even without carrier info.
        assert_eq!(
            flag_labels(loopback, None, Some("unknown")),
            vec!["LOOPBACK"]
        );
    }
}
