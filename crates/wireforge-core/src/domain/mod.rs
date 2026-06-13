//! Pure domain entities and value objects. No I/O, no framework.

pub mod audit;
pub mod ban;
pub mod identity;
pub mod interface;
pub mod keys;
pub mod peer;
pub mod role;
pub mod settings;
pub mod sysnet;
pub mod user;
pub mod webhook;

pub use audit::{AuditAction, AuditEvent};
pub use ban::IpBan;
pub use identity::Id;
pub use interface::{Interface, InterfaceStatus, NewInterface};
pub use keys::{PresharedKey, WgPrivateKey, WgPublicKey};
pub use peer::{NewPeer, Peer};
pub use role::Role;
pub use settings::RuntimeSettings;
pub use sysnet::SysInterface;
pub use user::{NewUser, User};
pub use webhook::{NewWebhook, Webhook};
