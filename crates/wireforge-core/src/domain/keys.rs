//! WireGuard key types. These wrap base64-encoded 32-byte values and provide
//! type-safety so a public key cannot be passed where a private key is expected.

use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::CoreError;

const KEY_LEN: usize = 32;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WgPrivateKey(String);

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WgPublicKey(String);

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PresharedKey(String);

macro_rules! impl_key {
    ($t:ident) => {
        impl $t {
            pub fn from_base64(s: impl Into<String>) -> Result<Self, CoreError> {
                let s = s.into();
                let raw = STANDARD
                    .decode(&s)
                    .map_err(|e| CoreError::Validation(format!("invalid base64 key: {e}")))?;
                if raw.len() != KEY_LEN {
                    return Err(CoreError::Validation(format!(
                        "invalid key length {} (expected {KEY_LEN})",
                        raw.len()
                    )));
                }
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($t), "(redacted)"))
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

impl_key!(WgPrivateKey);
impl_key!(WgPublicKey);
impl_key!(PresharedKey);
