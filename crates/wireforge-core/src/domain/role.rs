use serde::{Deserialize, Serialize};

/// User roles for RBAC.
///
/// - `Admin`: full system control, can manage users, interfaces, peers, settings.
/// - `Operator`: can manage interfaces and peers but not users or system settings.
/// - `Auditor`: read-only access plus audit log inspection.
/// - `Viewer`: read-only access; no audit log access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Auditor,
    Viewer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Auditor => "auditor",
            Role::Viewer => "viewer",
        }
    }

    pub fn can_mutate(&self) -> bool {
        matches!(self, Role::Admin | Role::Operator)
    }

    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::Admin)
    }

    pub fn can_read_audit(&self) -> bool {
        matches!(self, Role::Admin | Role::Auditor)
    }

    pub fn can_manage_settings(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "auditor" => Ok(Role::Auditor),
            "viewer" => Ok(Role::Viewer),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
