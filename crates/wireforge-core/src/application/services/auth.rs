use std::sync::Arc;

use crate::application::ports::UserRepository;
use crate::crypto::{hash_password, verify_password};
use crate::domain::{NewUser, Role, User};
use crate::{CoreError, CoreResult};

pub struct AuthService<R: UserRepository> {
    users: Arc<R>,
}

impl<R: UserRepository> AuthService<R> {
    pub fn new(users: Arc<R>) -> Self {
        Self { users }
    }

    /// Register the first admin account. Fails if any user already exists.
    pub async fn register_initial_admin(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
    ) -> CoreResult<User> {
        if self.users.count().await? > 0 {
            return Err(CoreError::Conflict("initial admin already exists".into()));
        }
        let hash = hash_password(password)?;
        let new = NewUser {
            username: username.to_string(),
            email: email.map(str::to_string),
            password_hash: hash,
            role: Role::Admin,
        };
        self.users.create(new).await
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
        role: Role,
    ) -> CoreResult<User> {
        if self.users.find_by_username(username).await?.is_some() {
            return Err(CoreError::Conflict(format!("user '{username}' exists")));
        }
        let hash = hash_password(password)?;
        self.users
            .create(NewUser {
                username: username.to_string(),
                email: email.map(str::to_string),
                password_hash: hash,
                role,
            })
            .await
    }

    /// Validate username + password. Does NOT enforce TOTP — callers must check.
    pub async fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> CoreResult<User> {
        let user = self
            .users
            .find_by_username(username)
            .await?
            .ok_or(CoreError::InvalidCredentials)?;
        if !verify_password(password, &user.password_hash)? {
            return Err(CoreError::InvalidCredentials);
        }
        Ok(user)
    }

    pub async fn has_any_user(&self) -> CoreResult<bool> {
        Ok(self.users.count().await? > 0)
    }
}
