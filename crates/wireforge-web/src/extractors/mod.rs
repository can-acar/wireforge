pub mod auth_user;

pub use auth_user::AuthUser;
// Re-export at the crate root so external crates (like wireforge-api) can
// extract the same authenticated session user.
pub use auth_user::read_session_user;
