use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use thiserror::Error;
use wireforge_core::CoreError;

#[derive(Debug, Error)]
pub enum WebError {
    #[error("validation: {0}")]
    Validation(String),

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal: {0}")]
    Internal(String),

    #[error(transparent)]
    Core(#[from] CoreError),
}

impl WebError {
    pub fn status(&self) -> StatusCode {
        match self {
            WebError::Validation(_) => StatusCode::BAD_REQUEST,
            WebError::NotFound => StatusCode::NOT_FOUND,
            WebError::Forbidden => StatusCode::FORBIDDEN,
            WebError::Unauthorized => StatusCode::UNAUTHORIZED,
            WebError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WebError::Core(e) => match e {
                CoreError::NotFound(_) => StatusCode::NOT_FOUND,
                CoreError::Conflict(_) | CoreError::Validation(_) => StatusCode::BAD_REQUEST,
                CoreError::Forbidden(_) => StatusCode::FORBIDDEN,
                CoreError::Unauthorized
                | CoreError::InvalidCredentials
                | CoreError::TwoFactorRequired
                | CoreError::TwoFactorInvalid => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }
}

#[derive(Template)]
#[template(path = "errors/error.html")]
struct ErrorPage<'a> {
    status: u16,
    message: &'a str,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = self.to_string();

        // Web (HTML) handlers: an unauthenticated request should not see a
        // raw 401 page — it should land on /login. The REST API in
        // `wireforge-api` returns its own ApiError (JSON 401) so this
        // redirect is local to the web layer only.
        if matches!(self, WebError::Unauthorized)
            || matches!(self, WebError::Core(CoreError::Unauthorized))
        {
            tracing::debug!("unauthenticated request — redirecting to /login");
            return Redirect::to("/login").into_response();
        }

        tracing::warn!(status = %status, error = %body, "request failed");
        let page = ErrorPage {
            status: status.as_u16(),
            message: &body,
        };
        let html = page
            .render()
            .unwrap_or_else(|_| format!("<h1>{}</h1><p>{}</p>", status, body));
        (status, Html(html)).into_response()
    }
}
