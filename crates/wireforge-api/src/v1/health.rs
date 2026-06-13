use axum::Json;

use super::dto::HealthDto;

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "system",
    responses(
        (status = 200, description = "Service is healthy", body = HealthDto)
    )
)]
pub async fn healthz() -> Json<HealthDto> {
    Json(HealthDto {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}
