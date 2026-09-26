use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("{0}")]
    NotFound(&'static str),
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Database(err) => {
                eprintln!("database error: {err}");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error")
            }
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub(crate) fn parse_id(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| ApiError::BadRequest("id must be a uuid"))
}

pub(crate) fn parse_limit(raw: Option<&str>, default: i64, max: i64) -> Result<i64, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let parsed: i64 = raw
        .parse()
        .map_err(|_| ApiError::BadRequest("limit must be an integer"))?;
    if parsed < 1 {
        return Err(ApiError::BadRequest("limit must be at least 1"));
    }
    Ok(parsed.min(max))
}

pub(crate) async fn hospital_exists(pool: &sqlx::PgPool, id: Uuid) -> Result<(), ApiError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM hospitals WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::NotFound("hospital not found"))
    }
}
