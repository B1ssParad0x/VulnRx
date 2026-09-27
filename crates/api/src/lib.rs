//! Read API over the public-record store.
//!
//! Responses contain stored rows only. An empty list means no linked record,
//! which is different from a stored zero.

mod error;
mod explain;
mod guide;
mod hospitals;
mod incidents;
mod kev;
mod map_pins;
mod pages;
mod vendors;

use std::net::SocketAddr;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use sqlx::PgPool;

use crate::error::ApiError;

/// Routes for hospital search, profiles, vendor rollups, and the incident ticker.
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/", get(pages::home))
        .route("/dashboard", get(pages::dashboard))
        .route("/kev", get(pages::kev))
        .route("/search", get(pages::search_results))
        .route("/hospitals/{id}", get(pages::hospital))
        .route("/vendors/{id}", get(pages::vendor))
        .route("/static/app.css", get(pages::css))
        .route("/static/htmx.min.js", get(pages::script))
        .route("/static/scanner.js", get(pages::scanner))
        .route("/favicon.ico", get(pages::favicon))
        .route("/api/health", get(health))
        .route("/api/hospitals/search", get(hospitals::search))
        .route("/api/hospitals/{id}", get(hospitals::profile))
        .route(
            "/api/hospitals/{id}/vulnerabilities",
            get(hospitals::vulnerabilities),
        )
        .route("/api/vendors/{id}", get(vendors::profile))
        .route("/api/incidents/recent", get(incidents::recent))
        .route("/api/kev", get(kev::catalog))
        .route("/api/cves/{id}/explain", post(explain::json))
        .route("/cves/{id}/explain", post(explain::fragment))
        .route("/ask", post(guide::ask))
        .route("/hospitals/{id}/remediate", post(guide::remediate))
        .fallback(unknown_route)
        .with_state(pool)
}

/// Bind `addr` and serve until the process is stopped.
pub async fn serve(pool: PgPool, addr: SocketAddr) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(pool)).await
}

async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

async fn unknown_route() -> ApiError {
    ApiError::NotFound("not found")
}

#[derive(Serialize)]
struct Health {
    ok: bool,
}

/// Same display rule as [`vulnrx_models::Hospital::label`].
pub(crate) fn public_name<'a>(name: &'a str, display_name: Option<&'a str>) -> &'a str {
    display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(name)
}
