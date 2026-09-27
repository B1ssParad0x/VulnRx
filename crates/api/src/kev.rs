//! CISA's known-exploited catalog, as CISA published it.
//!
//! A row names the vendor and product from the catalog. It is not a claim that
//! a hospital in this registry runs that product.

use axum::Json;
use axum::extract::{Query, State};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::error::ApiError;

pub(crate) const PAGE_SIZE: i64 = 50;

const NOTE: &str = "Each row is the vendor and product CISA named in its known-exploited catalog. A row is not a claim that a hospital in this registry runs that product.";

#[derive(Deserialize)]
pub(crate) struct CatalogQuery {
    page: Option<String>,
}

impl CatalogQuery {
    pub(crate) fn page_raw(&self) -> Option<&str> {
        self.page.as_deref()
    }
}

#[derive(Serialize)]
pub(crate) struct CatalogResponse {
    source: &'static str,
    note: &'static str,
    total: i64,
    page: i64,
    page_size: i64,
    entries: Vec<CatalogEntry>,
}

#[derive(Serialize)]
pub(crate) struct CatalogEntry {
    pub(crate) cve_id: String,
    pub(crate) vendor: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) published_date: Option<NaiveDate>,
    pub(crate) cvss_score: Option<Decimal>,
    pub(crate) epss_score: Option<Decimal>,
}

#[derive(FromRow)]
struct CatalogRow {
    cve_id: String,
    kev_vendor: Option<String>,
    kev_product: Option<String>,
    description: Option<String>,
    published_date: Option<NaiveDate>,
    cvss_score: Option<Decimal>,
    epss_score: Option<Decimal>,
}

pub(crate) async fn catalog(
    State(pool): State<PgPool>,
    Query(query): Query<CatalogQuery>,
) -> Result<Json<CatalogResponse>, ApiError> {
    let page = crate::error::parse_page(query.page.as_deref())?;
    let (total, entries) = load(&pool, page).await?;
    Ok(Json(CatalogResponse {
        source: "cisa_kev",
        note: NOTE,
        total,
        page,
        page_size: PAGE_SIZE,
        entries,
    }))
}

pub(crate) async fn load(pool: &PgPool, page: i64) -> Result<(i64, Vec<CatalogEntry>), ApiError> {
    let (total, rows) = load_rows(pool, page).await?;
    Ok((total, rows.into_iter().map(entry_from).collect()))
}

async fn load_rows(pool: &PgPool, page: i64) -> Result<(i64, Vec<CatalogRow>), ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM cves WHERE is_kev IS TRUE")
        .fetch_one(pool)
        .await?;
    let offset = page
        .checked_sub(1)
        .and_then(|value| value.checked_mul(PAGE_SIZE))
        .ok_or(ApiError::BadRequest("page must be at least 1"))?;
    let rows = sqlx::query_as::<_, CatalogRow>(
        "SELECT cve_id, kev_vendor, kev_product, description, published_date, cvss_score, epss_score
         FROM cves
         WHERE is_kev IS TRUE
         ORDER BY published_date DESC NULLS LAST, cve_id DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok((total, rows))
}

fn entry_from(row: CatalogRow) -> CatalogEntry {
    CatalogEntry {
        cve_id: row.cve_id,
        vendor: blank_to_none(row.kev_vendor),
        product: blank_to_none(row.kev_product),
        description: blank_to_none(row.description),
        published_date: row.published_date,
        cvss_score: row.cvss_score,
        epss_score: row.epss_score,
    }
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}
