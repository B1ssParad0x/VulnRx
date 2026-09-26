//! Newest hospital cyber incidents for the ticker.
//!
//! A row appears only when a breach or an Item 1.05 filing is already linked to
//! one hospital. 10-K governance disclosures stay on the hospital profile.

use axum::Json;
use axum::extract::{Query, State};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{self, ApiError};
use crate::public_name;

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 50;

#[derive(Deserialize)]
pub(crate) struct RecentQuery {
    limit: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct IncidentResponse {
    incidents: Vec<Incident>,
}

#[derive(Serialize)]
pub(crate) struct Incident {
    pub(crate) hospital_id: Uuid,
    pub(crate) hospital_name: String,
    pub(crate) state: Option<String>,
    pub(crate) kind: String,
    pub(crate) occurred_on: Option<NaiveDate>,
    pub(crate) detail: Option<String>,
    pub(crate) individuals_affected: Option<i32>,
    pub(crate) source: String,
    pub(crate) source_url: Option<String>,
}

#[derive(FromRow)]
struct IncidentRow {
    hospital_id: Uuid,
    name: String,
    display_name: Option<String>,
    state: Option<String>,
    kind: String,
    occurred_on: Option<NaiveDate>,
    detail: Option<String>,
    individuals_affected: Option<i32>,
    source: String,
    source_url: Option<String>,
}

pub(crate) async fn recent(
    State(pool): State<PgPool>,
    Query(query): Query<RecentQuery>,
) -> Result<Json<IncidentResponse>, ApiError> {
    let limit = error::parse_limit(query.limit.as_deref(), DEFAULT_LIMIT, MAX_LIMIT)?;
    let incidents = load_incidents(&pool, limit).await?;
    Ok(Json(IncidentResponse { incidents }))
}

pub(crate) async fn load_incidents(pool: &PgPool, limit: i64) -> Result<Vec<Incident>, ApiError> {
    let rows = sqlx::query_as::<_, IncidentRow>(RECENT_SQL)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| Incident {
            hospital_name: public_name(&row.name, row.display_name.as_deref()).to_string(),
            hospital_id: row.hospital_id,
            state: row.state,
            kind: row.kind,
            occurred_on: row.occurred_on,
            detail: row.detail,
            individuals_affected: row.individuals_affected,
            source: row.source,
            source_url: row.source_url,
        })
        .collect())
}

const RECENT_SQL: &str = "
SELECT hospital_id, name, display_name, state, kind, occurred_on, detail,
       individuals_affected, source, source_url
FROM (
    SELECT h.id AS hospital_id, h.name, h.display_name, h.state,
           'breach'::text AS kind, b.date_reported AS occurred_on,
           b.breach_type AS detail, b.individuals_affected, b.source, b.source_url
    FROM breach_events b
    JOIN hospitals h ON h.id = b.hospital_id
    UNION ALL
    SELECT h.id, h.name, h.display_name, h.state,
           'filing'::text, f.filed_date, f.filing_type, NULL, f.source, f.source_url
    FROM sec_filings f
    JOIN hospitals h ON h.id = f.hospital_id
    WHERE f.filing_type LIKE '8-K%'
) incidents
ORDER BY occurred_on DESC NULLS LAST, name
LIMIT $1
";
