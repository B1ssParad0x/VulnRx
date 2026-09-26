//! Hospital search and the profile a result opens.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use vulnrx_models::{BreachEvent, Exposure, Hospital, RiskScore, SecFiling};

use crate::error::{self, ApiError};
use crate::public_name;

const SEARCH_DEFAULT: i64 = 10;
const SEARCH_MAX: i64 = 25;
const SEARCH_MIN_CHARS: usize = 2;

#[derive(Deserialize)]
pub(crate) struct SearchQuery {
    q: Option<String>,
    limit: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct SearchResponse {
    hospitals: Vec<SearchHit>,
}

#[derive(Serialize)]
pub(crate) struct SearchHit {
    pub(crate) id: Uuid,
    pub(crate) ccn: Option<String>,
    pub(crate) name: String,
    pub(crate) display_name: Option<String>,
    pub(crate) label: String,
    pub(crate) city: Option<String>,
    pub(crate) state: Option<String>,
}

#[derive(FromRow)]
struct SearchRow {
    id: Uuid,
    ccn: Option<String>,
    name: String,
    display_name: Option<String>,
    city: Option<String>,
    state: Option<String>,
}

pub(crate) async fn search(
    State(pool): State<PgPool>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    let limit = error::parse_limit(query.limit.as_deref(), SEARCH_DEFAULT, SEARCH_MAX)?;
    let hospitals = find_hospitals(&pool, query.q.as_deref().unwrap_or(""), limit).await?;
    Ok(Json(SearchResponse { hospitals }))
}

pub(crate) async fn find_hospitals(
    pool: &PgPool,
    raw_query: &str,
    limit: i64,
) -> Result<Vec<SearchHit>, ApiError> {
    let q = raw_query.trim();
    if q.chars().count() < SEARCH_MIN_CHARS {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, SearchRow>(SEARCH_SQL)
        .bind(like_contains(q))
        .bind(q)
        .bind(like_prefix(q))
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| SearchHit {
            label: public_name(&row.name, row.display_name.as_deref()).to_string(),
            id: row.id,
            ccn: row.ccn,
            name: row.name,
            display_name: row.display_name,
            city: row.city,
            state: row.state,
        })
        .collect())
}

#[derive(Serialize)]
pub(crate) struct ProfileResponse {
    pub(crate) hospital: HospitalBody,
    pub(crate) risk: Option<RiskScore>,
    pub(crate) vendors: Vec<VendorLink>,
    pub(crate) cehrt_reports: Vec<CehrtReport>,
    pub(crate) breaches: Vec<BreachEvent>,
    pub(crate) filings: Vec<SecFiling>,
    pub(crate) exposures: Vec<Exposure>,
}

#[derive(Serialize)]
pub(crate) struct HospitalBody {
    #[serde(flatten)]
    pub(crate) hospital: Hospital,
    pub(crate) label: String,
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct VendorLink {
    pub(crate) vendor_id: Uuid,
    pub(crate) vendor_name: String,
    pub(crate) category: Option<String>,
    pub(crate) product_id: Option<Uuid>,
    pub(crate) product_name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) chpl_id: Option<String>,
    pub(crate) source: String,
    pub(crate) source_url: Option<String>,
    pub(crate) confidence: Decimal,
    pub(crate) last_verified: Option<NaiveDate>,
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct CehrtReport {
    pub(crate) cehrt_id: String,
    pub(crate) meets_criteria: Option<bool>,
    pub(crate) period_start: Option<NaiveDate>,
    pub(crate) period_end: Option<NaiveDate>,
    pub(crate) source: String,
    pub(crate) source_url: Option<String>,
}

pub(crate) async fn profile(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Json<ProfileResponse>, ApiError> {
    let id = error::parse_id(&id)?;
    Ok(Json(load_profile(&pool, id).await?))
}

pub(crate) async fn load_profile(pool: &PgPool, id: Uuid) -> Result<ProfileResponse, ApiError> {
    let mut tx = pool.begin().await?;
    let hospital = sqlx::query_as::<_, Hospital>(HOSPITAL_SQL)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(hospital) = hospital else {
        return Err(ApiError::NotFound("hospital not found"));
    };
    let risk = sqlx::query_as::<_, RiskScore>(RISK_SQL)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let vendors = sqlx::query_as::<_, VendorLink>(VENDORS_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let cehrt_reports = sqlx::query_as::<_, CehrtReport>(CEHRT_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let breaches = sqlx::query_as::<_, BreachEvent>(BREACHES_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let filings = sqlx::query_as::<_, SecFiling>(FILINGS_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let exposures = sqlx::query_as::<_, Exposure>(EXPOSURES_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    let label = hospital.label().to_string();
    Ok(ProfileResponse {
        hospital: HospitalBody { hospital, label },
        risk,
        vendors,
        cehrt_reports,
        breaches,
        filings,
        exposures,
    })
}

#[derive(Serialize)]
pub(crate) struct VulnerabilityResponse {
    pub(crate) product_count: i64,
    pub(crate) vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct Vulnerability {
    pub(crate) cve_id: String,
    pub(crate) description: Option<String>,
    pub(crate) cvss_score: Option<Decimal>,
    pub(crate) epss_score: Option<Decimal>,
    pub(crate) is_kev: Option<bool>,
    pub(crate) vendor_name: String,
    pub(crate) product_name: String,
    pub(crate) match_basis: Option<String>,
    pub(crate) matched_cpe: Option<String>,
}

pub(crate) async fn vulnerabilities(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Json<VulnerabilityResponse>, ApiError> {
    let id = error::parse_id(&id)?;
    Ok(Json(load_vulnerabilities(&pool, id).await?))
}

pub(crate) async fn load_vulnerabilities(
    pool: &PgPool,
    id: Uuid,
) -> Result<VulnerabilityResponse, ApiError> {
    error::hospital_exists(pool, id).await?;
    let product_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT product_id) FROM hospital_vendor_map
         WHERE hospital_id = $1 AND product_id IS NOT NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let vulnerabilities = sqlx::query_as::<_, Vulnerability>(VULNS_SQL)
        .bind(id)
        .fetch_all(pool)
        .await?;
    Ok(VulnerabilityResponse {
        product_count,
        vulnerabilities,
    })
}

fn like_contains(query: &str) -> String {
    format!("%{}%", like_escape(query))
}

fn like_prefix(query: &str) -> String {
    format!("{}%", like_escape(query))
}

fn like_escape(query: &str) -> String {
    let mut escaped = String::with_capacity(query.len());
    for ch in query.chars() {
        if matches!(ch, '%' | '_' | '!') {
            escaped.push('!');
        }
        escaped.push(ch);
    }
    escaped
}

const SEARCH_SQL: &str = r#"
SELECT id, ccn, name, display_name, city, state
FROM hospitals
WHERE name ILIKE $1 ESCAPE '!'
   OR display_name ILIKE $1 ESCAPE '!'
   OR ccn = upper($2)
   OR EXISTS (
        SELECT 1 FROM unnest(aliases) AS alias
        WHERE alias ILIKE $1 ESCAPE '!'
   )
ORDER BY (ccn = upper($2)) DESC,
         (name ILIKE $3 ESCAPE '!' OR COALESCE(display_name, '') ILIKE $3 ESCAPE '!') DESC,
         GREATEST(
             similarity(name, $2),
             similarity(COALESCE(display_name, ''), $2)
         ) DESC,
         name
LIMIT $4
"#;

const HOSPITAL_SQL: &str = "
SELECT id, ccn, name, display_name, aliases, city, state, address, zip, phone,
       is_public_entity, source, source_url
FROM hospitals
WHERE id = $1
";

const RISK_SQL: &str = "
SELECT id, hospital_id, vendor_id, composite_score, breach_component, cve_component,
       exposure_component, method, computed_at
FROM risk_scores
WHERE hospital_id = $1 AND vendor_id IS NULL
ORDER BY computed_at DESC
LIMIT 1
";

const VENDORS_SQL: &str = "
SELECT v.id AS vendor_id, v.name AS vendor_name, v.category,
       p.id AS product_id, p.name AS product_name, p.version, p.chpl_id,
       m.source, m.source_url, m.confidence, m.last_verified
FROM hospital_vendor_map m
JOIN vendors v ON v.id = m.vendor_id
LEFT JOIN products p ON p.id = m.product_id
WHERE m.hospital_id = $1
ORDER BY v.name, p.name, m.source
";

const CEHRT_SQL: &str = "
SELECT cehrt_id, meets_criteria, period_start, period_end, source, source_url
FROM cehrt_reports
WHERE hospital_id = $1
ORDER BY period_end DESC NULLS LAST, cehrt_id
";

const BREACHES_SQL: &str = "
SELECT id, entity_name, entity_type, hospital_id, vendor_id, individuals_affected,
       breach_type, breach_location, portal_entity_type, date_reported, state, source, source_url
FROM breach_events
WHERE hospital_id = $1
ORDER BY date_reported DESC NULLS LAST, entity_name
";

const FILINGS_SQL: &str = "
SELECT id, company_name, hospital_id, vendor_id, filing_type, filed_date, summary, source, source_url
FROM sec_filings
WHERE hospital_id = $1
ORDER BY filed_date DESC NULLS LAST, filing_type
";

const EXPOSURES_SQL: &str = "
SELECT DISTINCT e.id, e.hospital_id, e.product_id, e.exposed_service, e.source, e.last_seen, e.raw_reference
FROM exposures e
LEFT JOIN hospital_vendor_map m
    ON m.product_id = e.product_id
   AND m.hospital_id = $1
WHERE e.hospital_id = $1
   OR m.id IS NOT NULL
ORDER BY e.last_seen DESC NULLS LAST, e.id
";

const VULNS_SQL: &str = "
SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.epss_score, c.is_kev,
       v.name AS vendor_name, p.name AS product_name, pcm.match_basis, pcm.matched_cpe
FROM hospital_vendor_map m
JOIN products p ON p.id = m.product_id
JOIN vendors v ON v.id = p.vendor_id
JOIN product_cve_map pcm ON pcm.product_id = p.id
JOIN cves c ON c.id = pcm.cve_id
WHERE m.hospital_id = $1
ORDER BY c.cve_id, p.name
";
