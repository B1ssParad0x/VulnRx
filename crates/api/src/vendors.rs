//! One vendor across every hospital a public source links to it.

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use vulnrx_models::{BreachEvent, Vendor};

use crate::error::{self, ApiError};
use crate::hospitals::Vulnerability;

#[derive(Serialize)]
pub(crate) struct VendorResponse {
    pub(crate) vendor: Vendor,
    pub(crate) hospital_count: i64,
    pub(crate) hospitals: Vec<VendorHospital>,
    pub(crate) products: Vec<VendorProduct>,
    pub(crate) breaches: Vec<BreachEvent>,
    pub(crate) vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct VendorHospital {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) city: Option<String>,
    pub(crate) state: Option<String>,
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct VendorProduct {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) chpl_id: Option<String>,
}

pub(crate) async fn profile(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Json<VendorResponse>, ApiError> {
    let id = error::parse_id(&id)?;
    Ok(Json(load_vendor(&pool, id).await?))
}

pub(crate) async fn load_vendor(pool: &PgPool, id: Uuid) -> Result<VendorResponse, ApiError> {
    let mut tx = pool.begin().await?;
    let vendor = sqlx::query_as::<_, Vendor>(
        "SELECT id, name, aliases, category FROM vendors WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(vendor) = vendor else {
        return Err(ApiError::NotFound("vendor not found"));
    };
    let hospitals = sqlx::query_as::<_, VendorHospital>(HOSPITALS_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let products = sqlx::query_as::<_, VendorProduct>(
        "SELECT id, name, version, chpl_id FROM products WHERE vendor_id = $1 ORDER BY name, id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let breaches = sqlx::query_as::<_, BreachEvent>(
        "SELECT id, entity_name, entity_type, hospital_id, vendor_id, individuals_affected,
                breach_type, breach_location, portal_entity_type, date_reported, state, source, source_url
         FROM breach_events
         WHERE vendor_id = $1
         ORDER BY date_reported DESC NULLS LAST, entity_name",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let vulnerabilities = sqlx::query_as::<_, Vulnerability>(VULNS_SQL)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    let hospital_count = i64::try_from(hospitals.len()).unwrap_or(i64::MAX);
    Ok(VendorResponse {
        vendor,
        hospital_count,
        hospitals,
        products,
        breaches,
        vulnerabilities,
    })
}

const HOSPITALS_SQL: &str = "
SELECT DISTINCT h.id, h.name, h.city, h.state
FROM hospital_vendor_map m
JOIN hospitals h ON h.id = m.hospital_id
WHERE m.vendor_id = $1
ORDER BY h.name, h.id
";

const VULNS_SQL: &str = "
SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.epss_score, c.is_kev,
       v.name AS vendor_name, p.name AS product_name, pcm.match_basis, pcm.matched_cpe
FROM products p
JOIN vendors v ON v.id = p.vendor_id
JOIN product_cve_map pcm ON pcm.product_id = p.id
JOIN cves c ON c.id = pcm.cve_id
WHERE p.vendor_id = $1
ORDER BY c.cve_id, p.name
";
