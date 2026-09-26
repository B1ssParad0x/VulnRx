use sqlx::Connection;
use sqlx::PgPool;

use crate::{PI_LINK_CONFIDENCE, PI_LINK_SOURCE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestReport {
    pub hospitals: u64,
    pub vendors: u64,
    pub products: u64,
    pub links: u64,
    pub rows_without_a_product_link: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("download failed: {0}")]
    Download(#[from] reqwest::Error),
    #[error("download of {url} returned HTTP {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("state filter must be two letters, got `{0}`")]
    BadState(String),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Load hospital, vendor, product, and link rows from one linkage CSV.
///
/// `state` is an optional USPS code. Rows for other states are left untouched.
/// A hospital is stored only with a 6-digit CCN and a non-empty name.
/// A vendor link is stored only when the row also names a developer, product, and CHPL id.
pub async fn ingest_pi_csv(
    pool: &PgPool,
    csv: &[u8],
    source_url: &str,
    state: Option<&str>,
) -> Result<IngestReport, IngestError> {
    let state = normalize_state(state)?;
    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS pi_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;

    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY pi_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(csv).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;

    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS pi_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }

    let loaded = load_stage(&mut conn, source_url, state.as_deref()).await;
    let _ = sqlx::query("DROP TABLE IF EXISTS pi_stage")
        .execute(&mut *conn)
        .await;
    loaded
}

async fn load_stage(
    conn: &mut sqlx::PgConnection,
    source_url: &str,
    state: Option<&str>,
) -> Result<IngestReport, IngestError> {
    let mut tx = conn.begin().await?;
    let hospitals = sqlx::query(UPSERT_HOSPITALS)
        .bind(state)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let vendors = sqlx::query(UPSERT_VENDORS)
        .bind(state)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let products = sqlx::query(UPSERT_PRODUCTS)
        .bind(state)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let links = sqlx::query(UPSERT_LINKS)
        .bind(state)
        .bind(PI_LINK_SOURCE)
        .bind(source_url)
        .bind(PI_LINK_CONFIDENCE)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let rows_without_a_product_link: i64 = sqlx::query_scalar(COUNT_UNLINKED)
        .bind(state)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(IngestReport {
        hospitals,
        vendors,
        products,
        links,
        rows_without_a_product_link,
    })
}

fn normalize_state(state: Option<&str>) -> Result<Option<String>, IngestError> {
    let Some(state) = state else {
        return Ok(None);
    };
    let state = state.trim().to_ascii_uppercase();
    if state.len() == 2 && state.chars().all(|c| c.is_ascii_uppercase()) {
        Ok(Some(state))
    } else {
        Err(IngestError::BadState(state))
    }
}

const CREATE_STAGE: &str = r#"
CREATE TEMP TABLE pi_stage (
    "Facility.ID" TEXT,
    "Facility.Name" TEXT,
    "Address" TEXT,
    "City.Town" TEXT,
    "State" TEXT,
    "ZIP.Code" TEXT,
    "County.Parish" TEXT,
    "Telephone.Number" TEXT,
    "Meets.criteria.for.promoting.interoperability.of.EHRs" TEXT,
    "Start.Date" TEXT,
    "End.Date" TEXT,
    "CEHRT.ID" TEXT,
    chpl_id TEXT,
    product_database_id TEXT,
    developer_name TEXT,
    product_name TEXT
)
"#;

const UPSERT_HOSPITALS: &str = r#"
INSERT INTO hospitals (ccn, name, city, state, address, zip, phone)
SELECT DISTINCT ON ("Facility.ID")
    btrim("Facility.ID"),
    btrim("Facility.Name"),
    NULLIF(btrim("City.Town"), ''),
    NULLIF(btrim("State"), ''),
    NULLIF(btrim("Address"), ''),
    NULLIF(btrim("ZIP.Code"), ''),
    NULLIF(btrim("Telephone.Number"), '')
FROM pi_stage
WHERE "Facility.ID" ~ '^[0-9]{6}$'
  AND btrim(COALESCE("Facility.Name", '')) <> ''
  AND (NULLIF(btrim("State"), '') IS NULL OR btrim("State") ~ '^[A-Z]{2}$')
  AND ($1::text IS NULL OR btrim("State") = $1)
ORDER BY "Facility.ID",
    CASE
        WHEN btrim("End.Date") ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$'
        THEN to_date(btrim("End.Date"), 'MM/DD/YYYY')
    END DESC NULLS LAST
ON CONFLICT (ccn) WHERE ccn IS NOT NULL
DO UPDATE SET
    name = EXCLUDED.name,
    city = EXCLUDED.city,
    state = EXCLUDED.state,
    address = EXCLUDED.address,
    zip = EXCLUDED.zip,
    phone = EXCLUDED.phone
"#;

const UPSERT_VENDORS: &str = r#"
INSERT INTO vendors (name)
SELECT DISTINCT btrim(developer_name)
FROM pi_stage
WHERE "Facility.ID" ~ '^[0-9]{6}$'
  AND btrim(COALESCE("Facility.Name", '')) <> ''
  AND (NULLIF(btrim("State"), '') IS NULL OR btrim("State") ~ '^[A-Z]{2}$')
  AND btrim(COALESCE(developer_name, '')) <> ''
  AND btrim(COALESCE(product_name, '')) <> ''
  AND btrim(COALESCE(chpl_id, '')) <> ''
  AND ($1::text IS NULL OR btrim("State") = $1)
ON CONFLICT ((lower(name))) DO UPDATE SET name = vendors.name
"#;

const UPSERT_PRODUCTS: &str = r#"
INSERT INTO products (vendor_id, name, chpl_id, chpl_database_id)
SELECT DISTINCT ON (btrim(s.chpl_id))
    v.id,
    btrim(s.product_name),
    btrim(s.chpl_id),
    NULLIF(btrim(s.product_database_id), '')
FROM pi_stage s
JOIN vendors v ON lower(v.name) = lower(btrim(s.developer_name))
WHERE s."Facility.ID" ~ '^[0-9]{6}$'
  AND btrim(COALESCE(s."Facility.Name", '')) <> ''
  AND (NULLIF(btrim(s."State"), '') IS NULL OR btrim(s."State") ~ '^[A-Z]{2}$')
  AND btrim(COALESCE(s.developer_name, '')) <> ''
  AND btrim(COALESCE(s.product_name, '')) <> ''
  AND btrim(COALESCE(s.chpl_id, '')) <> ''
  AND ($1::text IS NULL OR btrim(s."State") = $1)
ORDER BY btrim(s.chpl_id)
ON CONFLICT (chpl_id) WHERE chpl_id IS NOT NULL
DO UPDATE SET
    vendor_id = EXCLUDED.vendor_id,
    name = EXCLUDED.name,
    chpl_database_id = EXCLUDED.chpl_database_id
"#;

const UPSERT_LINKS: &str = r#"
INSERT INTO hospital_vendor_map (
    hospital_id, vendor_id, product_id, source, source_url, confidence, last_verified
)
SELECT
    h.id,
    v.id,
    p.id,
    $2,
    $3,
    $4,
    max(
        CASE
            WHEN btrim(s."End.Date") ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$'
            THEN to_date(btrim(s."End.Date"), 'MM/DD/YYYY')
        END
    )
FROM pi_stage s
JOIN hospitals h ON h.ccn = btrim(s."Facility.ID")
JOIN vendors v ON lower(v.name) = lower(btrim(s.developer_name))
JOIN products p ON p.chpl_id = btrim(s.chpl_id)
WHERE s."Facility.ID" ~ '^[0-9]{6}$'
  AND btrim(COALESCE(s."Facility.Name", '')) <> ''
  AND (NULLIF(btrim(s."State"), '') IS NULL OR btrim(s."State") ~ '^[A-Z]{2}$')
  AND btrim(COALESCE(s.developer_name, '')) <> ''
  AND btrim(COALESCE(s.product_name, '')) <> ''
  AND btrim(COALESCE(s.chpl_id, '')) <> ''
  AND ($1::text IS NULL OR btrim(s."State") = $1)
GROUP BY h.id, v.id, p.id
ON CONFLICT ON CONSTRAINT hospital_vendor_map_natural_uidx
DO UPDATE SET
    source_url = EXCLUDED.source_url,
    confidence = EXCLUDED.confidence,
    last_verified = GREATEST(hospital_vendor_map.last_verified, EXCLUDED.last_verified)
"#;

const COUNT_UNLINKED: &str = r#"
SELECT count(*)::bigint
FROM pi_stage
WHERE ($1::text IS NULL OR btrim("State") = $1)
  AND NOT (
    "Facility.ID" ~ '^[0-9]{6}$'
    AND btrim(COALESCE("Facility.Name", '')) <> ''
    AND (NULLIF(btrim("State"), '') IS NULL OR btrim("State") ~ '^[A-Z]{2}$')
    AND btrim(COALESCE(developer_name, '')) <> ''
    AND btrim(COALESCE(product_name, '')) <> ''
    AND btrim(COALESCE(chpl_id, '')) <> ''
  )
"#;
