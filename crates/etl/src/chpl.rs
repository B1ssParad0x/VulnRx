use rust_decimal::Decimal;
use serde::Deserialize;
use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;
use crate::pi2024::PI_2024_SOURCE;

pub const CEHRT_LINK_SOURCE: &str = "cms_pi_2024_chpl";

/// CMS reported the bundle and CHPL listed the products inside it.
pub const CEHRT_LINK_CONFIDENCE: Decimal = Decimal::from_parts(90, 0, 0, false, 2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleProduct {
    pub database_id: String,
    pub developer_name: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CehrtBundle {
    pub cehrt_id: String,
    pub products: Vec<BundleProduct>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpandReport {
    pub bundles: u64,
    pub vendors: u64,
    pub products: u64,
    pub links: u64,
    pub failed_lookups: u64,
}

/// Look up every stored 2024 CEHRT id and write the products CHPL returns.
pub async fn expand_cehrt(pool: &PgPool) -> Result<ExpandReport, IngestError> {
    let Some(api_key) = std::env::var("CHPL_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
    else {
        return Err(IngestError::MissingApiKey);
    };
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT cehrt_id FROM cehrt_reports WHERE source = $1")
            .bind(PI_2024_SOURCE)
            .fetch_all(pool)
            .await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("vulnrx/0.1")
        .build()?;
    let mut bundles = Vec::new();
    let mut failed_lookups = 0_u64;
    for (n, cehrt_id) in ids.iter().enumerate() {
        match fetch_bundle(&client, &api_key, cehrt_id).await {
            Ok(bundle) => bundles.push(bundle),
            Err(IngestError::HttpStatus { status: 404, .. }) => failed_lookups += 1,
            Err(err) => return Err(err),
        }
        if (n + 1) % 50 == 0 {
            eprintln!("looked up {} of {} CEHRT ids", n + 1, ids.len());
        }
    }
    let mut report = link_cehrt_bundles(pool, &bundles).await?;
    report.failed_lookups = failed_lookups;
    Ok(report)
}

pub async fn link_cehrt_bundles(
    pool: &PgPool,
    bundles: &[CehrtBundle],
) -> Result<ExpandReport, IngestError> {
    let mut projected = csv::Writer::from_writer(Vec::new());
    projected.write_record([
        "cehrt_id",
        "developer_name",
        "product_name",
        "chpl_database_id",
    ])?;
    for bundle in bundles {
        for product in &bundle.products {
            projected.write_record([
                bundle.cehrt_id.as_str(),
                product.developer_name.as_str(),
                product.name.as_str(),
                product.database_id.as_str(),
            ])?;
        }
    }
    projected.flush()?;
    let bytes = projected
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;

    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS cehrt_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY cehrt_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(bytes).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS cehrt_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let vendors = sqlx::query(UPSERT_VENDORS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let products = sqlx::query(UPSERT_PRODUCTS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let links = sqlx::query(UPSERT_LINKS)
        .bind(CEHRT_LINK_SOURCE)
        .bind(CEHRT_LINK_CONFIDENCE)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS cehrt_stage")
        .execute(&mut *conn)
        .await;
    Ok(ExpandReport {
        bundles: u64::try_from(bundles.len()).unwrap_or(u64::MAX),
        vendors,
        products,
        links,
        failed_lookups: 0,
    })
}

async fn fetch_bundle(
    client: &reqwest::Client,
    api_key: &str,
    cehrt_id: &str,
) -> Result<CehrtBundle, IngestError> {
    let url = format!("https://chpl.healthit.gov/rest/certification_ids/{cehrt_id}");
    let response = client.get(&url).header("API-Key", api_key).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(IngestError::HttpStatus {
            url,
            status: status.as_u16(),
        });
    }
    let bytes = response.bytes().await?;
    let body: LookupResponse = serde_json::from_slice(&bytes)?;
    let products = body
        .products
        .into_iter()
        .filter_map(|product| {
            let developer_name = product
                .developer_name
                .unwrap_or_default()
                .trim()
                .to_string();
            let name = product.name.unwrap_or_default().trim().to_string();
            let database_id = match product.id {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(value) => value,
                _ => String::new(),
            };
            if developer_name.is_empty() || name.is_empty() || database_id.is_empty() {
                None
            } else {
                Some(BundleProduct {
                    database_id,
                    developer_name,
                    name,
                })
            }
        })
        .collect();
    Ok(CehrtBundle {
        cehrt_id: cehrt_id.to_string(),
        products,
    })
}

#[derive(Debug, Deserialize)]
struct LookupResponse {
    #[serde(default)]
    products: Vec<ApiProduct>,
}

#[derive(Debug, Deserialize)]
struct ApiProduct {
    id: serde_json::Value,
    #[serde(rename = "developerName")]
    developer_name: Option<String>,
    name: Option<String>,
}

const CREATE_STAGE: &str = r#"
CREATE TEMP TABLE cehrt_stage (
    cehrt_id TEXT,
    developer_name TEXT,
    product_name TEXT,
    chpl_database_id TEXT
)
"#;

const UPSERT_VENDORS: &str = r#"
INSERT INTO vendors (name)
SELECT DISTINCT btrim(developer_name)
FROM cehrt_stage
WHERE btrim(developer_name) <> ''
ON CONFLICT ((lower(name))) DO UPDATE SET name = vendors.name
"#;

const UPSERT_PRODUCTS: &str = r#"
INSERT INTO products (vendor_id, name, chpl_database_id)
SELECT DISTINCT ON (btrim(s.chpl_database_id))
    v.id,
    btrim(s.product_name),
    btrim(s.chpl_database_id)
FROM cehrt_stage s
JOIN vendors v ON lower(v.name) = lower(btrim(s.developer_name))
WHERE btrim(s.chpl_database_id) <> ''
  AND btrim(s.product_name) <> ''
ORDER BY btrim(s.chpl_database_id)
ON CONFLICT (chpl_database_id) WHERE chpl_database_id IS NOT NULL
DO UPDATE SET
    vendor_id = EXCLUDED.vendor_id,
    name = EXCLUDED.name
"#;

const UPSERT_LINKS: &str = r#"
INSERT INTO hospital_vendor_map (
    hospital_id, vendor_id, product_id, source, source_url, confidence, last_verified
)
SELECT
    r.hospital_id,
    v.id,
    p.id,
    $1,
    'https://chpl.healthit.gov/rest/certification_ids/' || s.cehrt_id,
    $2,
    r.period_end
FROM cehrt_stage s
JOIN cehrt_reports r ON r.cehrt_id = s.cehrt_id AND r.source = 'cms_pi_2024'
JOIN vendors v ON lower(v.name) = lower(btrim(s.developer_name))
JOIN products p ON p.chpl_database_id = btrim(s.chpl_database_id)
GROUP BY r.hospital_id, v.id, p.id, s.cehrt_id, r.period_end
ON CONFLICT ON CONSTRAINT hospital_vendor_map_natural_uidx
DO UPDATE SET
    source_url = EXCLUDED.source_url,
    confidence = EXCLUDED.confidence,
    last_verified = GREATEST(hospital_vendor_map.last_verified, EXCLUDED.last_verified)
"#;
