use std::collections::HashMap;

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value;
use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;

pub const KEV_CATALOG_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
pub const NVD_KEV_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev";

const EPSS_BATCH: usize = 100;
const NVD_PAGE: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub description: String,
    pub date_added: NaiveDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KevReport {
    pub cves: u64,
    pub with_epss: u64,
    pub with_cvss: u64,
    pub product_links: u64,
}

pub fn parse_kev_catalog(body: &[u8]) -> Result<Vec<KevEntry>, IngestError> {
    let catalog: Catalog = serde_json::from_slice(body)?;
    let mut entries = Vec::new();
    for item in catalog.vulnerabilities {
        if !valid_cve(&item.cve_id) {
            continue;
        }
        let Some(date_added) = NaiveDate::parse_from_str(&item.date_added, "%Y-%m-%d").ok() else {
            continue;
        };
        entries.push(KevEntry {
            cve_id: item.cve_id,
            vendor: item.vendor_project,
            product: item.product,
            description: item.short_description,
            date_added,
        });
    }
    Ok(entries)
}

pub async fn fetch_epss(cve_ids: &[String]) -> Result<HashMap<String, Decimal>, IngestError> {
    let client = client()?;
    let mut scores = HashMap::new();
    for batch in cve_ids.chunks(EPSS_BATCH) {
        let url = format!("{EPSS_URL}?cve={}", batch.join(","));
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(IngestError::HttpStatus {
                url,
                status: response.status().as_u16(),
            });
        }
        let payload: EpssResponse = serde_json::from_slice(&response.bytes().await?)?;
        for row in payload.data {
            if let Ok(score) = row.epss.parse::<Decimal>()
                && (Decimal::ZERO..=Decimal::ONE).contains(&score)
            {
                scores.insert(row.cve, score.round_dp(5));
            }
        }
    }
    Ok(scores)
}

pub async fn fetch_nvd_kev() -> Result<HashMap<String, NvdFacts>, IngestError> {
    let client = client()?;
    let api_key = std::env::var("NVD_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty());
    let pause = if api_key.is_some() {
        std::time::Duration::from_millis(200)
    } else {
        std::time::Duration::from_secs(6)
    };
    let mut facts = HashMap::new();
    let mut start = 0_usize;
    let mut total = None;
    loop {
        if start > 0 {
            tokio::time::sleep(pause).await;
        }
        let url = format!("{NVD_KEV_URL}&resultsPerPage={NVD_PAGE}&startIndex={start}");
        let mut request = client.get(&url);
        if let Some(key) = &api_key {
            request = request.header("apiKey", key);
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(IngestError::HttpStatus {
                url,
                status: response.status().as_u16(),
            });
        }
        let payload: Value = serde_json::from_slice(&response.bytes().await?)?;
        if total.is_none() {
            total = payload.get("totalResults").and_then(Value::as_u64);
        }
        let page = payload
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if page.is_empty() {
            break;
        }
        for item in &page {
            if let Some((cve_id, fact)) = nvd_facts(item) {
                facts.insert(cve_id, fact);
            }
        }
        start += page.len();
        eprintln!("nvd kev: read {start} of {}", total.unwrap_or(start as u64));
        if total.is_some_and(|count| start as u64 >= count) {
            break;
        }
    }
    Ok(facts)
}

pub async fn ingest_kev(
    pool: &PgPool,
    entries: &[KevEntry],
    epss: &HashMap<String, Decimal>,
    nvd: &HashMap<String, NvdFacts>,
) -> Result<KevReport, IngestError> {
    let mut projected = csv::Writer::from_writer(Vec::new());
    projected.write_record([
        "cve_id",
        "description",
        "cvss_score",
        "epss_score",
        "published_date",
        "kev_vendor",
        "kev_product",
    ])?;
    let mut with_epss = 0_u64;
    let mut with_cvss = 0_u64;
    for entry in entries {
        let facts = nvd.get(&entry.cve_id);
        let cvss = facts.and_then(|fact| fact.cvss);
        let published = facts
            .and_then(|fact| fact.published)
            .unwrap_or(entry.date_added);
        let epss_score = epss.get(&entry.cve_id).copied();
        if epss_score.is_some() {
            with_epss += 1;
        }
        if cvss.is_some() {
            with_cvss += 1;
        }
        projected.write_record([
            entry.cve_id.as_str(),
            entry.description.as_str(),
            &cvss.map(|score| score.to_string()).unwrap_or_default(),
            &epss_score
                .map(|score| score.to_string())
                .unwrap_or_default(),
            &published.format("%Y-%m-%d").to_string(),
            entry.vendor.as_str(),
            entry.product.as_str(),
        ])?;
    }
    projected.flush()?;
    let bytes = projected
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;

    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS kev_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY kev_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(bytes).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS kev_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let cves = sqlx::query(UPSERT_CVES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let product_links = sqlx::query(LINK_PRODUCTS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS kev_stage")
        .execute(&mut *conn)
        .await;
    Ok(KevReport {
        cves,
        with_epss,
        with_cvss,
        product_links,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvdFacts {
    pub cvss: Option<Decimal>,
    pub published: Option<NaiveDate>,
}

fn nvd_facts(item: &Value) -> Option<(String, NvdFacts)> {
    let cve = item.get("cve")?;
    let cve_id = cve.get("id").and_then(Value::as_str)?.to_string();
    if !valid_cve(&cve_id) {
        return None;
    }
    let published = cve
        .get("published")
        .and_then(Value::as_str)
        .and_then(|value| {
            NaiveDate::parse_from_str(&value[..value.len().min(10)], "%Y-%m-%d").ok()
        });
    Some((
        cve_id,
        NvdFacts {
            cvss: cvss_score(cve.get("metrics")),
            published,
        },
    ))
}

fn cvss_score(metrics: Option<&Value>) -> Option<Decimal> {
    let metrics = metrics?;
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(rows) = metrics.get(key).and_then(Value::as_array) else {
            continue;
        };
        let chosen = rows
            .iter()
            .find(|row| row.get("type").and_then(Value::as_str) == Some("Primary"))
            .or(rows.first());
        if let Some(score) = chosen
            .and_then(|row| row.get("cvssData"))
            .and_then(|data| data.get("baseScore"))
            .and_then(decimal_value)
            && (Decimal::ZERO..=Decimal::TEN).contains(&score)
        {
            return Some(score);
        }
    }
    None
}

fn decimal_value(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(number) => number.to_string().parse().ok(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn valid_cve(cve_id: &str) -> bool {
    let mut parts = cve_id.split('-');
    let Some("CVE") = parts.next() else {
        return false;
    };
    let Some(year) = parts.next() else {
        return false;
    };
    let Some(number) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && number.len() >= 4
        && number.chars().all(|c| c.is_ascii_digit())
}

fn client() -> Result<reqwest::Client, IngestError> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .user_agent("vulnrx/0.1")
        .build()?)
}

#[derive(Debug, Deserialize)]
struct Catalog {
    vulnerabilities: Vec<CatalogEntry>,
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    product: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssRow>,
}

#[derive(Debug, Deserialize)]
struct EpssRow {
    cve: String,
    epss: String,
}

const CREATE_STAGE: &str = r#"
CREATE TEMP TABLE kev_stage (
    cve_id TEXT,
    description TEXT,
    cvss_score TEXT,
    epss_score TEXT,
    published_date TEXT,
    kev_vendor TEXT,
    kev_product TEXT
)
"#;

const UPSERT_CVES: &str = r#"
INSERT INTO cves (
    cve_id, description, cvss_score, epss_score, is_kev, published_date, kev_vendor, kev_product
)
SELECT
    cve_id,
    NULLIF(description, ''),
    NULLIF(cvss_score, '')::numeric,
    NULLIF(epss_score, '')::numeric,
    TRUE,
    NULLIF(published_date, '')::date,
    NULLIF(kev_vendor, ''),
    NULLIF(kev_product, '')
FROM kev_stage
WHERE cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
ON CONFLICT (cve_id) DO UPDATE SET
    description = COALESCE(EXCLUDED.description, cves.description),
    cvss_score = COALESCE(EXCLUDED.cvss_score, cves.cvss_score),
    epss_score = COALESCE(EXCLUDED.epss_score, cves.epss_score),
    is_kev = TRUE,
    published_date = COALESCE(EXCLUDED.published_date, cves.published_date),
    kev_vendor = COALESCE(EXCLUDED.kev_vendor, cves.kev_vendor),
    kev_product = COALESCE(EXCLUDED.kev_product, cves.kev_product)
"#;

const LINK_PRODUCTS: &str = r#"
INSERT INTO product_cve_map (product_id, cve_id, match_basis)
SELECT product.id, cve.id, 'cisa_kev'
FROM cves AS cve
JOIN vendors AS vendor
  ON length(regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g')) >= 4
 AND (
    regexp_replace(upper(vendor.name), '[^A-Z0-9]+', '', 'g')
      = regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g')
    OR regexp_replace(upper(vendor.name), '[^A-Z0-9]+', '', 'g')
      LIKE regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g') || '%'
 )
JOIN products AS product
  ON product.vendor_id = vendor.id
 AND length(regexp_replace(upper(cve.kev_product), '[^A-Z0-9]+', '', 'g')) >= 4
 AND regexp_replace(upper(product.name), '[^A-Z0-9]+', '', 'g')
   = regexp_replace(upper(cve.kev_product), '[^A-Z0-9]+', '', 'g')
WHERE cve.is_kev IS TRUE
  AND (
      SELECT count(DISTINCT other_product.id)
      FROM vendors AS other_vendor
      JOIN products AS other_product ON other_product.vendor_id = other_vendor.id
      WHERE length(regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g')) >= 4
        AND (
            regexp_replace(upper(other_vendor.name), '[^A-Z0-9]+', '', 'g')
              = regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g')
            OR regexp_replace(upper(other_vendor.name), '[^A-Z0-9]+', '', 'g')
              LIKE regexp_replace(upper(cve.kev_vendor), '[^A-Z0-9]+', '', 'g') || '%'
        )
        AND length(regexp_replace(upper(cve.kev_product), '[^A-Z0-9]+', '', 'g')) >= 4
        AND regexp_replace(upper(other_product.name), '[^A-Z0-9]+', '', 'g')
          = regexp_replace(upper(cve.kev_product), '[^A-Z0-9]+', '', 'g')
  ) = 1
ON CONFLICT (product_id, cve_id) DO UPDATE SET
    match_basis = EXCLUDED.match_basis
"#;

#[cfg(test)]
mod tests {
    use super::parse_kev_catalog;

    #[test]
    fn parses_a_catalog_entry() {
        let body = br#"{
            "vulnerabilities": [{
                "cveID": "CVE-2024-3400",
                "vendorProject": "Palo Alto Networks",
                "product": "PAN-OS",
                "shortDescription": "Palo Alto Networks PAN-OS contains a command injection vulnerability.",
                "dateAdded": "2024-04-12"
            }]
        }"#;
        let entries = parse_kev_catalog(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-3400");
        assert_eq!(entries[0].product, "PAN-OS");
    }
}
