//! Link a stored product when a CVE List v5 record names that product.
//!
//! The CVE Project record has a structured vendor and product, and sometimes a CPE.
//! A description that merely contains the name is not a match. `n/a` is not a name.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::cve_match::{cpe_vendor_product, vendor_tokens};
use crate::kev;
use crate::IngestError;

const RELEASES: &str = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=40";
const SOURCE: &str = "https://github.com/CVEProject/cvelistV5";

const GENERIC_VENDOR_WORDS: &[&str] = &[
    "health", "healthcare", "medical", "systems", "system", "solutions", "services", "group",
    "technologies", "technology", "software", "international", "digital", "information",
    "hospital", "hospitals", "company", "corporation", "incorporated", "limited", "associates",
    "consulting", "networks", "network", "cloud", "labs", "laboratory",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CveListReport {
    pub records: u64,
    pub skipped: u64,
    pub products_with_cves: u64,
    pub cves: u64,
    pub links: u64,
}

#[derive(Clone)]
struct StoredProduct {
    id: Uuid,
    name_key: String,
    vendor_keys: Vec<String>,
}

struct ListedCve {
    cve_id: String,
    description: String,
    cvss: Option<Decimal>,
    published: Option<NaiveDate>,
    product_id: Uuid,
    matched_cpe: Option<String>,
    basis: &'static str,
}

pub async fn match_cve_list(pool: &PgPool) -> Result<CveListReport, IngestError> {
    let products = load_products(pool).await?;
    let by_name = index_products(products);
    let zip_path = download_baseline().await?;
    let found = tokio::task::spawn_blocking(move || scan_zip(&zip_path, &by_name))
        .await
        .map_err(|err| IngestError::Portal(format!("cve list scan stopped: {err}")))??;
    let mut report = CveListReport {
        records: found.records,
        skipped: found.skipped,
        products_with_cves: 0,
        cves: 0,
        links: 0,
    };
    if found.listed.is_empty() {
        return Ok(report);
    }
    report.links = store_links(pool, &found.listed).await?;
    let mut products_hit = HashSet::new();
    let mut cve_ids = HashSet::new();
    for item in &found.listed {
        products_hit.insert(item.product_id);
        cve_ids.insert(item.cve_id.clone());
    }
    report.products_with_cves = products_hit.len() as u64;
    report.cves = cve_ids.len() as u64;
    let ids: Vec<String> = cve_ids.into_iter().collect();
    let scores = kev::fetch_epss(&ids).await?;
    for (cve_id, score) in scores {
        sqlx::query("UPDATE cves SET epss_score = $2 WHERE cve_id = $1 AND epss_score IS NULL")
            .bind(cve_id)
            .bind(score)
            .execute(pool)
            .await?;
    }
    Ok(report)
}

struct Scan {
    records: u64,
    skipped: u64,
    listed: Vec<ListedCve>,
}

fn scan_zip(path: &Path, by_name: &HashMap<String, Vec<StoredProduct>>) -> Result<Scan, IngestError> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| IngestError::Portal(err.to_string()))?;
    let mut scan = Scan {
        records: 0,
        skipped: 0,
        listed: Vec::new(),
    };
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| IngestError::Portal(err.to_string()))?;
        let name = entry.name().to_string();
        if !name.ends_with(".json") || !name.contains("CVE-") {
            continue;
        }
        let mut body = Vec::new();
        std::io::copy(&mut entry, &mut body)?;
        scan.records += 1;
        match links_from_record(&body, by_name) {
            Ok(links) => scan.listed.extend(links),
            Err(_) => scan.skipped += 1,
        }
        if scan.records.is_multiple_of(25_000) {
            eprintln!(
                "cve list: read {} records, {} links so far",
                scan.records,
                scan.listed.len()
            );
        }
    }
    Ok(scan)
}

fn index_products(products: Vec<StoredProduct>) -> HashMap<String, Vec<StoredProduct>> {
    let mut by_name: HashMap<String, Vec<StoredProduct>> = HashMap::new();
    for product in products {
        by_name.entry(product.name_key.clone()).or_default().push(product);
    }
    by_name
}

async fn load_products(pool: &PgPool) -> Result<Vec<StoredProduct>, IngestError> {
    let rows = sqlx::query_as::<_, ProductVendor>(
        "SELECT p.id, p.name, v.name AS vendor
         FROM products p
         JOIN vendors v ON v.id = p.vendor_id
         ORDER BY p.name, v.name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let name_key = name_key(&row.name)?;
            Some(StoredProduct {
                id: row.id,
                vendor_keys: vendor_keys(&row.vendor),
                name_key,
            })
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct ProductVendor {
    id: Uuid,
    name: String,
    vendor: String,
}

fn links_from_record(
    body: &[u8],
    by_name: &HashMap<String, Vec<StoredProduct>>,
) -> Result<Vec<ListedCve>, IngestError> {
    let value: Value = serde_json::from_slice(body)?;
    let cve = value.get("cveMetadata").unwrap_or(&value);
    if cve.get("state").and_then(Value::as_str) != Some("PUBLISHED") {
        return Ok(Vec::new());
    }
    let Some(cve_id) = cve.get("cveId").and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    if !cve_id.starts_with("CVE-") {
        return Ok(Vec::new());
    }
    let description = english_description(&value).unwrap_or_default();
    let published = cve
        .get("datePublished")
        .and_then(Value::as_str)
        .and_then(|text| NaiveDate::parse_from_str(&text[..text.len().min(10)], "%Y-%m-%d").ok());
    let cvss = cvss_score(&value);
    let mut listed = Vec::new();
    for affected in affected_entries(&value) {
        listed.extend(links_for_affected(
            cve_id,
            &description,
            cvss,
            published,
            affected,
            by_name,
        ));
    }
    Ok(dedup(listed))
}

fn links_for_affected(
    cve_id: &str,
    description: &str,
    cvss: Option<Decimal>,
    published: Option<NaiveDate>,
    affected: &Value,
    by_name: &HashMap<String, Vec<StoredProduct>>,
) -> Vec<ListedCve> {
    let mut listed = Vec::new();
    let vendor = affected.get("vendor").and_then(Value::as_str).unwrap_or("");
    if let Some(product) = affected.get("product").and_then(Value::as_str)
        && let Some(key) = name_key(product)
        && let Some(group) = by_name.get(&key)
    {
        for stored in group {
            if vendor_matches(stored, vendor) {
                listed.push(listed_cve(
                    cve_id, description, cvss, published, stored.id, None, "cve_list",
                ));
            }
        }
    }
    let cpes = affected
        .get("cpes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for cpe in cpes {
        let Some((cpe_vendor, cpe_product)) = cpe_vendor_product(cpe) else {
            continue;
        };
        let Some(key) = name_key(&cpe_product) else {
            continue;
        };
        let Some(group) = by_name.get(&key) else {
            continue;
        };
        let identity = format!("cpe:2.3:a:{cpe_vendor}:{cpe_product}");
        for stored in group {
            if stored.vendor_keys.iter().any(|token| token == &cpe_vendor) {
                listed.push(listed_cve(
                    cve_id,
                    description,
                    cvss,
                    published,
                    stored.id,
                    Some(identity.clone()),
                    "cve_list_cpe",
                ));
            }
        }
    }
    listed
}

fn listed_cve(
    cve_id: &str,
    description: &str,
    cvss: Option<Decimal>,
    published: Option<NaiveDate>,
    product_id: Uuid,
    matched_cpe: Option<String>,
    basis: &'static str,
) -> ListedCve {
    ListedCve {
        cve_id: cve_id.to_string(),
        description: description.to_string(),
        cvss,
        published,
        product_id,
        matched_cpe,
        basis,
    }
}

fn vendor_matches(product: &StoredProduct, affected_vendor: &str) -> bool {
    let Some(key) = name_key(affected_vendor) else {
        return false;
    };
    let lowered = key.to_ascii_lowercase();
    product.vendor_keys.iter().any(|token| token == &lowered)
}

fn vendor_keys(name: &str) -> Vec<String> {
    let mut keys: Vec<String> = vendor_tokens(name)
        .into_iter()
        .map(|token| token.replace('_', ""))
        .filter(|token| name_key(token).is_some())
        .collect();
    for word in name.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        if word.len() >= 4 && !GENERIC_VENDOR_WORDS.contains(&word.to_ascii_lowercase().as_str()) {
            keys.push(word.to_ascii_lowercase());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn name_key(value: &str) -> Option<String> {
    let key: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_uppercase())
        .collect();
    if key.len() < 4 || matches!(key.as_str(), "NA" | "NONE" | "UNKNOWN" | "UNSPECIFIED") {
        None
    } else {
        Some(key)
    }
}

fn affected_entries(value: &Value) -> Vec<&Value> {
    let mut entries = Vec::new();
    if let Some(cna) = value.pointer("/containers/cna/affected").and_then(Value::as_array) {
        entries.extend(cna);
    }
    if let Some(adp) = value.pointer("/containers/adp").and_then(Value::as_array) {
        for container in adp {
            if let Some(affected) = container.get("affected").and_then(Value::as_array) {
                entries.extend(affected);
            }
        }
    }
    entries
}

fn english_description(value: &Value) -> Option<String> {
    value
        .pointer("/containers/cna/descriptions")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("lang").and_then(Value::as_str) == Some("en"))
                .or(rows.first())
        })
        .and_then(|row| row.get("value").and_then(Value::as_str))
        .map(str::to_string)
}

fn cvss_score(value: &Value) -> Option<Decimal> {
    let metrics = value
        .pointer("/containers/cna/metrics")
        .or_else(|| value.pointer("/containers/adp/0/metrics"))
        .and_then(Value::as_array)?;
    for metric in metrics {
        for key in ["cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"] {
            if let Some(score) = metric
                .get(key)
                .and_then(|row| row.get("baseScore"))
                .and_then(Value::as_f64)
            {
                return score.to_string().parse::<Decimal>().ok().map(|parsed| parsed.round_dp(1));
            }
        }
    }
    None
}

fn dedup(listed: Vec<ListedCve>) -> Vec<ListedCve> {
    let mut by_product: HashMap<Uuid, ListedCve> = HashMap::new();
    for item in listed {
        by_product
            .entry(item.product_id)
            .and_modify(|existing| {
                if existing.basis != "cve_list_cpe" && item.basis == "cve_list_cpe" {
                    existing.basis = item.basis;
                    existing.matched_cpe = item.matched_cpe.clone();
                }
            })
            .or_insert(item);
    }
    by_product.into_values().collect()
}

async fn store_links(pool: &PgPool, listed: &[ListedCve]) -> Result<u64, IngestError> {
    let mut links = 0_u64;
    for cve in listed {
        sqlx::query(
            "INSERT INTO cves (cve_id, description, cvss_score, published_date)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (cve_id) DO UPDATE SET
               description = COALESCE(cves.description, EXCLUDED.description),
               cvss_score = COALESCE(cves.cvss_score, EXCLUDED.cvss_score),
               published_date = COALESCE(cves.published_date, EXCLUDED.published_date)",
        )
        .bind(&cve.cve_id)
        .bind(&cve.description)
        .bind(cve.cvss)
        .bind(cve.published)
        .execute(pool)
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO product_cve_map (product_id, cve_id, matched_cpe, match_basis)
             SELECT $1, id, $3, $4 FROM cves WHERE cve_id = $2
             ON CONFLICT (product_id, cve_id) DO UPDATE SET
               matched_cpe = COALESCE(product_cve_map.matched_cpe, EXCLUDED.matched_cpe),
               match_basis = CASE
                 WHEN product_cve_map.match_basis = 'cisa_kev' THEN product_cve_map.match_basis
                 ELSE EXCLUDED.match_basis
               END",
        )
        .bind(cve.product_id)
        .bind(&cve.cve_id)
        .bind(&cve.matched_cpe)
        .bind(cve.basis)
        .execute(pool)
        .await?
        .rows_affected();
        links += inserted;
    }
    Ok(links)
}

async fn download_baseline() -> Result<std::path::PathBuf, IngestError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60 * 45))
        .user_agent("vulnrx/0.1")
        .build()?;
    let response = client
        .get(RELEASES)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: RELEASES.split('?').next().unwrap_or(RELEASES).to_string(),
            status: response.status().as_u16(),
        });
    }
    let releases: Value = serde_json::from_slice(&response.bytes().await?)?;
    let Some((name, url)) = baseline_asset(&releases) else {
        return Err(IngestError::Portal(
            "cve list release has no midnight baseline zip".to_string(),
        ));
    };
    let path = std::env::temp_dir().join(format!("vulnrx-{name}"));
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > 50_000_000
    {
        eprintln!("cve list: using {name}");
        return Ok(path);
    }
    eprintln!("cve list: downloading {name} from {SOURCE}");
    let mut file = client.get(&url).send().await?;
    if !file.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: SOURCE.to_string(),
            status: file.status().as_u16(),
        });
    }
    let mut out = std::fs::File::create(&path)?;
    while let Some(chunk) = file.chunk().await? {
        std::io::Write::write_all(&mut out, &chunk)?;
    }
    Ok(path)
}

fn baseline_asset(releases: &Value) -> Option<(String, String)> {
    let rows = releases.as_array()?;
    for release in rows {
        let assets = release.get("assets")?.as_array()?;
        for asset in assets {
            let name = asset.get("name").and_then(Value::as_str)?;
            if name.contains("_all_CVEs_at_midnight.zip") {
                let url = asset.get("browser_download_url").and_then(Value::as_str)?;
                return Some((name.to_string(), url.to_string()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{links_from_record, index_products, StoredProduct};
    use sqlx::types::Uuid;

    fn product(name: &str, vendor: &str) -> StoredProduct {
        let name_key = super::name_key(name).unwrap();
        StoredProduct {
            id: Uuid::from_u128(1),
            name_key,
            vendor_keys: super::vendor_keys(vendor),
        }
    }

    #[test]
    fn links_a_named_product_and_ignores_a_placeholder() {
        let portal = product("Patient Portal", "eClinicalWorks, LLC");
        let mirth = StoredProduct {
            id: Uuid::from_u128(2),
            ..product("Mirth Connect", "NextGen Healthcare")
        };
        let by_name = index_products(vec![portal, mirth]);
        let named = br#"{
            "cveMetadata": {"cveId": "CVE-2024-10001", "state": "PUBLISHED", "datePublished": "2024-02-01T00:00:00.000Z"},
            "containers": {"cna": {
                "descriptions": [{"lang": "en", "value": "A flaw in the portal."}],
                "affected": [{
                    "vendor": "eClinicalWorks",
                    "product": "Patient Portal",
                    "cpes": ["cpe:2.3:a:eclinicalworks:patient_portal:7.0:*:*:*:*:*:*:*"]
                }]
            }}
        }"#;
        let links = links_from_record(named, &by_name).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].basis, "cve_list_cpe");
        assert_eq!(links[0].cve_id, "CVE-2024-10001");

        let placeholder = br#"{
            "cveMetadata": {"cveId": "CVE-2017-5569", "state": "PUBLISHED"},
            "containers": {"cna": {
                "descriptions": [{"lang": "en", "value": "An issue was discovered in eClinicalWorks Patient Portal."}],
                "affected": [{"vendor": "n/a", "product": "n/a"}]
            }}
        }"#;
        assert!(links_from_record(placeholder, &by_name).unwrap().is_empty());
    }

    #[test]
    fn cpe_vendor_word_matches_nextgen_and_not_a_different_vendor() {
        let mirth = product("Mirth Connect", "NextGen Healthcare");
        let other = StoredProduct {
            id: Uuid::from_u128(3),
            ..product("Mirth Connect", "Other Vendor")
        };
        let by_name = index_products(vec![mirth, other]);
        let body = br#"{
            "cveMetadata": {"cveId": "CVE-2023-43208", "state": "PUBLISHED"},
            "containers": {"cna": {
                "affected": [{
                    "vendor": "n/a",
                    "product": "n/a",
                    "cpes": ["cpe:2.3:a:nextgen:mirth_connect:4.4.0:*:*:*:*:*:*:*"]
                }]
            }}
        }"#;
        let links = links_from_record(body, &by_name).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].product_id, Uuid::from_u128(1));
        assert_eq!(links[0].basis, "cve_list_cpe");
    }
}
