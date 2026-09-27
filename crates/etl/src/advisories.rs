//! Link a stored product when a CISA CSAF advisory names that product and a CVE.
//!
//! The product name and vendor come from the advisory's product tree. A word in
//! the summary is not enough.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::cve_list::{name_key, vendor_keys};
use crate::kev;
use crate::IngestError;

const CSAF_ZIP: &str = "https://github.com/cisagov/CSAF/archive/refs/heads/develop.zip";
const SOURCE: &str = "https://github.com/cisagov/CSAF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvisoryReport {
    pub advisories: u64,
    pub skipped: u64,
    pub products_with_cves: u64,
    pub cves: u64,
    pub links: u64,
}

struct StoredProduct {
    id: Uuid,
    name_key: String,
    vendor_keys: Vec<String>,
}

struct NamedProduct {
    vendor: String,
    name: String,
}

struct ListedCve {
    cve_id: String,
    description: String,
    cvss: Option<Decimal>,
    published: Option<NaiveDate>,
    product_id: Uuid,
}

pub async fn match_advisories(pool: &PgPool) -> Result<AdvisoryReport, IngestError> {
    let products = load_products(pool).await?;
    let by_name = index_products(products);
    let zip_path = download_csaf().await?;
    let found = tokio::task::spawn_blocking(move || scan_zip(&zip_path, &by_name))
        .await
        .map_err(|err| IngestError::Portal(format!("advisory scan stopped: {err}")))??;
    let mut report = AdvisoryReport {
        advisories: found.advisories,
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
    advisories: u64,
    skipped: u64,
    listed: Vec<ListedCve>,
}

fn scan_zip(path: &Path, by_name: &HashMap<String, Vec<StoredProduct>>) -> Result<Scan, IngestError> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| IngestError::Portal(err.to_string()))?;
    let mut scan = Scan {
        advisories: 0,
        skipped: 0,
        listed: Vec::new(),
    };
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| IngestError::Portal(err.to_string()))?;
        let name = entry.name().to_string();
        if !name.ends_with(".json") || !name.contains("csaf_files/") {
            continue;
        }
        let mut body = Vec::new();
        std::io::copy(&mut entry, &mut body)?;
        scan.advisories += 1;
        match links_from_advisory(&body, by_name) {
            Ok(links) => scan.listed.extend(links),
            Err(_) => scan.skipped += 1,
        }
        if scan.advisories.is_multiple_of(500) {
            eprintln!(
                "cisa advisories: read {} files, {} links so far",
                scan.advisories,
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
         JOIN vendors v ON v.id = p.vendor_id",
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

fn links_from_advisory(
    body: &[u8],
    by_name: &HashMap<String, Vec<StoredProduct>>,
) -> Result<Vec<ListedCve>, IngestError> {
    let value: Value = serde_json::from_slice(body)?;
    let published = value
        .pointer("/document/tracking/initial_release_date")
        .and_then(Value::as_str)
        .and_then(|text| NaiveDate::parse_from_str(&text[..text.len().min(10)], "%Y-%m-%d").ok());
    let mut products = HashMap::new();
    if let Some(tree) = value.get("product_tree") {
        walk_tree(tree, "", "", &mut products);
    }
    let mut listed = Vec::new();
    let vulns = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for vuln in vulns {
        let Some(cve_id) = vuln.get("cve").and_then(Value::as_str) else {
            continue;
        };
        if !cve_id.starts_with("CVE-") {
            continue;
        }
        let description = vuln_summary(vuln).unwrap_or_default();
        let cvss = vuln
            .pointer("/scores/0/cvss_v3/baseScore")
            .and_then(Value::as_f64)
            .and_then(|score| score.to_string().parse::<Decimal>().ok())
            .map(|score| score.round_dp(1));
        let ids = vuln
            .pointer("/product_status/known_affected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        for id in ids {
            let Some(named) = products.get(id) else {
                continue;
            };
            let Some(key) = name_key(&named.name) else {
                continue;
            };
            let Some(group) = by_name.get(&key) else {
                continue;
            };
            for stored in group {
                if stored.vendor_keys.iter().any(|token| {
                    name_key(&named.vendor).is_some_and(|vendor| token == &vendor.to_ascii_lowercase())
                }) {
                    listed.push(ListedCve {
                        cve_id: cve_id.to_string(),
                        description: description.clone(),
                        cvss,
                        published,
                        product_id: stored.id,
                    });
                }
            }
        }
    }
    Ok(dedup(listed))
}

fn walk_tree(node: &Value, vendor: &str, product_name: &str, out: &mut HashMap<String, NamedProduct>) {
    let category = node.get("category").and_then(Value::as_str).unwrap_or("");
    let branch_name = node.get("name").and_then(Value::as_str).unwrap_or("");
    let vendor = if category == "vendor" && !branch_name.is_empty() {
        branch_name
    } else {
        vendor
    };
    let product_name = if category == "product_name" && !branch_name.is_empty() {
        branch_name
    } else {
        product_name
    };
    if let Some(id) = node.pointer("/product/product_id").and_then(Value::as_str)
        && !product_name.is_empty()
    {
        out.insert(
            id.to_string(),
            NamedProduct {
                vendor: vendor.to_string(),
                name: product_name.to_string(),
            },
        );
    }
    if let Some(branches) = node.get("branches").and_then(Value::as_array) {
        for branch in branches {
            walk_tree(branch, vendor, product_name, out);
        }
    }
}

fn vuln_summary(vuln: &Value) -> Option<String> {
    vuln.get("notes")
        .and_then(Value::as_array)
        .and_then(|notes| {
            notes.iter().find(|note| note.get("category").and_then(Value::as_str) == Some("summary"))
        })
        .and_then(|note| note.get("text").and_then(Value::as_str))
        .map(str::to_string)
}

fn dedup(listed: Vec<ListedCve>) -> Vec<ListedCve> {
    let mut seen = HashMap::new();
    for item in listed {
        seen.entry((item.product_id, item.cve_id.clone())).or_insert(item);
    }
    seen.into_values().collect()
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
            "INSERT INTO product_cve_map (product_id, cve_id, match_basis)
             SELECT $1, id, 'cisa_csaf' FROM cves WHERE cve_id = $2
             ON CONFLICT (product_id, cve_id) DO UPDATE SET
               match_basis = CASE
                 WHEN product_cve_map.match_basis IN ('cisa_kev', 'cve_list', 'cve_list_cpe', 'nvd_phrase', 'nvd_cpe')
                   THEN product_cve_map.match_basis
                 ELSE EXCLUDED.match_basis
               END",
        )
        .bind(cve.product_id)
        .bind(&cve.cve_id)
        .execute(pool)
        .await?
        .rows_affected();
        links += inserted;
    }
    Ok(links)
}

async fn download_csaf() -> Result<std::path::PathBuf, IngestError> {
    let path = std::env::temp_dir().join("vulnrx-cisa-csaf-develop.zip");
    if std::fs::metadata(&path).map(|meta| meta.len() > 1_000_000).unwrap_or(false) {
        eprintln!("cisa advisories: using cached CSAF archive");
        return Ok(path);
    }
    eprintln!("cisa advisories: downloading {SOURCE}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60 * 20))
        .user_agent("vulnrx/0.1")
        .build()?;
    let mut response = client.get(CSAF_ZIP).send().await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: SOURCE.to_string(),
            status: response.status().as_u16(),
        });
    }
    let mut out = std::fs::File::create(&path)?;
    while let Some(chunk) = response.chunk().await? {
        out.write_all(&chunk)?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{index_products, links_from_advisory, StoredProduct};
    use sqlx::types::Uuid;

    #[test]
    fn links_the_named_product_and_ignores_a_different_vendor() {
        let named = StoredProduct {
            id: Uuid::from_u128(1),
            name_key: crate::cve_list::name_key("ScadaBR").unwrap(),
            vendor_keys: crate::cve_list::vendor_keys("ScadaBR"),
        };
        let other = StoredProduct {
            id: Uuid::from_u128(2),
            name_key: crate::cve_list::name_key("ScadaBR").unwrap(),
            vendor_keys: crate::cve_list::vendor_keys("Other Vendor"),
        };
        let by_name = index_products(vec![named, other]);
        let body = br#"{
            "document": {"tracking": {"initial_release_date": "2026-05-19T06:00:00.000Z"}},
            "product_tree": {"branches": [{
                "category": "vendor", "name": "ScadaBR",
                "branches": [{
                    "category": "product_name", "name": "ScadaBR",
                    "branches": [{
                        "category": "product_version", "name": "1.2.0",
                        "product": {"name": "ScadaBR ScadaBR: 1.2.0", "product_id": "CSAFPID-0001"}
                    }]
                }]
            }]},
            "vulnerabilities": [{
                "cve": "CVE-2026-8602",
                "notes": [{"category": "summary", "text": "A flaw in the named product."}],
                "product_status": {"known_affected": ["CSAFPID-0001"]},
                "scores": [{"cvss_v3": {"baseScore": 9.1}}]
            }]
        }"#;
        let links = links_from_advisory(body, &by_name).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].product_id, Uuid::from_u128(1));
        assert_eq!(links[0].cve_id, "CVE-2026-8602");
        assert_eq!(links[0].cvss.unwrap().to_string(), "9.1");
    }
}
