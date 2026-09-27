//! Link a stored product to CVEs only when NVD's own record names that product.
//!
//! Two accepted paths, both exact:
//! the CVE description contains the product name as a phrase, or the official
//! CPE title does and the CPE vendor token is the stored vendor. A keyword
//! that merely shares a word is not a match.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::kev::{self, NvdFacts};
use crate::IngestError;

const NVD_CVE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const PAGE: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CveMatchReport {
    pub products_checked: u64,
    pub products_with_cves: u64,
    pub cves: u64,
    pub links: u64,
}

struct StoredProduct {
    id: Uuid,
    vendor: String,
    name: String,
}

struct ListedCve {
    cve_id: String,
    description: String,
    cvss: Option<Decimal>,
    published: Option<NaiveDate>,
    matched_cpe: Option<String>,
    basis: &'static str,
}

pub async fn match_product_cves(pool: &PgPool) -> Result<CveMatchReport, IngestError> {
    let api_key = std::env::var("NVD_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(IngestError::MissingKey("NVD_API_KEY"))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("vulnrx/0.1")
        .build()?;
    let products = load_products(pool).await?;
    let mut by_name: HashMap<String, Vec<StoredProduct>> = HashMap::new();
    for product in products {
        if !searchable(&product.name) {
            continue;
        }
        by_name.entry(product.name.clone()).or_default().push(product);
    }
    let mut report = CveMatchReport {
        products_checked: 0,
        products_with_cves: 0,
        cves: 0,
        links: 0,
    };
    let mut seen_cves = HashSet::new();
    let names: Vec<String> = by_name.keys().cloned().collect();
    for (index, name) in names.iter().enumerate() {
        let group = &by_name[name];
        report.products_checked += 1;
        let mut listed = phrase_cves(&client, &api_key, name).await?;
        if let Some(identity) = cpe_identity(&client, &api_key, name, group).await? {
            let more = cpe_cves(&client, &api_key, &identity).await?;
            listed.extend(more);
        }
        listed = dedup_cves(listed);
        let sole_vendor = group
            .iter()
            .map(|product| product.vendor.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 1;
        for product in group {
            let applicable: Vec<&ListedCve> = listed
                .iter()
                .filter(|cve| applies(product, cve, sole_vendor))
                .collect();
            if applicable.is_empty() {
                continue;
            }
            report.products_with_cves += 1;
            report.links += store_links(pool, product, &applicable).await?;
            for cve in applicable {
                seen_cves.insert(cve.cve_id.clone());
            }
        }
        if (index + 1) % 25 == 0 {
            eprintln!(
                "nvd product names: {} of {}, {} links so far",
                index + 1,
                names.len(),
                report.links
            );
        }
    }
    let ids: Vec<String> = seen_cves.into_iter().collect();
    report.cves = ids.len() as u64;
    if !ids.is_empty() {
        let scores = kev::fetch_epss(&ids).await?;
        for (cve_id, score) in scores {
            sqlx::query(
                "UPDATE cves SET epss_score = $2 WHERE cve_id = $1 AND epss_score IS NULL",
            )
            .bind(cve_id)
            .bind(score)
            .execute(pool)
            .await?;
        }
    }
    Ok(report)
}

fn searchable(name: &str) -> bool {
    let name = name.trim();
    name.chars().count() >= 10 && !name.contains(['\n', '\r'])
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
        .map(|row| StoredProduct {
            id: row.id,
            vendor: row.vendor,
            name: row.name,
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct ProductVendor {
    id: Uuid,
    name: String,
    vendor: String,
}

async fn phrase_cves(
    client: &reqwest::Client,
    api_key: &str,
    product_name: &str,
) -> Result<Vec<ListedCve>, IngestError> {
    let payload = nvd_get(
        client,
        api_key,
        &format!(
            "{NVD_CVE}?keywordSearch={}&keywordExactMatch&resultsPerPage={PAGE}",
            urlencoding(product_name)
        ),
    )
    .await?;
    Ok(cves_from_payload(&payload)
        .into_iter()
        .filter(|cve| contains_phrase(&cve.description, product_name))
        .map(|mut cve| {
            cve.basis = "nvd_phrase";
            cve
        })
        .collect())
}

async fn cpe_identity(
    client: &reqwest::Client,
    api_key: &str,
    product_name: &str,
    group: &[StoredProduct],
) -> Result<Option<String>, IngestError> {
    let payload = nvd_get(
        client,
        api_key,
        &format!(
            "{NVD_CPE}?keywordSearch={}&keywordExactMatch&resultsPerPage=20",
            urlencoding(product_name)
        ),
    )
    .await?;
    let products = payload
        .get("products")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut identities = HashSet::new();
    for item in products {
        let cpe = item.get("cpe").unwrap_or(&item);
        let title_ok = cpe
            .get("titles")
            .and_then(Value::as_array)
            .is_some_and(|titles| {
                titles.iter().any(|title| {
                    title
                        .get("title")
                        .and_then(Value::as_str)
                        .is_some_and(|text| contains_phrase(text, product_name))
                })
            });
        if !title_ok {
            continue;
        }
        let Some(name) = cpe.get("cpeName").and_then(Value::as_str) else {
            continue;
        };
        let Some((vendor, product)) = cpe_vendor_product(name) else {
            continue;
        };
        let vendor_ok = group.iter().any(|stored| {
            vendor_tokens(&stored.vendor)
                .iter()
                .any(|token| token == &vendor)
        });
        if vendor_ok {
            identities.insert(format!("cpe:2.3:a:{vendor}:{product}"));
        }
    }
    if identities.len() == 1 {
        Ok(identities.into_iter().next())
    } else {
        Ok(None)
    }
}

async fn cpe_cves(
    client: &reqwest::Client,
    api_key: &str,
    identity: &str,
) -> Result<Vec<ListedCve>, IngestError> {
    let mut listed = Vec::new();
    let mut start = 0_usize;
    loop {
        let payload = nvd_get(
            client,
            api_key,
            &format!(
                "{NVD_CVE}?virtualMatchString={}&resultsPerPage={PAGE}&startIndex={start}",
                urlencoding(identity)
            ),
        )
        .await?;
        let page = cves_from_payload(&payload);
        let total = payload
            .get("totalResults")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let count = page.len();
        for mut cve in page {
            cve.basis = "nvd_cpe";
            cve.matched_cpe = Some(identity.to_string());
            listed.push(cve);
        }
        start += count;
        if count == 0 || start as u64 >= total {
            break;
        }
    }
    Ok(listed)
}

fn cves_from_payload(payload: &Value) -> Vec<ListedCve> {
    payload
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let (cve_id, facts) = nvd_row(item)?;
            let description = english_description(item.get("cve")?)?;
            Some(ListedCve {
                cve_id,
                description,
                cvss: facts.cvss,
                published: facts.published,
                matched_cpe: None,
                basis: "nvd_phrase",
            })
        })
        .collect()
}

fn nvd_row(item: &Value) -> Option<(String, NvdFacts)> {
    let cve = item.get("cve")?;
    let cve_id = cve.get("id").and_then(Value::as_str)?.to_string();
    if !cve_id.starts_with("CVE-") {
        return None;
    }
    let published = cve
        .get("published")
        .and_then(Value::as_str)
        .and_then(|value| NaiveDate::parse_from_str(&value[..value.len().min(10)], "%Y-%m-%d").ok());
        let cvss = cve.get("metrics").and_then(|metrics| {
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
                    .and_then(Value::as_f64)
                {
                    return score.to_string().parse::<Decimal>().ok().map(|value| value.round_dp(1));
                }
            }
            None
        });
    Some((
        cve_id,
        NvdFacts {
            cvss,
            published,
        },
    ))
}

fn english_description(cve: &Value) -> Option<String> {
    cve.get("descriptions")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("lang").and_then(Value::as_str) == Some("en"))
                .or(rows.first())
        })
        .and_then(|row| row.get("value").and_then(Value::as_str))
        .map(str::to_string)
}

fn applies(product: &StoredProduct, cve: &ListedCve, sole_vendor: bool) -> bool {
    if let Some(cpe) = &cve.matched_cpe {
        return cpe_vendor_product(cpe).is_some_and(|(vendor, _)| {
            vendor_tokens(&product.vendor).iter().any(|token| token == &vendor)
        });
    }
    sole_vendor || contains_phrase(&cve.description, &product.vendor)
}

fn dedup_cves(listed: Vec<ListedCve>) -> Vec<ListedCve> {
    let mut by_id: HashMap<String, ListedCve> = HashMap::new();
    for cve in listed {
        by_id
            .entry(cve.cve_id.clone())
            .and_modify(|existing| {
                if existing.basis != "nvd_cpe" && cve.basis == "nvd_cpe" {
                    existing.basis = cve.basis;
                    existing.matched_cpe = cve.matched_cpe.clone();
                }
                if existing.cvss.is_none() {
                    existing.cvss = cve.cvss;
                }
            })
            .or_insert(cve);
    }
    by_id.into_values().collect()
}

async fn store_links(
    pool: &PgPool,
    product: &StoredProduct,
    listed: &[&ListedCve],
) -> Result<u64, IngestError> {
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
        .bind(product.id)
        .bind(&cve.cve_id)
        .bind(&cve.matched_cpe)
        .bind(cve.basis)
        .execute(pool)
        .await?
        .rows_affected();
        links += inserted;
        if let Some(cpe) = &cve.matched_cpe {
            sqlx::query(
                "UPDATE products SET cpe_string = $2
                 WHERE id = $1 AND cpe_string IS NULL",
            )
            .bind(product.id)
            .bind(cpe)
            .execute(pool)
            .await?;
        }
    }
    Ok(links)
}

async fn nvd_get(client: &reqwest::Client, api_key: &str, url: &str) -> Result<Value, IngestError> {
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;
    let response = client.get(url).header("apiKey", api_key).send().await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: url.split('?').next().unwrap_or(url).to_string(),
            status: response.status().as_u16(),
        });
    }
    Ok(serde_json::from_slice(&response.bytes().await?)?)
}

fn urlencoding(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn contains_phrase(haystack: &str, phrase: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&phrase.trim().to_ascii_lowercase())
}

pub fn cpe_vendor_product(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("cpe:2.3:")?;
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                current.push(escaped);
            }
            continue;
        }
        if ch == ':' {
            parts.push(std::mem::take(&mut current));
            if parts.len() == 3 {
                break;
            }
            continue;
        }
        current.push(ch);
    }
    if parts.len() < 3 && !current.is_empty() {
        parts.push(current);
    }
    if parts.len() < 3 {
        return None;
    }
    let vendor = parts[1].to_ascii_lowercase();
    let product = parts[2].to_ascii_lowercase();
    if vendor.is_empty() || product.is_empty() || vendor == "*" || product == "*" {
        return None;
    }
    Some((vendor, product))
}

pub fn vendor_tokens(name: &str) -> Vec<String> {
    let mut tokens = vec![cpe_token(name)];
    let stripped = strip_org(name);
    if stripped != name {
        tokens.push(cpe_token(&stripped));
    }
    tokens.retain(|token| token.len() >= 3);
    tokens.sort();
    tokens.dedup();
    tokens
}

fn strip_org(name: &str) -> String {
    let mut words: Vec<&str> = name.split_whitespace().collect();
    const SUFFIXES: &[&str] = &[
        "inc", "inc.", "incorporated", "corp", "corp.", "corporation", "llc", "l.l.c.", "ltd",
        "ltd.", "limited", "company", "co", "co.", "plc", "gmbh",
    ];
    while words
        .last()
        .is_some_and(|word| SUFFIXES.contains(&word.to_ascii_lowercase().as_str()))
    {
        words.pop();
    }
    words.join(" ")
}

fn cpe_token(name: &str) -> String {
    let mut token = String::new();
    let mut underscore = false;
    for ch in name.to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch);
            underscore = false;
        } else if !underscore && !token.is_empty() {
            token.push('_');
            underscore = true;
        }
    }
    while token.ends_with('_') {
        token.pop();
    }
    token
}

#[cfg(test)]
mod tests {
    use super::{cpe_vendor_product, vendor_tokens};

    #[test]
    fn parses_a_cpe_vendor_and_product() {
        let parsed = cpe_vendor_product(
            "cpe:2.3:a:meditech:expanse:2.2:*:*:*:*:*:*:*",
        )
        .unwrap();
        assert_eq!(parsed.0, "meditech");
        assert_eq!(parsed.1, "expanse");
    }

    #[test]
    fn vendor_tokens_drop_a_corporate_suffix() {
        let tokens = vendor_tokens("Medical Information Technology, Inc.");
        assert!(tokens.iter().any(|token| token == "medical_information_technology"));
    }
}
