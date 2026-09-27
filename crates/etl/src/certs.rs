//! Last-ditch exposure path. No ZoomEye or Netlas key is required.
//!
//! crt.sh is searched for a certificate whose identity contains one hospital
//! name and yields one hostname. That name is resolved, then Shodan InternetDB
//! is asked what it already knows. A row is stored only when a CPE names one
//! product linked to that hospital. The address is not stored, and no port
//! scan is sent to the hospital.

use std::collections::HashSet;
use std::net::ToSocketAddrs;

use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::cve_list::{name_key, vendor_keys};
use crate::cve_match::cpe_vendor_product;
use crate::index::IndexReport;
use crate::IngestError;

const CRT_SH: &str = "https://crt.sh/";
const INTERNETDB: &str = "https://internetdb.shodan.io";

struct HospitalQuery {
    id: Uuid,
    name: String,
}

struct LinkedProduct {
    id: Uuid,
    name_key: String,
    vendor_keys: Vec<String>,
}

pub async fn query_fallback(pool: &PgPool, limit: Option<i64>) -> Result<IndexReport, IngestError> {
    let limit = limit.unwrap_or(20).clamp(1, 50);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .user_agent("vulnrx/0.1")
        .build()?;
    let hospitals = hospitals_to_query(pool, limit).await?;
    let mut report = IndexReport {
        queries: 0,
        stored: 0,
        stopped: None,
    };
    for hospital in hospitals {
        let certs = match crt_search(&client, &hospital.name).await {
            Ok(certs) => certs,
            Err(status) if status == 429 || status == 503 => {
                report.stopped = Some(format!(
                    "crt.sh returned HTTP {status}; no further certificate lookups"
                ));
                break;
            }
            Err(status) => {
                eprintln!("crt.sh returned HTTP {status}; skipping one hospital");
                continue;
            }
        };
        report.queries += 1;
        let Some(host) = hostnames_for_hospital(&certs, &hospital.name) else {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };
        let products = products_for_hospital(pool, hospital.id).await?;
        if let Some(product_id) = internetdb_product(&client, &host, &products).await? {
            store_fallback(pool, hospital.id, product_id, &hospital.name).await?;
            report.stored += 1;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(report)
}

async fn hospitals_to_query(pool: &PgPool, limit: i64) -> Result<Vec<HospitalQuery>, IngestError> {
    let rows = sqlx::query_as::<_, HospitalRow>(
        "SELECT h.id, h.name
         FROM hospitals h
         WHERE length(btrim(h.name)) >= 12
           AND EXISTS (
             SELECT 1 FROM hospital_vendor_map m
             WHERE m.hospital_id = h.id AND m.product_id IS NOT NULL
           )
         ORDER BY (
             SELECT count(DISTINCT m.product_id)
             FROM hospital_vendor_map m
             WHERE m.hospital_id = h.id
         ) DESC, h.name
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| HospitalQuery {
            id: row.id,
            name: row.name,
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct HospitalRow {
    id: Uuid,
    name: String,
}

async fn products_for_hospital(pool: &PgPool, hospital: Uuid) -> Result<Vec<LinkedProduct>, IngestError> {
    let rows = sqlx::query_as::<_, ProductVendor>(
        "SELECT p.id, p.name, v.name AS vendor
         FROM products p
         JOIN hospital_vendor_map m ON m.product_id = p.id
         JOIN vendors v ON v.id = p.vendor_id
         WHERE m.hospital_id = $1",
    )
    .bind(hospital)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let name_key = name_key(&row.name)?;
            Some(LinkedProduct {
                id: row.id,
                name_key,
                vendor_keys: vendor_keys(&row.vendor),
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

async fn crt_search(client: &reqwest::Client, hospital: &str) -> Result<Vec<Value>, u16> {
    let url = format!(
        "{CRT_SH}?q={}&output=json&exclude=expired",
        urlencoding(hospital)
    );
    let response = client.get(&url).send().await.map_err(|_| 599_u16)?;
    let status = response.status();
    if !status.is_success() {
        return Err(status.as_u16());
    }
    let body = response.text().await.map_err(|_| 599_u16)?;
    let parsed: Value = serde_json::from_str(&body).map_err(|_| 599_u16)?;
    Ok(parsed
        .as_array()
        .cloned()
        .unwrap_or_default())
}

async fn internetdb_product(
    client: &reqwest::Client,
    host: &str,
    products: &[LinkedProduct],
) -> Result<Option<Uuid>, IngestError> {
    let addresses = tokio::task::spawn_blocking({
        let host = host.to_string();
        move || resolve_v4(&host)
    })
    .await
    .map_err(|err| IngestError::Portal(format!("name lookup stopped: {err}")))?;
    for address in addresses.into_iter().take(4) {
        let response = client
            .get(format!("{INTERNETDB}/{address}"))
            .send()
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(IngestError::Portal(
                "internetdb returned HTTP 429; no further lookups".to_string(),
            ));
        }
        if !status.is_success() {
            return Err(IngestError::HttpStatus {
                url: INTERNETDB.to_string(),
                status: status.as_u16(),
            });
        }
        let parsed: Value = serde_json::from_slice(&response.bytes().await?)?;
        let cpes = parsed
            .get("cpes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        if let Some(product_id) = product_for_cpes(cpes, products) {
            return Ok(Some(product_id));
        }
    }
    Ok(None)
}

fn resolve_v4(host: &str) -> Vec<String> {
    let Ok(found) = (host, 443).to_socket_addrs() else {
        return Vec::new();
    };
    let mut addresses = Vec::new();
    for socket in found {
        if let std::net::IpAddr::V4(address) = socket.ip() {
            let text = address.to_string();
            if !addresses.contains(&text) {
                addresses.push(text);
            }
        }
    }
    addresses
}

async fn store_fallback(
    pool: &PgPool,
    hospital_id: Uuid,
    product_id: Uuid,
    hospital_name: &str,
) -> Result<(), IngestError> {
    sqlx::query(
        "DELETE FROM exposures
         WHERE hospital_id = $1 AND product_id = $2 AND source = 'internetdb'",
    )
    .bind(hospital_id)
    .bind(product_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO exposures (hospital_id, product_id, exposed_service, source, raw_reference)
         VALUES ($1, $2, 'cpe', 'internetdb', $3)",
    )
    .bind(hospital_id)
    .bind(product_id)
    .bind(format!(
        "internetdb cpe matched a crt.sh identity containing {hospital_name}"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

fn hostnames_for_hospital(certs: &[Value], hospital: &str) -> Option<String> {
    let needle = hospital.trim().to_ascii_lowercase();
    if needle.chars().count() < 12 {
        return None;
    }
    let mut hosts = HashSet::new();
    for cert in certs {
        let identity = cert
            .get("name_value")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !identity.to_ascii_lowercase().contains(&needle) {
            continue;
        }
        for part in identity.split(|ch: char| ch.is_whitespace() || ch == ',') {
            if let Some(host) = dns_name(part) {
                hosts.insert(host);
            }
        }
    }
    if hosts.len() == 1 {
        hosts.into_iter().next()
    } else {
        None
    }
}

fn dns_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    if name.len() < 4
        || name.len() > 253
        || !name.contains('.')
        || name.parse::<std::net::Ipv4Addr>().is_ok()
    {
        return None;
    }
    if name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("..")
    {
        Some(name)
    } else {
        None
    }
}

fn product_for_cpes<'a>(
    cpes: impl Iterator<Item = &'a str>,
    products: &[LinkedProduct],
) -> Option<Uuid> {
    let mut found = HashSet::new();
    for cpe in cpes {
        let Some((vendor, product)) = cpe_parts(cpe) else {
            continue;
        };
        let Some(key) = name_key(&product.replace('_', " ")) else {
            continue;
        };
        let vendor_token = vendor.replace('_', "");
        for stored in products {
            if stored.name_key == key && stored.vendor_keys.iter().any(|token| token == &vendor_token)
            {
                found.insert(stored.id);
            }
        }
    }
    if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    }
}

fn cpe_parts(cpe: &str) -> Option<(String, String)> {
    if let Some(parsed) = cpe_vendor_product(cpe) {
        return Some(parsed);
    }
    let rest = cpe.strip_prefix("cpe:/")?;
    let mut parts = rest.split(':');
    let _kind = parts.next()?;
    let vendor = parts.next()?.to_ascii_lowercase();
    let product = parts.next()?.to_ascii_lowercase();
    if vendor.is_empty() || product.is_empty() || vendor == "*" || product == "*" {
        return None;
    }
    Some((vendor, product))
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

#[cfg(test)]
mod tests {
    use super::{hostnames_for_hospital, product_for_cpes, LinkedProduct};
    use serde_json::json;
    use sqlx::types::Uuid;

    #[test]
    fn keeps_one_hostname_when_the_certificate_names_the_hospital() {
        let certs = vec![json!({
            "name_value": "Alaska Native Medical Center\nportal.example-hospital.test"
        })];
        assert_eq!(
            hostnames_for_hospital(&certs, "Alaska Native Medical Center").as_deref(),
            Some("portal.example-hospital.test")
        );
        let two = vec![json!({
            "name_value": "Alaska Native Medical Center\none.test\ntwo.test"
        })];
        assert!(hostnames_for_hospital(&two, "Alaska Native Medical Center").is_none());
    }

    #[test]
    fn links_one_cpe_to_the_hospital_product() {
        let products = vec![LinkedProduct {
            id: Uuid::from_u128(7),
            name_key: crate::cve_list::name_key("Mirth Connect").unwrap(),
            vendor_keys: crate::cve_list::vendor_keys("NextGen Healthcare"),
        }];
        let matched = product_for_cpes(
            ["cpe:/a:nextgen:mirth_connect:4.4"].into_iter(),
            &products,
        );
        assert_eq!(matched, Some(Uuid::from_u128(7)));
        assert!(product_for_cpes(["cpe:/a:nginx:nginx:1.14"].into_iter(), &products).is_none());
    }
}
