//! Ask Shodan or Censys whether their existing index already names a stored product.
//!
//! This does not open a connection to a hospital. A hit is stored only when the
//! index result itself names that product. Host addresses are not stored.

use chrono::NaiveDate;
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::IngestError;

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexReport {
    pub queries: u64,
    pub stored: u64,
    pub stopped: Option<String>,
}

struct ProductQuery {
    id: Uuid,
    name: String,
    query: String,
}

pub async fn query_shodan(pool: &PgPool, limit: Option<i64>) -> Result<IndexReport, IngestError> {
    let key = require_key("SHODAN_API_KEY")?;
    let client = http_client()?;
    let products = products_to_query(pool, clamp_limit(limit)).await?;
    let mut report = IndexReport {
        queries: 0,
        stored: 0,
        stopped: None,
    };
    for product in products {
        match shodan_search(&client, &key, &product.query).await {
            Ok(search) => {
                report.queries += 1;
                if let Some(hit) = confirming_hit(&search.matches, &product.name) {
                    store_hit(
                        pool,
                        product.id,
                        "shodan",
                        &hit.service,
                        hit.seen,
                        &format!(
                            "shodan {} total {} {}",
                            product.query, search.total, hit.service
                        ),
                    )
                    .await?;
                    report.stored += 1;
                }
            }
            Err(Stop::Credits(message)) => {
                report.stopped = Some(message);
                break;
            }
            Err(Stop::Failed(err)) => return Err(err),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(report)
}

pub async fn query_censys(pool: &PgPool, limit: Option<i64>) -> Result<IndexReport, IngestError> {
    let key = require_key("CENSYS_API_KEY")?;
    let client = http_client()?;
    let products = products_to_query(pool, clamp_limit(limit)).await?;
    let mut report = IndexReport {
        queries: 0,
        stored: 0,
        stopped: None,
    };
    for product in products {
        match censys_search(&client, &key, &product.query).await {
            Ok(search) => {
                report.queries += 1;
                if let Some(hit) = confirming_hit(&search.matches, &product.name) {
                    store_hit(
                        pool,
                        product.id,
                        "censys",
                        &hit.service,
                        hit.seen,
                        &format!(
                            "censys {} total {} {}",
                            product.query, search.total, hit.service
                        ),
                    )
                    .await?;
                    report.stored += 1;
                }
            }
            Err(Stop::Credits(message)) => {
                report.stopped = Some(message);
                break;
            }
            Err(Stop::Failed(err)) => return Err(err),
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    Ok(report)
}

fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

fn require_key(name: &'static str) -> Result<String, IngestError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(IngestError::MissingKey(name))
}

fn http_client() -> Result<reqwest::Client, IngestError> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("vulnrx/0.1")
        .build()?)
}

async fn products_to_query(pool: &PgPool, limit: i64) -> Result<Vec<ProductQuery>, IngestError> {
    let rows = sqlx::query_as::<_, ProductRow>(
        "SELECT p.id, p.name
         FROM products p
         JOIN hospital_vendor_map m ON m.product_id = p.id
         GROUP BY p.id, p.name
         ORDER BY COUNT(DISTINCT m.hospital_id) DESC, p.name
         LIMIT $1",
    )
    .bind(limit.saturating_mul(3))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let query = index_query(&row.name)?;
            Some(ProductQuery {
                id: row.id,
                name: row.name,
                query,
            })
        })
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect())
}

#[derive(sqlx::FromRow)]
struct ProductRow {
    id: Uuid,
    name: String,
}

/// A quoted product name. Short names and names with quotes are skipped.
pub fn index_query(name: &str) -> Option<String> {
    let name = name.trim();
    if name.chars().count() < 8 || name.contains('"') || name.contains(['\n', '\r']) {
        return None;
    }
    Some(format!("\"{name}\""))
}

struct SearchHit {
    matches: Vec<Value>,
    total: i64,
}

struct ConfirmedHit {
    service: String,
    seen: Option<NaiveDate>,
}

enum Stop {
    Credits(String),
    Failed(IngestError),
}

async fn shodan_search(
    client: &reqwest::Client,
    key: &str,
    query: &str,
) -> Result<SearchHit, Stop> {
    let url = reqwest::Url::parse_with_params(
        "https://api.shodan.io/shodan/host/search",
        [("query", query), ("page", "1"), ("key", key)],
    )
    .map_err(|err| Stop::Failed(IngestError::Portal(err.to_string())))?;
    let response = client.get(url).send().await.map_err(|err| Stop::Failed(err.into()))?;
    let status = response.status();
    let body = response.text().await.map_err(|err| Stop::Failed(err.into()))?;
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::PAYMENT_REQUIRED
        || status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        return Err(Stop::Credits(format!(
            "shodan returned HTTP {status} ({}); no further index queries",
            redact(&body, key)
        )));
    }
    if !status.is_success() {
        return Err(Stop::Failed(IngestError::HttpStatus {
            url: "https://api.shodan.io/shodan/host/search".to_string(),
            status: status.as_u16(),
        }));
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|err| Stop::Failed(err.into()))?;
    let total = parsed.get("total").and_then(Value::as_i64).unwrap_or(0);
    let matches = parsed
        .get("matches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(SearchHit { matches, total })
}

async fn censys_search(
    client: &reqwest::Client,
    key: &str,
    query: &str,
) -> Result<SearchHit, Stop> {
    let response = client
        .post("https://api.platform.censys.io/v3/global/search/query")
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "query": query,
                "page_size": 5
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|err| Stop::Failed(err.into()))?;
    let status = response.status();
    let body = response.text().await.map_err(|err| Stop::Failed(err.into()))?;
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::PAYMENT_REQUIRED
        || status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        return Err(Stop::Credits(format!(
            "censys returned HTTP {status} ({}); no further index queries",
            redact(&body, key)
        )));
    }
    if !status.is_success() {
        return Err(Stop::Failed(IngestError::HttpStatus {
            url: "https://api.platform.censys.io/v3/global/search/query".to_string(),
            status: status.as_u16(),
        }));
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|err| Stop::Failed(err.into()))?;
    let result = parsed.get("result").unwrap_or(&parsed);
    let total = result
        .get("total")
        .or_else(|| result.get("total_hits"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let matches = result
        .get("hits")
        .or_else(|| result.get("matches"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(SearchHit { matches, total })
}

fn redact(body: &str, secret: &str) -> String {
    let text = if secret.is_empty() {
        body.to_string()
    } else {
        body.replace(secret, "[redacted]")
    };
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(160).collect()
}

fn confirming_hit(matches: &[Value], product_name: &str) -> Option<ConfirmedHit> {
    let needle = product_name.trim().to_ascii_lowercase();
    for hit in matches {
        let mut fields = Vec::new();
        collect_named_strings(hit, &["product", "title", "vendor"], &mut fields);
        if !fields.iter().any(|field| field.to_ascii_lowercase().contains(&needle)) {
            continue;
        }
        let port = hit.get("port").and_then(Value::as_i64);
        let transport = hit.get("transport").and_then(Value::as_str).unwrap_or("tcp");
        let service = match port {
            Some(port) => format!("{port}/{transport}"),
            None => "index".to_string(),
        };
        let seen = hit
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(|value| NaiveDate::parse_from_str(&value[..value.len().min(10)], "%Y-%m-%d").ok());
        return Some(ConfirmedHit { service, seen });
    }
    None
}

fn collect_named_strings<'a>(value: &'a Value, keys: &[&str], out: &mut Vec<&'a str>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if keys.contains(&key.as_str())
                    && let Some(text) = child.as_str()
                {
                    out.push(text);
                }
                collect_named_strings(child, keys, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_named_strings(item, keys, out);
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

async fn store_hit(
    pool: &PgPool,
    product_id: Uuid,
    source: &str,
    service: &str,
    seen: Option<NaiveDate>,
    reference: &str,
) -> Result<(), IngestError> {
    sqlx::query(
        "DELETE FROM exposures
         WHERE product_id = $1 AND source = $2 AND raw_reference LIKE $3",
    )
    .bind(product_id)
    .bind(source)
    .bind(format!("{source} %"))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO exposures (product_id, exposed_service, source, last_seen, raw_reference)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(product_id)
    .bind(service)
    .bind(source)
    .bind(seen)
    .bind(reference)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{confirming_hit, index_query};
    use serde_json::json;

    #[test]
    fn skips_a_short_or_quoted_product_name() {
        assert!(index_query("Chart").is_none());
        assert!(index_query("Epic \"Care\"").is_none());
        assert_eq!(
            index_query("EpicCare Inpatient Base").as_deref(),
            Some("\"EpicCare Inpatient Base\"")
        );
    }

    #[test]
    fn keeps_a_match_only_when_the_index_names_the_product() {
        let matches = vec![
            json!({"port": 80, "product": "nginx", "http": {"title": "Welcome"}}),
            json!({"port": 443, "transport": "tcp", "product": "EpicCare Inpatient Base", "timestamp": "2026-03-01T00:00:00"}),
        ];
        let hit = confirming_hit(&matches, "EpicCare Inpatient Base").unwrap();
        assert_eq!(hit.service, "443/tcp");
        assert!(confirming_hit(&matches[..1], "EpicCare Inpatient Base").is_none());
    }
}
