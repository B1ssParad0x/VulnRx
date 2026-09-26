//! One short Gemini reply per CVE, stored so the next view does not call the API.
//!
//! The model is Flash-Lite with thinking off and a 120-token cap. The prompt
//! asks for three sentences and forbids exploit steps.

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;

use crate::error::ApiError;

pub const MODEL: &str = "gemini-3.5-flash-lite";
const MAX_OUTPUT_TOKENS: u32 = 120;

#[derive(Serialize)]
pub(crate) struct ExplainBody {
    explanation: String,
    cached: bool,
    model: &'static str,
}

pub(crate) async fn fragment(
    State(pool): State<PgPool>,
    Path(cve_id): Path<String>,
) -> Response {
    match lookup_or_generate(&pool, &cve_id).await {
        Ok((text, cached)) => {
            let label = if cached {
                "Saved guidance. Not an assessment."
            } else {
                "Guidance, not an assessment. This reply is now saved."
            };
            Html(format!(
                "<p class=\"note\">{label}</p><p>{}</p>",
                escape(&text)
            ))
            .into_response()
        }
        Err(err) => err.into_response(),
    }
}

pub(crate) async fn json(
    State(pool): State<PgPool>,
    Path(cve_id): Path<String>,
) -> Result<Json<ExplainBody>, ApiError> {
    let (explanation, cached) = lookup_or_generate(&pool, &cve_id).await?;
    Ok(Json(ExplainBody {
        explanation,
        cached,
        model: MODEL,
    }))
}

pub(crate) async fn cached_for(
    pool: &PgPool,
    cve_ids: &[String],
) -> Result<Vec<(String, String)>, ApiError> {
    if cve_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, CachedRow>(
        "SELECT c.cve_id, e.explanation
         FROM cve_explanations e
         JOIN cves c ON c.id = e.cve_id
         WHERE c.cve_id = ANY($1::text[])",
    )
    .bind(cve_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.cve_id, row.explanation))
        .collect())
}

#[derive(sqlx::FromRow)]
struct CachedRow {
    cve_id: String,
    explanation: String,
}

async fn lookup_or_generate(pool: &PgPool, cve_id: &str) -> Result<(String, bool), ApiError> {
    if !valid_cve_id(cve_id) {
        return Err(ApiError::BadRequest("cve id is not valid"));
    }
    if let Some(saved) = saved_explanation(pool, cve_id).await? {
        return Ok((saved, true));
    }
    let facts = cve_facts(pool, cve_id).await?;
    let Some(key) = std::env::var("GEMINI_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::Unavailable(
            "GEMINI_API_KEY is not set, so this CVE has no saved explanation",
        ));
    };
    let text = generate(&key, &prompt(&facts)).await?;
    sqlx::query(
        "INSERT INTO cve_explanations (cve_id, model, explanation)
         VALUES ($1, $2, $3)
         ON CONFLICT (cve_id) DO NOTHING",
    )
    .bind(facts.id)
    .bind(MODEL)
    .bind(&text)
    .execute(pool)
    .await?;
    Ok((text, false))
}

#[derive(sqlx::FromRow)]
struct CveFacts {
    id: uuid::Uuid,
    cve_id: String,
    description: Option<String>,
    cvss_score: Option<rust_decimal::Decimal>,
    epss_score: Option<rust_decimal::Decimal>,
    is_kev: Option<bool>,
    product_name: Option<String>,
}

fn valid_cve_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let year = parts.next().unwrap_or("");
    let number = parts.next().unwrap_or("");
    parts.next().is_none()
        && year.len() == 4
        && year.chars().all(|ch| ch.is_ascii_digit())
        && (4..=7).contains(&number.len())
        && number.chars().all(|ch| ch.is_ascii_digit())
}

async fn saved_explanation(pool: &PgPool, cve_id: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar(
        "SELECT e.explanation
         FROM cve_explanations e
         JOIN cves c ON c.id = e.cve_id
         WHERE c.cve_id = $1",
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)
}

async fn cve_facts(pool: &PgPool, cve_id: &str) -> Result<CveFacts, ApiError> {
    let facts = sqlx::query_as::<_, CveFacts>(
        "SELECT c.id, c.cve_id, c.description, c.cvss_score, c.epss_score, c.is_kev,
                (
                    SELECT p.name
                    FROM product_cve_map m
                    JOIN products p ON p.id = m.product_id
                    WHERE m.cve_id = c.id
                    ORDER BY p.name
                    LIMIT 1
                ) AS product_name
         FROM cves c
         WHERE c.cve_id = $1",
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await?;
    facts.ok_or(ApiError::NotFound("cve not found"))
}

fn prompt(facts: &CveFacts) -> String {
    let description = facts
        .description
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| truncate_chars(text, 400))
        .unwrap_or_else(|| "No description is stored.".to_string());
    let cvss = facts
        .cvss_score
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let epss = facts
        .epss_score
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let kev = match facts.is_kev {
        Some(true) => "yes",
        Some(false) => "no",
        None => "not checked",
    };
    let product = facts
        .product_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("not linked to a stored product");
    format!(
        "CVE {}. CVSS {}. EPSS {}. Listed in CISA KEV: {}. Product: {}. Description: {}",
        facts.cve_id, cvss, epss, kev, product, description
    )
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    text.chars().take(max).collect()
}

async fn generate(key: &str, prompt: &str) -> Result<String, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| ApiError::Unavailable("could not start the Gemini request"))?;
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
    );
    let body = serde_json::json!({
        "systemInstruction": {
            "parts": [{
                "text": "You explain one public vulnerability record to a hospital administrator. Three sentences maximum. No security jargon. Do not describe exploit steps, payloads, or how to attack a system. This is guidance, not an assessment."
            }]
        },
        "contents": [{
            "role": "user",
            "parts": [{ "text": prompt }]
        }],
        "generationConfig": {
            "maxOutputTokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.2
        }
    });
    let response = client
        .post(url)
        .header("x-goog-api-key", key)
        .json(&body)
        .send()
        .await
        .map_err(|_| ApiError::Unavailable("Gemini request failed"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|_| ApiError::Unavailable("Gemini returned an unreadable reply"))?;
    if !status.is_success() {
        let detail: String = body
            .replace(key, "[redacted]")
            .chars()
            .take(500)
            .collect();
        eprintln!("gemini HTTP {status}: {detail}");
        return Err(ApiError::Unavailable("Gemini did not return an explanation"));
    }
    let parsed: Value = serde_json::from_str(&body)
        .map_err(|_| ApiError::Unavailable("Gemini returned an unreadable reply"))?;
    reply_text(&parsed).ok_or(ApiError::Unavailable("Gemini returned an empty reply"))
}

fn reply_text(body: &Value) -> Option<String> {
    let parts = body["candidates"][0]["content"]["parts"].as_array()?;
    let mut text = String::new();
    for part in parts {
        if part.get("thought").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(piece) = part.get("text").and_then(Value::as_str) {
            text.push_str(piece);
        }
    }
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::{prompt, reply_text, truncate_chars, valid_cve_id, CveFacts};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn accepts_a_normal_cve_id() {
        assert!(valid_cve_id("CVE-2024-12345"));
        assert!(!valid_cve_id("CVE-24-1"));
        assert!(!valid_cve_id("not-a-cve"));
    }

    #[test]
    fn prompt_stays_short_and_names_the_stored_facts() {
        let facts = CveFacts {
            id: Uuid::nil(),
            cve_id: "CVE-2024-12345".to_string(),
            description: Some("A".repeat(800)),
            cvss_score: None,
            epss_score: None,
            is_kev: Some(true),
            product_name: Some("Charting".to_string()),
        };
        let text = prompt(&facts);
        assert!(text.contains("CVE-2024-12345"));
        assert!(text.contains("Listed in CISA KEV: yes"));
        assert!(text.contains("Charting"));
        assert!(text.chars().count() < 600);
        assert_eq!(truncate_chars("abcdef", 3), "abc");
    }

    #[test]
    fn reply_ignores_a_thought_part() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"thought": true, "text": "hidden"},
                        {"text": "Use the vendor patch first."}
                    ]
                }
            }]
        });
        assert_eq!(
            reply_text(&body).as_deref(),
            Some("Use the vendor patch first.")
        );
    }
}
