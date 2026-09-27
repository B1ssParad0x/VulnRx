//! Natural-language questions and one remediation note per hospital.
//!
//! Gemini is called only when stored facts exist for the question or hospital.
//! The reply is saved. Exploit steps are refused by the instruction.

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;
use crate::explain::{self, MODEL};
use crate::hospitals;
use crate::public_name;

const STOP: &[&str] = &[
    "where", "about", "which", "there", "their", "would", "should", "could", "hospital",
    "hospitals", "breach", "breaches", "vendor", "vendors", "records", "record",
];

const ASK_SYSTEM: &str = "Answer in at most three sentences using only the facts provided. If the facts do not answer the question, say the records do not say. Do not name a hospital, vendor, or CVE that is not in the facts. Do not describe exploit steps. This is guidance, not an assessment.";
const GUIDE_SYSTEM: &str = "Give a hospital administrator at most three sentences of next steps based only on these facts. Prefer vendor follow-up, known-exploited listings, and breach follow-up. Do not describe exploit steps, payloads, or how to attack a system. If a fact is missing, say it is not in the records. This is guidance, not an assessment.";

#[derive(Deserialize)]
pub(crate) struct AskForm {
    q: Option<String>,
}

pub(crate) async fn ask(State(pool): State<PgPool>, Form(form): Form<AskForm>) -> Response {
    match answer(&pool, form.q.as_deref().unwrap_or("")).await {
        Ok(html) => Html(html).into_response(),
        Err(err) => err.into_response(),
    }
}

pub(crate) async fn remediate(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Response {
    match guidance(&pool, &id).await {
        Ok(html) => Html(html).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn answer(pool: &PgPool, raw: &str) -> Result<String, ApiError> {
    let question = normalize_question(raw)?;
    if let Some(saved) = saved_answer(pool, &question).await? {
        return Ok(note("Saved answer. Not an assessment.", &saved));
    }
    let facts = question_facts(pool, &question).await?;
    let Some(facts) = facts else {
        return Ok(note(
            "No model call.",
            "The stored records do not name a hospital or CVE for that question.",
        ));
    };
    let text = reply(ASK_SYSTEM, &format!("Question: {question}\nFacts:\n{facts}")).await?;
    sqlx::query(
        "INSERT INTO nl_answers (question_key, question, model, answer)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (question_key) DO NOTHING",
    )
    .bind(&question)
    .bind(&question)
    .bind(MODEL)
    .bind(&text)
    .execute(pool)
    .await?;
    Ok(note("Guidance, not an assessment. This reply is now saved.", &text))
}

async fn guidance(pool: &PgPool, raw_id: &str) -> Result<String, ApiError> {
    let id = crate::error::parse_id(raw_id)?;
    if let Some(saved) = saved_guidance(pool, id).await? {
        return Ok(note("Saved guidance. Not an assessment.", &saved));
    }
    let facts = hospital_facts(pool, id).await?;
    let Some(facts) = facts else {
        return Ok(note(
            "No model call.",
            "This hospital has no linked breach, certified product, or CVE in the records.",
        ));
    };
    let text = reply(GUIDE_SYSTEM, &facts).await?;
    sqlx::query(
        "INSERT INTO hospital_guidance (hospital_id, model, guidance)
         VALUES ($1, $2, $3)
         ON CONFLICT (hospital_id) DO NOTHING",
    )
    .bind(id)
    .bind(MODEL)
    .bind(&text)
    .execute(pool)
    .await?;
    Ok(note("Guidance, not an assessment. This reply is now saved.", &text))
}

fn normalize_question(raw: &str) -> Result<String, ApiError> {
    let question = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let len = question.chars().count();
    if len < 8 {
        return Err(ApiError::BadRequest("question must be at least 8 characters"));
    }
    if len > 180 {
        return Err(ApiError::BadRequest("question must be at most 180 characters"));
    }
    Ok(question.to_ascii_lowercase())
}

async fn saved_answer(pool: &PgPool, question: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar("SELECT answer FROM nl_answers WHERE question_key = $1")
        .bind(question)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::from)
}

async fn saved_guidance(pool: &PgPool, id: Uuid) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar("SELECT guidance FROM hospital_guidance WHERE hospital_id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::from)
}

async fn question_facts(pool: &PgPool, question: &str) -> Result<Option<String>, ApiError> {
    let mut lines = Vec::new();
    if let Some(cve_id) = cve_in(question) {
        if let Some(line) = cve_line(pool, &cve_id).await? {
            lines.push(line);
        } else {
            lines.push(format!("{cve_id} is not in the stored records."));
        }
    }
    let mut seen = Vec::new();
    let mut hits = hospitals::find_hospitals(pool, question, 4).await?;
    for word in question.split_whitespace().take(6) {
        if word.chars().count() < 5 || STOP.contains(&word) {
            continue;
        }
        hits.extend(hospitals::find_hospitals(pool, word, 2).await?);
    }
    for hit in hits {
        if seen.contains(&hit.id) || seen.len() == 4 {
            continue;
        }
        seen.push(hit.id);
        if let Some(line) = hospital_line(pool, hit.id).await? {
            lines.push(line);
        }
    }
    if lines.is_empty() {
        return Ok(None);
    }
    let mut facts = lines.join("\n");
    if facts.chars().count() > 1200 {
        facts = facts.chars().take(1200).collect();
    }
    Ok(Some(facts))
}

async fn hospital_facts(pool: &PgPool, id: Uuid) -> Result<Option<String>, ApiError> {
    let Some(line) = hospital_line(pool, id).await? else {
        return Err(ApiError::NotFound("hospital not found"));
    };
    if line.contains("breaches 0") && line.contains("vendors none") && line.contains("cves none") {
        return Ok(None);
    }
    Ok(Some(line))
}

async fn hospital_line(pool: &PgPool, id: Uuid) -> Result<Option<String>, ApiError> {
    let row = sqlx::query_as::<_, FactRow>(HOSPITAL_FACT_SQL)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let label = public_name(&row.name, row.display_name.as_deref());
    let state = row.state.unwrap_or_else(|| "unknown state".to_string());
    let vendors = blank_as(&row.vendors, "none");
    let cves = blank_as(&row.cves, "none");
    Ok(Some(format!(
        "{label} ({state}): breaches {}, vendors {vendors}, cves {cves}.",
        row.breaches
    )))
}

async fn cve_line(pool: &PgPool, cve_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query_as::<_, CveRow>(
        "SELECT cve_id, cvss_score::text AS cvss, is_kev,
                left(COALESCE(description, ''), 160) AS description
         FROM cves WHERE cve_id = $1",
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let kev = match row.is_kev {
            Some(true) => "KEV yes",
            Some(false) => "KEV no",
            None => "KEV not checked",
        };
        let cvss = row.cvss.unwrap_or_else(|| "unknown".to_string());
        format!(
            "{} CVSS {cvss} {kev}. {}",
            row.cve_id,
            row.description.trim()
        )
    }))
}

#[derive(sqlx::FromRow)]
struct FactRow {
    name: String,
    display_name: Option<String>,
    state: Option<String>,
    breaches: i64,
    vendors: Option<String>,
    cves: Option<String>,
}

#[derive(sqlx::FromRow)]
struct CveRow {
    cve_id: String,
    cvss: Option<String>,
    is_kev: Option<bool>,
    description: String,
}

const HOSPITAL_FACT_SQL: &str = "
SELECT h.name, h.display_name, h.state,
       (SELECT count(*) FROM breach_events b WHERE b.hospital_id = h.id) AS breaches,
       (
         SELECT string_agg(vendor_name, ', ' ORDER BY vendor_name)
         FROM (
           SELECT DISTINCT v.name AS vendor_name
           FROM hospital_vendor_map m
           JOIN vendors v ON v.id = m.vendor_id
           WHERE m.hospital_id = h.id
           ORDER BY v.name
           LIMIT 4
         ) named
       ) AS vendors,
       (
         SELECT string_agg(cve_id, ', ' ORDER BY cve_id)
         FROM (
           SELECT DISTINCT c.cve_id
           FROM hospital_vendor_map m
           JOIN product_cve_map pcm ON pcm.product_id = m.product_id
           JOIN cves c ON c.id = pcm.cve_id
           WHERE m.hospital_id = h.id
           ORDER BY c.cve_id
           LIMIT 3
         ) named
       ) AS cves
FROM hospitals h
WHERE h.id = $1
";

fn cve_in(question: &str) -> Option<String> {
    let upper = question.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut index = 0;
    while index + 13 <= bytes.len() {
        if bytes[index..].starts_with(b"CVE-") {
            let rest = &upper[index + 4..];
            let mut parts = rest.split(|ch: char| !ch.is_ascii_digit());
            let year = parts.next().unwrap_or("");
            let after_year = rest.get(year.len()..).unwrap_or("");
            if year.len() == 4 && after_year.starts_with('-') {
                let number: String = after_year[1..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                if (4..=7).contains(&number.len()) {
                    return Some(format!("CVE-{year}-{number}"));
                }
            }
        }
        index += 1;
    }
    None
}

fn blank_as(value: &Option<String>, fallback: &str) -> String {
    value
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

async fn reply(system: &str, prompt: &str) -> Result<String, ApiError> {
    let Some(key) = std::env::var("GEMINI_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::Unavailable(
            "GEMINI_API_KEY is not set, so this question has no saved answer",
        ));
    };
    explain::complete(&key, system, prompt, 160).await
}

fn note(label: &str, text: &str) -> String {
    format!(
        "<p class=\"note\">{}</p><p>{}</p>",
        explain::escape(label),
        explain::escape(text)
    )
}

#[cfg(test)]
mod tests {
    use super::{cve_in, normalize_question};

    #[test]
    fn finds_a_cve_id_inside_a_question() {
        assert_eq!(
            cve_in("what about cve-2024-12345 today").as_deref(),
            Some("CVE-2024-12345")
        );
        assert!(cve_in("no identifier here").is_none());
    }

    #[test]
    fn rejects_a_short_question() {
        assert!(normalize_question("tiny").is_err());
        assert_eq!(
            normalize_question("  Where   is  Mercy  ").unwrap(),
            "where is mercy"
        );
    }
}
