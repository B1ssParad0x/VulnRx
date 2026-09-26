use chrono::NaiveDate;
use scraper::{Html, Selector};
use serde::Deserialize;
use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;

pub const EDGAR_SEARCH_URL: &str = "https://efts.sec.gov/LATEST/search-index";
pub const EDGAR_SOURCE: &str = "sec_edgar";

const PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgarFiling {
    pub company_name: String,
    pub filing_type: String,
    pub filed_date: Option<NaiveDate>,
    pub summary: Option<String>,
    pub source_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgarReport {
    pub filings: u64,
    pub with_summary: u64,
    pub linked_hospitals: i64,
    pub linked_vendors: i64,
}

/// Material cybersecurity incident reports (8-K Item 1.05) since the rule took effect.
pub async fn fetch_item_105_filings() -> Result<Vec<EdgarFiling>, IngestError> {
    let client = sec_client()?;
    let mut filings = Vec::new();
    let mut from = 0_usize;
    loop {
        if from > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let url = format!(
            "{EDGAR_SEARCH_URL}?q=%22Item%201.05%22&forms=8-K&dateRange=custom&startdt=2023-12-18&enddt={}&from={from}",
            chrono::Utc::now().format("%Y-%m-%d")
        );
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(IngestError::HttpStatus {
                url,
                status: response.status().as_u16(),
            });
        }
        let body = response.bytes().await?;
        let page = parse_search(&body)?;
        let total = page.total;
        if page.filings.is_empty() {
            break;
        }
        let count = page.filings.len();
        filings.extend(page.filings);
        from += count;
        if from >= total || count < PAGE_SIZE {
            break;
        }
    }
    for filing in &mut filings {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        filing.summary = match client.get(&filing.source_url).send().await {
            Ok(response) if response.status().is_success() => response
                .text()
                .await
                .ok()
                .and_then(|html| excerpt_item_105(&html)),
            _ => None,
        };
    }
    Ok(filings)
}

pub fn parse_search(body: &[u8]) -> Result<SearchPage, IngestError> {
    let parsed: SearchResponse = serde_json::from_slice(body)?;
    let mut filings = Vec::new();
    for hit in parsed.hits.hits {
        let Some(filing) = filing_from_hit(hit) else {
            continue;
        };
        filings.push(filing);
    }
    Ok(SearchPage {
        total: parsed.hits.total.value,
        filings,
    })
}

pub fn excerpt_item_105(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("body").expect("body selector");
    let text = document
        .select(&selector)
        .next()
        .map(|body| body.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = collapsed.to_ascii_lowercase();
    let start = lower.find("item 1.05")?;
    let excerpt: String = collapsed[start..].chars().take(480).collect();
    let excerpt = excerpt.split_whitespace().collect::<Vec<_>>().join(" ");
    if excerpt.len() < 40 {
        None
    } else {
        Some(excerpt)
    }
}

pub async fn ingest_filings(
    pool: &PgPool,
    filings: &[EdgarFiling],
) -> Result<EdgarReport, IngestError> {
    let mut projected = csv::Writer::from_writer(Vec::new());
    projected.write_record([
        "company_name",
        "filing_type",
        "filed_date",
        "summary",
        "source_url",
    ])?;
    let mut with_summary = 0_u64;
    for filing in filings {
        if filing.summary.is_some() {
            with_summary += 1;
        }
        projected.write_record([
            filing.company_name.as_str(),
            filing.filing_type.as_str(),
            &filing
                .filed_date
                .map(|date| date.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
            filing.summary.as_deref().unwrap_or(""),
            filing.source_url.as_str(),
        ])?;
    }
    projected.flush()?;
    let bytes = projected
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;

    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS edgar_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY edgar_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(bytes).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS edgar_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let stored = sqlx::query(UPSERT)
        .bind(EDGAR_SOURCE)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(LINK_HOSPITALS)
        .bind(EDGAR_SOURCE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(LINK_VENDORS)
        .bind(EDGAR_SOURCE)
        .execute(&mut *tx)
        .await?;
    let linked_hospitals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sec_filings WHERE source = $1 AND hospital_id IS NOT NULL",
    )
    .bind(EDGAR_SOURCE)
    .fetch_one(&mut *tx)
    .await?;
    let linked_vendors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sec_filings WHERE source = $1 AND vendor_id IS NOT NULL",
    )
    .bind(EDGAR_SOURCE)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS edgar_stage")
        .execute(&mut *conn)
        .await;
    Ok(EdgarReport {
        filings: stored,
        with_summary,
        linked_hospitals,
        linked_vendors,
    })
}

#[derive(Debug)]
pub struct SearchPage {
    pub total: usize,
    pub filings: Vec<EdgarFiling>,
}

fn filing_from_hit(hit: SearchHit) -> Option<EdgarFiling> {
    let source = hit.source;
    let display = source.display_names.into_iter().next()?;
    let company_name = company_name(&display);
    if company_name.is_empty() {
        return None;
    }
    let filename = hit.id.split_once(':').map(|(_, name)| name)?;
    let cik = source.ciks.into_iter().next()?;
    let source_url = filing_url(&cik, &source.adsh, filename);
    let filing_type = if source.items.iter().any(|item| item == "1.05") {
        "8-K Item 1.05".to_string()
    } else {
        source.form
    };
    Some(EdgarFiling {
        company_name,
        filing_type,
        filed_date: NaiveDate::parse_from_str(&source.file_date, "%Y-%m-%d").ok(),
        summary: None,
        source_url,
    })
}

fn company_name(display: &str) -> String {
    display
        .split("  (")
        .next()
        .unwrap_or(display)
        .trim()
        .to_string()
}

fn filing_url(cik: &str, adsh: &str, filename: &str) -> String {
    let cik_num = cik.trim_start_matches('0');
    let cik_num = if cik_num.is_empty() { "0" } else { cik_num };
    let accession = adsh.replace('-', "");
    format!("https://www.sec.gov/Archives/edgar/data/{cik_num}/{accession}/{filename}")
}

fn sec_client() -> Result<reqwest::Client, IngestError> {
    let user_agent = std::env::var("SEC_USER_AGENT")
        .unwrap_or_else(|_| "VulnRx B1ssParad0x@proton.me".to_string());
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(user_agent)
        .build()?)
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    hits: SearchHits,
}

#[derive(Debug, Deserialize)]
struct SearchHits {
    total: SearchTotal,
    hits: Vec<SearchHit>,
}

#[derive(Debug, Deserialize)]
struct SearchTotal {
    value: usize,
}

#[derive(Debug, Deserialize)]
struct SearchHit {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_source")]
    source: HitSource,
}

#[derive(Debug, Deserialize)]
struct HitSource {
    ciks: Vec<String>,
    display_names: Vec<String>,
    file_date: String,
    form: String,
    adsh: String,
    #[serde(default)]
    items: Vec<String>,
}

const CREATE_STAGE: &str = r#"
CREATE TEMP TABLE edgar_stage (
    company_name TEXT,
    filing_type TEXT,
    filed_date TEXT,
    summary TEXT,
    source_url TEXT
)
"#;

const UPSERT: &str = r#"
INSERT INTO sec_filings (company_name, filing_type, filed_date, summary, source, source_url)
SELECT
    company_name,
    NULLIF(filing_type, ''),
    NULLIF(filed_date, '')::date,
    NULLIF(summary, ''),
    $1,
    source_url
FROM (
    SELECT DISTINCT ON (source_url)
        btrim(company_name) AS company_name,
        btrim(filing_type) AS filing_type,
        btrim(filed_date) AS filed_date,
        btrim(summary) AS summary,
        btrim(source_url) AS source_url
    FROM edgar_stage
    WHERE btrim(company_name) <> '' AND btrim(source_url) <> ''
    ORDER BY source_url
) AS deduped
ON CONFLICT (source_url) WHERE source_url IS NOT NULL
DO UPDATE SET
    company_name = EXCLUDED.company_name,
    filing_type = EXCLUDED.filing_type,
    filed_date = EXCLUDED.filed_date,
    summary = COALESCE(EXCLUDED.summary, sec_filings.summary)
"#;

const LINK_HOSPITALS: &str = r#"
UPDATE sec_filings AS filing
SET hospital_id = hospital.id
FROM hospitals AS hospital
WHERE filing.source = $1
  AND regexp_replace(upper(hospital.name), '[^A-Z0-9]+', '', 'g')
    = regexp_replace(upper(filing.company_name), '[^A-Z0-9]+', '', 'g')
  AND (
      SELECT count(*)
      FROM hospitals AS other
      WHERE regexp_replace(upper(other.name), '[^A-Z0-9]+', '', 'g')
        = regexp_replace(upper(filing.company_name), '[^A-Z0-9]+', '', 'g')
  ) = 1
"#;

const LINK_VENDORS: &str = r#"
UPDATE sec_filings AS filing
SET vendor_id = vendor.id
FROM vendors AS vendor
WHERE filing.source = $1
  AND regexp_replace(upper(vendor.name), '[^A-Z0-9]+', '', 'g')
    = regexp_replace(upper(filing.company_name), '[^A-Z0-9]+', '', 'g')
  AND (
      SELECT count(*)
      FROM vendors AS other
      WHERE regexp_replace(upper(other.name), '[^A-Z0-9]+', '', 'g')
        = regexp_replace(upper(filing.company_name), '[^A-Z0-9]+', '', 'g')
  ) = 1
"#;

#[cfg(test)]
mod tests {
    use super::{excerpt_item_105, parse_search};

    #[test]
    fn parses_an_item_105_hit_into_an_archives_url() {
        let body = br#"{
          "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{
              "_id": "0001193125-24-147625:d774339d8ka.htm",
              "_source": {
                "ciks": ["0000790816"],
                "display_names": ["BRANDYWINE REALTY TRUST  (BDN)  (CIK 0000790816)"],
                "file_date": "2024-05-28",
                "form": "8-K/A",
                "adsh": "0001193125-24-147625",
                "items": ["1.05"]
              }
            }]
          }
        }"#;
        let page = parse_search(body).unwrap();
        assert_eq!(page.filings.len(), 1);
        let filing = &page.filings[0];
        assert_eq!(filing.company_name, "BRANDYWINE REALTY TRUST");
        assert_eq!(filing.filing_type, "8-K Item 1.05");
        assert_eq!(
            filing.source_url,
            "https://www.sec.gov/Archives/edgar/data/790816/000119312524147625/d774339d8ka.htm"
        );
    }

    #[test]
    fn excerpt_starts_at_item_105() {
        let html = "<html><body><p>Intro</p><p>Item 1.05 Material Cybersecurity Incidents. The company experienced an event.</p></body></html>";
        let excerpt = excerpt_item_105(html).unwrap();
        assert!(excerpt.starts_with("Item 1.05"));
        assert!(excerpt.contains("experienced an event"));
    }
}
