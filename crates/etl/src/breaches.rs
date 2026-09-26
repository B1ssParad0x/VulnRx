use std::collections::BTreeSet;

use chrono::NaiveDate;
use scraper::{Html, Selector};
use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;

pub const BREACH_PORTAL_URL: &str = "https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf";
pub const BREACH_SOURCE: &str = "hhs_ocr_breach_portal";

const PAGE_SIZE: usize = 100;
const ORIGIN: &str = "https://ocrportal.hhs.gov";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BreachRecord {
    pub entity_name: String,
    pub state: Option<String>,
    pub portal_entity_type: String,
    pub entity_type: String,
    pub individuals_affected: Option<i32>,
    pub date_reported: Option<NaiveDate>,
    pub breach_type: Option<String>,
    pub breach_location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreachReport {
    pub fetched: u64,
    pub stored: u64,
    pub linked_hospitals: i64,
    pub linked_vendors: i64,
}

/// Read the public OCR breach portal: cases under investigation, then the archive.
pub async fn fetch_breach_portal() -> Result<Vec<BreachRecord>, IngestError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("vulnrx/0.1 (public breach portal read)")
        .build()?;
    let response = client.get(BREACH_PORTAL_URL).send().await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: BREACH_PORTAL_URL.to_string(),
            status: response.status().as_u16(),
        });
    }
    let cookie = jsessionid(response.headers())?;
    let body = response.text().await?;
    let post_url = form_action(&body)?;
    let mut viewstate = input_value(&body, "javax.faces.ViewState")
        .ok_or_else(|| IngestError::Portal("missing view state".to_string()))?;
    let mut records = parse_breach_html(&body);
    let total = portal_total(&body).unwrap_or(records.len());
    let mut offset = PAGE_SIZE;
    while offset < total {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let page = post_form(
            &client,
            &post_url,
            &cookie,
            &pagination_form(&viewstate, offset),
        )
        .await?;
        viewstate = partial_viewstate(&page).unwrap_or(viewstate);
        let parsed = parse_breach_html(&page);
        if parsed.is_empty() {
            return Err(IngestError::Portal(format!(
                "investigation page at offset {offset} was empty"
            )));
        }
        records.extend(parsed);
        offset += PAGE_SIZE;
    }

    let tab = archive_tab_id(&body)?;
    let widget = tab
        .rsplit_once(':')
        .map(|(prefix, _)| prefix.to_string())
        .ok_or_else(|| IngestError::Portal("archive tab id has no prefix".to_string()))?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let archive = post_form(
        &client,
        &post_url,
        &cookie,
        &archive_form(&viewstate, &widget, &tab),
    )
    .await?;
    viewstate = partial_viewstate(&archive).unwrap_or(viewstate);
    let mut archive_rows = parse_breach_html(&archive);
    let archive_total = portal_total(&archive).unwrap_or(archive_rows.len());
    records.append(&mut archive_rows);
    offset = PAGE_SIZE;
    while offset < archive_total {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let page = post_form(
            &client,
            &post_url,
            &cookie,
            &pagination_form(&viewstate, offset),
        )
        .await?;
        viewstate = partial_viewstate(&page).unwrap_or(viewstate);
        let parsed = parse_breach_html(&page);
        if parsed.is_empty() {
            return Err(IngestError::Portal(format!(
                "archive page at offset {offset} was empty"
            )));
        }
        records.extend(parsed);
        offset += PAGE_SIZE;
    }
    Ok(dedup(records))
}

/// Store portal rows and link a healthcare provider only when one hospital in that state has the same name.
pub async fn ingest_breaches(
    pool: &PgPool,
    records: &[BreachRecord],
    source_url: &str,
    state: Option<&str>,
) -> Result<BreachReport, IngestError> {
    let state = normalize_state(state)?;
    let selected: Vec<&BreachRecord> = records
        .iter()
        .filter(|record| {
            state
                .as_deref()
                .is_none_or(|wanted| record.state.as_deref() == Some(wanted))
        })
        .collect();
    let mut projected = csv::Writer::from_writer(Vec::new());
    projected.write_record([
        "entity_name",
        "state",
        "portal_entity_type",
        "entity_type",
        "individuals_affected",
        "date_reported",
        "breach_type",
        "breach_location",
    ])?;
    for record in &selected {
        projected.write_record([
            record.entity_name.as_str(),
            record.state.as_deref().unwrap_or(""),
            record.portal_entity_type.as_str(),
            record.entity_type.as_str(),
            &record
                .individuals_affected
                .map(|count| count.to_string())
                .unwrap_or_default(),
            &record
                .date_reported
                .map(|date| date.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
            record.breach_type.as_deref().unwrap_or(""),
            record.breach_location.as_deref().unwrap_or(""),
        ])?;
    }
    projected.flush()?;
    let bytes = projected
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;

    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS breach_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY breach_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(bytes).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS breach_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let stored = sqlx::query(UPSERT)
        .bind(BREACH_SOURCE)
        .bind(source_url)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(LINK_HOSPITALS)
        .bind(BREACH_SOURCE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(CLEAR_UNMATCHED_HOSPITALS)
        .bind(BREACH_SOURCE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(LINK_VENDORS)
        .bind(BREACH_SOURCE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(CLEAR_UNMATCHED_VENDORS)
        .bind(BREACH_SOURCE)
        .execute(&mut *tx)
        .await?;
    let linked_hospitals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM breach_events WHERE source = $1 AND hospital_id IS NOT NULL",
    )
    .bind(BREACH_SOURCE)
    .fetch_one(&mut *tx)
    .await?;
    let linked_vendors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM breach_events WHERE source = $1 AND vendor_id IS NOT NULL",
    )
    .bind(BREACH_SOURCE)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS breach_stage")
        .execute(&mut *conn)
        .await;
    Ok(BreachReport {
        fetched: u64::try_from(records.len()).unwrap_or(u64::MAX),
        stored,
        linked_hospitals,
        linked_vendors,
    })
}

pub fn parse_breach_html(body: &str) -> Vec<BreachRecord> {
    let html = if body.contains("<partial-response") {
        format!("<table><tbody>{}</tbody></table>", table_markup(body))
    } else {
        body.to_string()
    };
    let document = Html::parse_fragment(&html);
    let tr_selector = Selector::parse("tr").expect("tr selector");
    let td_selector = Selector::parse("td").expect("td selector");
    let mut records = Vec::new();
    for row in document.select(&tr_selector) {
        let cells: Vec<String> = row
            .select(&td_selector)
            .map(|cell| {
                cell.text()
                    .collect::<String>()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        if cells.len() < 9 {
            continue;
        }
        let entity_name = cells[1].trim();
        if entity_name.is_empty() || entity_name.eq_ignore_ascii_case("Name of Covered Entity") {
            continue;
        }
        let portal_entity_type = cells[3].trim().to_string();
        let entity_type = if portal_entity_type.eq_ignore_ascii_case("Business Associate") {
            "business_associate"
        } else {
            "covered_entity"
        };
        records.push(BreachRecord {
            entity_name: entity_name.to_string(),
            state: postal_state(cells[2].trim()),
            portal_entity_type,
            entity_type: entity_type.to_string(),
            individuals_affected: parse_affected(cells[4].trim()),
            date_reported: NaiveDate::parse_from_str(cells[5].trim(), "%m/%d/%Y").ok(),
            breach_type: blank_to_none(cells[6].trim()),
            breach_location: blank_to_none(cells[7].trim()),
        });
    }
    records
}

fn dedup(records: Vec<BreachRecord>) -> Vec<BreachRecord> {
    let mut seen = BTreeSet::new();
    records
        .into_iter()
        .filter(|record| seen.insert(record.clone()))
        .collect()
}

fn postal_state(value: &str) -> Option<String> {
    if value.len() == 2 && value.chars().all(|c| c.is_ascii_uppercase()) {
        Some(value.to_string())
    } else {
        None
    }
}

fn parse_affected(value: &str) -> Option<i32> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let count = digits.parse::<i32>().ok()?;
    Some(count)
}

fn blank_to_none(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn table_markup(body: &str) -> String {
    if !body.contains("<partial-response") {
        return body.to_string();
    }
    let mut best = String::new();
    for chunk in cdata_chunks(body) {
        let trimmed = chunk.trim_start();
        if trimmed.starts_with("<tr") && chunk.contains("<td") && chunk.len() > best.len() {
            best = chunk;
        }
    }
    best
}

fn cdata_chunks(body: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<![CDATA[") {
        rest = &rest[start + 9..];
        if let Some(end) = rest.find("]]>") {
            chunks.push(rest[..end].to_string());
            rest = &rest[end + 3..];
        } else {
            break;
        }
    }
    chunks
}

fn portal_total(html: &str) -> Option<usize> {
    let start = html.find("Displaying ")?;
    let window = &html[start..html.len().min(start + 80)];
    let of = window.find(" of ")?;
    let digits: String = window[of + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn input_value(html: &str, name: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("input").expect("input selector");
    document.select(&selector).find_map(|input| {
        if input.attr("name") == Some(name) {
            input.attr("value").map(str::to_string)
        } else {
            None
        }
    })
}

fn form_action(html: &str) -> Result<String, IngestError> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("form").expect("form selector");
    let action = document
        .select(&selector)
        .find(|form| form.attr("id") == Some("ocrForm"))
        .and_then(|form| form.attr("action"))
        .ok_or_else(|| IngestError::Portal("missing form action".to_string()))?;
    if action.starts_with("http") {
        Ok(action.to_string())
    } else if let Some(path) = action.strip_prefix('/') {
        Ok(format!("{ORIGIN}/{path}"))
    } else {
        Ok(format!("{ORIGIN}/ocr/breach/{action}"))
    }
}

fn archive_tab_id(html: &str) -> Result<String, IngestError> {
    let marker = "archiveTab";
    let index = html
        .find(marker)
        .ok_or_else(|| IngestError::Portal("missing archive tab".to_string()))?;
    let start = html[..index].rfind("ocrForm:").ok_or_else(|| {
        IngestError::Portal("archive tab is not an ocrForm component".to_string())
    })?;
    Ok(html[start..index + marker.len()].to_string())
}

fn jsessionid(headers: &reqwest::header::HeaderMap) -> Result<String, IngestError> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| cookie.split(';').next())
        .filter(|cookie| cookie.starts_with("JSESSIONID="))
        .map(str::to_string)
        .ok_or_else(|| IngestError::Portal("missing session cookie".to_string()))
}

fn partial_viewstate(body: &str) -> Option<String> {
    let marker = "javax.faces.ViewState";
    let index = body.find(marker)?;
    let rest = &body[index..];
    let start = rest.find("<![CDATA[")? + 9;
    let end = rest[start..].find("]]>")?;
    Some(rest[start..start + end].to_string())
}

async fn post_form(
    client: &reqwest::Client,
    url: &str,
    cookie: &str,
    fields: &[(String, String)],
) -> Result<String, IngestError> {
    let body = fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode_form(key), encode_form(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = client
        .post(url)
        .header(reqwest::header::COOKIE, cookie)
        .header("Faces-Request", "partial/ajax")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: url.to_string(),
            status: response.status().as_u16(),
        });
    }
    Ok(response.text().await?)
}

fn pagination_form(viewstate: &str, offset: usize) -> Vec<(String, String)> {
    [
        ("javax.faces.partial.ajax", "true"),
        ("javax.faces.source", "ocrForm:reportResultTable"),
        ("javax.faces.partial.execute", "ocrForm:reportResultTable"),
        ("javax.faces.partial.render", "ocrForm:reportResultTable"),
        ("ocrForm:reportResultTable", "ocrForm:reportResultTable"),
        ("ocrForm:reportResultTable_pagination", "true"),
        ("ocrForm:reportResultTable_rows", "100"),
        ("ocrForm:reportResultTable_skipChildren", "true"),
        ("ocrForm:reportResultTable_encodeFeature", "true"),
        ("ocrForm:reportResultTable_rppDD", "100"),
        ("ocrForm", "ocrForm"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .chain([
        (
            "ocrForm:reportResultTable_first".to_string(),
            offset.to_string(),
        ),
        ("javax.faces.ViewState".to_string(), viewstate.to_string()),
    ])
    .collect()
}

fn archive_form(viewstate: &str, widget: &str, tab: &str) -> Vec<(String, String)> {
    vec![
        ("javax.faces.partial.ajax".to_string(), "true".to_string()),
        ("javax.faces.source".to_string(), widget.to_string()),
        (
            "javax.faces.partial.execute".to_string(),
            widget.to_string(),
        ),
        (
            "javax.faces.partial.render".to_string(),
            "ocrForm:breachReports ocrForm:results".to_string(),
        ),
        (
            "javax.faces.behavior.event".to_string(),
            "tabChange".to_string(),
        ),
        (
            "javax.faces.partial.event".to_string(),
            "tabChange".to_string(),
        ),
        (format!("{widget}_newTab"), tab.to_string()),
        (format!("{widget}_tabindex"), "1".to_string()),
        (format!("{widget}_activeIndex"), "1".to_string()),
        ("ocrForm".to_string(), "ocrForm".to_string()),
        (
            "ocrForm:reportResultTable_rppDD".to_string(),
            "100".to_string(),
        ),
        ("javax.faces.ViewState".to_string(), viewstate.to_string()),
    ]
}

fn encode_form(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn normalize_state(state: Option<&str>) -> Result<Option<String>, IngestError> {
    let Some(state) = state else {
        return Ok(None);
    };
    let state = state.trim().to_ascii_uppercase();
    if state.len() == 2 && state.chars().all(|c| c.is_ascii_uppercase()) {
        Ok(Some(state))
    } else {
        Err(IngestError::BadState(state))
    }
}

const CREATE_STAGE: &str = r#"
CREATE TEMP TABLE breach_stage (
    entity_name TEXT,
    state TEXT,
    portal_entity_type TEXT,
    entity_type TEXT,
    individuals_affected TEXT,
    date_reported TEXT,
    breach_type TEXT,
    breach_location TEXT
)
"#;

const UPSERT: &str = r#"
INSERT INTO breach_events (
    entity_name, state, portal_entity_type, entity_type, individuals_affected,
    date_reported, breach_type, breach_location, source, source_url
)
SELECT
    entity_name, state, portal_entity_type, entity_type, individuals_affected,
    date_reported, breach_type, breach_location, $1, $2
FROM (
    SELECT DISTINCT ON (
        entity_name,
        COALESCE(state, ''),
        COALESCE(date_reported, DATE '0001-01-01'),
        COALESCE(individuals_affected, -1),
        COALESCE(breach_type, ''),
        COALESCE(breach_location, '')
    )
        entity_name, state, portal_entity_type, entity_type, individuals_affected,
        date_reported, breach_type, breach_location
    FROM (
        SELECT
            btrim(entity_name) AS entity_name,
            NULLIF(btrim(state), '') AS state,
            NULLIF(btrim(portal_entity_type), '') AS portal_entity_type,
            NULLIF(btrim(entity_type), '') AS entity_type,
            NULLIF(btrim(individuals_affected), '')::integer AS individuals_affected,
            NULLIF(btrim(date_reported), '')::date AS date_reported,
            NULLIF(btrim(breach_type), '') AS breach_type,
            NULLIF(btrim(breach_location), '') AS breach_location
        FROM breach_stage
        WHERE btrim(entity_name) <> ''
    ) AS normalized
    ORDER BY
        entity_name,
        COALESCE(state, ''),
        COALESCE(date_reported, DATE '0001-01-01'),
        COALESCE(individuals_affected, -1),
        COALESCE(breach_type, ''),
        COALESCE(breach_location, '')
) AS deduped
ON CONFLICT ON CONSTRAINT breach_events_natural_uidx
DO UPDATE SET
    portal_entity_type = EXCLUDED.portal_entity_type,
    entity_type = EXCLUDED.entity_type,
    source_url = EXCLUDED.source_url
"#;

const LINK_HOSPITALS: &str = r#"
UPDATE breach_events AS breach
SET hospital_id = hospital.id
FROM hospitals AS hospital
WHERE breach.source = $1
  AND breach.portal_entity_type = 'Healthcare Provider'
  AND hospital.state = breach.state
  AND regexp_replace(upper(hospital.name), '[^A-Z0-9]+', '', 'g')
    = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
  AND (
      SELECT count(*)
      FROM hospitals AS other
      WHERE other.state = breach.state
        AND regexp_replace(upper(other.name), '[^A-Z0-9]+', '', 'g')
          = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
  ) = 1
"#;

const CLEAR_UNMATCHED_HOSPITALS: &str = r#"
UPDATE breach_events AS breach
SET hospital_id = NULL
WHERE breach.source = $1
  AND breach.hospital_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM hospitals AS hospital
      WHERE hospital.id = breach.hospital_id
        AND hospital.state = breach.state
        AND regexp_replace(upper(hospital.name), '[^A-Z0-9]+', '', 'g')
          = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
        AND breach.portal_entity_type = 'Healthcare Provider'
        AND (
            SELECT count(*)
            FROM hospitals AS other
            WHERE other.state = breach.state
              AND regexp_replace(upper(other.name), '[^A-Z0-9]+', '', 'g')
                = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
        ) = 1
  )
"#;

const LINK_VENDORS: &str = r#"
UPDATE breach_events AS breach
SET vendor_id = vendor.id
FROM vendors AS vendor
WHERE breach.source = $1
  AND breach.entity_type = 'business_associate'
  AND regexp_replace(upper(vendor.name), '[^A-Z0-9]+', '', 'g')
    = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
  AND (
      SELECT count(*)
      FROM vendors AS other
      WHERE regexp_replace(upper(other.name), '[^A-Z0-9]+', '', 'g')
        = regexp_replace(upper(breach.entity_name), '[^A-Z0-9]+', '', 'g')
  ) = 1
"#;

const CLEAR_UNMATCHED_VENDORS: &str = r#"
UPDATE breach_events AS breach
SET vendor_id = NULL
WHERE breach.source = $1
  AND breach.vendor_id IS NOT NULL
  AND breach.entity_type <> 'business_associate'
"#;

#[cfg(test)]
mod tests {
    use super::parse_breach_html;

    #[test]
    fn parses_a_portal_row_and_decodes_the_name() {
        let html = r#"
            <span>(Displaying 1 - 2 of 2)</span>
            <table><tbody>
            <tr>
              <td></td>
              <td>L.A. Care Health Plan</td>
              <td>CA</td>
              <td>Health Plan</td>
              <td>4,553</td>
              <td>09/08/2026</td>
              <td>Hacking/IT Incident</td>
              <td>Network Server</td>
              <td>Yes</td>
              <td></td>
            </tr>
            <tr>
              <td></td>
              <td>Hollister Family Dental &amp; Implant Center</td>
              <td>CA</td>
              <td>Healthcare Provider</td>
              <td>8181</td>
              <td>09/06/2026</td>
              <td>Hacking/IT Incident</td>
              <td>Email</td>
              <td>No</td>
              <td></td>
            </tr>
            </tbody></table>
        "#;
        let rows = parse_breach_html(html);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].entity_name, "L.A. Care Health Plan");
        assert_eq!(rows[0].entity_type, "covered_entity");
        assert_eq!(rows[0].individuals_affected, Some(4553));
        assert_eq!(
            rows[1].entity_name,
            "Hollister Family Dental & Implant Center"
        );
        assert_eq!(rows[1].portal_entity_type, "Healthcare Provider");
    }

    #[test]
    fn parses_rows_from_a_partial_response() {
        let html = r#"<?xml version='1.0' encoding='UTF-8'?>
            <partial-response><changes><update id="ocrForm:reportResultTable"><![CDATA[<tr data-ri="100"><td></td><td>SportsMed PT, LLC</td><td>NJ</td><td>Healthcare Provider</td><td>1200</td><td>08/01/2026</td><td>Hacking/IT Incident</td><td>Email</td><td>No</td><td></td></tr>]]></update></changes></partial-response>"#;
        let rows = parse_breach_html(html);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entity_name, "SportsMed PT, LLC");
        assert_eq!(rows[0].state.as_deref(), Some("NJ"));
    }
}
