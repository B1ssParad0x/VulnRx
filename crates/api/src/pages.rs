//! Server-rendered search, hospital profile, and vendor pages.

use std::collections::HashMap;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{self, ApiError};
use crate::hospitals::{self, SearchHit};
use crate::incidents;

const SEARCH_LIMIT: i64 = 10;
const TICKER_LIMIT: i64 = 24;

#[derive(Deserialize)]
pub(crate) struct PageQuery {
    q: Option<String>,
}

#[derive(Template)]
#[template(path = "landing.html")]
struct LandingPage {
    title: String,
    incidents: Vec<IncidentCard>,
}

#[derive(Deserialize)]
pub(crate) struct DashboardQuery {
    q: Option<String>,
    state: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    title: String,
    query: String,
    short: bool,
    searched: bool,
    hits: Vec<Hit>,
    incidents: Vec<IncidentCard>,
    map_style: String,
    selected: String,
    selected_name: String,
    hospital_count: String,
    breach_count: String,
    state_hospitals: Vec<StateHospital>,
}

#[derive(Template)]
#[template(path = "results.html")]
struct ResultsPage {
    short: bool,
    searched: bool,
    hits: Vec<Hit>,
}

#[derive(Template)]
#[template(path = "hospital.html")]
struct HospitalPage {
    title: String,
    incidents: Vec<IncidentCard>,
    label: String,
    place: String,
    ccn: String,
    public_entity: bool,
    facility_source: String,
    score_present: bool,
    score_value: String,
    score_width: String,
    score_note: String,
    score_breach: String,
    score_cve: String,
    score_exposure: String,
    vendors: Vec<VendorCard>,
    timeline: Vec<TimelineRow>,
    cve_note: String,
    cves: Vec<CveRow>,
    exposures: Vec<ExposureRow>,
    cehrt: Vec<CehrtRow>,
}

#[derive(Template)]
#[template(path = "vendor.html")]
struct VendorPage {
    title: String,
    incidents: Vec<IncidentCard>,
    name: String,
    summary: String,
    products: Vec<String>,
    hospitals: Vec<VendorHospitalRow>,
}

#[derive(Template)]
#[template(path = "kev.html")]
struct KevPage {
    title: String,
    incidents: Vec<IncidentCard>,
    range: String,
    prev: String,
    next: String,
    entries: Vec<KevRow>,
}

#[derive(Template)]
#[template(path = "missing.html")]
struct MissingPage {
    title: String,
    heading: String,
    incidents: Vec<IncidentCard>,
}

struct KevRow {
    cve_id: String,
    named: String,
    description: String,
    scores: String,
}

struct Hit {
    id: Uuid,
    label: String,
    meta: String,
}

struct IncidentCard {
    href: String,
    when: String,
    name: String,
    state: String,
    detail: String,
}

struct VendorCard {
    href: String,
    vendor: String,
    product: String,
    meta: String,
}

struct TimelineRow {
    when: String,
    kind: String,
    title: String,
    body: String,
    source_label: String,
    source_href: String,
}

struct CveRow {
    cve_id: String,
    kev: bool,
    product: String,
    scores: String,
    description: String,
    explanation: String,
}

struct ExposureRow {
    service: String,
    meta: String,
}

struct CehrtRow {
    line: String,
}

struct VendorHospitalRow {
    id: Uuid,
    name: String,
    meta: String,
}

struct StateHospital {
    id: Uuid,
    name: String,
    meta: String,
}

#[derive(sqlx::FromRow)]
struct StateCountRow {
    state: String,
    hospitals: i64,
    with_breach: i64,
}

#[derive(sqlx::FromRow)]
struct StateHospitalRow {
    id: Uuid,
    name: String,
    display_name: Option<String>,
    city: Option<String>,
    breaches: i64,
    vendors: Vec<String>,
}

pub(crate) async fn home(State(pool): State<PgPool>) -> Result<Response, ApiError> {
    Ok(render(
        LandingPage {
            title: "VulnRx".to_string(),
            incidents: ticker(&pool).await?,
        },
        StatusCode::OK,
    ))
}

pub(crate) async fn dashboard(
    State(pool): State<PgPool>,
    Query(query): Query<DashboardQuery>,
) -> Result<Response, ApiError> {
    let raw = query.q.unwrap_or_default();
    let (short, searched, hits) = search_state(&pool, &raw).await?;
    let selected = query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|code| {
            code.len() == 2 && code.chars().all(|ch| ch.is_ascii_alphabetic())
        })
        .map(|code| code.to_ascii_uppercase())
        .filter(|code| state_name(code) != code.as_str());
    let counts = state_counts(&pool).await?;
    let (selected_name, hospital_count, breach_count, state_hospitals) = match selected.as_deref()
    {
        Some(code) => {
            let stats = counts.get(code).copied().unwrap_or((0, 0));
            let rows = state_hospitals(&pool, code).await?;
            (
                state_name(code).to_string(),
                hospitals_label(stats.0),
                grouped(stats.1),
                rows,
            )
        }
        None => (String::new(), String::new(), String::new(), Vec::new()),
    };
    Ok(render(
        DashboardPage {
            title: "Map · VulnRx".to_string(),
            query: raw.trim().to_string(),
            short,
            searched,
            hits,
            incidents: ticker(&pool).await?,
            map_style: map_style(&counts, selected.as_deref()),
            selected: selected.unwrap_or_default(),
            selected_name,
            hospital_count,
            breach_count,
            state_hospitals,
        },
        StatusCode::OK,
    ))
}

pub(crate) async fn kev(
    State(pool): State<PgPool>,
    Query(query): Query<crate::kev::CatalogQuery>,
) -> Result<Response, ApiError> {
    let page = error::parse_page(query.page_raw())?;
    let (total, entries) = crate::kev::load(&pool, page).await?;
    let shown = entries.len() as i64;
    let offset = page
        .checked_sub(1)
        .and_then(|value| value.checked_mul(crate::kev::PAGE_SIZE))
        .unwrap_or(0);
    let range = if total == 0 {
        "0 entries in the stored catalog".to_string()
    } else if shown == 0 {
        format!("page {} of {}", page, grouped(total))
    } else {
        format!(
            "{}–{} of {}",
            grouped(offset + 1),
            grouped(offset + shown),
            grouped(total)
        )
    };
    let prev = if page > 1 {
        format!("/kev?page={}", page - 1)
    } else {
        String::new()
    };
    let next = if offset + shown < total {
        format!("/kev?page={}", page + 1)
    } else {
        String::new()
    };
    Ok(render(
        KevPage {
            title: "Known exploited · VulnRx".to_string(),
            incidents: ticker(&pool).await?,
            range,
            prev,
            next,
            entries: entries.into_iter().map(kev_row).collect(),
        },
        StatusCode::OK,
    ))
}

fn kev_row(entry: crate::kev::CatalogEntry) -> KevRow {
    let named = match (entry.vendor, entry.product) {
        (Some(vendor), Some(product)) => format!("{vendor} · {product}"),
        (Some(vendor), None) => vendor,
        (None, Some(product)) => product,
        (None, None) => String::new(),
    };
    let mut scores = Vec::new();
    if let Some(date) = entry.published_date {
        scores.push(date.to_string());
    }
    if let Some(cvss) = entry.cvss_score {
        scores.push(format!("CVSS {cvss}"));
    }
    if let Some(epss) = entry.epss_score {
        scores.push(format!("EPSS {epss}"));
    }
    KevRow {
        cve_id: entry.cve_id,
        named,
        description: entry.description.unwrap_or_default(),
        scores: scores.join(" · "),
    }
}

pub(crate) async fn search_results(
    State(pool): State<PgPool>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let raw = query.q.unwrap_or_default();
    let (short, searched, hits) = search_state(&pool, &raw).await?;
    Ok(render(
        ResultsPage {
            short,
            searched,
            hits,
        },
        StatusCode::OK,
    ))
}

pub(crate) async fn hospital(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = error::parse_id(&id)?;
    let profile = match hospitals::load_profile(&pool, id).await {
        Ok(profile) => profile,
        Err(ApiError::NotFound(_)) => return missing(&pool, "Hospital not found").await,
        Err(err) => return Err(err),
    };
    let vulns = hospitals::load_vulnerabilities(&pool, id).await?;
    let incidents = ticker(&pool).await?;
    let hospital = &profile.hospital.hospital;
    let (score_present, score_value, score_width, score_note, score_breach, score_cve, score_exposure) =
        score_fields(profile.risk.as_ref());
    Ok(render(
        HospitalPage {
            title: format!("{} · VulnRx", profile.hospital.label),
            label: profile.hospital.label.clone(),
            place: location(
                hospital.address.as_deref(),
                hospital.city.as_deref(),
                hospital.state.as_deref(),
                hospital.zip.as_deref(),
            ),
            ccn: hospital.ccn.clone().unwrap_or_default(),
            public_entity: hospital.is_public_entity,
            facility_source: hospital
                .source
                .as_deref()
                .map(source_label)
                .unwrap_or_default()
                .to_string(),
            score_present,
            score_value,
            score_width,
            score_note,
            score_breach,
            score_cve,
            score_exposure,
            vendors: profile
                .vendors
                .iter()
                .map(|link| VendorCard {
                    href: format!("/vendors/{}", link.vendor_id),
                    vendor: link.vendor_name.clone(),
                    product: product_line(link.product_name.as_deref(), link.version.as_deref()),
                    meta: vendor_meta(link),
                })
                .collect(),
            timeline: timeline(&profile),
            cve_note: cve_note(vulns.product_count, vulns.vulnerabilities.len()),
            cves: {
                let ids: Vec<String> = vulns
                    .vulnerabilities
                    .iter()
                    .map(|cve| cve.cve_id.clone())
                    .collect();
                let saved = crate::explain::cached_for(&pool, &ids).await?;
                vulns
                    .vulnerabilities
                    .iter()
                    .map(|cve| CveRow {
                        explanation: saved
                            .iter()
                            .find(|(id, _)| id == &cve.cve_id)
                            .map(|(_, text)| text.clone())
                            .unwrap_or_default(),
                        cve_id: cve.cve_id.clone(),
                        kev: cve.is_kev == Some(true),
                        product: format!("{} · {}", cve.vendor_name, cve.product_name),
                        scores: cve_scores(cve),
                        description: cve.description.clone().unwrap_or_default(),
                    })
                    .collect()
            },
            exposures: profile
                .exposures
                .iter()
                .map(|row| ExposureRow {
                    service: row
                        .exposed_service
                        .clone()
                        .unwrap_or_else(|| "index hit".to_string()),
                    meta: exposure_meta(row),
                })
                .collect(),
            cehrt: profile
                .cehrt_reports
                .iter()
                .map(|row| CehrtRow {
                    line: cehrt_line(row),
                })
                .collect(),
            incidents,
        },
        StatusCode::OK,
    ))
}

pub(crate) async fn vendor(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = error::parse_id(&id)?;
    let vendor = match crate::vendors::load_vendor(&pool, id).await {
        Ok(vendor) => vendor,
        Err(ApiError::NotFound(_)) => return missing(&pool, "Vendor not found").await,
        Err(err) => return Err(err),
    };
    let count = grouped(vendor.hospital_count);
    Ok(render(
        VendorPage {
            title: format!("{} · VulnRx", vendor.vendor.name),
            name: vendor.vendor.name.clone(),
            summary: format!(
                "{count} hospitals have a public source linking this vendor."
            ),
            products: vendor
                .products
                .iter()
                .map(|product| {
                    let mut line = product.name.clone();
                    if let Some(version) = product.version.as_deref().filter(|v| !v.is_empty()) {
                        line.push(' ');
                        line.push_str(version);
                    }
                    if let Some(chpl) = product.chpl_id.as_deref().filter(|v| !v.is_empty()) {
                        line.push_str(" · CHPL ");
                        line.push_str(chpl);
                    }
                    line
                })
                .collect(),
            hospitals: vendor
                .hospitals
                .iter()
                .map(|hospital| VendorHospitalRow {
                    id: hospital.id,
                    name: hospital.name.clone(),
                    meta: match (hospital.city.as_deref(), hospital.state.as_deref()) {
                        (Some(city), Some(state)) if !city.is_empty() => format!("{city}, {state}"),
                        (_, Some(state)) => state.to_string(),
                        (Some(city), _) if !city.is_empty() => city.to_string(),
                        _ => String::new(),
                    },
                })
                .collect(),
            incidents: ticker(&pool).await?,
        },
        StatusCode::OK,
    ))
}

pub(crate) async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/app.css"),
    )
}

pub(crate) async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/htmx.min.js"),
    )
}

pub(crate) async fn scanner() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/scanner.js"),
    )
}

pub(crate) async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn missing(pool: &PgPool, heading: &str) -> Result<Response, ApiError> {
    Ok(render(
        MissingPage {
            title: format!("{heading} · VulnRx"),
            heading: heading.to_string(),
            incidents: ticker(pool).await?,
        },
        StatusCode::NOT_FOUND,
    ))
}

async fn ticker(pool: &PgPool) -> Result<Vec<IncidentCard>, ApiError> {
    let rows = incidents::load_incidents(pool, TICKER_LIMIT).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let mut detail = row.detail.unwrap_or_default();
            let source = source_label(&row.source);
            if detail.is_empty() {
                detail = source.to_string();
            } else {
                detail.push_str(" · ");
                detail.push_str(source);
            }
            IncidentCard {
                href: format!("/hospitals/{}", row.hospital_id),
                when: row
                    .occurred_on
                    .map(|date| date.to_string())
                    .unwrap_or_else(|| "undated".to_string()),
                name: row.hospital_name,
                state: row.state.unwrap_or_default(),
                detail,
            }
        })
        .collect())
}

async fn state_counts(pool: &PgPool) -> Result<HashMap<String, (i64, i64)>, ApiError> {
    let rows = sqlx::query_as::<_, StateCountRow>(
        "SELECT h.state AS state,
                COUNT(*)::bigint AS hospitals,
                COUNT(DISTINCT b.hospital_id)::bigint AS with_breach
         FROM hospitals h
         LEFT JOIN breach_events b ON b.hospital_id = h.id
         WHERE h.state IS NOT NULL
         GROUP BY h.state",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.state, (row.hospitals, row.with_breach)))
        .collect())
}

async fn state_hospitals(pool: &PgPool, state: &str) -> Result<Vec<StateHospital>, ApiError> {
    let rows = sqlx::query_as::<_, StateHospitalRow>(STATE_HOSPITALS_SQL)
        .bind(state)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let breach = match row.breaches {
                0 => "no linked breach".to_string(),
                1 => "1 linked breach".to_string(),
                n => format!("{} linked breaches", grouped(n)),
            };
            let vendors = vendor_stack(&row.vendors);
            let mut meta = format!("{breach} · {vendors}");
            if let Some(city) = row.city.filter(|city| !city.trim().is_empty()) {
                meta = format!("{city} · {meta}");
            }
            StateHospital {
                id: row.id,
                name: crate::public_name(&row.name, row.display_name.as_deref()).to_string(),
                meta,
            }
        })
        .collect())
}

fn hospitals_label(count: i64) -> String {
    if count == 1 {
        "1 hospital".to_string()
    } else {
        format!("{} hospitals", grouped(count))
    }
}

fn vendor_stack(vendors: &[String]) -> String {
    match vendors {
        [] => "no certified product".to_string(),
        [one] => one.clone(),
        [first, second] => format!("{first}, {second}"),
        many => format!("{}, {} · {} vendors", many[0], many[1], many.len()),
    }
}

const STATE_HOSPITALS_SQL: &str = "SELECT h.id, h.name, h.display_name, h.city,
        COUNT(DISTINCT b.id)::bigint AS breaches,
        COALESCE((
            SELECT ARRAY(
                SELECT v.name
                FROM (
                    SELECT DISTINCT vendor.name
                    FROM hospital_vendor_map m
                    JOIN vendors vendor ON vendor.id = m.vendor_id
                    WHERE m.hospital_id = h.id
                ) v(name)
                ORDER BY v.name
            )
        ), '{}') AS vendors
 FROM hospitals h
 LEFT JOIN breach_events b ON b.hospital_id = h.id
 WHERE h.state = $1
 GROUP BY h.id, h.name, h.display_name, h.city
 ORDER BY breaches DESC, h.name";

fn map_style(counts: &HashMap<String, (i64, i64)>, selected: Option<&str>) -> String {
    let mut css = String::new();
    for (code, stats) in counts {
        if code.len() == 2 && code.chars().all(|ch| ch.is_ascii_uppercase()) {
            css.push_str(&format!(
                ".us-map .{} {{ fill: {}; }}\n",
                code.to_ascii_lowercase(),
                breach_fill(stats.1)
            ));
        }
    }
    if let Some(code) = selected {
        css.push_str(&format!(
            ".us-map a[href$=\"state={code}\"] path, .us-map a[href$=\"state={code}\"] circle {{ stroke: #c6f54a; stroke-width: 2px; }}\n"
        ));
    }
    css
}

fn breach_fill(count: i64) -> &'static str {
    match count {
        0 => "#172018",
        1..=2 => "#6a3414",
        3..=7 => "#9a3e10",
        8..=15 => "#d45312",
        _ => "#ff6a1a",
    }
}

fn state_name(code: &str) -> &str {
    match code {
        "AL" => "Alabama",
        "AK" => "Alaska",
        "AZ" => "Arizona",
        "AR" => "Arkansas",
        "CA" => "California",
        "CO" => "Colorado",
        "CT" => "Connecticut",
        "DE" => "Delaware",
        "DC" => "District of Columbia",
        "FL" => "Florida",
        "GA" => "Georgia",
        "HI" => "Hawaii",
        "ID" => "Idaho",
        "IL" => "Illinois",
        "IN" => "Indiana",
        "IA" => "Iowa",
        "KS" => "Kansas",
        "KY" => "Kentucky",
        "LA" => "Louisiana",
        "ME" => "Maine",
        "MD" => "Maryland",
        "MA" => "Massachusetts",
        "MI" => "Michigan",
        "MN" => "Minnesota",
        "MS" => "Mississippi",
        "MO" => "Missouri",
        "MT" => "Montana",
        "NE" => "Nebraska",
        "NV" => "Nevada",
        "NH" => "New Hampshire",
        "NJ" => "New Jersey",
        "NM" => "New Mexico",
        "NY" => "New York",
        "NC" => "North Carolina",
        "ND" => "North Dakota",
        "OH" => "Ohio",
        "OK" => "Oklahoma",
        "OR" => "Oregon",
        "PA" => "Pennsylvania",
        "RI" => "Rhode Island",
        "SC" => "South Carolina",
        "SD" => "South Dakota",
        "TN" => "Tennessee",
        "TX" => "Texas",
        "UT" => "Utah",
        "VT" => "Vermont",
        "VA" => "Virginia",
        "WA" => "Washington",
        "WV" => "West Virginia",
        "WI" => "Wisconsin",
        "WY" => "Wyoming",
        other => other,
    }
}

async fn search_state(
    pool: &PgPool,
    raw: &str,
) -> Result<(bool, bool, Vec<Hit>), ApiError> {
    let trimmed = raw.trim();
    let chars = trimmed.chars().count();
    if chars == 0 {
        return Ok((false, false, Vec::new()));
    }
    if chars < 2 {
        return Ok((true, false, Vec::new()));
    }
    let hits = hospitals::find_hospitals(pool, trimmed, SEARCH_LIMIT)
        .await?
        .into_iter()
        .map(hit_from)
        .collect();
    Ok((false, true, hits))
}

fn hit_from(hit: SearchHit) -> Hit {
    let mut parts = Vec::new();
    match (hit.city.as_deref(), hit.state.as_deref()) {
        (Some(city), Some(state)) if !city.is_empty() => parts.push(format!("{city}, {state}")),
        (_, Some(state)) => parts.push(state.to_string()),
        (Some(city), _) if !city.is_empty() => parts.push(city.to_string()),
        _ => {}
    }
    if let Some(ccn) = hit.ccn.as_deref() {
        parts.push(format!("CCN {ccn}"));
    }
    Hit {
        id: hit.id,
        label: hit.label,
        meta: parts.join(" · "),
    }
}

fn score_fields(
    risk: Option<&vulnrx_models::RiskScore>,
) -> (bool, String, String, String, String, String, String) {
    let Some(risk) = risk else {
        return (
            false,
            String::new(),
            "0%".to_string(),
            "No rollup is stored. A score is written only when a linked breach, Item 1.05 filing, product CVE, or exposure exists.".to_string(),
            String::new(),
            String::new(),
            String::new(),
        );
    };
    let width = format!("{}%", percent(&risk.composite_score));
    (
        true,
        risk.composite_score.to_string(),
        width,
        score_note(&risk.method),
        component_text(&risk.method, "breach", &risk.breach_component),
        component_text(&risk.method, "cve", &risk.cve_component),
        component_text(&risk.method, "exposure", &risk.exposure_component),
    )
}

fn score_note(method: &str) -> String {
    let Some(inputs) = method.strip_prefix("v1:") else {
        return format!("Method {method}.");
    };
    let parts: Vec<&str> = inputs.split('+').filter(|part| !part.is_empty()).collect();
    let mut missing = Vec::new();
    for name in ["breach", "cve", "exposure"] {
        if !parts.contains(&name) {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        format!("Inputs: {}.", parts.join(", "))
    } else {
        format!(
            "Inputs: {}. Not inputs: {}.",
            parts.join(", "),
            missing.join(", ")
        )
    }
}

fn component_text(method: &str, key: &str, value: &Decimal) -> String {
    let inputs = method.strip_prefix("v1:").unwrap_or("");
    if inputs.split('+').any(|part| part == key) {
        value.to_string()
    } else {
        "not an input".to_string()
    }
}

fn percent(score: &Decimal) -> u8 {
    let text = score.round_dp(0).to_string();
    text.parse::<u16>().unwrap_or(0).min(100) as u8
}

fn timeline(profile: &hospitals::ProfileResponse) -> Vec<TimelineRow> {
    let mut rows: Vec<(Option<NaiveDate>, TimelineRow)> = Vec::new();
    for breach in &profile.breaches {
        let mut body = Vec::new();
        if let Some(kind) = breach.breach_type.as_deref() {
            body.push(kind.to_string());
        }
        if let Some(count) = breach.individuals_affected {
            body.push(format!("{} people", grouped(i64::from(count))));
        }
        if let Some(location) = breach.breach_location.as_deref().filter(|v| !v.is_empty()) {
            body.push(location.to_string());
        }
        rows.push((
            breach.date_reported,
            TimelineRow {
                when: date_text(breach.date_reported),
                kind: "breach".to_string(),
                title: breach.entity_name.clone(),
                body: body.join(" · "),
                source_label: source_label(&breach.source).to_string(),
                source_href: safe_href(breach.source_url.as_deref())
                    .unwrap_or_default()
                    .to_string(),
            },
        ));
    }
    for filing in &profile.filings {
        rows.push((
            filing.filed_date,
            TimelineRow {
                when: date_text(filing.filed_date),
                kind: "filing".to_string(),
                title: filing
                    .filing_type
                    .clone()
                    .unwrap_or_else(|| filing.company_name.clone()),
                body: filing.summary.clone().unwrap_or_default(),
                source_label: source_label(&filing.source).to_string(),
                source_href: safe_href(filing.source_url.as_deref())
                    .unwrap_or_default()
                    .to_string(),
            },
        ));
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    rows.into_iter().map(|(_, row)| row).collect()
}

fn cve_note(product_count: i64, vuln_count: usize) -> String {
    if vuln_count == 0 && product_count == 0 {
        "No certified product is linked to this hospital.".to_string()
    } else if vuln_count == 0 {
        format!("{product_count} certified products are linked. None is linked to a CVE.")
    } else {
        format!("{vuln_count} linked CVE records.")
    }
}

fn cve_scores(cve: &hospitals::Vulnerability) -> String {
    let mut parts = Vec::new();
    if let Some(cvss) = cve.cvss_score.as_ref() {
        parts.push(format!("CVSS {cvss}"));
    }
    if let Some(epss) = cve.epss_score.as_ref() {
        parts.push(format!("EPSS {epss}"));
    }
    if let Some(basis) = cve.match_basis.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("match {basis}"));
    }
    parts.join(" · ")
}

fn exposure_meta(row: &vulnrx_models::Exposure) -> String {
    let mut parts = vec![source_label(&row.source).to_string()];
    if let Some(seen) = row.last_seen {
        parts.push(seen.to_string());
    }
    parts.push(row.raw_reference.clone());
    parts.join(" · ")
}

fn cehrt_line(row: &hospitals::CehrtReport) -> String {
    let mut line = row.cehrt_id.clone();
    if let Some(meets) = row.meets_criteria {
        line.push_str(if meets {
            " · meets criteria"
        } else {
            " · does not meet criteria"
        });
    }
    if let Some(end) = row.period_end {
        line.push_str(" · period ending ");
        line.push_str(&end.to_string());
    }
    line.push_str(" · ");
    line.push_str(source_label(&row.source));
    line
}

fn product_line(name: Option<&str>, version: Option<&str>) -> String {
    match name.filter(|value| !value.is_empty()) {
        Some(name) => match version.filter(|value| !value.is_empty()) {
            Some(version) => format!("{name} {version}"),
            None => name.to_string(),
        },
        None => "No product named on this link.".to_string(),
    }
}

fn vendor_meta(link: &hospitals::VendorLink) -> String {
    format!(
        "{} · confidence {}",
        source_label(&link.source),
        link.confidence
    )
}

fn location(address: Option<&str>, city: Option<&str>, state: Option<&str>, zip: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(address) = address.filter(|value| !value.is_empty()) {
        parts.push(address.to_string());
    }
    let mut city_line = String::new();
    if let Some(city) = city.filter(|value| !value.is_empty()) {
        city_line.push_str(city);
    }
    if let Some(state) = state.filter(|value| !value.is_empty()) {
        if !city_line.is_empty() {
            city_line.push_str(", ");
        }
        city_line.push_str(state);
    }
    if let Some(zip) = zip.filter(|value| !value.is_empty()) {
        if !city_line.is_empty() {
            city_line.push(' ');
        }
        city_line.push_str(zip);
    }
    if !city_line.is_empty() {
        parts.push(city_line);
    }
    parts.join(" · ")
}

fn date_text(date: Option<NaiveDate>) -> String {
    date.map(|value| value.to_string())
        .unwrap_or_else(|| "undated".to_string())
}

fn source_label(source: &str) -> &str {
    match source {
        "hhs_ocr_breach_portal" => "HHS OCR breach portal",
        "sec_edgar" => "SEC EDGAR",
        "cms_pi_chpl" => "CMS promoting interoperability / CHPL",
        "cms_pi_2024" => "CMS 2024 promoting interoperability",
        "cms_hospital_general_information" => "CMS hospital general information",
        "shodan" => "Shodan",
        "censys" => "Censys",
        "zoomeye" => "ZoomEye",
        "netlas" => "Netlas",
        "internetdb" => "Shodan InternetDB",
        other => other,
    }
}

fn safe_href(url: Option<&str>) -> Option<&str> {
    url.filter(|value| value.starts_with("https://") || value.starts_with("http://"))
}

fn grouped(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index.is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    let text: String = out.chars().rev().collect();
    if n < 0 { format!("-{text}") } else { text }
}

fn render<T: Template>(template: T, status: StatusCode) -> Response {
    match template.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(err) => {
            eprintln!("template error: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}
