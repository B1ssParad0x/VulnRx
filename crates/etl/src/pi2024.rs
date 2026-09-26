use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;

/// Current CMS Promoting Interoperability hospital file. One row per hospital, with a CEHRT bundle id.
pub const PI_2024_URL: &str = "https://data.cms.gov/provider-data/sites/default/files/resources/5462b19a756c53c1becccf13787d9157_1785189974/Promoting_Interoperability-Hospital.csv";

pub const PI_2024_SOURCE: &str = "cms_pi_2024";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pi2024Report {
    pub hospitals: u64,
    pub cehrt_reports: u64,
    pub skipped: i64,
}

/// Store 2024 facility rows and the certified-product bundle each hospital reported.
///
/// The bundle id is not itself a product. `expand_cehrt` asks CHPL which products are inside it.
pub async fn ingest_pi_2024(
    pool: &PgPool,
    csv_bytes: &[u8],
    source_url: &str,
    state: Option<&str>,
) -> Result<Pi2024Report, IngestError> {
    let state = normalize_state(state)?;
    let (projected, skipped) = project_pi_2024(csv_bytes, state.as_deref())?;
    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS pi2024_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY pi2024_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(projected).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS pi2024_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let hospitals = sqlx::query(UPSERT_HOSPITALS)
        .bind(source_url)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let cehrt_reports = sqlx::query(UPSERT_CEHRT)
        .bind(source_url)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS pi2024_stage")
        .execute(&mut *conn)
        .await;
    Ok(Pi2024Report {
        hospitals,
        cehrt_reports,
        skipped,
    })
}

fn project_pi_2024(csv_bytes: &[u8], state: Option<&str>) -> Result<(Vec<u8>, i64), IngestError> {
    let mut reader = csv::Reader::from_reader(csv_bytes);
    let headers = reader.headers()?.clone();
    let index = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .ok_or_else(|| IngestError::MissingColumn(name.to_string()))
    };
    let facility_id = index("Facility ID")?;
    let name = index("Facility Name")?;
    let address = index("Address")?;
    let city = index("City/Town")?;
    let state_col = index("State")?;
    let zip = index("ZIP Code")?;
    let phone = index("Telephone Number")?;
    let cehrt = index("CEHRT ID")?;
    let meets = index("Meets criteria for promoting interoperability of EHRs")?;
    let start = index("Start Date")?;
    let end = index("End Date")?;

    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "ccn",
        "name",
        "address",
        "city",
        "state",
        "zip",
        "phone",
        "cehrt_id",
        "meets_criteria",
        "period_start",
        "period_end",
    ])?;
    let mut skipped = 0_i64;
    for record in reader.records() {
        let record = record?;
        let ccn = record.get(facility_id).unwrap_or("").trim();
        let hospital_name = record.get(name).unwrap_or("").trim();
        let hospital_state = record.get(state_col).unwrap_or("").trim();
        let in_scope = state.is_none_or(|wanted| hospital_state == wanted);
        if !in_scope {
            continue;
        }
        let state_ok = hospital_state.is_empty()
            || (hospital_state.len() == 2
                && hospital_state.chars().all(|c| c.is_ascii_uppercase()));
        if !state_ok
            || ccn.len() != 6
            || !ccn.chars().all(|c| c.is_ascii_digit())
            || hospital_name.is_empty()
        {
            skipped += 1;
            continue;
        }
        let cehrt_id = record.get(cehrt).unwrap_or("").trim().to_ascii_uppercase();
        let cehrt_ok = cehrt_id.len() == 15 && cehrt_id.chars().all(|c| c.is_ascii_alphanumeric());
        writer.write_record([
            ccn,
            hospital_name,
            record.get(address).unwrap_or("").trim(),
            record.get(city).unwrap_or("").trim(),
            hospital_state,
            record.get(zip).unwrap_or("").trim(),
            record.get(phone).unwrap_or("").trim(),
            if cehrt_ok { cehrt_id.as_str() } else { "" },
            record.get(meets).unwrap_or("").trim(),
            record.get(start).unwrap_or("").trim(),
            record.get(end).unwrap_or("").trim(),
        ])?;
    }
    writer.flush()?;
    let bytes = writer
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;
    Ok((bytes, skipped))
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
CREATE TEMP TABLE pi2024_stage (
    ccn TEXT,
    name TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    phone TEXT,
    cehrt_id TEXT,
    meets_criteria TEXT,
    period_start TEXT,
    period_end TEXT
)
"#;

const UPSERT_HOSPITALS: &str = r#"
INSERT INTO hospitals (ccn, name, city, state, address, zip, phone, source, source_url)
SELECT ccn, name, NULLIF(city, ''), NULLIF(state, ''), NULLIF(address, ''), NULLIF(zip, ''), NULLIF(phone, ''),
       'cms_pi_2024', $1
FROM pi2024_stage
ON CONFLICT (ccn) WHERE ccn IS NOT NULL
DO UPDATE SET
    source = COALESCE(hospitals.source, EXCLUDED.source),
    source_url = COALESCE(hospitals.source_url, EXCLUDED.source_url)
"#;

const UPSERT_CEHRT: &str = r#"
INSERT INTO cehrt_reports (
    hospital_id, cehrt_id, meets_criteria, period_start, period_end, source, source_url
)
SELECT
    h.id,
    s.cehrt_id,
    CASE s.meets_criteria WHEN 'Y' THEN TRUE WHEN 'N' THEN FALSE END,
    CASE
        WHEN s.period_start ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$'
        THEN to_date(s.period_start, 'MM/DD/YYYY')
    END,
    CASE
        WHEN s.period_end ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}$'
        THEN to_date(s.period_end, 'MM/DD/YYYY')
    END,
    'cms_pi_2024',
    $1
FROM pi2024_stage s
JOIN hospitals h ON h.ccn = s.ccn
WHERE s.cehrt_id ~ '^[0-9A-Z]{15}$'
ON CONFLICT ON CONSTRAINT cehrt_reports_natural_uidx
DO UPDATE SET
    meets_criteria = EXCLUDED.meets_criteria,
    period_start = EXCLUDED.period_start,
    period_end = EXCLUDED.period_end,
    source_url = EXCLUDED.source_url
"#;
