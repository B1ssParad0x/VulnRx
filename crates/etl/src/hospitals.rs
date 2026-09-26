use sqlx::Connection;
use sqlx::PgPool;

use crate::load::IngestError;

pub const HOSPITAL_REGISTRY_URL: &str = "https://data.cms.gov/provider-data/sites/default/files/resources/893c372430d9d71a1c52737d01239d47_1785189955/Hospital_General_Information.csv";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HospitalLoadReport {
    pub hospitals: u64,
    pub skipped: i64,
}

/// Load every Medicare-registered hospital from the CMS Hospital General Information file.
///
/// This does not create vendor links. A hospital that never reported a certified product
/// still exists here. Government ownership sets `is_public_entity`; other ownership values
/// do not clear a flag that another source already set.
pub async fn ingest_hospital_registry(
    pool: &PgPool,
    csv_bytes: &[u8],
    source_url: &str,
    state: Option<&str>,
) -> Result<HospitalLoadReport, IngestError> {
    let state = normalize_state(state)?;
    let (projected, skipped) = project_registry(csv_bytes, state.as_deref())?;
    let mut conn = pool.acquire().await?;
    sqlx::query("DROP TABLE IF EXISTS hgi_stage")
        .execute(&mut *conn)
        .await?;
    sqlx::query(CREATE_STAGE).execute(&mut *conn).await?;
    let copied = async {
        let mut copy = conn
            .copy_in_raw("COPY hgi_stage FROM STDIN WITH (FORMAT csv, HEADER MATCH)")
            .await?;
        copy.send(projected).await?;
        copy.finish().await?;
        Ok::<_, IngestError>(())
    }
    .await;
    if let Err(err) = copied {
        let _ = sqlx::query("DROP TABLE IF EXISTS hgi_stage")
            .execute(&mut *conn)
            .await;
        return Err(err);
    }
    let mut tx = conn.begin().await?;
    let hospitals = sqlx::query(UPSERT)
        .bind(source_url)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    let _ = sqlx::query("DROP TABLE IF EXISTS hgi_stage")
        .execute(&mut *conn)
        .await;
    Ok(HospitalLoadReport { hospitals, skipped })
}

fn project_registry(csv_bytes: &[u8], state: Option<&str>) -> Result<(Vec<u8>, i64), IngestError> {
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
    let ownership = index("Hospital Ownership")?;

    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "ccn",
        "name",
        "address",
        "city",
        "state",
        "zip",
        "phone",
        "government_owned",
    ])?;
    let mut skipped = 0_i64;
    for record in reader.records() {
        let record = record?;
        let ccn = record.get(facility_id).unwrap_or("").trim();
        let hospital_name = record.get(name).unwrap_or("").trim();
        let hospital_state = record.get(state_col).unwrap_or("").trim();
        let state_ok = hospital_state.is_empty()
            || (hospital_state.len() == 2
                && hospital_state.chars().all(|c| c.is_ascii_uppercase()));
        let in_scope = state.is_none_or(|wanted| hospital_state == wanted);
        if !in_scope {
            continue;
        }
        if !valid_facility_id(ccn) || hospital_name.is_empty() || !state_ok {
            skipped += 1;
            continue;
        }
        let ownership = record.get(ownership).unwrap_or("").trim();
        let government = ownership.starts_with("Government")
            || ownership == "Veterans Health Administration"
            || ownership == "Department of Defense";
        writer.write_record([
            ccn,
            hospital_name,
            record.get(address).unwrap_or("").trim(),
            record.get(city).unwrap_or("").trim(),
            hospital_state,
            record.get(zip).unwrap_or("").trim(),
            record.get(phone).unwrap_or("").trim(),
            if government { "true" } else { "false" },
        ])?;
    }
    writer.flush()?;
    let bytes = writer
        .into_inner()
        .map_err(csv::IntoInnerError::into_error)?;
    Ok((bytes, skipped))
}

fn valid_facility_id(ccn: &str) -> bool {
    let bytes = ccn.as_bytes();
    if bytes.len() != 6 {
        return false;
    }
    if ccn.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    bytes[..5].iter().all(u8::is_ascii_digit) && bytes[5].is_ascii_uppercase()
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
CREATE TEMP TABLE hgi_stage (
    ccn TEXT,
    name TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    phone TEXT,
    government_owned TEXT
)
"#;

const UPSERT: &str = r#"
INSERT INTO hospitals (
    ccn, name, city, state, address, zip, phone, is_public_entity, source, source_url
)
SELECT
    ccn,
    name,
    NULLIF(city, ''),
    NULLIF(state, ''),
    NULLIF(address, ''),
    NULLIF(zip, ''),
    NULLIF(phone, ''),
    government_owned = 'true',
    'cms_hospital_general_information',
    $1
FROM hgi_stage
ON CONFLICT (ccn) WHERE ccn IS NOT NULL
DO UPDATE SET
    name = EXCLUDED.name,
    city = EXCLUDED.city,
    state = EXCLUDED.state,
    address = EXCLUDED.address,
    zip = EXCLUDED.zip,
    phone = EXCLUDED.phone,
    source = EXCLUDED.source,
    source_url = EXCLUDED.source_url,
    is_public_entity = hospitals.is_public_entity OR EXCLUDED.is_public_entity
"#;
