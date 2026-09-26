use std::collections::HashMap;
use std::str::FromStr;

use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use sqlx::FromRow;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::test]
async fn scores_only_linked_evidence_and_omits_missing_inputs() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_score_test");
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin)
        .await
        .expect("connect to the maintenance database; start it with docker compose up -d");
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
    sqlx::query(CREATE_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&test_url)
        .await
        .unwrap();
    vulnrx_models::migrate(&pool).await.unwrap();

    sqlx::query(
        "INSERT INTO hospitals (name, state) VALUES
            ('RECENT GENERAL', 'MO'),
            ('OLDER GENERAL', 'MO'),
            ('STACK GENERAL', 'MO'),
            ('FILING GENERAL', 'TX'),
            ('UNKNOWN GENERAL', 'KS'),
            ('CVEONLY GENERAL', 'KS'),
            ('QUIET GENERAL', 'KS'),
            ('GOVERNANCE GENERAL', 'TX')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, hospital_id, individuals_affected, date_reported, source)
         SELECT 'Recent General', 'covered_entity', id, 12000, CURRENT_DATE - 30, 'hhs_ocr_breach_portal'
         FROM hospitals WHERE name = 'RECENT GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, hospital_id, individuals_affected, date_reported, source)
         SELECT 'Older General', 'covered_entity', id, 100, (CURRENT_DATE - INTERVAL '4 years')::date, 'hhs_ocr_breach_portal'
         FROM hospitals WHERE name = 'OLDER GENERAL'
         UNION ALL
         SELECT 'Older General', 'covered_entity', id, 600, (CURRENT_DATE - INTERVAL '2 years')::date, 'hhs_ocr_breach_portal'
         FROM hospitals WHERE name = 'OLDER GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, hospital_id, individuals_affected, date_reported, source)
         SELECT 'Stack General', 'covered_entity', id, 12000, CURRENT_DATE - 30, 'hhs_ocr_breach_portal'
         FROM hospitals WHERE name = 'STACK GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, hospital_id, individuals_affected, date_reported, source)
         SELECT 'Unknown General', 'covered_entity', id, NULL, NULL, 'hhs_ocr_breach_portal'
         FROM hospitals WHERE name = 'UNKNOWN GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, hospital_id, individuals_affected, date_reported, source)
         VALUES ('Unlinked Clinic', 'covered_entity', NULL, 9000, CURRENT_DATE, 'hhs_ocr_breach_portal')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sec_filings (company_name, hospital_id, filing_type, filed_date, source)
         SELECT 'Filing General', id, '8-K Item 1.05', CURRENT_DATE, 'sec_edgar'
         FROM hospitals WHERE name = 'FILING GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sec_filings (company_name, hospital_id, filing_type, filed_date, source)
         SELECT 'Governance General', id, '10-K Item 1C', CURRENT_DATE, 'sec_edgar'
         FROM hospitals WHERE name = 'GOVERNANCE GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO vendors (name) VALUES ('Example EHR')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO products (vendor_id, name)
         SELECT id, 'Charting' FROM vendors WHERE name = 'Example EHR'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO cves (cve_id, cvss_score, epss_score, is_kev)
         VALUES ('CVE-2024-12345', 9.0, 0.50000, TRUE)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO hospital_vendor_map (hospital_id, vendor_id, product_id, source, confidence)
         SELECT h.id, v.id, p.id, src.source, 0.95
         FROM hospitals h
         JOIN vendors v ON v.name = 'Example EHR'
         JOIN products p ON p.vendor_id = v.id
         JOIN (VALUES ('STACK GENERAL', 'cms_pi_chpl'), ('CVEONLY GENERAL', 'cms_pi_chpl'), ('CVEONLY GENERAL', 'cms_pi_2024_chpl'))
            AS src(hospital_name, source) ON src.hospital_name = h.name",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO product_cve_map (product_id, cve_id, match_basis)
         SELECT p.id, c.id, 'cisa_kev'
         FROM products p
         JOIN cves c ON c.cve_id = 'CVE-2024-12345'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO exposures (hospital_id, exposed_service, source, raw_reference)
         SELECT id, 'https', 'shodan', 'index-hit-1'
         FROM hospitals WHERE name = 'STACK GENERAL'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let report = vulnrx_etl::score_hospitals(&pool).await.unwrap();
    assert_eq!(report.hospitals, 6);
    assert_eq!(report.breach_only, 4);
    assert_eq!(report.with_cve, 2);
    assert_eq!(report.with_exposure, 1);

    let rows = sqlx::query_as::<_, StoredScore>(
        "SELECT h.name, r.composite_score, r.breach_component, r.cve_component,
                r.exposure_component, r.method, r.vendor_id IS NULL AS hospital_rollup
         FROM risk_scores r
         JOIN hospitals h ON h.id = r.hospital_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let by_name: HashMap<String, StoredScore> = rows
        .into_iter()
        .map(|row| (row.name.clone(), row))
        .collect();

    let recent = by_name.get("RECENT GENERAL").unwrap();
    assert!(recent.hospital_rollup);
    assert_eq!(recent.method, "v1:breach");
    assert_eq!(recent.composite_score, dec("60.00"));
    assert_eq!(recent.breach_component, dec("60.00"));
    assert_eq!(recent.cve_component, dec("0.00"));
    assert_eq!(recent.exposure_component, dec("0.00"));

    let older = by_name.get("OLDER GENERAL").unwrap();
    assert_eq!(older.method, "v1:breach");
    assert_eq!(older.composite_score, dec("38.00"));
    assert_eq!(older.breach_component, dec("38.00"));

    let unknown = by_name.get("UNKNOWN GENERAL").unwrap();
    assert_eq!(unknown.composite_score, dec("5.25"));

    let filing = by_name.get("FILING GENERAL").unwrap();
    assert_eq!(filing.method, "v1:breach");
    assert_eq!(filing.composite_score, dec("40.00"));

    let stack = by_name.get("STACK GENERAL").unwrap();
    assert_eq!(stack.method, "v1:breach+cve+exposure");
    assert_eq!(stack.breach_component, dec("60.00"));
    assert_eq!(stack.cve_component, dec("76.00"));
    assert_eq!(stack.exposure_component, dec("40.00"));
    assert_eq!(stack.composite_score, dec("63.40"));

    let cve_only = by_name.get("CVEONLY GENERAL").unwrap();
    assert_eq!(cve_only.method, "v1:cve");
    assert_eq!(cve_only.composite_score, dec("76.00"));
    assert_eq!(cve_only.breach_component, dec("0.00"));

    assert!(!by_name.contains_key("QUIET GENERAL"));
    assert!(!by_name.contains_key("GOVERNANCE GENERAL"));

    let again = vulnrx_etl::score_hospitals(&pool).await.unwrap();
    assert_eq!(again.hospitals, 6);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_scores")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 6);

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

#[derive(Debug, FromRow)]
struct StoredScore {
    name: String,
    composite_score: Decimal,
    breach_component: Decimal,
    cve_component: Decimal,
    exposure_component: Decimal,
    method: String,
    hospital_rollup: bool,
}

fn dec(text: &str) -> Decimal {
    Decimal::from_str(text).unwrap()
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_score_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_score_test";

fn with_database(database_url: &str, database: &str) -> String {
    let (without_query, query) = database_url.split_once('?').unwrap_or((database_url, ""));
    let Some(idx) = without_query.rfind('/') else {
        return database_url.to_string();
    };
    let mut url = format!("{}/{database}", &without_query[..idx]);
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    url
}
