use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::test]
async fn reads_linked_records_and_leaves_unlinked_rows_out() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_api_test");
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
    seed(&pool).await;

    let health = call(&pool, "/api/health").await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json["ok"], true);

    let short = call(&pool, "/api/hospitals/search?q=s").await;
    assert_eq!(short.json["hospitals"].as_array().unwrap().len(), 0);

    let south = call(&pool, "/api/hospitals/search?q=south").await;
    assert_eq!(names(&south.json), vec!["SOUTHEAST HEALTH MEDICAL CENTER"]);

    let by_ccn = call(&pool, "/api/hospitals/search?q=010001").await;
    assert_eq!(names(&by_ccn.json), vec!["SOUTHEAST HEALTH MEDICAL CENTER"]);

    let by_display = call(&pool, "/api/hospitals/search?q=downtown").await;
    assert_eq!(by_display.json["hospitals"][0]["label"], "Mercy Downtown");

    let by_alias = call(&pool, "/api/hospitals/search?q=regional").await;
    assert_eq!(names(&by_alias.json), vec!["SOUTHEAST HEALTH MEDICAL CENTER"]);

    let percent = call(&pool, "/api/hospitals/search?q=0%25").await;
    assert_eq!(names(&percent.json), vec!["100% MEMORIAL"]);

    let hospital_id = by_ccn.json["hospitals"][0]["id"].as_str().unwrap();
    let profile = call(&pool, &format!("/api/hospitals/{hospital_id}")).await;
    assert_eq!(profile.status, StatusCode::OK);
    assert_eq!(profile.json["hospital"]["label"], "SOUTHEAST HEALTH MEDICAL CENTER");
    assert_eq!(profile.json["hospital"]["ccn"], "010001");
    assert_eq!(profile.json["risk"]["method"], "v1:breach");
    assert_eq!(profile.json["risk"]["composite_score"], "60.00");
    assert_eq!(profile.json["risk"]["cve_component"], "0");
    assert_eq!(profile.json["vendors"].as_array().unwrap().len(), 1);
    assert_eq!(profile.json["vendors"][0]["vendor_name"], "Example EHR");
    assert_eq!(profile.json["vendors"][0]["source"], "cms_pi_chpl");
    assert_eq!(profile.json["cehrt_reports"][0]["cehrt_id"], "1234567890ABCDE");
    assert_eq!(profile.json["breaches"].as_array().unwrap().len(), 1);
    assert_eq!(profile.json["breaches"][0]["individuals_affected"], 12000);
    assert_eq!(profile.json["filings"][0]["filing_type"], "10-K Item 1C");
    assert_eq!(profile.json["exposures"][0]["source"], "shodan");

    let vulns = call(
        &pool,
        &format!("/api/hospitals/{hospital_id}/vulnerabilities"),
    )
    .await;
    assert_eq!(vulns.json["product_count"], 1);
    assert_eq!(vulns.json["vulnerabilities"][0]["cve_id"], "CVE-2024-12345");
    assert_eq!(vulns.json["vulnerabilities"][0]["is_kev"], true);
    assert_eq!(vulns.json["vulnerabilities"][0]["match_basis"], "cisa_kev");

    let county = call(&pool, "/api/hospitals/search?q=county").await;
    let county_id = county.json["hospitals"][0]["id"].as_str().unwrap();
    let county_profile = call(&pool, &format!("/api/hospitals/{county_id}")).await;
    assert_eq!(county_profile.json["hospital"]["label"], "Mercy Downtown");
    assert!(county_profile.json["risk"].is_null());
    assert_eq!(
        county_profile.json["filings"][0]["filing_type"],
        "8-K Item 1.05"
    );
    let county_vulns = call(
        &pool,
        &format!("/api/hospitals/{county_id}/vulnerabilities"),
    )
    .await;
    assert_eq!(county_vulns.json["product_count"], 0);
    assert_eq!(county_vulns.json["vulnerabilities"].as_array().unwrap().len(), 0);

    let missing = call(
        &pool,
        &format!("/api/hospitals/{}", Uuid::nil()),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let bad = call(&pool, "/api/hospitals/not-a-uuid").await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.json["error"], "id must be a uuid");

    let vendor_id = profile.json["vendors"][0]["vendor_id"].as_str().unwrap();
    let vendor = call(&pool, &format!("/api/vendors/{vendor_id}")).await;
    assert_eq!(vendor.json["vendor"]["name"], "Example EHR");
    assert_eq!(vendor.json["hospital_count"], 1);
    assert_eq!(vendor.json["hospitals"][0]["name"], "SOUTHEAST HEALTH MEDICAL CENTER");
    assert_eq!(vendor.json["products"][0]["name"], "Charting");
    assert_eq!(vendor.json["vulnerabilities"][0]["cve_id"], "CVE-2024-12345");
    let missing_vendor = call(&pool, &format!("/api/vendors/{}", Uuid::nil())).await;
    assert_eq!(missing_vendor.status, StatusCode::NOT_FOUND);

    let incidents = call(&pool, "/api/incidents/recent").await;
    assert_eq!(incidents.json["incidents"].as_array().unwrap().len(), 2);
    assert_eq!(incidents.json["incidents"][0]["kind"], "filing");
    assert_eq!(incidents.json["incidents"][0]["hospital_name"], "Mercy Downtown");
    assert_eq!(incidents.json["incidents"][1]["kind"], "breach");
    assert_eq!(
        incidents.json["incidents"][1]["hospital_name"],
        "SOUTHEAST HEALTH MEDICAL CENTER"
    );
    let one = call(&pool, "/api/incidents/recent?limit=1").await;
    assert_eq!(one.json["incidents"].as_array().unwrap().len(), 1);
    let bad_limit = call(&pool, "/api/incidents/recent?limit=nope").await;
    assert_eq!(bad_limit.status, StatusCode::BAD_REQUEST);

    let unknown = call(&pool, "/api/missing").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let home = call_text(&pool, "/").await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.body.contains("VULNRX"));
    assert!(home.body.contains("Open the map"));
    assert!(home.body.contains("/static/scanner.js"));
    assert!(home.body.contains("Mercy Downtown"));
    assert!(home.body.contains("SOUTHEAST HEALTH MEDICAL CENTER"));
    assert!(!home.body.contains("Unlinked Clinic"));
    assert!(!home.body.contains("10-K Item 1C"));

    let dash = call_text(&pool, "/dashboard").await;
    assert_eq!(dash.status, StatusCode::OK);
    assert!(dash.body.contains("state=AL"));
    assert!(dash.body.contains("linked HHS OCR breach"));
    let alabama = call_text(&pool, "/dashboard?state=AL").await;
    assert!(alabama.body.contains("Alabama"));
    assert!(alabama.body.contains("1 hospital"));
    assert!(alabama.body.contains("1 with a linked breach"));
    assert!(alabama.body.contains("SOUTHEAST HEALTH MEDICAL CENTER"));
    assert!(alabama.body.contains("1 linked breach · Example EHR"));
    let alaska = call_text(&pool, "/dashboard?state=AK").await;
    assert!(alaska.body.contains("ALASKA NATIVE MEDICAL CENTER"));
    assert!(alaska.body.contains("0 with a linked breach"));
    assert!(alaska.body.contains("no linked breach · no certified product"));
    let typed = call_text(&pool, "/dashboard?q=south").await;
    assert!(typed.body.contains("SOUTHEAST HEALTH MEDICAL CENTER"));
    let fragment = call_text(&pool, "/search?q=south").await;
    assert!(fragment.body.contains("SOUTHEAST HEALTH MEDICAL CENTER"));
    assert!(!fragment.body.contains("VULNRX"));
    let short_html = call_text(&pool, "/search?q=s").await;
    assert!(short_html.body.contains("two characters"));

    let page = call_text(&pool, &format!("/hospitals/{hospital_id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Example EHR"));
    assert!(page.body.contains("not an input"));
    assert!(page.body.contains("10-K Item 1C"));
    assert!(page.body.contains("Hacking/IT Incident"));
    let county_page = call_text(&pool, &format!("/hospitals/{county_id}")).await;
    assert!(county_page.body.contains("Mercy Downtown"));
    assert!(county_page.body.contains("8-K Item 1.05"));
    let vendor_page = call_text(&pool, &format!("/vendors/{vendor_id}")).await;
    assert!(vendor_page.body.contains("Example EHR"));
    assert!(vendor_page.body.contains("SOUTHEAST HEALTH MEDICAL CENTER"));
    assert!(!page.body.contains("NetScaler"));

    let kev_page = call_text(&pool, "/kev").await;
    assert_eq!(kev_page.status, StatusCode::OK);
    assert!(kev_page.body.contains("not a claim that a hospital"));
    assert!(kev_page.body.contains("Citrix · NetScaler"));
    assert!(kev_page.body.contains("CVE-2024-12345"));
    assert!(!kev_page.body.contains("CVE-2020-1111"));
    let kev_next = call_text(&pool, "/kev?page=2").await;
    assert_eq!(kev_next.status, StatusCode::OK);
    assert!(!kev_next.body.contains("NetScaler"));
    let kev_bad = call(&pool, "/kev?page=nope").await;
    assert_eq!(kev_bad.status, StatusCode::BAD_REQUEST);
    let kev = call(&pool, "/api/kev").await;
    assert_eq!(kev.status, StatusCode::OK);
    assert_eq!(kev.json["total"], 1);
    assert_eq!(kev.json["entries"][0]["vendor"], "Citrix");
    assert_eq!(kev.json["entries"][0]["product"], "NetScaler");
    assert_eq!(kev.json["source"], "cisa_kev");
    let missing_page = call_text(&pool, &format!("/hospitals/{}", Uuid::nil())).await;
    assert_eq!(missing_page.status, StatusCode::NOT_FOUND);

    sqlx::query(
        "INSERT INTO cve_explanations (cve_id, model, explanation)
         SELECT id, 'gemini-3.5-flash-lite', 'Stored guidance for the test.'
         FROM cves WHERE cve_id = 'CVE-2024-12345'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let explained = call_method(&pool, "POST", "/cves/CVE-2024-12345/explain").await;
    assert_eq!(explained.status, StatusCode::OK);
    assert!(explained.body.contains("Stored guidance for the test."));
    let missing_cve = call_method(&pool, "POST", "/cves/CVE-1999-0001/explain").await;
    assert_eq!(missing_cve.status, StatusCode::NOT_FOUND);
    assert!(missing_page.body.contains("Hospital not found"));

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

struct Call {
    status: StatusCode,
    json: Value,
}

struct TextCall {
    status: StatusCode,
    body: String,
}

async fn call_method(pool: &sqlx::PgPool, method: &str, uri: &str) -> TextCall {
    let response = vulnrx_api::router(pool.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    TextCall { status, body }
}

async fn call_text(pool: &sqlx::PgPool, uri: &str) -> TextCall {
    call_method(pool, "GET", uri).await
}

async fn call(pool: &sqlx::PgPool, uri: &str) -> Call {
    let response = vulnrx_api::router(pool.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Call { status, json }
}

fn names(json: &Value) -> Vec<&str> {
    json["hospitals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| hit["name"].as_str().unwrap())
        .collect()
}

async fn seed(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO hospitals (ccn, name, state, aliases) VALUES
            ('010001', 'SOUTHEAST HEALTH MEDICAL CENTER', 'AL', ARRAY['Southeast Regional']),
            ('020001', 'ALASKA NATIVE MEDICAL CENTER', 'AK', '{}'),
            (NULL, 'COUNTY HOSPITAL', 'MO', '{}'),
            (NULL, '100% MEMORIAL', 'TX', '{}'),
            (NULL, '0 GENERAL', 'TX', '{}')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE hospitals SET display_name = 'Mercy Downtown' WHERE name = 'COUNTY HOSPITAL'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO vendors (name) VALUES ('Example EHR')")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO products (vendor_id, name)
         SELECT id, 'Charting' FROM vendors WHERE name = 'Example EHR'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO hospital_vendor_map (hospital_id, vendor_id, product_id, source, source_url, confidence)
         SELECT h.id, v.id, p.id, 'cms_pi_chpl', 'https://example.test/pi', 0.95
         FROM hospitals h
         JOIN vendors v ON v.name = 'Example EHR'
         JOIN products p ON p.vendor_id = v.id
         WHERE h.name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO cves (cve_id, description, cvss_score, epss_score, is_kev, published_date, kev_vendor, kev_product)
         VALUES ('CVE-2024-12345', 'Example', 9.0, 0.50000, TRUE, DATE '2024-04-12', 'Citrix', 'NetScaler'),
                ('CVE-2020-1111', 'Not in the catalog', NULL, NULL, FALSE, NULL, NULL, NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO product_cve_map (product_id, cve_id, match_basis)
         SELECT p.id, c.id, 'cisa_kev'
         FROM products p JOIN cves c ON c.cve_id = 'CVE-2024-12345'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (
            entity_name, entity_type, hospital_id, individuals_affected, breach_type,
            date_reported, state, source, source_url
         )
         SELECT 'Southeast Health Medical Center', 'covered_entity', id, 12000,
                'Hacking/IT Incident', DATE '2024-06-01', 'AL',
                'hhs_ocr_breach_portal', 'https://example.test/breach'
         FROM hospitals WHERE name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO breach_events (entity_name, entity_type, individuals_affected, date_reported, source)
         VALUES ('Unlinked Clinic', 'covered_entity', 50, DATE '2026-03-01', 'hhs_ocr_breach_portal')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sec_filings (company_name, hospital_id, filing_type, filed_date, summary, source, source_url)
         SELECT 'County Hospital', id, '8-K Item 1.05', DATE '2026-01-15',
                'Item 1.05 Material Cybersecurity Incidents.', 'sec_edgar', 'https://example.test/8k'
         FROM hospitals WHERE name = 'COUNTY HOSPITAL'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sec_filings (company_name, hospital_id, filing_type, filed_date, summary, source, source_url)
         SELECT 'Southeast Health', id, '10-K Item 1C', DATE '2026-02-01',
                'Item 1C. Cybersecurity.', 'sec_edgar', 'https://example.test/10k'
         FROM hospitals WHERE name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO exposures (hospital_id, exposed_service, source, last_seen, raw_reference)
         SELECT id, 'https', 'shodan', DATE '2026-01-01', 'index-hit-1'
         FROM hospitals WHERE name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO cehrt_reports (hospital_id, cehrt_id, meets_criteria, source, source_url)
         SELECT id, '1234567890ABCDE', TRUE, 'cms_pi_2024', 'https://example.test/pi2024'
         FROM hospitals WHERE name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO risk_scores (
            hospital_id, composite_score, breach_component, cve_component, exposure_component, method
         )
         SELECT id, 60.00, 60.00, 0, 0, 'v1:breach'
         FROM hospitals WHERE name = 'SOUTHEAST HEALTH MEDICAL CENTER'",
    )
    .execute(pool)
    .await
    .unwrap();
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_api_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_api_test";

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
