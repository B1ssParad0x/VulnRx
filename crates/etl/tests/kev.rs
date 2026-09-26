use std::collections::HashMap;

use chrono::NaiveDate;
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::test]
async fn links_a_kev_entry_only_when_one_product_matches() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_kev_test");
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
    sqlx::query("INSERT INTO vendors (name) VALUES ('Citrix Systems, Inc.')")
        .execute(&pool)
        .await
        .unwrap();
    let vendor_id: String =
        sqlx::query_scalar("SELECT id::text FROM vendors WHERE name = 'Citrix Systems, Inc.'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO products (vendor_id, name) VALUES ($1::uuid, 'NetScaler'), ($1::uuid, 'Other Product')",
    )
    .bind(vendor_id)
    .execute(&pool)
    .await
    .unwrap();

    let entries = vec![
        vulnrx_etl::KevEntry {
            cve_id: "CVE-2019-19781".to_string(),
            vendor: "Citrix".to_string(),
            product: "NetScaler".to_string(),
            description: "Citrix ADC and Gateway directory traversal.".to_string(),
            date_added: NaiveDate::from_ymd_opt(2020, 1, 10).unwrap(),
        },
        vulnrx_etl::KevEntry {
            cve_id: "CVE-2024-0001".to_string(),
            vendor: "Example".to_string(),
            product: "Widget".to_string(),
            description: "No stored product uses this name.".to_string(),
            date_added: NaiveDate::from_ymd_opt(2024, 1, 2).unwrap(),
        },
    ];
    let mut epss = HashMap::new();
    epss.insert("CVE-2019-19781".to_string(), Decimal::new(94321, 5));
    let mut nvd = HashMap::new();
    nvd.insert(
        "CVE-2019-19781".to_string(),
        vulnrx_etl::NvdFacts {
            cvss: Some(Decimal::new(98, 1)),
            published: NaiveDate::from_ymd_opt(2019, 12, 27),
        },
    );
    let report = vulnrx_etl::ingest_kev(&pool, &entries, &epss, &nvd)
        .await
        .unwrap();
    assert_eq!(report.cves, 2);
    assert_eq!(report.with_epss, 1);
    assert_eq!(report.with_cvss, 1);
    assert_eq!(report.product_links, 1);

    let (is_kev, cvss, basis): (bool, Decimal, String) = sqlx::query_as(
        "SELECT c.is_kev, c.cvss_score, m.match_basis
         FROM product_cve_map m
         JOIN cves c ON c.id = m.cve_id
         JOIN products p ON p.id = m.product_id
         WHERE p.name = 'NetScaler'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_kev);
    assert_eq!(cvss, Decimal::new(98, 1));
    assert_eq!(basis, "cisa_kev");

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_kev_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_kev_test";

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
