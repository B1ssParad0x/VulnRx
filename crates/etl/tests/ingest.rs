use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";
const FIXTURE: &[u8] = include_bytes!("fixtures/pi_sample.csv");

#[tokio::test]
async fn linkage_csv_upserts_real_rows_and_skips_a_bad_ccn() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_etl_test");

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

    let missouri =
        vulnrx_etl::ingest_pi_csv(&pool, FIXTURE, vulnrx_etl::PI_CHPL_CSV_URL, Some("mo"))
            .await
            .unwrap();
    assert_eq!(missouri.hospitals, 1);
    assert_eq!(missouri.links, 1);
    assert_eq!(missouri.rows_without_a_product_link, 0);

    let report = vulnrx_etl::ingest_pi_csv(&pool, FIXTURE, vulnrx_etl::PI_CHPL_CSV_URL, None)
        .await
        .unwrap();
    assert_eq!(report.hospitals, 3);
    assert_eq!(report.vendors, 1);
    assert_eq!(report.products, 1);
    assert_eq!(report.links, 3);
    assert_eq!(report.rows_without_a_product_link, 1);

    let again = vulnrx_etl::ingest_pi_csv(&pool, FIXTURE, vulnrx_etl::PI_CHPL_CSV_URL, None)
        .await
        .unwrap();
    assert_eq!(again.hospitals, 3);
    assert_eq!(again.links, 3);

    let (name, city, zip, phone): (String, String, String, String) =
        sqlx::query_as("SELECT name, city, zip, phone FROM hospitals WHERE ccn = '260095'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(name, "CENTERPOINT MEDICAL CENTER");
    assert_eq!(city, "INDEPENDENCE");
    assert_eq!(zip, "64057");
    assert_eq!(phone, "(816) 698-7000");
    let facility_source: String =
        sqlx::query_scalar("SELECT source FROM hospitals WHERE ccn = '260095'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(facility_source, vulnrx_etl::PI_LINK_SOURCE);

    let vendor_category: Option<String> =
        sqlx::query_scalar("SELECT category FROM vendors WHERE name = 'Surescripts, LLC'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(vendor_category.is_none());

    let (chpl_id, source, source_url, confidence, last_verified): (
        String,
        String,
        String,
        rust_decimal::Decimal,
        chrono::NaiveDate,
    ) = sqlx::query_as(
        "SELECT p.chpl_id, m.source, m.source_url, m.confidence, m.last_verified
         FROM hospital_vendor_map m
         JOIN hospitals h ON h.id = m.hospital_id
         JOIN products p ON p.id = m.product_id
         WHERE h.ccn = '260095'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(chpl_id, "15.02.04.2391.Sure.02.01.1.211209");
    assert_eq!(source, vulnrx_etl::PI_LINK_SOURCE);
    assert_eq!(source_url, vulnrx_etl::PI_CHPL_CSV_URL);
    assert_eq!(confidence, vulnrx_etl::PI_LINK_CONFIDENCE);
    assert_eq!(
        last_verified,
        chrono::NaiveDate::from_ymd_opt(2023, 12, 31).unwrap()
    );

    let invented: i64 =
        sqlx::query_scalar("SELECT count(*) FROM hospitals WHERE name = 'not a hospital'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invented, 0);

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_etl_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_etl_test";

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
