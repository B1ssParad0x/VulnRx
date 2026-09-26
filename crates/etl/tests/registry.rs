use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";
const HOSPITALS: &[u8] = include_bytes!("fixtures/hospitals_sample.csv");
const PI_2024: &[u8] = include_bytes!("fixtures/pi_2024_sample.csv");

#[tokio::test]
async fn registry_keeps_every_medicare_hospital_and_cehrt_expansion_adds_links() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_registry_test");
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

    let hospitals = vulnrx_etl::ingest_hospital_registry(
        &pool,
        HOSPITALS,
        vulnrx_etl::HOSPITAL_REGISTRY_URL,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hospitals.hospitals, 3);
    assert_eq!(hospitals.skipped, 1);

    let public_flag: bool =
        sqlx::query_scalar("SELECT is_public_entity FROM hospitals WHERE ccn = '010001'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(public_flag);
    let va_flag: bool =
        sqlx::query_scalar("SELECT is_public_entity FROM hospitals WHERE ccn = '01014F'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(va_flag);
    let private_flag: bool =
        sqlx::query_scalar("SELECT is_public_entity FROM hospitals WHERE ccn = '010006'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!private_flag);

    let reports = vulnrx_etl::ingest_pi_2024(&pool, PI_2024, vulnrx_etl::PI_2024_URL, None)
        .await
        .unwrap();
    assert_eq!(reports.cehrt_reports, 1);
    let source: String = sqlx::query_scalar("SELECT source FROM hospitals WHERE ccn = '010001'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(source, "cms_hospital_general_information");

    // The product is the CHPL payload handed to the linker, not a lookup of this bundle.
    let expanded = vulnrx_etl::link_cehrt_bundles(
        &pool,
        &[vulnrx_etl::CehrtBundle {
            cehrt_id: "0015CFH8CSZ4V7K".to_string(),
            products: vec![vulnrx_etl::BundleProduct {
                database_id: "900001".to_string(),
                developer_name: "Fixture Developer".to_string(),
                name: "Fixture Product".to_string(),
            }],
        }],
    )
    .await
    .unwrap();
    assert_eq!(expanded.links, 1);
    let link_source: String = sqlx::query_scalar(
        "SELECT m.source FROM hospital_vendor_map m
         JOIN hospitals h ON h.id = m.hospital_id
         WHERE h.ccn = '010001'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(link_source, "cms_pi_2024_chpl");

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_registry_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_registry_test";

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
