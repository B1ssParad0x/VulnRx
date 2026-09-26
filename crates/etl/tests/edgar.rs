use chrono::NaiveDate;
use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::test]
async fn links_a_filing_when_the_company_name_matches_one_hospital() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_edgar_test");
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
        "INSERT INTO hospitals (name, state) VALUES ('SOUTHEAST HEALTH MEDICAL CENTER', 'AL')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let filings = vec![vulnrx_etl::EdgarFiling {
        company_name: "Southeast Health Medical Center".to_string(),
        filing_type: "8-K Item 1.05".to_string(),
        filed_date: NaiveDate::from_ymd_opt(2024, 5, 28),
        summary: Some(
            "Item 1.05 Material Cybersecurity Incidents. The company experienced an event."
                .to_string(),
        ),
        source_url: "https://www.sec.gov/Archives/edgar/data/1/000000000000000001/example.htm"
            .to_string(),
    }];
    let report = vulnrx_etl::ingest_filings(&pool, &filings).await.unwrap();
    assert_eq!(report.filings, 1);
    assert_eq!(report.linked_hospitals, 1);
    assert_eq!(report.with_summary, 1);

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_edgar_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_edgar_test";

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
