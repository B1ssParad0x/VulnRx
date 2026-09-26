use chrono::NaiveDate;
use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::test]
async fn links_a_provider_only_when_one_hospital_in_that_state_matches() {
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, "vulnrx_breach_test");
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
    sqlx::query("INSERT INTO hospitals (name, state) VALUES ('SOUTHEAST HEALTH MEDICAL CENTER', 'AL'), ('MEMORIAL HOSPITAL', 'TX'), ('MEMORIAL HOSPITAL', 'TX')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO vendors (name) VALUES ('Acme Billing LLC')")
        .execute(&pool)
        .await
        .unwrap();

    let records = vec![
        breach(
            "Southeast Health Medical Center",
            "AL",
            "Healthcare Provider",
        ),
        breach("Memorial Hospital", "TX", "Healthcare Provider"),
        breach("L.A. Care Health Plan", "CA", "Health Plan"),
        breach("Acme Billing, LLC", "CA", "Business Associate"),
    ];
    let report = vulnrx_etl::ingest_breaches(&pool, &records, vulnrx_etl::BREACH_PORTAL_URL, None)
        .await
        .unwrap();
    assert_eq!(report.stored, 4);
    assert_eq!(report.linked_hospitals, 1);
    assert_eq!(report.linked_vendors, 1);

    let linked: String = sqlx::query_scalar(
        "SELECT h.name FROM breach_events b JOIN hospitals h ON h.id = b.hospital_id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(linked, "SOUTHEAST HEALTH MEDICAL CENTER");

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

fn breach(name: &str, state: &str, portal_type: &str) -> vulnrx_etl::BreachRecord {
    let entity_type = if portal_type == "Business Associate" {
        "business_associate"
    } else {
        "covered_entity"
    };
    vulnrx_etl::BreachRecord {
        entity_name: name.to_string(),
        state: Some(state.to_string()),
        portal_entity_type: portal_type.to_string(),
        entity_type: entity_type.to_string(),
        individuals_affected: Some(500),
        date_reported: NaiveDate::from_ymd_opt(2024, 1, 15),
        breach_type: Some("Hacking/IT Incident".to_string()),
        breach_location: Some("Network Server".to_string()),
    }
}

const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_breach_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_breach_test";

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
