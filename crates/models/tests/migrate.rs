use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";
const TEST_DATABASE: &str = "vulnrx_schema_test";
const DROP_TEST_DATABASE: &str = "DROP DATABASE IF EXISTS vulnrx_schema_test WITH (FORCE)";
const CREATE_TEST_DATABASE: &str = "CREATE DATABASE vulnrx_schema_test";

#[tokio::test]
async fn migration_creates_the_risk_score_hypertable() {
    assert!(DROP_TEST_DATABASE.contains(TEST_DATABASE));
    assert!(CREATE_TEST_DATABASE.contains(TEST_DATABASE));

    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let admin = with_database(&app_url, "postgres");
    let test_url = with_database(&app_url, TEST_DATABASE);

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
    vulnrx_models::migrate(&pool).await.unwrap();

    let hypertable: String = sqlx::query_scalar(
        "SELECT hypertable_name
         FROM timescaledb_information.hypertables
         WHERE hypertable_name = 'risk_scores'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(hypertable, "risk_scores");

    let rejected = sqlx::query("INSERT INTO hospitals (name, state) VALUES ('Probe', 'missouri')")
        .execute(&pool)
        .await;
    assert!(rejected.is_err(), "a non-postal state should be rejected");

    drop(pool);
    sqlx::query(DROP_TEST_DATABASE)
        .execute(&admin_pool)
        .await
        .unwrap();
}

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
