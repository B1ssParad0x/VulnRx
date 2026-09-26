use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::main]
async fn main() -> ExitCode {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    match apply(&url).await {
        Ok(()) => {
            println!("migrations applied");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("migration failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn apply(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new().max_connections(1).connect(url).await?;
    vulnrx_models::migrate(&pool).await?;
    Ok(())
}
