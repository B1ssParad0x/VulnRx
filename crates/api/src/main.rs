use std::net::SocketAddr;
use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";
const DEFAULT_BIND: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("api failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), StartupError> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| StartupError::BadAddress(bind.clone()))?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    vulnrx_models::migrate(&pool).await?;
    println!("vulnrx-api listening on http://{addr}");
    vulnrx_api::serve(pool, addr).await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    #[error("bind address `{0}` is invalid")]
    BadAddress(String),
}
