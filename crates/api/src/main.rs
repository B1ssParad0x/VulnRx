use std::net::SocketAddr;
use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

fn load_env_file() {
    for path in [".env", "../.env", "../../.env"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let _ = dotenvy::from_read(normalize_env(&text).as_bytes());
        return;
    }
}

fn normalize_env(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let value = value.trim();
        if value.contains(' ') && !value.starts_with('"') {
            out.push_str(key.trim());
            out.push_str("=\"");
            out.push_str(value);
            out.push('"');
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
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
    load_env_file();
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
