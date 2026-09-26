use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;

const LOCAL_DATABASE_URL: &str = "postgres://vulnrx:vulnrx@localhost:5432/vulnrx";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ingest failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode, vulnrx_etl::IngestError> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(usage) => {
            eprintln!("{usage}");
            return Ok(ExitCode::from(2));
        }
    };
    if args.help {
        println!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let csv_url = args.url.as_deref().unwrap_or(vulnrx_etl::PI_CHPL_CSV_URL);
    let csv = vulnrx_etl::download_pi_csv(csv_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await?;
    vulnrx_models::migrate(&pool).await?;
    let report = vulnrx_etl::ingest_pi_csv(&pool, &csv, csv_url, args.state.as_deref()).await?;
    println!(
        "upserted {} hospitals, {} vendors, {} products, {} links; {} rows had no product link",
        report.hospitals,
        report.vendors,
        report.products,
        report.links,
        report.rows_without_a_product_link
    );
    Ok(ExitCode::SUCCESS)
}

struct Args {
    help: bool,
    state: Option<String>,
    url: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        help: false,
        state: None,
        url: None,
    };
    let mut raw = std::env::args().skip(1);
    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--help" | "-h" => args.help = true,
            "--state" => {
                args.state = Some(raw.next().ok_or_else(usage)?);
            }
            "--url" => {
                args.url = Some(raw.next().ok_or_else(usage)?);
            }
            _ => return Err(usage()),
        }
    }
    Ok(args)
}

fn usage() -> String {
    "Usage: vulnrx-etl [--state XX] [--url CSV_URL]\n\
     Loads the ONC CMS Promoting Interoperability / CHPL linkage file.\n\
     --state limits the load to one USPS state code. The default is every row in the file."
        .to_string()
}
