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
    let command = match parse_args() {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            return Ok(ExitCode::from(2));
        }
    };
    if matches!(command, Command::Help) {
        println!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| LOCAL_DATABASE_URL.to_string());
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await?;
    vulnrx_models::migrate(&pool).await?;

    match command {
        Command::Help => Ok(ExitCode::SUCCESS),
        Command::Pi { state, url } => {
            let csv_url = url.as_deref().unwrap_or(vulnrx_etl::PI_CHPL_CSV_URL);
            let csv = vulnrx_etl::download_csv(csv_url).await?;
            let report = vulnrx_etl::ingest_pi_csv(&pool, &csv, csv_url, state.as_deref()).await?;
            println!(
                "2023 linkage: upserted {} hospitals, {} vendors, {} products, {} links; {} rows had no product link",
                report.hospitals,
                report.vendors,
                report.products,
                report.links,
                report.rows_without_a_product_link
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Hospitals { state, url } => {
            let csv_url = url.as_deref().unwrap_or(vulnrx_etl::HOSPITAL_REGISTRY_URL);
            let csv = vulnrx_etl::download_csv(csv_url).await?;
            let report =
                vulnrx_etl::ingest_hospital_registry(&pool, &csv, csv_url, state.as_deref())
                    .await?;
            println!(
                "medicare hospital registry: upserted {} hospitals; skipped {} rows",
                report.hospitals, report.skipped
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Pi2024 { state, url } => {
            let csv_url = url.as_deref().unwrap_or(vulnrx_etl::PI_2024_URL);
            let csv = vulnrx_etl::download_csv(csv_url).await?;
            let report = vulnrx_etl::ingest_pi_2024(&pool, &csv, csv_url, state.as_deref()).await?;
            println!(
                "2024 promoting interoperability: upserted {} hospitals and {} CEHRT reports; skipped {} rows",
                report.hospitals, report.cehrt_reports, report.skipped
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::ExpandCehrt => {
            let report = vulnrx_etl::expand_cehrt(&pool).await?;
            println!(
                "CHPL bundles: {} looked up, {} failed; upserted {} vendors, {} products, {} links",
                report.bundles,
                report.failed_lookups,
                report.vendors,
                report.products,
                report.links
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Breaches { state } => {
            let records = vulnrx_etl::fetch_breach_portal().await?;
            let report = vulnrx_etl::ingest_breaches(
                &pool,
                &records,
                vulnrx_etl::BREACH_PORTAL_URL,
                state.as_deref(),
            )
            .await?;
            println!(
                "ocr breach portal: fetched {} rows, upserted {}, linked {} hospitals and {} vendors",
                report.fetched, report.stored, report.linked_hospitals, report.linked_vendors
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Kev => {
            let catalog = vulnrx_etl::download_csv(vulnrx_etl::KEV_CATALOG_URL).await?;
            let entries = vulnrx_etl::parse_kev_catalog(&catalog)?;
            let ids: Vec<String> = entries.iter().map(|entry| entry.cve_id.clone()).collect();
            let epss = vulnrx_etl::fetch_epss(&ids).await?;
            let nvd = vulnrx_etl::fetch_nvd_kev().await?;
            let report = vulnrx_etl::ingest_kev(&pool, &entries, &epss, &nvd).await?;
            println!(
                "cisa kev: upserted {} cves ({} with epss, {} with cvss), linked {} products",
                report.cves, report.with_epss, report.with_cvss, report.product_links
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Edgar => {
            let filings = vulnrx_etl::fetch_item_105_filings().await?;
            let report = vulnrx_etl::ingest_filings(&pool, &filings).await?;
            println!(
                "sec edgar: upserted {} cybersecurity filings ({} with an excerpt), linked {} hospitals and {} vendors",
                report.filings, report.with_summary, report.linked_hospitals, report.linked_vendors
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

enum Command {
    Help,
    Pi {
        state: Option<String>,
        url: Option<String>,
    },
    Hospitals {
        state: Option<String>,
        url: Option<String>,
    },
    Pi2024 {
        state: Option<String>,
        url: Option<String>,
    },
    ExpandCehrt,
    Breaches {
        state: Option<String>,
    },
    Kev,
    Edgar,
}

fn parse_args() -> Result<Command, String> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let kind = match raw.first().map(String::as_str) {
        Some("hospitals") => {
            raw.remove(0);
            "hospitals"
        }
        Some("pi-2024") => {
            raw.remove(0);
            "pi-2024"
        }
        Some("expand-cehrt") => {
            raw.remove(0);
            "expand-cehrt"
        }
        Some("breaches") => {
            raw.remove(0);
            "breaches"
        }
        Some("kev") => {
            raw.remove(0);
            "kev"
        }
        Some("edgar") => {
            raw.remove(0);
            "edgar"
        }
        Some("pi") => {
            raw.remove(0);
            "pi"
        }
        Some(arg) if arg.starts_with('-') => "pi",
        Some(_) => return Err(usage()),
        None => "pi",
    };
    let mut state = None;
    let mut url = None;
    let mut rest = raw.into_iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--state" => state = Some(rest.next().ok_or_else(usage)?),
            "--url" => url = Some(rest.next().ok_or_else(usage)?),
            _ => return Err(usage()),
        }
    }
    Ok(match kind {
        "hospitals" => Command::Hospitals { state, url },
        "pi-2024" => Command::Pi2024 { state, url },
        "expand-cehrt" => {
            if state.is_some() || url.is_some() {
                return Err(usage());
            }
            Command::ExpandCehrt
        }
        "breaches" => {
            if url.is_some() {
                return Err(usage());
            }
            Command::Breaches { state }
        }
        "kev" => {
            if state.is_some() || url.is_some() {
                return Err(usage());
            }
            Command::Kev
        }
        "edgar" => {
            if state.is_some() || url.is_some() {
                return Err(usage());
            }
            Command::Edgar
        }
        _ => Command::Pi { state, url },
    })
}

fn usage() -> String {
    "Usage:\n\
     vulnrx-etl pi [--state XX] [--url CSV_URL]\n\
     vulnrx-etl hospitals [--state XX] [--url CSV_URL]\n\
     vulnrx-etl pi-2024 [--state XX] [--url CSV_URL]\n\
     vulnrx-etl expand-cehrt\n\
     vulnrx-etl breaches [--state XX]\n\
     vulnrx-etl kev\n\
     vulnrx-etl edgar\n\
     \n\
     pi loads the 2023 ONC file that already joins hospitals to CHPL products.\n\
     hospitals loads every Medicare-registered hospital. It does not invent vendor links.\n\
     pi-2024 stores the 2024 certified-product bundle id reported by each hospital.\n\
     expand-cehrt asks CHPL which products are inside those bundle ids. It requires CHPL_API_KEY.\n\
     breaches reads the HHS OCR breach portal and links a row to a hospital only when the name and state match one facility.\n\
     kev loads the CISA known-exploited catalog, FIRST.org EPSS, and NVD CVSS. A product is linked only when the catalog's vendor and product names match one stored product.\n\
     edgar loads 8-K Item 1.05 incident reports since December 2023 and 10-K Item 1C cybersecurity disclosures filed from 2024 onward for hospital, nursing, health-plan, and medical-device industries. The summary is an excerpt of the filing. SEC requires a contact in the user agent; set SEC_USER_AGENT if the default is rejected.\n\
     With no command, pi is used."
        .to_string()
}
