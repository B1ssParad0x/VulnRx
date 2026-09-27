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

/// dotenv stops at an unquoted space. Values such as the SEC user agent are quoted here.
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
    load_env_file();
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
        Command::Score => {
            let report = vulnrx_etl::score_hospitals(&pool).await?;
            println!(
                "risk scores: wrote {} hospital rollups ({} from incidents only, {} include a linked CVE, {} include an exposure)",
                report.hospitals, report.breach_only, report.with_cve, report.with_exposure
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Shodan { limit } => {
            let report = vulnrx_etl::query_shodan(&pool, limit).await?;
            println!(
                "shodan: {} index queries, {} products with a confirming hit{}",
                report.queries,
                report.stored,
                stopped_suffix(report.stopped.as_deref())
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Cve => {
            let report = vulnrx_etl::match_product_cves(&pool).await?;
            println!(
                "nvd cve: checked {} product names, {} products gained a list, {} cves, {} links",
                report.products_checked, report.products_with_cves, report.cves, report.links
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Advisories => {
            let report = vulnrx_etl::match_advisories(&pool).await?;
            println!(
                "cisa advisories: read {} files, skipped {}, {} products gained a list, {} cves, {} links",
                report.advisories,
                report.skipped,
                report.products_with_cves,
                report.cves,
                report.links
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::CveList => {
            let report = vulnrx_etl::match_cve_list(&pool).await?;
            println!(
                "cve list: read {} records, skipped {}, {} products gained a list, {} cves, {} links",
                report.records,
                report.skipped,
                report.products_with_cves,
                report.cves,
                report.links
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Censys { limit } => {
            let report = vulnrx_etl::query_censys(&pool, limit).await?;
            println!(
                "censys: {} index queries, {} products with a confirming hit{}",
                report.queries,
                report.stored,
                stopped_suffix(report.stopped.as_deref())
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn stopped_suffix(stopped: Option<&str>) -> String {
    match stopped {
        Some(reason) => format!("; stopped: {reason}"),
        None => String::new(),
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
    Score,
    Shodan { limit: Option<i64> },
    Censys { limit: Option<i64> },
    Cve,
    CveList,
    Advisories,
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
        Some("score") => {
            raw.remove(0);
            "score"
        }
        Some("shodan") => {
            raw.remove(0);
            "shodan"
        }
        Some("censys") => {
            raw.remove(0);
            "censys"
        }
        Some("cve") => {
            raw.remove(0);
            "cve"
        }
        Some("cve-list") => {
            raw.remove(0);
            "cve-list"
        }
        Some("advisories") => {
            raw.remove(0);
            "advisories"
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
    let mut limit = None;
    let mut rest = raw.into_iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--state" => state = Some(rest.next().ok_or_else(usage)?),
            "--url" => url = Some(rest.next().ok_or_else(usage)?),
            "--limit" => {
                let raw_limit = rest.next().ok_or_else(usage)?;
                limit = Some(
                    raw_limit
                        .parse::<i64>()
                        .map_err(|_| "limit must be an integer".to_string())?,
                );
            }
            _ => return Err(usage()),
        }
    }
    Ok(match kind {
        "hospitals" => {
            if limit.is_some() {
                return Err(usage());
            }
            Command::Hospitals { state, url }
        }
        "pi-2024" => {
            if limit.is_some() {
                return Err(usage());
            }
            Command::Pi2024 { state, url }
        }
        "expand-cehrt" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::ExpandCehrt
        }
        "breaches" => {
            if url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Breaches { state }
        }
        "kev" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Kev
        }
        "edgar" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Edgar
        }
        "score" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Score
        }
        "shodan" => {
            if state.is_some() || url.is_some() {
                return Err(usage());
            }
            Command::Shodan { limit }
        }
        "censys" => {
            if state.is_some() || url.is_some() {
                return Err(usage());
            }
            Command::Censys { limit }
        }
        "cve" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Cve
        }
        "cve-list" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::CveList
        }
        "advisories" => {
            if state.is_some() || url.is_some() || limit.is_some() {
                return Err(usage());
            }
            Command::Advisories
        }
        _ => {
            if limit.is_some() {
                return Err(usage());
            }
            Command::Pi { state, url }
        }
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
     vulnrx-etl score\n\
     vulnrx-etl shodan [--limit N]\n\
     vulnrx-etl censys [--limit N]\n\
     vulnrx-etl cve\n\
     vulnrx-etl cve-list\n\
     vulnrx-etl advisories\n\
     \n\
     pi loads the 2023 ONC file that already joins hospitals to CHPL products.\n\
     hospitals loads every Medicare-registered hospital. It does not invent vendor links.\n\
     pi-2024 stores the 2024 certified-product bundle id reported by each hospital.\n\
     expand-cehrt asks CHPL which products are inside those bundle ids. It requires CHPL_API_KEY.\n\
     breaches reads the HHS OCR breach portal and links a row to a hospital only when the name and state match one facility.\n\
     kev loads the CISA known-exploited catalog, FIRST.org EPSS, and NVD CVSS. A product is linked only when the catalog's vendor and product names match one stored product.\n\
     edgar loads 8-K Item 1.05 incident reports since December 2023 and 10-K Item 1C cybersecurity disclosures filed from 2024 onward for hospital, nursing, health-plan, and medical-device industries. The summary is an excerpt of the filing. SEC requires a contact in the user agent; set SEC_USER_AGENT if the default is rejected.\n\
     score writes a hospital rollup only where a linked breach, Item 1.05 filing, product CVE, or exposure exists. Components with no linked input are stored as 0 and left out of the average. method names the inputs that were used.\n\
     shodan and censys query an existing public index for stored product names. Shodan search requires a paid membership. Censys search needs CENSYS_ORGANIZATION_ID, which free accounts do not have. Default limit is 20 queries, and the maximum is 50. A hit is stored only when the result names that product. Host addresses are not stored.\n\
     cve asks NVD, using NVD_API_KEY, for vulnerabilities whose description or official CPE title contains the stored product name as an exact phrase. The CPE vendor must match the stored vendor. Requires NVD_API_KEY.\n\
     cve-list reads the CVE Project's CVE List v5 baseline. A product is linked only when the record's vendor and product fields, or its CPE, name that stored product. A placeholder such as n/a is ignored.\n\
     advisories reads CISA CSAF files. A product is linked only when the advisory's product tree names that vendor and product and the CVE lists that product as known affected.\n\
     With no command, pi is used."
        .to_string()
}
