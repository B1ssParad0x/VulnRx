//! Load public CMS and ONC files into the VulnRx store.

mod advisories;
mod breaches;
mod chpl;
mod cve_list;
mod cve_match;
mod edgar;
mod hospitals;
mod index;
mod kev;
mod load;
mod pi2024;
mod score;

pub use advisories::{AdvisoryReport, match_advisories};
pub use breaches::{
    BREACH_PORTAL_URL, BreachRecord, BreachReport, fetch_breach_portal, ingest_breaches,
};
pub use chpl::{BundleProduct, CehrtBundle, ExpandReport, expand_cehrt, link_cehrt_bundles};
pub use cve_list::{CveListReport, match_cve_list};
pub use cve_match::{CveMatchReport, match_product_cves};
pub use edgar::{EdgarFiling, EdgarReport, fetch_item_105_filings, ingest_filings};
pub use hospitals::{HOSPITAL_REGISTRY_URL, HospitalLoadReport, ingest_hospital_registry};
pub use index::{IndexReport, query_censys, query_shodan};
pub use kev::{
    KEV_CATALOG_URL, KevEntry, KevReport, NvdFacts, fetch_epss, fetch_nvd_kev, ingest_kev,
    parse_kev_catalog,
};
pub use load::{IngestError, IngestReport, ingest_pi_csv};
pub use pi2024::{PI_2024_URL, Pi2024Report, ingest_pi_2024};
pub use score::{ScoreReport, score_hospitals};

/// Public CSV published by ONC. Each row is a hospital-reported CEHRT id joined to a CHPL product.
pub const PI_CHPL_CSV_URL: &str = "https://healthit.gov/data/wp-content/uploads/sites/2/2025/06/hospital-promoting-interoperability-2023-chpl-linkage.csv";

/// How strongly a row in that file supports the hospital-product link.
/// The hospital reported the CEHRT id to CMS, and ONC joined it to CHPL.
pub const PI_LINK_CONFIDENCE: rust_decimal::Decimal =
    rust_decimal::Decimal::from_parts(95, 0, 0, false, 2);

pub const PI_LINK_SOURCE: &str = "cms_pi_chpl";

/// Download a public CSV. Does not write the database.
pub async fn download_csv(url: &str) -> Result<Vec<u8>, IngestError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("vulnrx/0.1")
        .build()?;
    let response = client.get(url).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(IngestError::HttpStatus {
            url: url.to_string(),
            status: status.as_u16(),
        });
    }
    Ok(response.bytes().await?.to_vec())
}
