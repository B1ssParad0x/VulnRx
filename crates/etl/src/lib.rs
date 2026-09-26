//! Load the ONC file that joins CMS Promoting Interoperability hospital reports
//! to Certified Health IT Product List (CHPL) listings.

mod load;

pub use load::{IngestError, IngestReport, ingest_pi_csv};

/// Public CSV published by ONC. Each row is a hospital-reported CEHRT id joined to a CHPL product.
pub const PI_CHPL_CSV_URL: &str = "https://healthit.gov/data/wp-content/uploads/sites/2/2025/06/hospital-promoting-interoperability-2023-chpl-linkage.csv";

/// How strongly a row in that file supports the hospital-product link.
/// The hospital reported the CEHRT id to CMS, and ONC joined it to CHPL.
pub const PI_LINK_CONFIDENCE: rust_decimal::Decimal =
    rust_decimal::Decimal::from_parts(95, 0, 0, false, 2);

pub const PI_LINK_SOURCE: &str = "cms_pi_chpl";

/// Download the linkage CSV. Does not write the database.
pub async fn download_pi_csv(url: &str) -> Result<Vec<u8>, IngestError> {
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
