use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A CVE record. Scores stay empty until the corresponding public feed has been read.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct Cve {
    pub id: Uuid,
    pub cve_id: String,
    pub description: Option<String>,
    /// NULL until NVD has been queried.
    pub cvss_score: Option<Decimal>,
    /// NULL until FIRST.org EPSS has been queried.
    pub epss_score: Option<Decimal>,
    /// NULL until the CISA KEV catalog has been checked.
    /// `false` means checked and absent. `true` means listed.
    pub is_kev: Option<bool>,
    pub published_date: Option<NaiveDate>,
    pub kev_vendor: Option<String>,
    pub kev_product: Option<String>,
}

/// Link between a product and a CVE, with the CPE that justified the match.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct ProductCveMap {
    pub product_id: Uuid,
    pub cve_id: Uuid,
    pub matched_cpe: Option<String>,
    /// Why the link exists. `cisa_kev` means the CISA catalog named this vendor and product.
    pub match_basis: Option<String>,
}
