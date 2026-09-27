//! Row types for the VulnRx store, and the migration runner that creates it.
//!
//! These structs mirror `migrations/`. A field being optional means the public
//! source has not supplied that fact yet.

mod breach;
mod exposure;
mod filing;
mod hospital;
mod risk;
mod vendor;
mod vuln;

pub use breach::{BreachEntityType, BreachEvent, InvalidBreachEntityType};
pub use exposure::{Exposure, ExposureSource, InvalidExposureSource};
pub use filing::SecFiling;
pub use hospital::{Hospital, HospitalVendorMap};
pub use risk::RiskScore;
pub use vendor::{InvalidVendorCategory, Product, Vendor, VendorCategory};
pub use vuln::{Cve, ProductCveMap};

/// Applies embedded SQL migrations. Safe to call on every startup.
/// New files under `migrations/` are picked up the next time this crate builds.
/// `0007_cve_explanations.sql` stores one Gemini reply per CVE.
/// `0008_gemini_model.sql` names the Flash-Lite model new projects can call.
/// `0009_exposure_sources.sql` allows ZoomEye, Netlas, and InternetDB hits.
/// `0010_guidance.sql` stores one natural-language answer and one remediation note.
pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}
