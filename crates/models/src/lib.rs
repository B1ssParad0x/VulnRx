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
pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}
