use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// One computed risk score.
///
/// `vendor_id` is empty for the hospital-level rollup. `method` names the formula
/// and which inputs were present (`v1:breach`, `v1:cve`, `v1:breach+cve+exposure`).
/// A component stored as 0 was not an input. It is not a claim that the risk is zero.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct RiskScore {
    pub id: Uuid,
    pub hospital_id: Uuid,
    pub vendor_id: Option<Uuid>,
    pub composite_score: Decimal,
    pub breach_component: Decimal,
    pub cve_component: Decimal,
    pub exposure_component: Decimal,
    pub method: String,
    pub computed_at: DateTime<Utc>,
}
