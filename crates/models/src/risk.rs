use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// One computed risk score.
///
/// `vendor_id` is empty for the hospital-level rollup. `method` names the formula
/// so a later change does not look like a change in risk.
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
