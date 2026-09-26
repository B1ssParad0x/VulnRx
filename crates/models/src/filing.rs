use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A public EDGAR disclosure. `summary` must be taken from the filing.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct SecFiling {
    pub id: Uuid,
    pub company_name: String,
    pub hospital_id: Option<Uuid>,
    pub vendor_id: Option<Uuid>,
    pub filing_type: Option<String>,
    pub filed_date: Option<NaiveDate>,
    pub summary: Option<String>,
    pub source: String,
    pub source_url: Option<String>,
}
