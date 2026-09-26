use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachEntityType {
    CoveredEntity,
    BusinessAssociate,
}

impl BreachEntityType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoveredEntity => "covered_entity",
            Self::BusinessAssociate => "business_associate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown breach entity type `{value}`")]
pub struct InvalidBreachEntityType {
    value: String,
}

impl InvalidBreachEntityType {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl TryFrom<&str> for BreachEntityType {
    type Error = InvalidBreachEntityType;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "covered_entity" => Ok(Self::CoveredEntity),
            "business_associate" => Ok(Self::BusinessAssociate),
            other => Err(InvalidBreachEntityType {
                value: other.to_string(),
            }),
        }
    }
}

/// A public breach record. Hospital and vendor ids stay empty until entity resolution.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct BreachEvent {
    pub id: Uuid,
    pub entity_name: String,
    pub entity_type: Option<String>,
    pub hospital_id: Option<Uuid>,
    pub vendor_id: Option<Uuid>,
    pub individuals_affected: Option<i32>,
    pub breach_type: Option<String>,
    pub date_reported: Option<NaiveDate>,
    pub source: String,
    pub source_url: Option<String>,
}

impl BreachEvent {
    pub fn entity_kind(&self) -> Result<Option<BreachEntityType>, InvalidBreachEntityType> {
        self.entity_type
            .as_deref()
            .map(BreachEntityType::try_from)
            .transpose()
    }
}
