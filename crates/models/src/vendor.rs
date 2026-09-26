use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Closed set stored in `vendors.category`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorCategory {
    Ehr,
    Imaging,
    Cloud,
    Networking,
    Device,
    Other,
}

impl VendorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ehr => "ehr",
            Self::Imaging => "imaging",
            Self::Cloud => "cloud",
            Self::Networking => "networking",
            Self::Device => "device",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown vendor category `{value}`")]
pub struct InvalidVendorCategory {
    value: String,
}

impl InvalidVendorCategory {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl TryFrom<&str> for VendorCategory {
    type Error = InvalidVendorCategory;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ehr" => Ok(Self::Ehr),
            "imaging" => Ok(Self::Imaging),
            "cloud" => Ok(Self::Cloud),
            "networking" => Ok(Self::Networking),
            "device" => Ok(Self::Device),
            "other" => Ok(Self::Other),
            other => Err(InvalidVendorCategory {
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct Vendor {
    pub id: Uuid,
    pub name: String,
    pub aliases: Vec<String>,
    pub category: Option<String>,
}

impl Vendor {
    pub fn category_kind(&self) -> Result<Option<VendorCategory>, InvalidVendorCategory> {
        self.category
            .as_deref()
            .map(VendorCategory::try_from)
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct Product {
    pub id: Uuid,
    pub vendor_id: Uuid,
    pub name: String,
    pub cpe_string: Option<String>,
    pub version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::VendorCategory;

    #[test]
    fn category_round_trips_the_database_spellings() {
        for value in ["ehr", "imaging", "cloud", "networking", "device", "other"] {
            let category = VendorCategory::try_from(value).unwrap();
            assert_eq!(category.as_str(), value);
        }
    }

    #[test]
    fn category_rejects_values_outside_the_check_constraint() {
        let err = VendorCategory::try_from("EHR").unwrap_err();
        assert_eq!(err.value(), "EHR");
    }
}
