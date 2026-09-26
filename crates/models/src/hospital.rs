use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A hospital or health system.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct Hospital {
    pub id: Uuid,
    pub ccn: Option<String>,
    pub name: String,
    pub display_name: Option<String>,
    pub aliases: Vec<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub address: Option<String>,
    pub zip: Option<String>,
    pub phone: Option<String>,
    pub is_public_entity: bool,
}

impl Hospital {
    /// Name shown in the UI. Uses the canonical name when no display name is set.
    pub fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(self.name.as_str())
    }
}

/// A hospital-vendor relationship taken from one public source.
///
/// `confidence` is how strongly that source supports the link, from 0.00 to 1.00.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct HospitalVendorMap {
    pub id: Uuid,
    pub hospital_id: Uuid,
    pub vendor_id: Uuid,
    pub product_id: Option<Uuid>,
    pub source: String,
    pub source_url: Option<String>,
    pub confidence: Decimal,
    pub last_verified: Option<NaiveDate>,
}

#[cfg(test)]
mod tests {
    use super::Hospital;
    use uuid::Uuid;

    fn hospital(name: &str, display_name: Option<&str>) -> Hospital {
        Hospital {
            id: Uuid::nil(),
            ccn: None,
            name: name.to_string(),
            display_name: display_name.map(str::to_string),
            aliases: Vec::new(),
            city: None,
            state: None,
            address: None,
            zip: None,
            phone: None,
            is_public_entity: false,
        }
    }

    #[test]
    fn label_uses_the_canonical_name_without_a_display_name() {
        assert_eq!(hospital("City Hospital", None).label(), "City Hospital");
    }

    #[test]
    fn label_prefers_a_non_empty_display_name() {
        let hospital = hospital("City Hospital", Some("City"));
        assert_eq!(hospital.label(), "City");
    }

    #[test]
    fn label_ignores_a_blank_display_name() {
        let hospital = hospital("City Hospital", Some("   "));
        assert_eq!(hospital.label(), "City Hospital");
    }
}
