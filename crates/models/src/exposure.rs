use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Index that was queried. This project does not originate scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposureSource {
    Shodan,
    Censys,
    Zoomeye,
    Netlas,
    InternetDb,
}

impl ExposureSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shodan => "shodan",
            Self::Censys => "censys",
            Self::Zoomeye => "zoomeye",
            Self::Netlas => "netlas",
            Self::InternetDb => "internetdb",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown exposure source `{value}`")]
pub struct InvalidExposureSource {
    value: String,
}

impl InvalidExposureSource {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl TryFrom<&str> for ExposureSource {
    type Error = InvalidExposureSource;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "shodan" => Ok(Self::Shodan),
            "censys" => Ok(Self::Censys),
            "zoomeye" => Ok(Self::Zoomeye),
            "netlas" => Ok(Self::Netlas),
            "internetdb" => Ok(Self::InternetDb),
            other => Err(InvalidExposureSource {
                value: other.to_string(),
            }),
        }
    }
}

/// One hit from an existing public index. Host addresses are not stored.
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Serialize, Deserialize)]
pub struct Exposure {
    pub id: Uuid,
    pub hospital_id: Option<Uuid>,
    pub product_id: Option<Uuid>,
    pub exposed_service: Option<String>,
    pub source: String,
    pub last_seen: Option<NaiveDate>,
    pub raw_reference: String,
}

impl Exposure {
    pub fn source_kind(&self) -> Result<ExposureSource, InvalidExposureSource> {
        ExposureSource::try_from(self.source.as_str())
    }
}
