//! Hospital rollup scores from public records already in the store.
//!
//! A component is an input only when a linked row supports it. Missing CVE matches
//! and missing exposure-index hits are left out of the average. They are stored as
//! 0, and `method` names the inputs that were actually present (`v1:breach`,
//! `v1:breach+cve+exposure`, and so on). A hospital with no linked incident, CVE,
//! or exposure gets no row.

use sqlx::PgPool;

use crate::IngestError;

/// How many hospital rollups this run wrote, and which inputs those rows used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoreReport {
    pub hospitals: u64,
    pub breach_only: u64,
    pub with_cve: u64,
    pub with_exposure: u64,
}

#[derive(sqlx::FromRow)]
struct ScoreCounts {
    hospitals: i64,
    breach_only: i64,
    with_cve: i64,
    with_exposure: i64,
}

/// Weights for inputs that are present. Renormalized when one of them is missing,
/// so a 0 stored for an absent input does not dilute the score.
const BREACH_WEIGHT: &str = "45";
const CVE_WEIGHT: &str = "40";
const EXPOSURE_WEIGHT: &str = "15";

/// Append one hospital-level score per hospital that has linked evidence.
///
/// A second run on the same UTC day replaces that day's row for the same method
/// instead of stacking identical points. Older days stay, so the hypertable can
/// show a change over time. `vendor_id` stays empty: this is the hospital rollup.
pub async fn score_hospitals(pool: &PgPool) -> Result<ScoreReport, IngestError> {
    let counts = sqlx::query_as::<_, ScoreCounts>(SCORE_SQL)
        .bind(BREACH_WEIGHT)
        .bind(CVE_WEIGHT)
        .bind(EXPOSURE_WEIGHT)
        .fetch_one(pool)
        .await?;
    Ok(ScoreReport {
        hospitals: as_count(counts.hospitals),
        breach_only: as_count(counts.breach_only),
        with_cve: as_count(counts.with_cve),
        with_exposure: as_count(counts.with_exposure),
    })
}

fn as_count(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

/// Incident size is the OCR headcount when the portal published one.
/// A linked 8-K Item 1.05 has no headcount we are willing to parse out of prose,
/// so it contributes a fixed material-incident size. 10-K Item 1C is governance
/// disclosure and is not an incident input.
const SCORE_SQL: &str = r"
WITH day_start AS (
    SELECT (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS start_at
),
incident_rows AS (
    SELECT
        hospital_id,
        CASE
            WHEN individuals_affected IS NULL THEN 15
            WHEN individuals_affected < 500 THEN 20
            WHEN individuals_affected < 10000 THEN 40
            WHEN individuals_affected < 50000 THEN 60
            WHEN individuals_affected < 250000 THEN 80
            ELSE 100
        END::numeric AS size_points,
        CASE
            WHEN date_reported IS NULL THEN 0.35
            WHEN date_reported >= (CURRENT_DATE - INTERVAL '1 year')::date THEN 1.00
            WHEN date_reported >= (CURRENT_DATE - INTERVAL '3 years')::date THEN 0.75
            WHEN date_reported >= (CURRENT_DATE - INTERVAL '5 years')::date THEN 0.50
            ELSE 0.35
        END::numeric AS recency
    FROM breach_events
    WHERE hospital_id IS NOT NULL
    UNION ALL
    SELECT
        hospital_id,
        40::numeric AS size_points,
        CASE
            WHEN filed_date IS NULL THEN 0.35
            WHEN filed_date >= (CURRENT_DATE - INTERVAL '1 year')::date THEN 1.00
            WHEN filed_date >= (CURRENT_DATE - INTERVAL '3 years')::date THEN 0.75
            WHEN filed_date >= (CURRENT_DATE - INTERVAL '5 years')::date THEN 0.50
            ELSE 0.35
        END::numeric AS recency
    FROM sec_filings
    WHERE hospital_id IS NOT NULL
      AND filing_type LIKE '8-K%'
),
breach_scored AS (
    SELECT
        hospital_id,
        LEAST(
            100::numeric,
            ROUND(
                MAX(size_points * recency)
                    + LEAST(32::numeric, (COUNT(*) - 1) * 8::numeric),
                2
            )
        ) AS breach_component
    FROM incident_rows
    GROUP BY hospital_id
),
cve_rows AS (
    SELECT DISTINCT
        m.hospital_id,
        c.id AS cve_row,
        c.is_kev,
        CASE
            WHEN c.cvss_score IS NOT NULL
                AND (c.epss_score IS NOT NULL OR c.is_kev IS TRUE)
            THEN ROUND(
                0.7 * GREATEST(
                    CASE WHEN c.is_kev IS TRUE THEN 70::numeric ELSE 0::numeric END,
                    COALESCE(c.epss_score, 0) * 100
                )
                + 0.3 * (c.cvss_score / 10::numeric * 100),
                2
            )
            WHEN c.epss_score IS NOT NULL OR c.is_kev IS TRUE
            THEN ROUND(
                GREATEST(
                    CASE WHEN c.is_kev IS TRUE THEN 70::numeric ELSE 0::numeric END,
                    COALESCE(c.epss_score, 0) * 100
                ),
                2
            )
            WHEN c.cvss_score IS NOT NULL
            THEN ROUND(c.cvss_score / 10::numeric * 100, 2)
            ELSE NULL
        END AS signal
    FROM hospital_vendor_map m
    JOIN product_cve_map pcm ON pcm.product_id = m.product_id
    JOIN cves c ON c.id = pcm.cve_id
    WHERE m.product_id IS NOT NULL
),
cve_scored AS (
    SELECT
        hospital_id,
        LEAST(
            100::numeric,
            ROUND(
                MAX(signal)
                    + LEAST(
                        20::numeric,
                        GREATEST(0, COUNT(*) FILTER (WHERE is_kev IS TRUE) - 1) * 5::numeric
                    ),
                2
            )
        ) AS cve_component
    FROM cve_rows
    WHERE signal IS NOT NULL
    GROUP BY hospital_id
),
exposure_hits AS (
    SELECT hospital_id, id
    FROM exposures
    WHERE hospital_id IS NOT NULL
    UNION
    SELECT m.hospital_id, e.id
    FROM exposures e
    JOIN hospital_vendor_map m ON m.product_id = e.product_id
    WHERE e.product_id IS NOT NULL
),
exposure_scored AS (
    SELECT
        hospital_id,
        LEAST(
            100::numeric,
            40::numeric + LEAST(60::numeric, (COUNT(*) - 1) * 15::numeric)
        ) AS exposure_component
    FROM exposure_hits
    GROUP BY hospital_id
),
scored AS (
    SELECT
        h.id AS hospital_id,
        b.breach_component,
        c.cve_component,
        x.exposure_component,
        ROUND(
            (
                COALESCE(b.breach_component, 0) * $1::numeric
                + COALESCE(c.cve_component, 0) * $2::numeric
                + COALESCE(x.exposure_component, 0) * $3::numeric
            ) / (
                CASE WHEN b.hospital_id IS NOT NULL THEN $1::numeric ELSE 0::numeric END
                + CASE WHEN c.hospital_id IS NOT NULL THEN $2::numeric ELSE 0::numeric END
                + CASE WHEN x.hospital_id IS NOT NULL THEN $3::numeric ELSE 0::numeric END
            ),
            2
        ) AS composite_score,
        'v1:' || concat_ws(
            '+',
            CASE WHEN b.hospital_id IS NOT NULL THEN 'breach' END,
            CASE WHEN c.hospital_id IS NOT NULL THEN 'cve' END,
            CASE WHEN x.hospital_id IS NOT NULL THEN 'exposure' END
        ) AS method
    FROM hospitals h
    LEFT JOIN breach_scored b ON b.hospital_id = h.id
    LEFT JOIN cve_scored c ON c.hospital_id = h.id
    LEFT JOIN exposure_scored x ON x.hospital_id = h.id
    WHERE b.hospital_id IS NOT NULL
       OR c.hospital_id IS NOT NULL
       OR x.hospital_id IS NOT NULL
),
removed AS (
    DELETE FROM risk_scores r
    USING scored s, day_start d
    WHERE r.hospital_id = s.hospital_id
      AND r.vendor_id IS NULL
      AND r.method = s.method
      AND r.computed_at >= d.start_at
    RETURNING r.id
),
inserted AS (
    INSERT INTO risk_scores (
        hospital_id,
        vendor_id,
        composite_score,
        breach_component,
        cve_component,
        exposure_component,
        method
    )
    SELECT
        hospital_id,
        NULL,
        composite_score,
        COALESCE(breach_component, 0),
        COALESCE(cve_component, 0),
        COALESCE(exposure_component, 0),
        method
    FROM scored
    RETURNING method
)
SELECT
    COUNT(*)::bigint AS hospitals,
    COUNT(*) FILTER (WHERE method = 'v1:breach')::bigint AS breach_only,
    COUNT(*) FILTER (WHERE method LIKE '%cve%')::bigint AS with_cve,
    COUNT(*) FILTER (WHERE method LIKE '%exposure%')::bigint AS with_exposure
FROM inserted
WHERE (SELECT COUNT(*) FROM removed) >= 0
";
