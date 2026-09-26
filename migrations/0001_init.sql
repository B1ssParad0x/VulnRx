-- VulnRx canonical store.
-- Facts only: every relationship or event row names the public source it came from.
-- Exposure rows are results of queries against existing indexes (Shodan, Censys),
-- never the product of a scan this project originated.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- Core entities
-- ---------------------------------------------------------------------------

CREATE TABLE hospitals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ccn TEXT,
    name TEXT NOT NULL,
    display_name TEXT,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    city TEXT,
    state TEXT,
    is_public_entity BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT hospitals_ccn_chk CHECK (ccn IS NULL OR ccn ~ '^[0-9]{6}$'),
    CONSTRAINT hospitals_state_chk CHECK (state IS NULL OR state ~ '^[A-Z]{2}$')
);

COMMENT ON TABLE hospitals IS
    'A hospital or health system. display_name is what the UI shows; name is the canonical record name.';
COMMENT ON COLUMN hospitals.ccn IS
    'CMS Certification Number when a public source provides one. Six digits, leading zeros preserved.';
COMMENT ON COLUMN hospitals.is_public_entity IS
    'TRUE when SEC or public-procurement coverage applies (publicly traded system or government-owned).';

CREATE UNIQUE INDEX hospitals_ccn_uidx ON hospitals (ccn) WHERE ccn IS NOT NULL;
CREATE INDEX hospitals_name_trgm_idx ON hospitals USING gin (name gin_trgm_ops);
CREATE INDEX hospitals_display_name_trgm_idx ON hospitals USING gin (display_name gin_trgm_ops);
CREATE INDEX hospitals_aliases_idx ON hospitals USING gin (aliases);
CREATE INDEX hospitals_state_idx ON hospitals (state);

CREATE TABLE vendors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    category TEXT,
    CONSTRAINT vendors_category_chk CHECK (
        category IS NULL OR category IN (
            'ehr', 'imaging', 'cloud', 'networking', 'device', 'other'
        )
    )
);

COMMENT ON COLUMN vendors.category IS
    'ehr, imaging, cloud, networking, device, or other. NULL until a source supports a category.';

CREATE UNIQUE INDEX vendors_name_lower_uidx ON vendors (lower(name));
CREATE INDEX vendors_aliases_idx ON vendors USING gin (aliases);
CREATE INDEX vendors_category_idx ON vendors (category);

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id UUID NOT NULL REFERENCES vendors (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cpe_string TEXT,
    version TEXT,
    CONSTRAINT products_vendor_name_version_uidx UNIQUE NULLS NOT DISTINCT (vendor_id, name, version)
);

CREATE INDEX products_vendor_idx ON products (vendor_id);
CREATE INDEX products_cpe_idx ON products (cpe_string) WHERE cpe_string IS NOT NULL;

-- Hospital <-> vendor/product, with provenance.
CREATE TABLE hospital_vendor_map (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id UUID NOT NULL REFERENCES hospitals (id) ON DELETE CASCADE,
    vendor_id UUID NOT NULL REFERENCES vendors (id) ON DELETE CASCADE,
    product_id UUID REFERENCES products (id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    source_url TEXT,
    confidence NUMERIC(3, 2) NOT NULL,
    last_verified DATE,
    CONSTRAINT hospital_vendor_map_confidence_chk CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT hospital_vendor_map_source_chk CHECK (length(btrim(source)) > 0),
    CONSTRAINT hospital_vendor_map_natural_uidx UNIQUE NULLS NOT DISTINCT (
        hospital_id, vendor_id, product_id, source
    )
);

COMMENT ON TABLE hospital_vendor_map IS
    'A claimed hospital-vendor relationship. source and confidence are required; do not insert a row without a citable source.';
COMMENT ON COLUMN hospital_vendor_map.confidence IS
    '0.00-1.00. How strongly the cited source supports this relationship, not a guess about unstated vendors.';

CREATE INDEX hospital_vendor_map_hospital_idx ON hospital_vendor_map (hospital_id);
CREATE INDEX hospital_vendor_map_vendor_idx ON hospital_vendor_map (vendor_id);

-- ---------------------------------------------------------------------------
-- Vulnerabilities
-- ---------------------------------------------------------------------------

CREATE TABLE cves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL,
    description TEXT,
    cvss_score NUMERIC(3, 1),
    epss_score NUMERIC(5, 4),
    is_kev BOOLEAN,
    published_date DATE,
    CONSTRAINT cves_cve_id_chk CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT cves_cvss_chk CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    CONSTRAINT cves_epss_chk CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)),
    CONSTRAINT cves_cve_id_uidx UNIQUE (cve_id)
);

COMMENT ON COLUMN cves.is_kev IS
    'NULL until this CVE has been checked against the CISA KEV catalog. FALSE means checked and absent. TRUE means listed.';
COMMENT ON COLUMN cves.epss_score IS
    'FIRST.org EPSS probability for the next 30 days. NULL until that API has been queried for this CVE.';

CREATE INDEX cves_kev_idx ON cves (cve_id) WHERE is_kev IS TRUE;
CREATE INDEX cves_published_idx ON cves (published_date);

CREATE TABLE product_cve_map (
    product_id UUID NOT NULL REFERENCES products (id) ON DELETE CASCADE,
    cve_id UUID NOT NULL REFERENCES cves (id) ON DELETE CASCADE,
    matched_cpe TEXT,
    PRIMARY KEY (product_id, cve_id)
);

COMMENT ON COLUMN product_cve_map.matched_cpe IS
    'The CPE that justified this product-CVE link. Kept on the match, not the CVE, because one CVE can apply to many products.';

CREATE INDEX product_cve_map_cve_idx ON product_cve_map (cve_id);

-- ---------------------------------------------------------------------------
-- Breach and regulatory disclosure history
-- ---------------------------------------------------------------------------

CREATE TABLE breach_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_name TEXT NOT NULL,
    entity_type TEXT,
    hospital_id UUID REFERENCES hospitals (id) ON DELETE SET NULL,
    vendor_id UUID REFERENCES vendors (id) ON DELETE SET NULL,
    individuals_affected INTEGER,
    breach_type TEXT,
    date_reported DATE,
    source TEXT NOT NULL,
    source_url TEXT,
    CONSTRAINT breach_events_entity_type_chk CHECK (
        entity_type IS NULL OR entity_type IN ('covered_entity', 'business_associate')
    ),
    CONSTRAINT breach_events_affected_chk CHECK (
        individuals_affected IS NULL OR individuals_affected >= 0
    ),
    CONSTRAINT breach_events_source_chk CHECK (length(btrim(source)) > 0)
);

COMMENT ON TABLE breach_events IS
    'HHS OCR breach portal entries and similar public breach records. hospital_id and vendor_id stay NULL until entity resolution cites a match.';

CREATE INDEX breach_events_hospital_idx ON breach_events (hospital_id);
CREATE INDEX breach_events_vendor_idx ON breach_events (vendor_id);
CREATE INDEX breach_events_reported_idx ON breach_events (date_reported);
CREATE INDEX breach_events_entity_name_trgm_idx ON breach_events USING gin (entity_name gin_trgm_ops);

CREATE TABLE sec_filings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name TEXT NOT NULL,
    hospital_id UUID REFERENCES hospitals (id) ON DELETE SET NULL,
    vendor_id UUID REFERENCES vendors (id) ON DELETE SET NULL,
    filing_type TEXT,
    filed_date DATE,
    summary TEXT,
    source TEXT NOT NULL,
    source_url TEXT,
    CONSTRAINT sec_filings_source_chk CHECK (length(btrim(source)) > 0)
);

COMMENT ON TABLE sec_filings IS
    'Public EDGAR disclosures, typically 8-K Item 1.05 and 10-K Item 106. Summary text must be drawn from the filing, not invented.';

CREATE INDEX sec_filings_hospital_idx ON sec_filings (hospital_id);
CREATE INDEX sec_filings_vendor_idx ON sec_filings (vendor_id);
CREATE INDEX sec_filings_filed_idx ON sec_filings (filed_date);
CREATE UNIQUE INDEX sec_filings_source_url_uidx ON sec_filings (source_url) WHERE source_url IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Exposure evidence from existing public indexes only
-- ---------------------------------------------------------------------------

CREATE TABLE exposures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id UUID REFERENCES hospitals (id) ON DELETE CASCADE,
    product_id UUID REFERENCES products (id) ON DELETE CASCADE,
    exposed_service TEXT,
    source TEXT NOT NULL,
    last_seen DATE,
    raw_reference TEXT NOT NULL,
    CONSTRAINT exposures_source_chk CHECK (source IN ('shodan', 'censys')),
    CONSTRAINT exposures_subject_chk CHECK (hospital_id IS NOT NULL OR product_id IS NOT NULL),
    CONSTRAINT exposures_reference_chk CHECK (length(btrim(raw_reference)) > 0)
);

COMMENT ON TABLE exposures IS
    'A hit from a Shodan or Censys index query. raw_reference stores the query or result id. This table must not be filled from an active scan.';

CREATE INDEX exposures_hospital_idx ON exposures (hospital_id);
CREATE INDEX exposures_product_idx ON exposures (product_id);

-- ---------------------------------------------------------------------------
-- Computed risk scores (TimescaleDB hypertable)
-- vendor_id NULL is the hospital-level rollup. A row exists only after a real computation.
-- ---------------------------------------------------------------------------

CREATE TABLE risk_scores (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    hospital_id UUID NOT NULL REFERENCES hospitals (id) ON DELETE CASCADE,
    vendor_id UUID REFERENCES vendors (id) ON DELETE CASCADE,
    composite_score NUMERIC(5, 2) NOT NULL,
    breach_component NUMERIC(5, 2) NOT NULL,
    cve_component NUMERIC(5, 2) NOT NULL,
    exposure_component NUMERIC(5, 2) NOT NULL,
    method TEXT NOT NULL DEFAULT 'v1',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, computed_at),
    CONSTRAINT risk_scores_composite_chk CHECK (composite_score >= 0 AND composite_score <= 100),
    CONSTRAINT risk_scores_breach_chk CHECK (breach_component >= 0 AND breach_component <= 100),
    CONSTRAINT risk_scores_cve_chk CHECK (cve_component >= 0 AND cve_component <= 100),
    CONSTRAINT risk_scores_exposure_chk CHECK (exposure_component >= 0 AND exposure_component <= 100),
    CONSTRAINT risk_scores_method_chk CHECK (length(btrim(method)) > 0)
);

COMMENT ON TABLE risk_scores IS
    'Point-in-time risk scores. method distinguishes formula versions so a chart does not treat a formula change as a change in risk.';
COMMENT ON COLUMN risk_scores.vendor_id IS
    'NULL for the hospital-level rollup. Set when the score is for one vendor at that hospital.';

SELECT create_hypertable('risk_scores', 'computed_at');

CREATE INDEX risk_scores_hospital_time_idx
    ON risk_scores (hospital_id, computed_at DESC);
CREATE INDEX risk_scores_hospital_vendor_time_idx
    ON risk_scores (hospital_id, vendor_id, computed_at DESC);
