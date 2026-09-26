-- Facility identity is its own fact, separate from a vendor link.
-- A CEHRT id is the bundle a hospital reported; products inside it come from CHPL.

ALTER TABLE hospitals
    ADD COLUMN source TEXT,
    ADD COLUMN source_url TEXT;

COMMENT ON COLUMN hospitals.source IS
    'Public source of the facility record. Vendor links keep their own source.';

CREATE TABLE cehrt_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id UUID NOT NULL REFERENCES hospitals (id) ON DELETE CASCADE,
    cehrt_id TEXT NOT NULL,
    meets_criteria BOOLEAN,
    period_start DATE,
    period_end DATE,
    source TEXT NOT NULL,
    source_url TEXT,
    CONSTRAINT cehrt_reports_id_chk CHECK (cehrt_id ~ '^[0-9A-Z]{15}$'),
    CONSTRAINT cehrt_reports_source_chk CHECK (length(btrim(source)) > 0),
    CONSTRAINT cehrt_reports_natural_uidx UNIQUE (hospital_id, cehrt_id, source)
);

COMMENT ON TABLE cehrt_reports IS
    'A hospital-reported CMS EHR Certification ID. Product links are added only after CHPL lists the products inside that id.';

CREATE INDEX cehrt_reports_hospital_idx ON cehrt_reports (hospital_id);
CREATE INDEX cehrt_reports_cehrt_idx ON cehrt_reports (cehrt_id);

CREATE UNIQUE INDEX products_chpl_database_id_uidx
    ON products (chpl_database_id)
    WHERE chpl_database_id IS NOT NULL;
