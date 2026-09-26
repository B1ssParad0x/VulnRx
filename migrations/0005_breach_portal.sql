-- OCR breach rows need a state for a same-state name match, and a stable identity for re-runs.

ALTER TABLE breach_events
    ADD COLUMN state TEXT,
    ADD COLUMN breach_location TEXT,
    ADD COLUMN portal_entity_type TEXT;

ALTER TABLE breach_events
    ADD CONSTRAINT breach_events_state_chk CHECK (
        state IS NULL OR state ~ '^[A-Z]{2}$'
    );

ALTER TABLE breach_events
    ADD CONSTRAINT breach_events_natural_uidx
    UNIQUE NULLS NOT DISTINCT (
        entity_name,
        state,
        date_reported,
        individuals_affected,
        breach_type,
        breach_location,
        source
    );

COMMENT ON COLUMN breach_events.portal_entity_type IS
    'Covered-entity type as published by HHS OCR, such as Healthcare Provider or Health Plan.';
