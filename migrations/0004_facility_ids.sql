-- Hospital Compare uses a trailing letter on some VA and military facility ids.

ALTER TABLE hospitals DROP CONSTRAINT hospitals_ccn_chk;

ALTER TABLE hospitals
    ADD CONSTRAINT hospitals_ccn_chk CHECK (
        ccn IS NULL OR ccn ~ '^[0-9]{6}$' OR ccn ~ '^[0-9]{5}[A-Z]$'
    );

COMMENT ON COLUMN hospitals.ccn IS
    'CMS facility id. Six digits, or five digits and a letter for some VA and military hospitals.';
