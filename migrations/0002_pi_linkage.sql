-- Columns carried by the CMS Promoting Interoperability / CHPL linkage file.
-- A CHPL id identifies a certified listing. Two listings can share a display name,
-- so vendor + name + version is no longer a unique key.

ALTER TABLE hospitals
    ADD COLUMN address TEXT,
    ADD COLUMN zip TEXT,
    ADD COLUMN phone TEXT;

COMMENT ON COLUMN hospitals.address IS
    'Street address when a public source provides one.';

ALTER TABLE products
    ADD COLUMN chpl_id TEXT,
    ADD COLUMN chpl_database_id TEXT;

COMMENT ON COLUMN products.chpl_id IS
    'ONC Certified Health IT Product List id when a public source provides one. Not a CPE string.';

ALTER TABLE products
    DROP CONSTRAINT products_vendor_name_version_uidx;

CREATE UNIQUE INDEX products_chpl_id_uidx
    ON products (chpl_id)
    WHERE chpl_id IS NOT NULL;

CREATE INDEX products_vendor_name_idx ON products (vendor_id, lower(name));
