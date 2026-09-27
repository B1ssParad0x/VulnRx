-- The page that named both the product and the CVE. Catalog matches leave this empty.

ALTER TABLE product_cve_map
    ADD COLUMN source_url TEXT;

COMMENT ON COLUMN product_cve_map.source_url IS
    'Public notice that named this product and this CVE. NULL when the link came from a catalog rather than one page.';
