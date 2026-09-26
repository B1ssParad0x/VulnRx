-- Keep enough precision for an EPSS probability, and record how a KEV entry was linked.

ALTER TABLE cves
    ADD COLUMN kev_vendor TEXT,
    ADD COLUMN kev_product TEXT;

ALTER TABLE cves
    ALTER COLUMN epss_score TYPE NUMERIC(6, 5);

COMMENT ON COLUMN cves.kev_vendor IS
    'vendorProject from the CISA KEV catalog when this CVE is listed there.';
COMMENT ON COLUMN cves.kev_product IS
    'product from the CISA KEV catalog when this CVE is listed there.';

ALTER TABLE product_cve_map
    ADD COLUMN match_basis TEXT;

COMMENT ON COLUMN product_cve_map.match_basis IS
    'Why this product and CVE were linked. cisa_kev means the catalog named this vendor and product. Not a CPE match.';
