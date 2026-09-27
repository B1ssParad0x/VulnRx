-- ZoomEye and Netlas are free search indexes. InternetDB is a free
-- address lookup used only after crt.sh names one hospital. Still not a scan.

ALTER TABLE exposures DROP CONSTRAINT exposures_source_chk;

ALTER TABLE exposures
    ADD CONSTRAINT exposures_source_chk
    CHECK (source IN ('shodan', 'censys', 'zoomeye', 'netlas', 'internetdb'));

COMMENT ON TABLE exposures IS
    'A hit from an existing public index. raw_reference stores the query, not a host address. This table must not be filled from an active scan.';
