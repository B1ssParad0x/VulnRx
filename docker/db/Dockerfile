FROM timescale/timescaledb:2.30.1-pg16-oss

# Runs after the image's own Timescale install and tune scripts.
COPY migrations/0001_init.sql /docker-entrypoint-initdb.d/002_vulnrx_schema.sql
