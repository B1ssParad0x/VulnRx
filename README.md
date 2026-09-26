# VulnRx

Hospital vendor and vulnerability risk intelligence. Search a U.S. hospital and see which technology vendors public records associate with it, which known vulnerabilities apply to that stack, and a composite risk score computed from those records.

## Guardrails

- Show evidence of exploitability (CVSS, EPSS, KEV status, confirmed exposure). Do not generate exploit code or proof-of-concept steps.
- Do not scan or probe hospital networks. Exposure data, when present, comes from querying an existing public index.
- Every stored relationship or event names its public source. Do not insert a vendor link, breach, or filing that has no citable source.

## Database

Postgres 16 with TimescaleDB. [`docker/db/Dockerfile`](docker/db/Dockerfile) copies [`migrations/0001_init.sql`](migrations/0001_init.sql) into the image so the first boot applies it after Timescale's own setup.

```bash
docker compose up -d --build
```

Copy `.env.example` to `.env` if a tool expects `DATABASE_URL`. The local password is a development default, not a credential.

Init scripts do not re-run inside an existing volume. After a schema change, reset and rebuild:

```bash
docker compose down -v
docker compose up -d --build
```
