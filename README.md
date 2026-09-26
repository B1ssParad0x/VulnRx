# VulnRx

Hospital vendor and vulnerability risk intelligence. Search a U.S. hospital and see which technology vendors public records associate with it, which known vulnerabilities apply to that stack, and a composite risk score computed from those records.

## Guardrails

- Shows evidence of exploitability (CVSS, EPSS, KEV status, confirmed exposure). Does not generate exploit code or proof-of-concept steps.
- Does not scan or probe hospital networks. Exposure data, when present, comes from querying an existing public index.
- Every stored relationship or event names its public source.

## Database

Postgres 16 with TimescaleDB. The image only starts the server. Schema lives in [`migrations/`](migrations) and is applied by the `vulnrx-models` crate, so the same files run in Docker and anywhere else.

```bash
docker compose up -d
cargo run -p vulnrx-models --bin migrate
```

`migrate` uses `DATABASE_URL` when it is set, and otherwise connects to the local Compose database. Copy `.env.example` to `.env` if you want that variable defined. The local password is a development default, not a credential.

```bash
cargo test -p vulnrx-models
```

## Hospital products

[`vulnrx-etl`](crates/etl) loads the ONC file that joins CMS Promoting Interoperability hospital reports to CHPL products. Each stored link keeps that file URL as its source. The CHPL API itself requires a key; this file is the public join ONC already published.

```bash
cargo run -p vulnrx-etl
cargo run -p vulnrx-etl -- --state MO
```

`--state` limits the load to one USPS code. The default reads every row in the file.
