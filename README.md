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

[`vulnrx-etl`](crates/etl) loads public CMS and ONC files. Vendor links are written only when a file or a CHPL lookup names the product.

```bash
cargo run -p vulnrx-etl -- hospitals
cargo run -p vulnrx-etl -- pi
cargo run -p vulnrx-etl -- pi-2024
cargo run -p vulnrx-etl -- expand-cehrt
cargo run -p vulnrx-etl -- breaches
cargo run -p vulnrx-etl -- kev
```

`hospitals` loads every Medicare-registered hospital and does not invent vendor links. `pi` loads the 2023 ONC file that already joins each hospital to CHPL products. `pi-2024` stores the newer bundle id CMS published for each hospital. `expand-cehrt` asks CHPL which products are inside those ids; it requires `CHPL_API_KEY` from `.env.example`. `breaches` reads the HHS OCR breach portal. A healthcare provider is linked to a hospital only when the normalized name and state match exactly one facility. `kev` loads CISA's known-exploited catalog with EPSS and CVSS, and links a CVE to a product only when the catalog names that vendor and product. `--state` limits `hospitals`, `pi`, `pi-2024`, and `breaches` to one USPS code.
