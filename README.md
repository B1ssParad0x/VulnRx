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
cargo run -p vulnrx-etl -- cve
cargo run -p vulnrx-etl -- edgar
cargo run -p vulnrx-etl -- score
cargo run -p vulnrx-etl -- shodan
cargo run -p vulnrx-etl -- censys
```

`hospitals` loads every Medicare-registered hospital and does not invent vendor links. `pi` loads the 2023 ONC file that already joins each hospital to CHPL products. `pi-2024` stores the newer bundle id CMS published for each hospital. `expand-cehrt` asks CHPL which products are inside those ids; it requires `CHPL_API_KEY` from `.env.example`. `breaches` reads the HHS OCR breach portal. A healthcare provider is linked to a hospital only when the normalized name and state match exactly one facility. `kev` loads CISA's known-exploited catalog with EPSS and CVSS, and links a CVE to a product only when the catalog names that vendor and product. `edgar` loads 8-K Item 1.05 incident reports from December 2023 through today, and 10-K Item 1C cybersecurity disclosures filed since 2024 by hospital operators, nursing facilities, health plans, and medical-device companies. Each summary is an excerpt of the filing. `shodan` is optional and only works on a paid Shodan membership; a free key is refused and nothing is stored. `censys` queries that same kind of index when `CENSYS_ORGANIZATION_ID` is set. Free Censys accounts do not have an organization id. The default is 20 queries and the maximum is 50. A hit is stored only when the result names that product. `cve` asks NVD for CVEs whose record contains the stored product name as an exact phrase, or whose official CPE title does, and whose CPE vendor matches that product's vendor. A one-word name is searched only when it contains a digit or a capital after the first letter, and every word of a multi-word name must be at least four letters, so an ordinary word is not treated as a product. `score` writes a hospital rollup only for facilities with a linked breach, Item 1.05 filing, product CVE, or exposure. A component with no linked input is stored as 0 and left out of the average; `method` names the inputs that were used. `--state` limits `hospitals`, `pi`, `pi-2024`, and `breaches` to one USPS code. Explain on a CVE calls Gemini 3.5 Flash-Lite once, with thinking off, and saves the reply.

## API

[`vulnrx-api`](crates/api) reads the store. It does not invent rows for hospitals that have no linked record.

```bash
cargo run -p vulnrx-api
```

Open `http://127.0.0.1:8080` for the landing page. `/dashboard` is the US map and the hospital search. `/kev` is CISA's known-exploited catalog, with the vendor and product CISA named. A row there is not a claim that a hospital runs that product. `BIND_ADDR` defaults to `127.0.0.1:8080`. The ticker lists linked OCR breaches and Item 1.05 filings only. A state is colored by how many hospitals there have a linked HHS OCR breach. A score component that was not an input is labeled that way.

- `GET /api/hospitals/search?q=` matches name, display name, alias, or CCN
- `GET /api/hospitals/{id}` returns the facility, vendor links, CEHRT ids, breaches, filings, exposures, and the latest rollup
- `GET /api/hospitals/{id}/vulnerabilities` returns CVEs linked to that hospital's products. `product_count` is the stack size when the CVE list is empty
- `GET /api/vendors/{id}` returns the vendor, its products, and every hospital a public source links to it
- `GET /api/incidents/recent` returns linked OCR breaches and Item 1.05 filings, newest first
- `GET /api/kev` returns CISA's known-exploited catalog. `vendor` and `product` are the catalog strings
