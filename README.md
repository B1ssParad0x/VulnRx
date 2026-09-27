# VulnRx

![VulnRx](Logo.png)

Hospital vendor and vulnerability risk from the public record. Search a U.S. Medicare-registered hospital and see which technology vendors public files already name, which CVEs and breaches attach to that stack, and a composite rollup built only from those links.

TigerHacks 2026 · health theme.

## Guardrails

- Surfaces evidence of exploitability (CVSS, EPSS, KEV, confirmed exposure). Does **not** generate exploit code or proof-of-concept steps.
- Does **not** scan or probe hospital networks. Exposure rows come from querying an existing public index.
- Every stored relationship or event names its public source. No invented vendor links, placeholder hospitals, or seeded CVEs.

## Quick start

```bash
cp .env.example .env
docker compose up -d
cargo run -p vulnrx-models --bin migrate
cargo run -p vulnrx-api
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). `BIND_ADDR` defaults to `127.0.0.1:8080`.

`migrate` uses `DATABASE_URL` when set; otherwise it connects to the local Compose database. The Compose password is a development default, not a secret.

```bash
cargo test -p vulnrx-models
cargo test -p vulnrx-api
```

## What you see

| Surface | What it shows |
| --- | --- |
| `/` | Landing page |
| `/dashboard` | US map, hospital search, and ask-the-records |
| `/hospitals/{id}` | Facility, vendors, breaches/filings, CVEs, exposure, rollup, remediation |
| `/vendors/{id}` | Vendor products, linked hospitals, CVEs, and breaches that name that vendor |
| `/kev` | CISA known-exploited catalog (catalog vendor/product strings only) |

On the map: fill is how many hospitals in that state have a linked HHS OCR breach. A green outline means the state is in the registry and has no linked breach. A green dot is a hospital whose certified product is named in a CVE record. Alaska and Hawaii are inset. The ticker lists linked OCR breaches and Item 1.05 filings only.

Gemini (`gemini-3.5-flash-lite`) runs only on click for CVE Explain, Ask, and Remediation. Each reply is saved so the same prompt is not sent again. A hospital with no linked breach, product, or CVE is not sent to the model.

## Stack

| Piece | Choice |
| --- | --- |
| Store | Postgres 16 + TimescaleDB (`docker compose`) |
| Schema | [`migrations/`](migrations), applied by `vulnrx-models` |
| Ingest | [`vulnrx-etl`](crates/etl) |
| Serve | [`vulnrx-api`](crates/api) — Axum, Askama, HTMX |

## Load data

[`vulnrx-etl`](crates/etl) writes a row only when a public source names the entities being linked. `--state` limits `hospitals`, `pi`, `pi-2024`, and `breaches` to one USPS code.

```bash
cargo run -p vulnrx-etl -- hospitals
cargo run -p vulnrx-etl -- pi
cargo run -p vulnrx-etl -- pi-2024
cargo run -p vulnrx-etl -- expand-cehrt
cargo run -p vulnrx-etl -- breaches
cargo run -p vulnrx-etl -- kev
cargo run -p vulnrx-etl -- cve
cargo run -p vulnrx-etl -- cve-list
cargo run -p vulnrx-etl -- advisories
cargo run -p vulnrx-etl -- fda
cargo run -p vulnrx-etl -- edgar
cargo run -p vulnrx-etl -- score
cargo run -p vulnrx-etl -- exposure
cargo run -p vulnrx-etl -- fallback
```

Optional paid or keyed indexes (see [`.env.example`](.env.example)):

```bash
cargo run -p vulnrx-etl -- shodan
cargo run -p vulnrx-etl -- censys
cargo run -p vulnrx-etl -- zoomeye
cargo run -p vulnrx-etl -- netlas
```

### Source notes

- **hospitals** — every Medicare-registered hospital; no invented vendor links.
- **pi / pi-2024** — ONC/CMS promoting-interoperability files that join hospitals to CHPL products or 2024 CEHRT bundle ids.
- **expand-cehrt** — CHPL API unpack of those bundle ids (`CHPL_API_KEY`). `expand-cehrt --missing` retries only ids still without a product link; a 404 stays unlinked.
- **breaches** — HHS OCR breach portal. A provider links to a hospital only when normalized name and state match exactly one facility.
- **kev** — CISA KEV with EPSS/CVSS. A CVE links to a product only when the catalog names that vendor and product.
- **cve / cve-list** — NVD exact-phrase / CPE title matches, and the CVE Project baseline. Ordinary dictionary words are not treated as product names.
- **advisories / fda** — CISA CSAF and FDA safety communications; link only when the notice names the product (and for FDA, a CVE id).
- **edgar** — 8-K Item 1.05 and 10-K Item 1C excerpts. `edgar --sic 8062` loads one industry code and keeps a page only when the result carries that code.
- **exposure / fallback** — ZoomEye/Netlas when keyed; otherwise crt.sh then Shodan InternetDB. A hit stores only when a certificate names one hospital and a CPE names one product already linked to that hospital. Host addresses are not stored. Default 20 queries, max 50.
- **score** — hospital rollup only when a linked breach, Item 1.05 filing, product CVE, or exposure exists. Unused components store as 0 and stay out of the average; `method` names the inputs used.

Shodan search, Censys search, and ZoomEye credits are paid. That paywall shaped coverage: exposure rows exist only where a free index, or a certificate plus InternetDB, names a product already stored. CVE rows exist only where NVD, the CVE List, a CISA advisory, or an FDA notice names that same product. EpicCare, MEDITECH Expanse, and Oracle Health Millennium are certified widely and are not those catalog names, so most hospitals show a vendor stack without a CVE.

## HTTP API

The API reads the store. It does not invent rows for hospitals with no linked record.

- `GET /api/hospitals/search?q=` — name, display name, alias, or CCN
- `GET /api/hospitals/{id}` — facility, vendors, CEHRT ids, breaches, filings, exposures, latest rollup
- `GET /api/hospitals/{id}/vulnerabilities` — CVEs for that hospital's products (`product_count` when the list is empty)
- `GET /api/vendors/{id}` — vendor, products, linked hospitals
- `GET /api/incidents/recent` — linked OCR breaches and Item 1.05 filings, newest first
- `GET /api/kev` — CISA known-exploited catalog (`vendor` / `product` are catalog strings)
