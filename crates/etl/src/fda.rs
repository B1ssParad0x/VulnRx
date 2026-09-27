//! Link a stored product when one FDA cybersecurity notice names that product and a CVE.
//!
//! The product name has to appear as its own words, the vendor has to appear as its
//! own word, and a CVE id has to be in that same notice. A word in a different notice
//! is not a link.

use std::collections::HashSet;

use chrono::NaiveDate;
use scraper::{Html, Selector};
use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::cve_list::vendor_keys;
use crate::kev;
use crate::IngestError;

const INDEX_URL: &str =
    "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity";
const FDA_ORIGIN: &str = "https://www.fda.gov";
const SECTION: &str = "Cybersecurity Safety Communications";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdaReport {
    pub notices: u64,
    pub skipped: u64,
    pub products_with_cves: u64,
    pub cves: u64,
    pub links: u64,
}

struct StoredProduct {
    id: Uuid,
    name: String,
    tokens: Vec<String>,
    vendor_keys: Vec<String>,
}

struct ListedCve {
    cve_id: String,
    title: String,
    published: Option<NaiveDate>,
    product_id: Uuid,
    product_name: String,
    source_url: String,
}

pub async fn match_fda_notices(pool: &PgPool) -> Result<FdaReport, IngestError> {
    let products = load_products(pool).await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .user_agent("VulnRx B1ssParad0x@proton.me")
        .build()?;
    let index = fetch_text(&client, INDEX_URL).await?;
    let urls = notice_urls(&index);
    if urls.is_empty() {
        return Err(IngestError::Portal(
            "FDA cybersecurity page has no safety-communication links".to_string(),
        ));
    }
    eprintln!("fda: {} safety communications", urls.len());
    let mut listed = Vec::new();
    let mut skipped = 0_u64;
    for url in &urls {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let html = match fetch_text(&client, url).await {
            Ok(html) => html,
            Err(err) => {
                eprintln!("fda: skipped {url}: {err}");
                skipped += 1;
                continue;
            }
        };
        let body = notice_text(&html);
        let title = notice_title(&html);
        let published = issued_date(&body);
        listed.extend(links_from_notice(
            &body,
            &products,
            url,
            &title,
            published,
        ));
    }
    let mut report = FdaReport {
        notices: urls.len() as u64,
        skipped,
        products_with_cves: 0,
        cves: 0,
        links: 0,
    };
    if listed.is_empty() {
        return Ok(report);
    }
    report.links = store_links(pool, &listed).await?;
    let mut products_hit = HashSet::new();
    let mut cve_ids = HashSet::new();
    for item in &listed {
        products_hit.insert(item.product_id);
        cve_ids.insert(item.cve_id.clone());
        eprintln!(
            "fda: {} {} {} {}",
            item.product_name, item.cve_id, item.source_url, item.title
        );
    }
    report.products_with_cves = products_hit.len() as u64;
    report.cves = cve_ids.len() as u64;
    let ids: Vec<String> = cve_ids.into_iter().collect();
    let scores = kev::fetch_epss(&ids).await?;
    for (cve_id, score) in scores {
        sqlx::query("UPDATE cves SET epss_score = $2 WHERE cve_id = $1 AND epss_score IS NULL")
            .bind(cve_id)
            .bind(score)
            .execute(pool)
            .await?;
    }
    Ok(report)
}

async fn load_products(pool: &PgPool) -> Result<Vec<StoredProduct>, IngestError> {
    let rows = sqlx::query_as::<_, ProductVendor>(
        "SELECT p.id, p.name, v.name AS vendor
         FROM products p
         JOIN vendors v ON v.id = p.vendor_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            if !name_can_be_cited(&row.name) {
                return None;
            }
            let tokens = name_tokens(&row.name);
            Some(StoredProduct {
                id: row.id,
                vendor_keys: vendor_keys(&row.vendor),
                tokens,
                name: row.name,
            })
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct ProductVendor {
    id: Uuid,
    name: String,
    vendor: String,
}

fn links_from_notice(
    text: &str,
    products: &[StoredProduct],
    url: &str,
    title: &str,
    published: Option<NaiveDate>,
) -> Vec<ListedCve> {
    let page = page_tokens(text);
    let page_words: HashSet<String> = page.iter().map(|token| token.to_ascii_lowercase()).collect();
    let cves = cve_ids(text);
    if cves.is_empty() || page.is_empty() {
        return Vec::new();
    }
    let mut listed = Vec::new();
    let mut seen = HashSet::new();
    for product in products {
        if product.vendor_keys.iter().all(|key| !page_words.contains(key)) {
            continue;
        }
        if !phrase_in(&page, &product.tokens) {
            continue;
        }
        for cve_id in &cves {
            if seen.insert((product.id, cve_id.clone())) {
                listed.push(ListedCve {
                    cve_id: cve_id.clone(),
                    title: title.to_string(),
                    published,
                    product_id: product.id,
                    product_name: product.name.clone(),
                    source_url: url.to_string(),
                });
            }
        }
    }
    listed
}

async fn store_links(pool: &PgPool, listed: &[ListedCve]) -> Result<u64, IngestError> {
    let mut links = 0_u64;
    for cve in listed {
        let description = if cve.title.is_empty() {
            None
        } else {
            Some(cve.title.as_str())
        };
        sqlx::query(
            "INSERT INTO cves (cve_id, description, published_date)
             VALUES ($1, $2, $3)
             ON CONFLICT (cve_id) DO UPDATE SET
               description = COALESCE(cves.description, EXCLUDED.description),
               published_date = COALESCE(cves.published_date, EXCLUDED.published_date)",
        )
        .bind(&cve.cve_id)
        .bind(description)
        .bind(cve.published)
        .execute(pool)
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO product_cve_map (product_id, cve_id, match_basis, source_url)
             SELECT $1, id, 'fda_notice', $3 FROM cves WHERE cve_id = $2
             ON CONFLICT (product_id, cve_id) DO UPDATE SET
               source_url = COALESCE(product_cve_map.source_url, EXCLUDED.source_url),
               match_basis = CASE
                 WHEN product_cve_map.match_basis IS NOT NULL
                  AND product_cve_map.match_basis <> 'fda_notice'
                   THEN product_cve_map.match_basis
                 ELSE EXCLUDED.match_basis
               END",
        )
        .bind(cve.product_id)
        .bind(&cve.cve_id)
        .bind(&cve.source_url)
        .execute(pool)
        .await?
        .rows_affected();
        links += inserted;
    }
    Ok(links)
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String, IngestError> {
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(IngestError::HttpStatus {
            url: url.to_string(),
            status: response.status().as_u16(),
        });
    }
    Ok(response.text().await?)
}

fn notice_urls(html: &str) -> Vec<String> {
    let Some(section) = section_after(html, SECTION) else {
        return Vec::new();
    };
    let document = Html::parse_fragment(section);
    let selector = Selector::parse("a[href]").expect("href selector");
    let mut urls = Vec::new();
    for link in document.select(&selector) {
        let Some(href) = link.attr("href") else {
            continue;
        };
        let Some(url) = fda_html_url(href) else {
            continue;
        };
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

fn section_after<'a>(html: &'a str, heading: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let needle = heading.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find(&needle) {
        let start = search_from + rel;
        let before = &lower[..start];
        if let Some(h2) = before.rfind("<h2") {
            let between = &before[h2..];
            if !between.contains("</h2") {
                let rest = &html[start + needle.len()..];
                let rest_lower = rest.to_ascii_lowercase();
                let close = rest_lower.find("</h2>")? + "</h2>".len();
                let body = &rest[close..];
                let end = body
                    .to_ascii_lowercase()
                    .find("<h2")
                    .unwrap_or(body.len());
                return Some(&body[..end]);
            }
        }
        search_from = start + needle.len();
    }
    None
}

fn fda_html_url(href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() || href.starts_with('#') {
        return None;
    }
    let candidate = if let Some(path) = href.strip_prefix('/') {
        if path.starts_with('/') {
            return None;
        }
        format!("{FDA_ORIGIN}/{path}")
    } else if href.starts_with("https://www.fda.gov/") || archive_of_fda(href) {
        href.to_string()
    } else {
        return None;
    };
    let without_hash = candidate.split('#').next()?.to_string();
    let lower = without_hash.to_ascii_lowercase();
    if lower.ends_with(".pdf")
        || lower.ends_with(".zip")
        || lower.contains("/download")
        || lower.contains("subscribe")
    {
        return None;
    }
    let notice = lower.contains("/safety-communications/")
        || lower.contains("/letters-health-care-providers/")
        || lower.contains("/safetyalertsforhumanmedicalproducts/")
        || lower.contains("/alertsandnotices/");
    if notice { Some(without_hash) } else { None }
}

fn archive_of_fda(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    lower.contains("fda.gov")
        && (lower.contains("pagefreezer.com")
            || lower.contains("archive-it.org")
            || lower.contains("web.archive.org"))
}

fn notice_title(html: &str) -> String {
    let document = Html::parse_document(html);
    let selector = Selector::parse("h1").expect("h1 selector");
    let title = document
        .select(&selector)
        .next()
        .map(|node| node.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    title.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(240).collect()
}

fn notice_text(html: &str) -> String {
    let document = Html::parse_document(html);
    let selector = Selector::parse("article, main, body").expect("body selector");
    document
        .select(&selector)
        .next()
        .map(|node| node.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

fn issued_date(text: &str) -> Option<NaiveDate> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("date issued:")? + "date issued:".len();
    let head: String = text[start..].split_whitespace().take(3).collect::<Vec<_>>().join(" ");
    NaiveDate::parse_from_str(head.trim_end_matches(['.', ',']), "%B %d, %Y").ok()
}

fn cve_ids(text: &str) -> Vec<String> {
    let upper = text.to_ascii_uppercase();
    let mut ids = Vec::new();
    let mut rest = upper.as_str();
    while let Some(pos) = rest.find("CVE-") {
        let after = &rest[pos + 4..];
        let year: String = after.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if year.len() == 4 {
            let tail = &after[year.len()..];
            if let Some(tail) = tail.strip_prefix('-') {
                let number: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
                if (4..=7).contains(&number.len()) {
                    ids.push(format!("CVE-{year}-{number}"));
                }
            }
        }
        rest = &rest[pos + 4..];
    }
    ids.sort();
    ids.dedup();
    ids
}

fn page_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_uppercase())
        .collect()
}

fn name_tokens(name: &str) -> Vec<String> {
    page_tokens(name)
}

fn name_can_be_cited(name: &str) -> bool {
    let tokens: Vec<&str> = name
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    let long_enough = tokens.iter().any(|token| token.chars().count() >= 4);
    let distinctive = tokens.iter().any(|token| {
        token.chars().any(|ch| ch.is_ascii_digit())
            || token.chars().skip(1).any(|ch| ch.is_ascii_uppercase())
    });
    long_enough && distinctive
}

fn phrase_in(page: &[String], phrase: &[String]) -> bool {
    !phrase.is_empty() && page.windows(phrase.len()).any(|window| window == phrase)
}

#[cfg(test)]
mod tests {
    use super::{cve_ids, fda_html_url, links_from_notice, name_can_be_cited, name_tokens, notice_urls, StoredProduct};
    use sqlx::types::Uuid;

    fn product(id: u128, name: &str, vendor: &str) -> StoredProduct {
        StoredProduct {
            id: Uuid::from_u128(id),
            tokens: name_tokens(name),
            vendor_keys: crate::cve_list::vendor_keys(vendor),
            name: name.to_string(),
        }
    }

    #[test]
    fn keeps_fda_html_notices_from_the_safety_section() {
        let html = r##"
            <p><a href="#safety">Cybersecurity Safety Communications and Other Alerts</a></p>
            <h2><a id="safety"></a>Cybersecurity Safety Communications and Other Alerts</h2>
            <p><a href="/medical-devices/safety-communications/minimed">MiniMed</a></p>
            <p><a href="https://www.cisa.gov/news-events/ics-medical-advisories/x">CISA</a></p>
            <p><a href="https://public4.pagefreezer.com/browse/FDA/08-02-2023T11:48/https://www.fda.gov/medical-devices/safety-communications/sweyntooth">Archive</a></p>
            <p><a href="/files/alert.pdf">PDF</a></p>
            <h2>Reporting Cybersecurity Issues</h2>
            <p><a href="/medical-devices/safety-communications/later">Later</a></p>
        "##;
        assert_eq!(
            notice_urls(html),
            vec![
                "https://www.fda.gov/medical-devices/safety-communications/minimed".to_string(),
                "https://public4.pagefreezer.com/browse/FDA/08-02-2023T11:48/https://www.fda.gov/medical-devices/safety-communications/sweyntooth".to_string(),
            ]
        );
        assert!(fda_html_url("/files/alert.pdf").is_none());
        assert!(fda_html_url("https://www.cisa.gov/uscert/ics/advisories/icsa-22-067-01").is_none());
    }

    #[test]
    fn links_only_the_named_product_on_that_notice() {
        let minimed = product(1, "MiniMed 600", "Medtronic");
        let other = product(2, "MiniMed 600", "Other Vendor");
        let ordinary = product(3, "Communicate", "Medtronic");
        let epic = product(4, "EpicCare Inpatient", "Epic Systems Corporation");
        assert!(name_can_be_cited("MiniMed 600"));
        assert!(!name_can_be_cited("Communicate"));
        assert!(!name_can_be_cited("Clinical Information"));
        let text = "Date Issued: January 30, 2025. Medtronic MiniMed 600 Series. CVE-2022-12345. epinephrine";
        let links = links_from_notice(
            text,
            &[minimed, other, ordinary, epic],
            "https://www.fda.gov/medical-devices/safety-communications/minimed",
            "Medtronic MiniMed 600 Series",
            None,
        );
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].product_id, Uuid::from_u128(1));
        assert_eq!(links[0].cve_id, "CVE-2022-12345");
        assert_eq!(cve_ids("see cve-2021-44228 and CVE-2021-44228"), vec!["CVE-2021-44228".to_string()]);
    }
}
