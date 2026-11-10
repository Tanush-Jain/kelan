# Vulnerability Intelligence Sources

This document records the official endpoints, payload schemas, rate limits, authentication requirements, licensing terms, and verification status for all threat intelligence feeds integrated into Kelan's offline-first intelligence library (`kelan/intel/`).

---

## Source Comparison Matrix

| Source | Primary Ingestion URL | Data Format | Auth / Key | Rate Limits | License / Terms | Sandbox Reachability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NVD (NIST)** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON (CVE API 2.0) | Optional API key (`apiKey` header) | 5 req / 30s rolling (public)<br>50 req / 30s rolling (keyed) | U.S. Public Domain | **Unreachable** (HTTP 403 via sandbox proxy) |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON (`vulnerabilities` array) | None | CDN cached (`ETag`, `Last-Modified`) | U.S. Public Domain | **Unreachable** (HTTP 403 via sandbox proxy) |
| **FIRST EPSS** | Bulk: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`<br>API: `https://api.first.org/data/v1/epss` | CSV.gz (`cve,epss,percentile`) / JSON API | None | Bulk: unmetered CDN<br>API: soft IP limits (~10 req/s) | FIRST.org EPSS Terms (Free with attribution) | **Unreachable** (HTTP 403 via sandbox proxy) |
| **OSV.dev** | Bulk: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`<br>Delta: `gs://osv-vulnerabilities/<ECOSYSTEM>/modified_id.csv`<br>API: `https://api.osv.dev/v1/query` | OpenSSF OSV Schema JSON | None | Bulk: GCS CDN cacheable<br>API: unmetered fair-use | CC-BY 4.0 | **Unreachable** (HTTP 403 via sandbox proxy) |
| **GitHub Advisory (GHSA)** | API: `https://api.github.com/advisories`<br>Git Mirror: `https://github.com/github/advisory-database` | JSON (GHSA & OSV schemas) | Optional `GITHUB_TOKEN` (`Bearer` token) | 60 req/hr (unauth)<br>5,000 req/hr (auth) | CC-BY 4.0 | **Reachable** (HTTP 200 OK) |

---

## Detailed Source Specifications

### 1. NVD (National Vulnerability Database) - CVE API 2.0
* **Official Documentation:** https://nvd.nist.gov/developers/vulnerabilities
* **Endpoints:**
  * Base API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
  * Incremental parameters:
    * `lastModStartDate`: Extended ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS.000Z`)
    * `lastModEndDate`: Extended ISO-8601 UTC timestamp (Required if `lastModStartDate` is specified)
    * `resultsPerPage`: Default 2,000 (maximum per request)
    * `startIndex`: Zero-based pagination offset
  * Constraint: The maximum date window between `lastModStartDate` and `lastModEndDate` is **120 consecutive days**.
* **Payload Format:** JSON. Root key `vulnerabilities` containing objects with `cve.id`, `cve.descriptions`, `cve.metrics.cvssMetricV31` / `cvssMetricV30` / `cvssMetricV2`, `cve.configurations`, `cve.references`.
* **Rate Limits:**
  * Anonymous: 5 requests within any rolling 30-second window (recommending a 6-second sleep between requests).
  * With API Key: 50 requests within any rolling 30-second window (~1.5 requests per second). Passed via header `apiKey: <YOUR_NVD_KEY>`.
* **Licensing & Terms:** U.S. Government work, public domain (NIST). Free for commercial and non-commercial use.
* **Environment Reachability:** Blocked by sandbox egress proxy (HTTP 403 Forbidden). Handled via offline mock fixtures in test suites and configured retry/backoff in production.

---

### 2. CISA Known Exploited Vulnerabilities (KEV) Catalogue
* **Official Documentation:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
* **Endpoints:**
  * Live Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
* **Payload Format:** JSON.
  * Header metadata: `catalogVersion`, `dateReleased`, `count`.
  * `vulnerabilities` array:
    * `cveID`: Standard CVE identifier (e.g. `CVE-2023-4863`)
    * `vendorProject`: Vendor or open-source project name
    * `product`: Affected product or system name
    * `vulnerabilityName`: Descriptive vulnerability title
    * `dateAdded`: Date added to the KEV catalog (`YYYY-MM-DD`)
    * `shortDescription`: Description of the vulnerability and exploitation context
    * `requiredAction`: Mandatory remediation action
    * `dueDate`: Federal remediation deadline
    * `knownRansomwareCampaignUse`: `"Known"` or `"Unknown"`
    * `notes`: Additional references or notes
* **Rate Limits & Caching:** Hosted on public CDN infrastructure with full support for `ETag` and `If-Modified-Since` conditional GET requests.
* **Authentication:** None required.
* **Licensing & Terms:** U.S. Government work, public domain.
* **Environment Reachability:** Blocked by sandbox egress proxy (HTTP 403 Forbidden).

---

### 3. FIRST EPSS (Exploit Prediction Scoring System)
* **Official Documentation:** https://www.first.org/epss/data_stats
* **Endpoints:**
  * Daily Bulk Scores: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (also accessible historically via `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz`)
  * REST API: `https://api.first.org/data/v1/epss` (supports parameters `cve`, `date`, `days`, `epss-gt`, `percentile-gt`)
* **Payload Format:**
  * Bulk: Gzipped CSV (`.csv.gz`). Header comment lines (`#model_version:...`, `#score_date:...`) followed by header: `cve,epss,percentile`.
  * REST API: JSON with `status`, `status-code`, `total`, `data` array containing `cve`, `epss` (float probability 0-1), `percentile` (float 0-1), `date`.
* **Rate Limits:**
  * Bulk download file: Unmetered static CDN.
  * REST API: Soft IP-based rate limiting (approximately 10 req/s); clients receiving HTTP 429 must back off.
* **Authentication:** None required.
* **Licensing & Terms:** Free for commercial and non-commercial use with attribution to FIRST.org.
* **Environment Reachability:** Blocked by sandbox egress proxy (HTTP 403 Forbidden).

---

### 4. OSV.dev (Open Source Vulnerabilities)
* **Official Documentation:** https://ossf.github.io/osv-schema/ and https://google.github.io/osv.dev/
* **Endpoints:**
  * Ecosystem Bulk Archives: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`
    * Supported Ecosystems: `PyPI`, `npm`, `Go`, `crates.io`, `Maven`, `NuGet`, `RubyGems`, `Packagist`, etc.
  * Global Bulk Archive: `https://storage.googleapis.com/osv-vulnerabilities/all.zip`
  * Incremental Delta Tracker: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/modified_id.csv` (CSV with `timestamp,id`)
  * REST API: `https://api.osv.dev/v1/query` and `https://api.osv.dev/v1/vulns/{id}`
* **Payload Format:** JSON adhering to OpenSSF OSV Schema (version 1.6.0). Contains `id` (e.g. `GHSA-...`, `PYSEC-...`, `GO-...`), `published`, `modified`, `aliases` (list of matching CVEs), `summary`, `details`, `affected` array containing `package.name`, `package.ecosystem`, `ranges` (`type`: `SEMVER` or `ECOSYSTEM`, `events`: `introduced`, `fixed`), and `versions` list.
* **Rate Limits & Caching:** Bulk archives support standard HTTP `ETag` and `Last-Modified` headers. API endpoints are unmetered within fair-use standards.
* **Authentication:** None required.
* **Licensing & Terms:** Creative Commons Attribution 4.0 International (CC-BY 4.0).
* **Environment Reachability:** Blocked by sandbox egress proxy (HTTP 403 Forbidden).

---

### 5. GitHub Advisory Database (GHSA)
* **Official Documentation:** https://docs.github.com/en/rest/security-advisories/global-advisories
* **Endpoints:**
  * REST API: `https://api.github.com/advisories`
  * Specific Advisory: `https://api.github.com/advisories/{ghsa_id}`
  * Query Parameters: `type=reviewed`, `ecosystem`, `severity`, `affects`, `per_page=100`, `page`, `modified`
  * Git Mirror: `https://github.com/github/advisory-database`
* **Payload Format:** JSON adhering to the GitHub Global Security Advisory schema and OSV format. Includes `ghsa_id`, `cve_id`, `url`, `summary`, `description`, `severity`, `cvss.score`, `cvss.vector_string`, `vulnerabilities` (affected package, vulnerable_version_range, patched_versions).
* **Rate Limits:**
  * Unauthenticated: 60 requests per hour per IP.
  * Authenticated: 5,000 requests per hour via standard GitHub Personal Access Token (`Authorization: Bearer <token>`).
* **Authentication:** Optional `GITHUB_TOKEN`.
* **Licensing & Terms:** Creative Commons Attribution 4.0 International (CC-BY 4.0).
* **Environment Reachability:** **Reachable** (HTTP 200 OK verified in sandbox).

---

## Environment Reachability Summary

During live verification from the current containerized environment:
* **Reachable:** GitHub Security Advisories (`api.github.com`) - HTTP 200 OK.
* **Blocked by Egress Proxy:** NVD (`services.nvd.nist.gov`), CISA (`cisa.gov`), FIRST EPSS (`api.first.org` / `epss.empiricalsecurity.com`), and Google Cloud Storage OSV (`storage.googleapis.com`) returned HTTP 403 Forbidden due to network sandbox restrictions.

Consequently, all unit and integration tests are engineered to run completely offline using deterministic test fixtures, and network calls are strictly restricted to explicit invocation of `kelan update` or `kelan scan --online`.

