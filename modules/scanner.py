from __future__ import annotations
from __future__ import annotations
"""
VendorScanner — core engine for scraping and regex matching vendor threat intel.
"""

import re
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Regex Pattern Library ────────────────────────────────────────────────────

BREACH_PATTERNS = {
    "data_breach": re.compile(
        r"\b(data breach|databreach|security breach|information breach)\b",
        re.IGNORECASE,
    ),
    "ransomware": re.compile(
        r"\b(ransomware|ransom(ware)? attack|encrypted files|ransom demand|ransom note)\b",
        re.IGNORECASE,
    ),
    "credential_leak": re.compile(
        r"\b(credential(s)? (leak|dump|exposed|stolen)|password(s)? (leaked|stolen|exposed|compromised)|"
        r"login(s)? (exposed|leaked)|account takeover)\b",
        re.IGNORECASE,
    ),
    "unauthorized_access": re.compile(
        r"\b(unauthorized access|intrusion|threat actor(s)?|attacker(s)? gained access|"
        r"hacker(s)? (accessed|broke into|infiltrated)|compromised (system|network|server))\b",
        re.IGNORECASE,
    ),
    "data_exposure": re.compile(
        r"\b(data (exposed|leaked|left exposed|misconfigured)|exposed database|"
        r"unsecured (bucket|server|database|S3)|publicly accessible)\b",
        re.IGNORECASE,
    ),
    "supply_chain": re.compile(
        r"\b(supply chain (attack|compromise|breach)|third.party (breach|compromise|attack)|"
        r"software supply chain)\b",
        re.IGNORECASE,
    ),
    "vulnerability_exploit": re.compile(
        r"\b(critical vulnerability|zero.day|CVE-\d{4}-\d+|actively exploited|"
        r"RCE|remote code execution|SQL injection|authentication bypass)\b",
        re.IGNORECASE,
    ),
    "pii_exposure": re.compile(
        r"\b(PII|personally identifiable information|SSN|social security|"
        r"medical record(s)?|health data|financial (data|record(s)?|information) (exposed|leaked|stolen))\b",
        re.IGNORECASE,
    ),
    "ddos": re.compile(
        r"\b(DDoS|distributed denial.of.service|service disruption|outage caused by attack)\b",
        re.IGNORECASE,
    ),
    "insider_threat": re.compile(
        r"\b(insider threat|rogue employee|malicious insider|employee (stole|exfiltrated|leaked))\b",
        re.IGNORECASE,
    ),
    "regulatory_action": re.compile(
        r"\b(FTC|GDPR|HIPAA|PCI DSS|regulatory (fine|penalty|action|enforcement)|"
        r"data protection violation|consent order)\b",
        re.IGNORECASE,
    ),
    "threat_actor": re.compile(
        r"\b(APT\d+|Lazarus Group|REvil|LockBit|BlackCat|ALPHV|Cl0p|Scattered Spider|"
        r"nation.state|state.sponsored|threat group)\b",
        re.IGNORECASE,
    ),
}

SEVERITY_WEIGHTS = {
    "ransomware": 5,
    "supply_chain": 5,
    "unauthorized_access": 4,
    "data_breach": 4,
    "credential_leak": 4,
    "pii_exposure": 4,
    "vulnerability_exploit": 3,
    "data_exposure": 3,
    "threat_actor": 3,
    "ddos": 2,
    "regulatory_action": 2,
    "insider_threat": 2,
}


# ─── Sources Configuration ────────────────────────────────────────────────────

SOURCES = [
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/search/?q={query}",
        "type": "search",
        "category": "News",
        "article_selector": "article.bc_news_item, div.article_section",
        "title_selector": "h4 a, h2 a",
        "link_selector": "h4 a, h2 a",
        "snippet_selector": "p",
    },
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com/search?q={query}",
        "type": "search",
        "category": "News",
        "article_selector": "div.body-post",
        "title_selector": "h2.home-title a, h2 a",
        "link_selector": "h2.home-title a, h2 a",
        "snippet_selector": "div.home-desc p, p.home-desc",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/search#q={query}&t=All",
        "type": "search",
        "category": "News",
        "article_selector": "div.listing__item, article",
        "title_selector": "h3 a, h2 a",
        "link_selector": "h3 a, h2 a",
        "snippet_selector": "p.listing__description, p",
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/?s={query}",
        "type": "search",
        "category": "News",
        "article_selector": "article",
        "title_selector": "h2 a, h3 a",
        "link_selector": "h2 a, h3 a",
        "snippet_selector": "div.excerpt p, p",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/?s={query}",
        "type": "search",
        "category": "Blog",
        "article_selector": "article, div.post",
        "title_selector": "h2 a, h1 a",
        "link_selector": "h2 a, h1 a",
        "snippet_selector": "div.entry-content p, p",
    },
    {
        "name": "HaveIBeenPwned (API)",
        "url": "https://haveibeenpwned.com/api/v3/breaches",
        "type": "api",
        "category": "Breach DB",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json_feed",
        "category": "Government",
    },
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ─── Scanner Class ────────────────────────────────────────────────────────────

class VendorScanner:
    def __init__(self, timeout: int = 15, max_workers: int = 5):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def get_sources(self):
        return [{"name": s["name"], "category": s["category"], "url": s["url"]} for s in SOURCES]

    def scan(self, vendor: str) -> dict:
        start_time = time.time()
        findings = []
        source_statuses = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for source in SOURCES:
                if source["type"] == "search":
                    future = executor.submit(self._scrape_search_source, vendor, source)
                elif source["type"] == "api":
                    future = executor.submit(self._query_hibp, vendor)
                elif source["type"] == "json_feed":
                    future = executor.submit(self._query_cisa_kev, vendor)
                else:
                    continue
                futures[future] = source["name"]

            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    result = future.result(timeout=self.timeout + 5)
                    findings.extend(result.get("findings", []))
                    source_statuses.append({
                        "name": source_name,
                        "status": "ok",
                        "count": result.get("count", 0),
                    })
                except Exception as e:
                    logger.warning(f"Source {source_name} failed: {e}")
                    source_statuses.append({
                        "name": source_name,
                        "status": "error",
                        "error": str(e)[:100],
                        "count": 0,
                    })

        # Deduplicate by URL
        seen_urls = set()
        unique_findings = []
        for f in findings:
            url = f.get("url", "")
            if url not in seen_urls:
                seen_urls.add(url)
                unique_findings.append(f)

        # Sort by severity score descending
        unique_findings.sort(key=lambda x: x.get("severity_score", 0), reverse=True)

        elapsed = round(time.time() - start_time, 2)

        return {
            "vendor": vendor,
            "scan_time": elapsed,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(unique_findings),
            "risk_summary": self._compute_risk_summary(unique_findings),
            "findings": unique_findings,
            "source_statuses": source_statuses,
        }

    # ── Scrape generic search-result pages ──────────────────────────────────

    def _scrape_search_source(self, vendor: str, source: dict) -> dict:
        url = source["url"].format(query=requests.utils.quote(vendor))
        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"[{source['name']}] Request failed: {e}")
            return {"findings": [], "count": 0}

        soup = BeautifulSoup(resp.text, "html.parser")
        articles = soup.select(source["article_selector"])

        findings = []
        for article in articles[:15]:  # cap per source
            title_el = article.select_one(source["title_selector"])
            link_el = article.select_one(source["link_selector"])
            snippet_el = article.select_one(source["snippet_selector"])

            title = title_el.get_text(strip=True) if title_el else ""
            href = link_el.get("href", "") if link_el else ""
            snippet = snippet_el.get_text(strip=True)[:500] if snippet_el else ""

            if not title:
                continue

            # Normalize href
            if href and not href.startswith("http"):
                base = re.match(r"https?://[^/]+", url)
                href = (base.group(0) if base else "") + href

            combined_text = f"{title} {snippet}"

            # Only include if vendor name appears
            if not re.search(re.escape(vendor), combined_text, re.IGNORECASE):
                continue

            matched = self._apply_patterns(combined_text)
            if not matched:
                continue

            severity_score = self._score(matched)
            findings.append({
                "source": source["name"],
                "category": source["category"],
                "title": title,
                "url": href,
                "snippet": snippet,
                "matched_patterns": matched,
                "severity_score": severity_score,
                "severity_label": self._label(severity_score),
            })

        return {"findings": findings, "count": len(findings)}

    # ── Have I Been Pwned ────────────────────────────────────────────────────

    def _query_hibp(self, vendor: str) -> dict:
        try:
            resp = self.session.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                timeout=self.timeout,
                headers={**HEADERS, "hibp-api-key": ""},  # public endpoint, no key needed for breach list
            )
            resp.raise_for_status()
            breaches = resp.json()
        except Exception as e:
            logger.warning(f"[HIBP] Failed: {e}")
            return {"findings": [], "count": 0}

        findings = []
        vendor_lower = vendor.lower()
        for breach in breaches:
            name = breach.get("Name", "")
            title = breach.get("Title", "")
            domain = breach.get("Domain", "")
            description = breach.get("Description", "")
            date = breach.get("BreachDate", "")
            pwn_count = breach.get("PwnCount", 0)
            data_classes = breach.get("DataClasses", [])

            # Match vendor against name, title, domain
            if not any(
                re.search(re.escape(vendor_lower), field.lower())
                for field in [name, title, domain, description]
            ):
                continue

            matched = self._apply_patterns(description)
            # Always include HIBP results that match the vendor
            matched.append("data_breach")
            matched = list(set(matched))

            score = self._score(matched)
            findings.append({
                "source": "HaveIBeenPwned",
                "category": "Breach DB",
                "title": f"HIBP Breach: {title}",
                "url": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                "snippet": (
                    f"Breach date: {date} | Records exposed: {pwn_count:,} | "
                    f"Data types: {', '.join(data_classes[:5])}"
                ),
                "matched_patterns": matched,
                "severity_score": score + 3,  # HIBP hits get a bump
                "severity_label": self._label(score + 3),
            })

        return {"findings": findings, "count": len(findings)}

    # ── CISA KEV Feed ────────────────────────────────────────────────────────

    def _query_cisa_kev(self, vendor: str) -> dict:
        try:
            resp = self.session.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning(f"[CISA KEV] Failed: {e}")
            return {"findings": [], "count": 0}

        findings = []
        vendor_lower = vendor.lower()
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            vendor_project = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            cve_id = vuln.get("cveID", "")
            description = vuln.get("shortDescription", "")
            date_added = vuln.get("dateAdded", "")
            due_date = vuln.get("dueDate", "")

            if not any(
                re.search(re.escape(vendor_lower), field.lower())
                for field in [vendor_project, product, description]
            ):
                continue

            matched = ["vulnerability_exploit"]
            if re.search(r"remote code execution|RCE", description, re.IGNORECASE):
                matched.append("unauthorized_access")

            score = self._score(matched)
            findings.append({
                "source": "CISA KEV",
                "category": "Government",
                "title": f"{cve_id} — {vendor_project} {product}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "snippet": (
                    f"Added: {date_added} | Remediation due: {due_date} | {description}"
                ),
                "matched_patterns": matched,
                "severity_score": score + 2,
                "severity_label": self._label(score + 2),
            })

        return {"findings": findings, "count": len(findings)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _apply_patterns(self, text: str) -> list[str]:
        """Return list of pattern keys that match the given text."""
        return [key for key, pattern in BREACH_PATTERNS.items() if pattern.search(text)]

    def _score(self, matched_patterns: list[str]) -> int:
        """Compute a severity score from matched pattern keys."""
        return sum(SEVERITY_WEIGHTS.get(p, 1) for p in matched_patterns)

    def _label(self, score: int) -> str:
        if score >= 10:
            return "CRITICAL"
        elif score >= 6:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def _compute_risk_summary(self, findings: list[dict]) -> dict:
        if not findings:
            return {
                "overall_risk": "NONE",
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "top_patterns": [],
            }

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        all_patterns = []
        for f in findings:
            label = f.get("severity_label", "LOW")
            counts[label] = counts.get(label, 0) + 1
            all_patterns.extend(f.get("matched_patterns", []))

        # Top patterns by frequency
        from collections import Counter
        top_patterns = [p for p, _ in Counter(all_patterns).most_common(5)]

        # Overall risk = highest severity present
        overall = "LOW"
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[level] > 0:
                overall = level
                break

        return {
            "overall_risk": overall,
            "total_findings": len(findings),
            **counts,
            "top_patterns": top_patterns,
        }