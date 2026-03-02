"""
CVE Intelligence & Threat Analysis Module

Real-time CVE monitoring via NVD API v2.0, exploitability analysis,
and exploit search across GitHub / Exploit-DB / Metasploit.
"""

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

import requests

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
_GITHUB_CODE_API = "https://api.github.com/search/code"
_NVD_RATE_LIMIT_DELAY = 6  # seconds between unauthenticated NVD requests


class CVEIntelligenceManager:
    """Real-time CVE intelligence powered by NVD, GitHub, and Exploit-DB references."""

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OmniNoval-CVEIntel/1.0"})
        if nvd_api_key:
            self.session.headers["apiKey"] = nvd_api_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_latest_cves(
        self,
        hours: int = 24,
        severity_filter: str = "HIGH,CRITICAL",
        keywords: str = "",
    ) -> Dict[str, Any]:
        """Fetch recent CVEs from NVD API v2.0."""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(hours=hours)

            params = {
                "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 100,
            }

            severity_levels = [s.strip().upper() for s in severity_filter.split(",")]
            resp = self.session.get(_NVD_API_BASE, params=params, timeout=30)

            if resp.status_code != 200:
                logger.warning("NVD API returned %s", resp.status_code)
                return {"success": False, "error": f"HTTP {resp.status_code}", "cves": []}

            cves: List[Dict[str, Any]] = []
            for item in resp.json().get("vulnerabilities", []):
                entry = self._parse_cve_item(item)
                if entry and entry["severity"] in severity_levels:
                    cves.append(entry)

            if keywords:
                kw_list = [k.strip().lower() for k in keywords.split(",")]
                cves = [c for c in cves if any(k in c["description"].lower() for k in kw_list)]

            return {
                "success": True,
                "cves": cves,
                "total_found": len(cves),
                "hours_searched": hours,
                "severity_filter": severity_filter,
            }
        except Exception as exc:
            logger.error("fetch_latest_cves failed: %s", exc)
            return {"success": False, "error": str(exc), "cves": []}

    def analyze_exploitability(self, cve_id: str) -> Dict[str, Any]:
        """Deep exploitability analysis for a single CVE."""
        try:
            resp = self.session.get(_NVD_API_BASE, params={"cveId": cve_id}, timeout=30)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}", "cve_id": cve_id}

            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                return {"success": False, "error": "CVE not found", "cve_id": cve_id}

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            cvss, severity, av, ac, pr, ui, exploit_sub = self._extract_cvss(metrics)

            score = self._calc_exploitability_score(av, ac, pr, ui, exploit_sub)
            description = self._english_description(cve_data)
            exploit_kw = self._find_exploit_keywords(description)
            has_public = self._has_public_exploits(cve_data.get("references", []))

            level = "HIGH" if score >= 0.8 else "MEDIUM" if score >= 0.5 else "LOW"
            priority = "IMMEDIATE" if score > 0.8 and severity == "CRITICAL" else (
                "HIGH" if score > 0.6 else "MEDIUM" if score > 0.4 else "LOW"
            )

            return {
                "success": True,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": severity,
                "exploitability_score": round(score, 2),
                "exploitability_level": level,
                "attack_vector": av,
                "attack_complexity": ac,
                "privileges_required": pr,
                "user_interaction": ui,
                "public_exploits": has_public,
                "exploit_indicators": exploit_kw,
                "recommended_priority": priority,
                "description": description[:500],
                "published": cve_data.get("published", ""),
            }
        except Exception as exc:
            logger.error("analyze_exploitability failed for %s: %s", cve_id, exc)
            return {"success": False, "error": str(exc), "cve_id": cve_id}

    def search_exploits(self, cve_id: str) -> Dict[str, Any]:
        """Search GitHub, Exploit-DB references, and Metasploit for public exploits."""
        exploits: List[Dict[str, Any]] = []
        sources_searched = []

        # 1) GitHub repos
        try:
            gh_params = {"q": f"{cve_id} exploit poc", "sort": "updated", "per_page": 10}
            gh_resp = self.session.get(_GITHUB_SEARCH_API, params=gh_params, timeout=15)
            if gh_resp.status_code == 200:
                for repo in gh_resp.json().get("items", [])[:5]:
                    name_desc = (repo.get("name", "") + repo.get("description", "")).lower()
                    if cve_id.lower() in name_desc:
                        exploits.append({
                            "source": "github",
                            "title": repo["name"],
                            "url": repo["html_url"],
                            "stars": repo.get("stargazers_count", 0),
                            "reliability": "GOOD" if repo.get("stargazers_count", 0) >= 20 else "FAIR",
                        })
            sources_searched.append("github")
        except Exception as exc:
            logger.warning("GitHub search error: %s", exc)

        # 2) NVD references pointing to exploit-db / packetstorm / metasploit
        try:
            time.sleep(1)
            nvd_resp = self.session.get(_NVD_API_BASE, params={"cveId": cve_id}, timeout=20)
            if nvd_resp.status_code == 200:
                for item in nvd_resp.json().get("vulnerabilities", []):
                    for ref in item.get("cve", {}).get("references", []):
                        url = ref.get("url", "").lower()
                        for domain, src_name in [
                            ("exploit-db.com", "exploit-db"),
                            ("packetstormsecurity.com", "packetstorm"),
                            ("rapid7.com", "rapid7"),
                        ]:
                            if domain in url:
                                exploits.append({
                                    "source": src_name,
                                    "title": f"Reference for {cve_id}",
                                    "url": ref["url"],
                                    "reliability": "GOOD",
                                })
                                if src_name not in sources_searched:
                                    sources_searched.append(src_name)
        except Exception as exc:
            logger.warning("NVD reference search error: %s", exc)

        # 3) Metasploit code search
        try:
            time.sleep(1)
            msf_params = {"q": f"{cve_id} filename:*.rb repo:rapid7/metasploit-framework", "per_page": 5}
            msf_resp = self.session.get(_GITHUB_CODE_API, params=msf_params, timeout=15)
            if msf_resp.status_code == 200:
                for code_item in msf_resp.json().get("items", []):
                    path = code_item.get("path", "")
                    if "exploits/" in path or "auxiliary/" in path:
                        exploits.append({
                            "source": "metasploit",
                            "title": f"MSF: {code_item.get('name', '')}",
                            "url": code_item.get("html_url", ""),
                            "reliability": "EXCELLENT",
                        })
                if "metasploit" not in sources_searched:
                    sources_searched.append("metasploit")
        except Exception as exc:
            logger.warning("Metasploit search error: %s", exc)

        exploits.sort(key=lambda e: {"EXCELLENT": 3, "GOOD": 2, "FAIR": 1}.get(e.get("reliability", ""), 0), reverse=True)

        return {
            "success": True,
            "cve_id": cve_id,
            "exploits_found": len(exploits),
            "exploits": exploits,
            "sources_searched": sources_searched,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_cve_item(self, item: Dict) -> Optional[Dict[str, Any]]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        cvss, severity, *_ = self._extract_cvss(metrics)
        if not severity or severity == "UNKNOWN":
            return None
        description = self._english_description(cve)
        return {
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": cvss,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }

    @staticmethod
    def _extract_cvss(metrics: Dict):
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                d = entries[0].get("cvssData", {})
                return (
                    d.get("baseScore", 0.0),
                    d.get("baseSeverity", "UNKNOWN").upper(),
                    d.get("attackVector", "UNKNOWN"),
                    d.get("attackComplexity", "UNKNOWN"),
                    d.get("privilegesRequired", "UNKNOWN"),
                    d.get("userInteraction", "UNKNOWN"),
                    d.get("exploitabilityScore", 0.0),
                )
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            score = v2[0].get("cvssData", {}).get("baseScore", 0.0)
            sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            return score, sev, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", 0.0
        return 0.0, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", 0.0

    @staticmethod
    def _calc_exploitability_score(av, ac, pr, ui, sub) -> float:
        if sub > 0:
            return min(sub / 3.9, 1.0)
        s = 0.0
        s += {"NETWORK": 0.4, "ADJACENT_NETWORK": 0.3, "LOCAL": 0.2, "PHYSICAL": 0.1}.get(av, 0.0)
        s += 0.3 if ac == "LOW" else 0.1
        s += {"NONE": 0.2, "LOW": 0.1}.get(pr, 0.0)
        s += 0.1 if ui == "NONE" else 0.0
        return min(s, 1.0)

    @staticmethod
    def _english_description(cve: Dict) -> str:
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                return d.get("value", "")
        return ""

    @staticmethod
    def _find_exploit_keywords(desc: str) -> List[str]:
        keywords = [
            "remote code execution", "rce", "buffer overflow", "sql injection",
            "command injection", "authentication bypass", "privilege escalation",
            "deserialization", "xxe", "ssrf", "xss", "directory traversal",
        ]
        dl = desc.lower()
        return [k for k in keywords if k in dl]

    @staticmethod
    def _has_public_exploits(refs: List[Dict]) -> bool:
        sources = ["exploit-db.com", "github.com", "packetstormsecurity.com"]
        return any(any(s in r.get("url", "").lower() for s in sources) for r in refs)


# Singleton
cve_intelligence = CVEIntelligenceManager()
