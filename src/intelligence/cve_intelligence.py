"""
CVE Intelligence Module — 实时漏洞情报系统

功能:
- 对接 NVD API v2.0 拉取最新 CVE
- 分析 CVE 可利用性 (CVSS 向量解析)
- 搜索已公开的 Exploit (GitHub / Exploit-DB / Metasploit)
"""

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

import requests

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
GITHUB_CODE_API = "https://api.github.com/search/code"


class CVEIntelligenceManager:
    """实时 CVE 情报与可利用性分析引擎"""

    def __init__(self, request_timeout: int = 30):
        self.timeout = request_timeout
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------
    # 1. 拉取最新 CVE
    # ------------------------------------------------------------------
    def fetch_latest_cves(
        self, hours: int = 24, severity_filter: str = "HIGH,CRITICAL"
    ) -> Dict[str, Any]:
        try:
            end = datetime.utcnow()
            start = end - timedelta(hours=hours)
            params = {
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 100,
            }
            resp = self._session.get(NVD_API_BASE, params=params, timeout=self.timeout)
            if resp.status_code != 200:
                return {"success": False, "error": f"NVD HTTP {resp.status_code}", "cves": []}

            severity_levels = {s.strip().upper() for s in severity_filter.split(",")}
            cves = []
            for item in resp.json().get("vulnerabilities", []):
                cve = self._parse_cve_item(item)
                if cve and (cve["severity"] in severity_levels or "ALL" in severity_levels):
                    cves.append(cve)

            return {
                "success": True,
                "cves": cves,
                "total_found": len(cves),
                "hours_searched": hours,
                "severity_filter": severity_filter,
            }
        except Exception as exc:
            logger.error("fetch_latest_cves error: %s", exc)
            return {"success": False, "error": str(exc), "cves": []}

    # ------------------------------------------------------------------
    # 2. 可利用性分析
    # ------------------------------------------------------------------
    def analyze_exploitability(self, cve_id: str) -> Dict[str, Any]:
        try:
            resp = self._session.get(NVD_API_BASE, params={"cveId": cve_id}, timeout=self.timeout)
            if resp.status_code != 200:
                return {"success": False, "error": f"NVD HTTP {resp.status_code}", "cve_id": cve_id}

            items = resp.json().get("vulnerabilities", [])
            if not items:
                return {"success": False, "error": "CVE not found", "cve_id": cve_id}

            cve_data = items[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            cvss, severity, av, ac, pr, ui, exploit_sub = self._extract_cvss(metrics)

            exploit_score = self._calc_exploit_score(av, ac, pr, ui, exploit_sub)
            description = self._english_description(cve_data)
            exploit_keywords = self._find_exploit_keywords(description)
            if any(k in description.lower() for k in ["remote code execution", "rce", "buffer overflow"]):
                exploit_score = min(exploit_score + 0.2, 1.0)

            refs = cve_data.get("references", [])
            public_exploits = any(
                s in r.get("url", "").lower()
                for r in refs
                for s in ["exploit-db.com", "github.com", "packetstormsecurity.com"]
            )

            level = "HIGH" if exploit_score >= 0.8 else "MEDIUM" if exploit_score >= 0.5 else "LOW"

            return {
                "success": True,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": severity,
                "exploitability_score": round(exploit_score, 2),
                "exploitability_level": level,
                "attack_vector": av,
                "attack_complexity": ac,
                "privileges_required": pr,
                "user_interaction": ui,
                "public_exploits_found": public_exploits,
                "exploit_indicators": exploit_keywords,
                "description": description[:500],
                "recommended_priority": "IMMEDIATE" if exploit_score > 0.8 and severity == "CRITICAL" else level,
            }
        except Exception as exc:
            logger.error("analyze_exploitability error: %s", exc)
            return {"success": False, "error": str(exc), "cve_id": cve_id}

    # ------------------------------------------------------------------
    # 3. 搜索已有 Exploit
    # ------------------------------------------------------------------
    def search_existing_exploits(self, cve_id: str) -> Dict[str, Any]:
        exploits: List[Dict[str, Any]] = []
        sources_searched: List[str] = []

        # GitHub repos
        try:
            r = self._session.get(
                GITHUB_SEARCH_API,
                params={"q": f"{cve_id} exploit poc", "sort": "updated", "per_page": 10},
                timeout=15,
            )
            if r.status_code == 200:
                for repo in r.json().get("items", [])[:5]:
                    if cve_id.lower() in (repo.get("name", "") + repo.get("description", "")).lower():
                        exploits.append({
                            "source": "github",
                            "title": repo["name"],
                            "url": repo["html_url"],
                            "stars": repo.get("stargazers_count", 0),
                            "reliability": "GOOD" if repo.get("stargazers_count", 0) >= 20 else "FAIR",
                        })
            sources_searched.append("github")
        except Exception:
            pass

        # NVD references (exploit-db / packetstorm / metasploit)
        try:
            time.sleep(1)
            r = self._session.get(NVD_API_BASE, params={"cveId": cve_id}, timeout=self.timeout)
            if r.status_code == 200:
                items = r.json().get("vulnerabilities", [])
                if items:
                    for ref in items[0].get("cve", {}).get("references", []):
                        url = ref.get("url", "")
                        for domain, name in [("exploit-db.com", "exploit-db"), ("packetstormsecurity.com", "packetstorm")]:
                            if domain in url.lower():
                                exploits.append({"source": name, "url": url, "reliability": "GOOD"})
                                if name not in sources_searched:
                                    sources_searched.append(name)
        except Exception:
            pass

        # Metasploit modules on GitHub
        try:
            time.sleep(1)
            r = self._session.get(
                GITHUB_CODE_API,
                params={"q": f"{cve_id} filename:*.rb repo:rapid7/metasploit-framework", "per_page": 5},
                timeout=15,
            )
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    if "exploits/" in item.get("path", ""):
                        exploits.append({
                            "source": "metasploit",
                            "title": item["name"],
                            "url": item.get("html_url", ""),
                            "reliability": "EXCELLENT",
                        })
                sources_searched.append("metasploit")
        except Exception:
            pass

        return {
            "success": True,
            "cve_id": cve_id,
            "exploits_found": len(exploits),
            "exploits": exploits,
            "sources_searched": sources_searched,
        }

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _parse_cve_item(self, item: Dict) -> Optional[Dict[str, Any]]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        cvss, severity, *_ = self._extract_cvss(cve.get("metrics", {}))
        desc = self._english_description(cve)
        return {
            "cve_id": cve_id,
            "description": desc[:300],
            "severity": severity,
            "cvss_score": cvss,
            "published_date": cve.get("published", ""),
            "source": "NVD",
        }

    @staticmethod
    def _extract_cvss(metrics: Dict):
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                d = metrics[key][0]["cvssData"]
                return (
                    d.get("baseScore", 0.0),
                    d.get("baseSeverity", "UNKNOWN").upper(),
                    d.get("attackVector", "UNKNOWN"),
                    d.get("attackComplexity", "UNKNOWN"),
                    d.get("privilegesRequired", "UNKNOWN"),
                    d.get("userInteraction", "UNKNOWN"),
                    d.get("exploitabilityScore", 0.0),
                )
        return 0.0, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", 0.0

    @staticmethod
    def _calc_exploit_score(av, ac, pr, ui, sub):
        if sub > 0:
            return min(sub / 3.9, 1.0)
        s = 0.0
        s += {"NETWORK": 0.4, "ADJACENT_NETWORK": 0.3, "LOCAL": 0.2, "PHYSICAL": 0.1}.get(av, 0)
        s += {"LOW": 0.3, "HIGH": 0.1}.get(ac, 0)
        s += {"NONE": 0.2, "LOW": 0.1}.get(pr, 0)
        s += 0.1 if ui == "NONE" else 0
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
        return [k for k in keywords if k in desc.lower()]


cve_intelligence = CVEIntelligenceManager()
