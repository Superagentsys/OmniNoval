"""
HTTP Testing Framework — Burp Suite 轻量替代

功能:
- 请求拦截与代理历史
- Match & Replace 规则
- Scope 作用域控制
- Repeater (自定义请求重放)
- Intruder (Sniper 模式参数 Fuzz)
- 被动漏洞检测 (安全头缺失、敏感信息泄露、SQL 报错)
- Spider (站点爬虫)
"""

import re
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin
from datetime import datetime

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class HTTPTestingFramework:
    """完整的 HTTP 安全测试框架"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "OmniNoval-HTTPFramework/1.0"
        self.proxy_history: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.match_replace_rules: List[Dict[str, str]] = []
        self.scope: Optional[Dict[str, Any]] = None
        self._req_id = 0

    # ---- Scope & Rules ----

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {"host": host, "include_subdomains": include_subdomains}

    def set_match_replace_rules(self, rules: List[Dict[str, str]]):
        self.match_replace_rules = rules or []

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        h = urlparse(url).hostname or ""
        target = self.scope["host"]
        if h == target:
            return True
        if self.scope.get("include_subdomains") and h.endswith(f".{target}"):
            return True
        return False

    def _apply_rules(self, url, data, headers):
        for rule in self.match_replace_rules:
            where = (rule.get("where") or "url").lower()
            pattern = rule.get("pattern", "")
            repl = rule.get("replacement", "")
            try:
                if where == "url":
                    url = re.sub(pattern, repl, url)
                elif where == "headers":
                    headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in headers.items()}
                elif where == "body" and isinstance(data, dict):
                    data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in data.items()}
            except Exception:
                continue
        return url, data, headers

    # ---- Core: Intercept Request ----

    def intercept_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        try:
            send_headers = dict(self.session.headers)
            if headers:
                send_headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            url, data, send_headers = self._apply_rules(url, data, send_headers)
            if not self._in_scope(url):
                return {"success": False, "error": "Out of scope"}

            response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            self._req_id += 1
            entry = {
                "id": self._req_id,
                "request": {"url": url, "method": method, "headers": dict(response.request.headers), "data": data},
                "response": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content": response.text[:10000],
                    "size": len(response.content),
                    "time": response.elapsed.total_seconds(),
                },
                "timestamp": datetime.now().isoformat(),
            }
            self.proxy_history.append(entry)
            self._passive_scan(url, response)

            return {"success": True, **entry}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ---- Repeater ----

    def send_custom_request(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        return self.intercept_request(
            spec.get("url", ""),
            spec.get("method", "GET"),
            spec.get("data"),
            spec.get("headers"),
            spec.get("cookies"),
        )

    # ---- Intruder (Sniper) ----

    def intruder_sniper(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        payloads: Optional[List[str]] = None,
        max_requests: int = 100,
    ) -> Dict[str, Any]:
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        baseline = self.intercept_request(url, method)
        base_status = baseline.get("response", {}).get("status_code")
        base_size = baseline.get("response", {}).get("size", 0)

        interesting = []
        tested = 0
        for p in params:
            for pay in payloads:
                if tested >= max_requests:
                    break
                pr = urlparse(url)
                q = dict(parse_qsl(pr.query, keep_blank_values=True))
                q[p] = pay
                fuzz_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                resp = self.intercept_request(fuzz_url, method)
                tested += 1
                if not resp.get("success"):
                    continue
                r = resp["response"]
                reflected = pay in (r.get("content") or "")
                changed = (r.get("status_code") != base_status) or abs(r.get("size", 0) - base_size) > 150
                if reflected or changed:
                    interesting.append({
                        "param": p, "payload": pay,
                        "status_code": r.get("status_code"), "size": r.get("size"),
                        "reflected": reflected,
                    })
        return {"success": True, "tested": tested, "interesting": interesting[:50]}

    # ---- Spider ----

    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> Dict[str, Any]:
        discovered = set()
        forms = []
        to_visit = [(base_url, 0)]
        visited = set()

        while to_visit and len(discovered) < max_pages:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                discovered.add(url)
                soup = BeautifulSoup(resp.text, "html.parser")

                for a in soup.find_all("a", href=True):
                    full = urljoin(url, a["href"])
                    if urlparse(full).netloc == urlparse(base_url).netloc and full not in visited:
                        to_visit.append((full, depth + 1))

                for form in soup.find_all("form"):
                    forms.append({
                        "url": url,
                        "action": urljoin(url, form.get("action", "")),
                        "method": (form.get("method") or "GET").upper(),
                        "inputs": [
                            {"name": i.get("name", ""), "type": i.get("type", "text")}
                            for i in form.find_all(["input", "textarea", "select"])
                        ],
                    })
            except Exception:
                continue

        return {
            "success": True,
            "discovered_urls": list(discovered),
            "forms": forms,
            "total_pages": len(discovered),
        }

    # ---- Passive Vulnerability Detection ----

    def _passive_scan(self, url: str, response: requests.Response):
        headers = response.headers
        missing = {
            "X-Frame-Options": "Clickjacking 防护缺失",
            "X-Content-Type-Options": "MIME 嗅探防护缺失",
            "Strict-Transport-Security": "HSTS 缺失",
            "Content-Security-Policy": "CSP 缺失",
        }
        for h, desc in missing.items():
            if h not in headers:
                self.vulnerabilities.append({"type": "missing_header", "severity": "medium", "description": desc, "url": url, "header": h})

        sensitive_patterns = [
            (r"password\s*[:=]\s*[\"']?(\S+)", "密码泄露"),
            (r"api[_-]?key\s*[:=]\s*[\"']?(\S+)", "API Key 泄露"),
        ]
        for pat, desc in sensitive_patterns:
            if re.search(pat, response.text, re.IGNORECASE):
                self.vulnerabilities.append({"type": "info_disclosure", "severity": "high", "description": desc, "url": url})

        sql_errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL query failed"]
        for err in sql_errors:
            if err.lower() in response.text.lower():
                self.vulnerabilities.append({"type": "sql_error", "severity": "high", "description": f"SQL 报错: {err}", "url": url})

    def get_proxy_history(self, limit: int = 100):
        return self.proxy_history[-limit:]

    def get_vulnerabilities(self, limit: int = 50):
        return self.vulnerabilities[-limit:]


http_framework = HTTPTestingFramework()
