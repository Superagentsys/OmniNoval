"""
Bug Bounty Workflow Manager — 赏金猎人专用工作流引擎

提供:
- 多阶段侦察工作流 (子域名→HTTP探测→内容发现→参数发现)
- 漏洞猎杀工作流 (按 RCE>SQLi>SSRF>IDOR>XSS 优先级排列)
- 业务逻辑测试工作流
- OSINT 情报收集工作流
- 文件上传漏洞测试框架
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class BugBountyTarget:
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"


class BugBountyWorkflowManager:
    """赏金猎人多阶段工作流编排器"""

    HIGH_IMPACT_VULNS = {
        "rce": {"priority": 10, "tools": ["nuclei", "jaeles", "sqlmap"]},
        "sqli": {"priority": 9, "tools": ["sqlmap", "nuclei"]},
        "ssrf": {"priority": 8, "tools": ["nuclei", "ffuf"]},
        "idor": {"priority": 8, "tools": ["arjun", "paramspider", "ffuf"]},
        "xss": {"priority": 7, "tools": ["dalfox", "nuclei"]},
        "lfi": {"priority": 7, "tools": ["ffuf", "nuclei"]},
        "xxe": {"priority": 6, "tools": ["nuclei"]},
        "csrf": {"priority": 5, "tools": ["nuclei"]},
    }

    def create_reconnaissance_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        return {
            "target": target.domain,
            "phases": [
                {
                    "name": "subdomain_discovery",
                    "description": "全面子域名枚举",
                    "tools": [
                        {"tool": "amass", "params": {"domain": target.domain, "mode": "enum"}},
                        {"tool": "subfinder", "params": {"domain": target.domain, "silent": True}},
                    ],
                    "estimated_time": 300,
                },
                {
                    "name": "http_service_discovery",
                    "description": "存活 HTTP 服务探测",
                    "tools": [
                        {"tool": "httpx", "params": {"probe": True, "tech_detect": True}},
                        {"tool": "nuclei", "params": {"tags": "tech", "severity": "info"}},
                    ],
                    "estimated_time": 180,
                },
                {
                    "name": "content_discovery",
                    "description": "隐藏内容与端点发现",
                    "tools": [
                        {"tool": "katana", "params": {"depth": 3, "js_crawl": True}},
                        {"tool": "gau", "params": {"include_subs": True}},
                        {"tool": "waybackurls", "params": {}},
                        {"tool": "dirsearch", "params": {"extensions": "php,html,js,txt,json"}},
                    ],
                    "estimated_time": 600,
                },
                {
                    "name": "parameter_discovery",
                    "description": "隐藏参数挖掘",
                    "tools": [
                        {"tool": "paramspider", "params": {"level": 2}},
                        {"tool": "arjun", "params": {"method": "GET,POST", "stable": True}},
                        {"tool": "x8", "params": {"method": "GET"}},
                    ],
                    "estimated_time": 240,
                },
            ],
            "estimated_time": 1320,
            "tools_count": 10,
        }

    def create_vulnerability_hunting_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        sorted_vulns = sorted(
            target.priority_vulns,
            key=lambda v: self.HIGH_IMPACT_VULNS.get(v, {}).get("priority", 0),
            reverse=True,
        )
        tests = []
        total_time = 0
        for vt in sorted_vulns:
            cfg = self.HIGH_IMPACT_VULNS.get(vt)
            if not cfg:
                continue
            est = cfg["priority"] * 30
            tests.append({
                "vulnerability_type": vt,
                "priority": cfg["priority"],
                "tools": cfg["tools"],
                "estimated_time": est,
            })
            total_time += est
        return {
            "target": target.domain,
            "vulnerability_tests": tests,
            "estimated_time": total_time,
        }

    def create_business_logic_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        return {
            "target": target.domain,
            "categories": [
                {
                    "name": "Authentication Bypass",
                    "tests": ["Password Reset Token Reuse", "JWT Algorithm Confusion", "Session Fixation", "OAuth Flow Manipulation"],
                },
                {
                    "name": "Authorization Flaws",
                    "tests": ["Horizontal Privilege Escalation", "Vertical Privilege Escalation", "RBAC Bypass"],
                },
                {
                    "name": "Business Process Manipulation",
                    "tests": ["Race Conditions", "Price Manipulation", "Quantity Limits Bypass", "Workflow State Manipulation"],
                },
                {
                    "name": "Input Validation Bypass",
                    "tests": ["File Upload Restrictions", "Content-Type Bypass", "Size Limit Bypass"],
                },
            ],
            "estimated_time": 480,
            "manual_testing_required": True,
        }

    def create_osint_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        return {
            "target": target.domain,
            "phases": [
                {"name": "Domain Intelligence", "tools": ["whois", "dnsrecon", "certificate_transparency"]},
                {"name": "Social Media Intelligence", "tools": ["sherlock", "social_mapper"]},
                {"name": "Email Intelligence", "tools": ["hunter_io", "haveibeenpwned"]},
                {"name": "Technology Intelligence", "tools": ["builtwith", "wappalyzer", "shodan"]},
            ],
            "estimated_time": 240,
        }

    def create_file_upload_testing(self, target_url: str) -> Dict[str, Any]:
        return {
            "target": target_url,
            "test_phases": [
                {"name": "reconnaissance", "tools": ["katana", "gau", "paramspider"]},
                {"name": "baseline_testing", "files": ["image.jpg", "document.pdf", "text.txt"]},
                {
                    "name": "malicious_upload",
                    "bypass_techniques": [
                        "double_extension", "null_byte", "content_type_spoofing",
                        "magic_bytes", "case_variation", "special_characters",
                    ],
                    "test_files": {
                        "web_shells": ["simple_php_shell.php", "asp_shell.asp", "jsp_shell.jsp"],
                        "bypass_files": ["shell.php.txt", "shell.php%00.txt", "shell.PhP"],
                        "polyglot": ["polyglot.jpg (GIF89a + PHP)"],
                    },
                },
                {"name": "post_upload_verification", "actions": ["file_access_test", "execution_test", "path_traversal_test"]},
            ],
            "estimated_time": 360,
        }

    def create_comprehensive_assessment(self, target: BugBountyTarget) -> Dict[str, Any]:
        recon = self.create_reconnaissance_workflow(target)
        hunting = self.create_vulnerability_hunting_workflow(target)
        biz = self.create_business_logic_workflow(target)
        osint = self.create_osint_workflow(target)
        total = recon["estimated_time"] + hunting["estimated_time"] + biz["estimated_time"] + osint["estimated_time"]
        return {
            "target": target.domain,
            "reconnaissance": recon,
            "vulnerability_hunting": hunting,
            "business_logic": biz,
            "osint": osint,
            "summary": {"total_estimated_time": total},
        }


bugbounty_manager = BugBountyWorkflowManager()
