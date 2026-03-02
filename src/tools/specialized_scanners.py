"""
Specialized Scanners — GraphQL / JWT / API 专项安全扫描

HexStrike 中的 graphql_scanner + jwt_analyzer + api_schema_analyzer 功能
"""

import re
import json
import base64
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


# ============================================================================
# GraphQL Scanner
# ============================================================================

class GraphQLScanner:
    """GraphQL 端点安全扫描器"""

    INTROSPECTION_QUERY = '{"query":"{__schema{types{name fields{name type{name}}}}}"'

    def scan(self, endpoint: str, query_depth: int = 10, test_batch: bool = True) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "endpoint": endpoint,
            "tests_performed": [],
            "vulnerabilities": [],
            "recommendations": [],
        }
        headers = {"Content-Type": "application/json"}

        # 1. Introspection
        try:
            r = requests.post(endpoint, data=self.INTROSPECTION_QUERY, headers=headers, timeout=15)
            results["tests_performed"].append("introspection")
            if "data" in r.text:
                results["vulnerabilities"].append({
                    "type": "introspection_enabled",
                    "severity": "MEDIUM",
                    "description": "GraphQL introspection 已开启",
                })
        except Exception:
            pass

        # 2. Query depth
        try:
            deep = "{ " * query_depth + "x" + " }" * query_depth
            r = requests.post(endpoint, json={"query": deep}, headers=headers, timeout=15)
            results["tests_performed"].append("query_depth")
            if "error" not in r.text.lower():
                results["vulnerabilities"].append({
                    "type": "no_depth_limit",
                    "severity": "HIGH",
                    "description": f"无查询深度限制 (测试深度 {query_depth})",
                })
        except Exception:
            pass

        # 3. Batch queries
        if test_batch:
            try:
                batch = json.dumps([{"query": "{__typename}"} for _ in range(10)])
                r = requests.post(endpoint, data=batch, headers=headers, timeout=15)
                results["tests_performed"].append("batch_query")
                if r.status_code == 200 and "data" in r.text:
                    results["vulnerabilities"].append({
                        "type": "batch_queries_allowed",
                        "severity": "MEDIUM",
                        "description": "批量查询未受限制",
                    })
            except Exception:
                pass

        if results["vulnerabilities"]:
            results["recommendations"] = [
                "生产环境禁用 introspection",
                "实施查询深度限制",
                "对批量查询设置速率限制",
                "启用查询复杂度分析",
            ]
        return results


# ============================================================================
# JWT Analyzer
# ============================================================================

class JWTAnalyzer:
    """JWT Token 安全分析器"""

    def analyze(self, token: str, target_url: str = "") -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "token": token[:50] + "..." if len(token) > 50 else token,
            "vulnerabilities": [],
            "token_info": {},
            "attack_vectors": [],
        }

        parts = token.split(".")
        if len(parts) < 2:
            results["vulnerabilities"].append({"type": "invalid_format", "severity": "HIGH", "description": "无效 JWT 格式"})
            return results

        try:
            header = json.loads(self._b64decode(parts[0]))
            payload = json.loads(self._b64decode(parts[1]))
            results["token_info"] = {"header": header, "payload": payload, "algorithm": header.get("alg", "unknown")}
        except Exception as e:
            results["vulnerabilities"].append({"type": "malformed", "severity": "HIGH", "description": f"解码失败: {e}"})
            return results

        alg = header.get("alg", "").lower()

        if alg == "none":
            results["vulnerabilities"].append({
                "type": "none_algorithm",
                "severity": "CRITICAL",
                "description": "使用 'none' 算法 — 无签名验证",
            })

        if alg in ("hs256", "hs384", "hs512"):
            results["vulnerabilities"].append({
                "type": "hmac_algorithm",
                "severity": "MEDIUM",
                "description": "HMAC 算法可受密钥混淆攻击",
            })
            results["attack_vectors"].append("hmac_key_confusion")

        if "exp" not in payload:
            results["vulnerabilities"].append({
                "type": "no_expiration",
                "severity": "HIGH",
                "description": "Token 无过期时间",
            })

        # None-algorithm attack test
        if target_url:
            try:
                none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
                none_token = f"{none_header}.{parts[1]}."
                r = requests.get(target_url, headers={"Authorization": f"Bearer {none_token}"}, timeout=10)
                if r.status_code == 200:
                    results["vulnerabilities"].append({
                        "type": "none_algorithm_accepted",
                        "severity": "CRITICAL",
                        "description": "服务端接受 none 算法 Token",
                    })
            except Exception:
                pass

        return results

    @staticmethod
    def _b64decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)


# ============================================================================
# API Schema Analyzer
# ============================================================================

class APISchemaAnalyzer:
    """OpenAPI / Swagger Schema 安全分析"""

    def analyze(self, schema_url: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "schema_url": schema_url,
            "endpoints_found": [],
            "security_issues": [],
            "recommendations": [],
        }
        try:
            r = requests.get(schema_url, timeout=15)
            schema = r.json()
        except Exception as e:
            results["security_issues"].append({"issue": "fetch_failed", "severity": "HIGH", "description": str(e)})
            return results

        for path, methods in schema.get("paths", {}).items():
            for method, detail in methods.items():
                if not isinstance(detail, dict):
                    continue
                ep = {"path": path, "method": method.upper(), "security": detail.get("security", [])}
                results["endpoints_found"].append(ep)

                if not ep["security"]:
                    results["security_issues"].append({
                        "endpoint": f"{method.upper()} {path}",
                        "issue": "no_auth",
                        "severity": "MEDIUM",
                        "description": "端点无认证要求",
                    })

                for param in detail.get("parameters", []):
                    pn = param.get("name", "").lower()
                    if any(s in pn for s in ("password", "token", "key", "secret")):
                        results["security_issues"].append({
                            "endpoint": f"{method.upper()} {path}",
                            "issue": "sensitive_param",
                            "severity": "HIGH",
                            "description": f"敏感参数: {pn}",
                        })

        if results["security_issues"]:
            results["recommendations"] = [
                "为所有端点启用认证",
                "全面使用 HTTPS",
                "验证并净化所有输入参数",
                "实施速率限制",
            ]
        return results


graphql_scanner = GraphQLScanner()
jwt_analyzer = JWTAnalyzer()
api_schema_analyzer = APISchemaAnalyzer()
