"""
Threat Intelligence Aggregator — 多源威胁情报聚合

聚合 CVE 分析、IP 信誉、文件哈希情报，输出综合威胁评分与建议
"""

import logging
from typing import Dict, List, Any

from .cve_intelligence import cve_intelligence

logger = logging.getLogger(__name__)


class ThreatIntelligenceAggregator:
    """聚合多类型安全指标并输出统一威胁评分"""

    def correlate(
        self,
        indicators: List[str],
        timeframe: str = "30d",
    ) -> Dict[str, Any]:
        correlations: List[Dict[str, Any]] = []
        threat_score = 0.0

        cve_ids = [i for i in indicators if i.upper().startswith("CVE-")]
        ip_addrs = [i for i in indicators if self._is_ip(i)]
        hashes = [i for i in indicators if len(i) in (32, 40, 64) and all(c in "0123456789abcdef" for c in i.lower())]

        for cve_id in cve_ids:
            analysis = cve_intelligence.analyze_exploitability(cve_id)
            if analysis.get("success"):
                correlations.append({"indicator": cve_id, "type": "cve", "analysis": analysis})
                threat_score += min(analysis.get("exploitability_score", 0) * 100, 100)

            exploits = cve_intelligence.search_existing_exploits(cve_id)
            if exploits.get("exploits_found", 0) > 0:
                correlations.append({
                    "indicator": cve_id,
                    "type": "exploit_availability",
                    "exploits_found": exploits["exploits_found"],
                })
                threat_score += 25

        for ip in ip_addrs:
            correlations.append({
                "indicator": ip,
                "type": "ip_reputation",
                "analysis": {"reputation": "unknown", "note": "Passive lookup not yet integrated"},
            })

        for h in hashes:
            hash_type = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "UNKNOWN")
            correlations.append({
                "indicator": h,
                "type": "file_hash",
                "hash_type": hash_type,
                "analysis": {"malware_family": "unknown"},
            })

        total = len(indicators) or 1
        normalized = min(threat_score / total, 100)
        recommendations = self._make_recommendations(normalized)

        return {
            "success": True,
            "indicators_analyzed": indicators,
            "correlations": correlations,
            "threat_score": round(normalized, 1),
            "recommendations": recommendations,
        }

    @staticmethod
    def _is_ip(s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    @staticmethod
    def _make_recommendations(score: float) -> List[str]:
        if score >= 75:
            return [
                "立即响应：阻断已识别 IOC",
                "紧急修补已知 CVE",
                "增强监控相关资产",
            ]
        if score >= 50:
            return [
                "加强监控已识别指标",
                "制定修补计划",
                "审查安全控制措施",
            ]
        return [
            "保持常规监控",
            "定期修补更新",
            "考虑引入更多威胁情报源",
        ]


threat_intelligence = ThreatIntelligenceAggregator()
