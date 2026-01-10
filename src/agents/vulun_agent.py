"""
VulunAgent - 漏洞检测和安全测试智能代理

基于 OmniNoval AI 架构设计，集成多种安全工具和漏洞检测能力
支持自动化渗透测试、漏洞扫描、安全评估等功能
"""

import logging
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from uuid import uuid4

from langgraph.prebuilt import create_react_agent
from src.llms.llm import get_llm_by_type
from src.prompts import apply_prompt_template
from src.tools.security_tools import security_tools
from src.tools.advanced_security_tools import OmniNoval_tools
from src.engine.decision_engine import decision_engine, TargetProfile, TargetType
from src.engine.parameter_optimizer import parameter_optimizer


logger = logging.getLogger(__name__)


class VulnSeverity(Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(Enum):
    """漏洞类别枚举"""
    WEB_APP = "web_application"
    NETWORK = "network"
    SYSTEM = "system"
    CLOUD = "cloud"
    MOBILE = "mobile"
    BINARY = "binary"
    OSINT = "osint"


@dataclass
class VulnerabilityReport:
    """漏洞报告数据结构"""
    id: str
    title: str
    description: str
    severity: VulnSeverity
    category: VulnCategory
    cvss_score: float
    cve_id: Optional[str] = None
    affected_component: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    discovered_at: Optional[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class ScanResult:
    """扫描结果数据结构"""
    target: str
    scan_type: str
    status: str
    vulnerabilities: List[VulnerabilityReport]
    scan_duration: float
    tools_used: List[str]
    raw_output: Dict[str, Any]
    timestamp: str


class VulunAgent:
    """
    漏洞检测智能代理
    HIGH_RISK_PORTS = {21, 22, 23, 25, 445, 3389, 5900, 5985, 5986, 3306, 5432, 6379}
    SEVERITY_SCORE = {
        VulnSeverity.CRITICAL: 10.0,
        VulnSeverity.HIGH: 7.5,
        VulnSeverity.MEDIUM: 5.0,
        VulnSeverity.LOW: 2.5,
        VulnSeverity.INFO: 0.0,
    }

    集成多种安全工具，提供自动化漏洞检测和安全评估能力
    支持 Web 应用、网络、系统等多种目标的安全测试
    """
    
    def __init__(self, llm_type: str = "reasoning"):
        """
        初始化 VulunAgent
        
        Args:
            llm_type: 使用的 LLM 类型
        """
        self.llm = get_llm_by_type(llm_type)
        self.scan_history: List[ScanResult] = []
        self.vulnerability_db: List[VulnerabilityReport] = []
        self.security_tools = security_tools
        self.advanced_tools = OmniNoval_tools
        self.tool_manager = security_tools.tool_manager
        self.config = self.tool_manager.config or {}
        self.scan_strategies = self.tool_manager.scan_strategies
        self.security_policies = self.tool_manager.security_policies
        self.reporting_config = self.tool_manager.reporting_config
        self._authorized_targets_cache: Optional[List[str]] = None
        
        # 集成决策引擎和优化器
        self.decision_engine = decision_engine
        self.parameter_optimizer = parameter_optimizer
        
        logger.info("VulunAgent 初始化完成，集成了智能决策引擎和参数优化器")

    def _get_strategy(self, strategy: str) -> Dict[str, Any]:
        return self.scan_strategies.get(
            strategy, self.scan_strategies.get("standard", {})
        )

    def _load_authorized_targets(self) -> List[str]:
        if self._authorized_targets_cache is not None:
            return self._authorized_targets_cache

        auth_file = self.security_policies.get("authorization_file")
        if auth_file:
            auth_path = Path(auth_file)
            if auth_path.exists():
                with open(auth_path, "r", encoding="utf-8") as f:
                    self._authorized_targets_cache = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.strip().startswith("#")
                    ]
            else:
                self._authorized_targets_cache = []
        else:
            self._authorized_targets_cache = []

        return self._authorized_targets_cache

    @staticmethod
    def _match_pattern(target: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            return target.endswith(pattern[1:])
        return target == pattern

    def _validate_target(self, target: str):
        blocked_targets = self.security_policies.get("blocked_targets", [])
        for pattern in blocked_targets:
            if self._match_pattern(target, pattern):
                raise PermissionError(f"目标 {target} 在禁止扫描列表中")

        require_auth = self.security_policies.get("require_authorization", False)
        if require_auth:
            authorized_targets = self._load_authorized_targets()
            if authorized_targets and target not in authorized_targets:
                raise PermissionError(
                    f"目标 {target} 未在授权列表中，拒绝执行扫描"
                )

    def _normalize_severity(self, severity: Optional[str]) -> VulnSeverity:
        if not severity:
            return VulnSeverity.INFO
        normalized = severity.lower()
        mapping = {
            "critical": VulnSeverity.CRITICAL,
            "high": VulnSeverity.HIGH,
            "medium": VulnSeverity.MEDIUM,
            "low": VulnSeverity.LOW,
            "info": VulnSeverity.INFO,
        }
        return mapping.get(normalized, VulnSeverity.INFO)

    def _severity_score(self, severity: VulnSeverity) -> float:
        return self.SEVERITY_SCORE.get(severity, 0.0)

    def _get_tool_setting(
        self, tool_name: str, key: str, default: Optional[Any] = None
    ) -> Any:
        return self.tool_manager.tools_config.get(tool_name, {}).get(key, default)
    
    def create_agent(self, tools: list):
        """创建 VulunAgent 实例"""
        return create_react_agent(
            self.llm,
            tools=tools,
            prompt=lambda state: apply_prompt_template("vulun_agent", state),
        )
    
    async def scan_target(
        self,
        target: str,
        scan_types: Optional[List[str]] = None,
        strategy: str = "standard",
    ) -> ScanResult:
        """
        使用智能决策引擎对目标进行安全扫描
        """
        self._validate_target(target)
        
        # 使用决策引擎分析目标
        profile = self.decision_engine.analyze_target(target)
        
        # 如果未指定 scan_types，使用决策引擎自动选择
        if scan_types is None:
            selected_tools = self.decision_engine.select_optimal_tools(profile, objective=strategy)
            # 根据工具推断扫描类型
            scan_types = []
            if any(t in selected_tools for t in ["nmap", "masscan", "rustscan"]):
                scan_types.append("port_scan")
            if any(t in selected_tools for t in ["gobuster", "dirsearch", "ffuf", "nikto"]):
                scan_types.append("web_scan")
            if "nuclei" in selected_tools:
                scan_types.append("vuln_scan")
            if any(t in selected_tools for t in ["subfinder", "amass"]):
                scan_types.append("subdomain_enum")
        
        strategy_config = self._get_strategy(strategy)
        
        logger.info(
            "🧠 智能扫描开始: %s, 目标类型: %s, 扫描类型: %s, 策略: %s",
            target,
            profile.target_type.value,
            scan_types,
            strategy,
        )
        
        vulnerabilities: List[VulnerabilityReport] = []
        tools_used: List[str] = []
        raw_output: Dict[str, Any] = {}
        
        start_time = time.perf_counter()
        
        try:
            # 端口扫描
            if "port_scan" in scan_types:
                port_results = await self._port_scan(
                    target,
                    profile=profile,
                    port_range=strategy_config.get("port_range"),
                )
                vulnerabilities.extend(port_results.get("vulnerabilities", []))
                tools_used.extend(port_results.get("tools", []))
                raw_output["port_scan"] = port_results
            
            # Web 应用扫描
            if "web_scan" in scan_types:
                web_results = await self._web_scan(target, profile=profile)
                vulnerabilities.extend(web_results.get("vulnerabilities", []))
                tools_used.extend(web_results.get("tools", []))
                raw_output["web_scan"] = web_results
            
            # 漏洞扫描
            if "vuln_scan" in scan_types:
                vuln_results = await self._vulnerability_scan(
                    target,
                    profile=profile,
                    severity=strategy_config.get("nuclei_severity"),
                )
                vulnerabilities.extend(vuln_results.get("vulnerabilities", []))
                tools_used.extend(vuln_results.get("tools", []))
                raw_output["vuln_scan"] = vuln_results
            
            # 子域名枚举
            if "subdomain_enum" in scan_types:
                subdomain_results = await self._subdomain_enumeration(target, profile=profile)
                vulnerabilities.extend(subdomain_results.get("vulnerabilities", []))
                tools_used.extend(subdomain_results.get("tools", []))
                raw_output["subdomain_enum"] = subdomain_results
            
            scan_duration = time.perf_counter() - start_time
            
            result = ScanResult(
                target=target,
                scan_type=",".join(scan_types),
                status="completed",
                vulnerabilities=vulnerabilities,
                scan_duration=scan_duration,
                tools_used=list(set(tools_used)),
                raw_output=raw_output,
                timestamp=datetime.utcnow().isoformat()
            )
            
            self.scan_history.append(result)
            logger.info(f"扫描完成，发现 {len(vulnerabilities)} 个漏洞")
            
            return result
            
        except Exception as e:
            logger.error(f"扫描过程中发生错误: {str(e)}")
            return ScanResult(
                target=target,
                scan_type=",".join(scan_types),
                status="failed",
                vulnerabilities=[],
                scan_duration=time.perf_counter() - start_time,
                tools_used=tools_used,
                raw_output={"error": str(e)},
                timestamp=datetime.utcnow().isoformat()
            )
    
    async def _port_scan(
        self,
        target: str,
        profile: Any,
        port_range: Optional[str] = None,
        scan_type: str = "syn",
    ) -> Dict[str, Any]:
        """端口扫描 (集成了参数优化)"""
        logger.info(f"执行端口扫描: {target}")
        
        # 使用参数优化器
        context = {"ports": port_range or "1-1000", "scan_type": scan_type}
        optimized_args = self.parameter_optimizer.optimize_parameters("nmap", profile, context)
        
        # 移除已在 optimized_args 中处理的 target，避免重复
        args = [arg for arg in optimized_args if arg != target] + [target]
        
        try:
            # 内部调用，绕过 Scanner 类直接用 tool_manager 运行，
            # 这样可以利用优化后的参数
            result = await self.security_tools.tool_manager.run_tool("nmap", args)
            
            # 简单的解析，实际可根据需要增强
            open_ports = self.security_tools.nmap._parse_nmap_output(result.output) if result.success else []
        except Exception as exc:
            logger.error("端口扫描失败: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "tools": ["nmap"],
                "vulnerabilities": [],
                "open_ports": [],
            }
        
        open_ports = result.get("open_ports", [])
        vulnerabilities = []
        for port in open_ports:
            port_num = port.get("port")
            severity = (
                VulnSeverity.HIGH
                if port_num in self.HIGH_RISK_PORTS
                else VulnSeverity.INFO
            )
            vulnerabilities.append(
                VulnerabilityReport(
                    id=f"PORT_{port_num}",
                    title=f"开放端口 {port_num}",
                    description=(
                        f"在目标 {target} 发现开放端口 {port_num}/{port.get('protocol')} "
                        f"服务: {port.get('service', 'unknown')}"
                    ),
                    severity=severity,
                    category=VulnCategory.NETWORK,
                    cvss_score=self._severity_score(severity),
                    affected_component="Network Services",
                )
            )
        
        return {
            "success": result.get("success", False),
            "error": result.get("error"),
            "vulnerabilities": vulnerabilities,
            "tools": ["nmap"],
            "open_ports": open_ports,
        }
    
    async def _web_scan(self, target: str, profile: Any) -> Dict[str, Any]:
        """Web 应用扫描 (集成了参数优化)"""
        logger.info(f"执行 Web 应用扫描: {target}")
        
        if not target.startswith(("http://", "https://")):
            return {
                "success": False,
                "error": "目标不是 Web 应用，跳过目录扫描",
                "tools": [],
                "vulnerabilities": [],
                "directories_found": [],
            }
        
        extensions = self._get_tool_setting(
            "gobuster", "default_extensions", ["php", "html", "js", "txt"]
        )
        
        # 使用参数优化器
        context = {"extensions": extensions}
        optimized_args = self.parameter_optimizer.optimize_parameters("gobuster", profile, context)
        args = [arg for arg in optimized_args if arg not in ["-u", target]] + ["-u", target]
        
        try:
            result = await self.security_tools.tool_manager.run_tool("gobuster", args)
            
            # 解析结果
            found_paths = []
            if result.success:
                for line in result.output.split('\n'):
                    if line.startswith('/'):
                        parts = line.split()
                        if len(parts) >= 2:
                            found_paths.append({
                                "path": parts[0],
                                "status_code": parts[1].strip('()'),
                                "size": parts[2] if len(parts) > 2 else "unknown"
                            })
        except Exception as exc:
            logger.error("Web 扫描失败: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "tools": ["gobuster"],
                "vulnerabilities": [],
                "directories_found": [],
            }
        
        sensitive_keywords = ["/admin", "/backup", "/config", "/database", "/.env"]
        vulnerabilities = []
        for path in result.get("found_paths", []):
            severity = (
                VulnSeverity.MEDIUM
                if any(keyword in path["path"].lower() for keyword in sensitive_keywords)
                else VulnSeverity.LOW
            )
            vulnerabilities.append(
                VulnerabilityReport(
                    id=f"WEB_{uuid4().hex[:8]}",
                    title=f"发现目录 {path['path']}",
                    description=(
                        f"目标 {target} 暴露目录 {path['path']} "
                        f"(状态码: {path.get('status_code')})"
                    ),
                    severity=severity,
                    category=VulnCategory.WEB_APP,
                    cvss_score=self._severity_score(severity),
                    affected_component="Web Application",
                )
            )
        
        return {
            "success": result.get("success", False),
            "error": result.get("error"),
            "vulnerabilities": vulnerabilities,
            "tools": ["gobuster"],
            "directories_found": result.get("found_paths", []),
        }
    
    async def _vulnerability_scan(
        self,
        target: str,
        profile: Any,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """漏洞扫描 (集成了参数优化)"""
        logger.info(f"执行漏洞扫描: {target}")
        
        # 使用参数优化器
        context = {"templates": templates, "severity": severity}
        optimized_args = self.parameter_optimizer.optimize_parameters("nuclei", profile, context)
        args = [arg for arg in optimized_args if arg not in ["-u", target]] + ["-u", target, "-json"]
        
        try:
            result = await self.security_tools.tool_manager.run_tool("nuclei", args)
            
            # 解析结果
            vulnerabilities_data = []
            if result.success and result.output:
                for line in result.output.strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities_data.append(vuln_data)
                        except json.JSONDecodeError:
                            continue
            result_dict = {
                "success": result.success,
                "vulnerabilities": vulnerabilities_data,
                "raw_output": result.output,
                "error": result.error
            }
        except Exception as exc:
            logger.error("漏洞扫描失败: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "tools": ["nuclei"],
                "vulnerabilities": [],
                "templates_used": templates or [],
            }
        
        vulnerabilities = []
        for vuln in result_dict.get("vulnerabilities", []):
            info = vuln.get("info", {})
            severity_enum = self._normalize_severity(info.get("severity"))
            references = info.get("reference") or info.get("references") or []
            if isinstance(references, str):
                references = [references]
            cvss = info.get("cvss")
            if isinstance(cvss, dict):
                cvss_score = cvss.get("score", self._severity_score(severity_enum))
            else:
                cvss_score = (
                    float(cvss) if isinstance(cvss, (int, float)) else self._severity_score(severity_enum)
                )
            vulnerabilities.append(
                VulnerabilityReport(
                    id=vuln.get("template-id", f"VULN_{uuid4().hex[:8]}"),
                    title=info.get("name", "未知漏洞"),
                    description=info.get("description", "未提供描述"),
                    severity=severity_enum,
                    category=VulnCategory.WEB_APP,
                    cvss_score=cvss_score,
                    cve_id=info.get("cve"),
                    affected_component=info.get("tags"),
                    proof_of_concept=vuln.get("matched-at"),
                    remediation=info.get("remediation"),
                    references=references,
                )
            )
        
        return {
            "success": result.get("success", False),
            "error": result.get("error"),
            "vulnerabilities": vulnerabilities,
            "tools": ["nuclei"],
            "templates_used": templates or [],
        }
    
    async def _subdomain_enumeration(self, target: str, profile: Any) -> Dict[str, Any]:
        """子域名枚举 (集成了参数优化)"""
        logger.info(f"执行子域名枚举: {target}")
        
        try:
            # 简单封装，目前 subfinder 优化较少
            result = await self.security_tools.subfinder.subdomain_scan(target)
        except Exception as exc:
            logger.error("子域名枚举失败: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "tools": ["subfinder"],
                "subdomains_found": [],
                "vulnerabilities": [],
            }
        
        subdomains = result.get("subdomains", [])
        vulnerabilities = []
        if subdomains:
            preview = ", ".join(subdomains[:5])
            if len(subdomains) > 5:
                preview += " 等"
            vulnerabilities.append(
                VulnerabilityReport(
                    id="SUBDOMAIN_ENUM",
                    title="子域名暴露",
                    description=f"发现 {len(subdomains)} 个子域名: {preview}",
                    severity=VulnSeverity.INFO,
                    category=VulnCategory.OSINT,
                    cvss_score=0.0,
                    references=subdomains,
                )
            )
        
        return {
            "success": result.get("success", False),
            "error": result.get("error"),
            "vulnerabilities": vulnerabilities,
            "tools": ["subfinder"],
            "subdomains_found": subdomains,
        }
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """
        生成漏洞扫描报告
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            str: 格式化的报告
        """
        report = f"""
# 漏洞扫描报告

## 基本信息
- **目标**: {scan_result.target}
- **扫描类型**: {scan_result.scan_type}
- **扫描状态**: {scan_result.status}
- **扫描时长**: {scan_result.scan_duration:.2f} 秒
- **使用工具**: {', '.join(scan_result.tools_used)}
- **扫描时间**: {scan_result.timestamp}

## 漏洞统计
- **总计**: {len(scan_result.vulnerabilities)} 个漏洞
"""
        
        # 按严重程度统计
        severity_count = {}
        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity.value
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        for severity, count in severity_count.items():
            report += f"- **{severity.upper()}**: {count} 个\n"
        
        report += "\n## 漏洞详情\n"
        
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            report += f"""
### {i}. {vuln.title}
- **ID**: {vuln.id}
- **严重程度**: {vuln.severity.value.upper()}
- **CVSS 评分**: {vuln.cvss_score}
- **类别**: {vuln.category.value}
- **描述**: {vuln.description}
"""
            if vuln.cve_id:
                report += f"- **CVE ID**: {vuln.cve_id}\n"
            if vuln.affected_component:
                report += f"- **影响组件**: {vuln.affected_component}\n"
            if vuln.proof_of_concept:
                report += f"- **概念验证**: {vuln.proof_of_concept}\n"
            if vuln.remediation:
                report += f"- **修复建议**: {vuln.remediation}\n"
        
        return report
    
    def get_scan_history(self) -> List[ScanResult]:
        """获取扫描历史"""
        return self.scan_history
    
    def get_vulnerability_stats(self) -> Dict[str, Any]:
        """获取漏洞统计信息"""
        total_vulns = sum(len(scan.vulnerabilities) for scan in self.scan_history)
        
        severity_stats = {}
        category_stats = {}
        
        for scan in self.scan_history:
            for vuln in scan.vulnerabilities:
                # 严重程度统计
                severity = vuln.severity.value
                severity_stats[severity] = severity_stats.get(severity, 0) + 1
                
                # 类别统计
                category = vuln.category.value
                category_stats[category] = category_stats.get(category, 0) + 1
        
        return {
            "total_scans": len(self.scan_history),
            "total_vulnerabilities": total_vulns,
            "severity_distribution": severity_stats,
            "category_distribution": category_stats
        }


# 创建全局 VulunAgent 实例
vulun_agent_service = VulunAgent()
