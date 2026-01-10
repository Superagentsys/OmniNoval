"""
VulunAgent 工具接口

为 VulunAgent 提供标准化的工具接口，集成各种安全工具
"""

import json
import logging
from typing import Dict, List, Any, Optional
from langchain.tools import tool

from .security_tools import security_tools
from ..agents.vulun_agent import (
    vulun_agent_service,
    VulnerabilityReport,
    ScanResult,
)
def _serialize_vulnerability_report(vuln: VulnerabilityReport) -> Dict[str, Any]:
    return {
        "id": vuln.id,
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity.value,
        "category": vuln.category.value,
        "cvss_score": vuln.cvss_score,
        "cve_id": vuln.cve_id,
        "affected_component": vuln.affected_component,
        "proof_of_concept": vuln.proof_of_concept,
        "remediation": vuln.remediation,
        "references": vuln.references,
        "discovered_at": vuln.discovered_at,
    }


def _serialize_scan_result(result: ScanResult) -> Dict[str, Any]:
    return {
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "scan_duration": result.scan_duration,
        "tools_used": result.tools_used,
        "timestamp": result.timestamp,
        "vulnerabilities": [
            _serialize_vulnerability_report(v) for v in result.vulnerabilities
        ],
        "raw_output": result.raw_output,
    }


@tool
def run_vulun_agent_scan(
    target: str,
    scan_types: str = "port_scan,web_scan,vuln_scan,subdomain_enum",
    strategy: str = "standard",
) -> str:
    """
    使用 VulunAgent 运行一键式综合扫描
    
    Args:
        target: 扫描目标
        scan_types: 逗号分隔的扫描类型列表
        strategy: 使用的扫描策略（quick、standard、comprehensive）
        
    Returns:
        str: JSON 格式的扫描结果
    """
    try:
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        scan_type_list = [
            scan.strip() for scan in scan_types.split(",") if scan.strip()
        ]
        result = loop.run_until_complete(
            vulun_agent_service.scan_target(
                target, scan_types=scan_type_list, strategy=strategy
            )
        )
        return json.dumps(
            {
                "success": True,
                "data": _serialize_scan_result(result),
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        logger.error(f"运行 VulunAgent 扫描失败: {e}")
        return json.dumps(
            {
                "success": False,
                "error": str(e),
            },
            ensure_ascii=False,
        )

logger = logging.getLogger(__name__)


@tool
def scan_target_ports(target: str, ports: str = "1-1000", scan_type: str = "syn") -> str:
    """
    对目标进行端口扫描
    
    Args:
        target: 目标 IP 地址或域名
        ports: 端口范围，例如 "1-1000" 或 "80,443,8080"
        scan_type: 扫描类型，可选值: syn, tcp, udp
        
    Returns:
        str: JSON 格式的扫描结果
    """
    try:
        import asyncio
        
        # 如果没有事件循环，创建一个新的
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            security_tools.nmap.port_scan(target, ports, scan_type)
        )
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"端口扫描失败: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "open_ports": []
        }, ensure_ascii=False)


@tool
def scan_vulnerabilities(target: str, severity: str = "high,critical") -> str:
    """
    对目标进行漏洞扫描
    
    Args:
        target: 目标 URL 或 IP 地址
        severity: 漏洞严重程度过滤，可选值: info,low,medium,high,critical
        
    Returns:
        str: JSON 格式的漏洞扫描结果
    """
    try:
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        severity_list = [s.strip() for s in severity.split(",")]
        result = loop.run_until_complete(
            security_tools.nuclei.vulnerability_scan(target, severity=severity_list)
        )
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"漏洞扫描失败: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "vulnerabilities": []
        }, ensure_ascii=False)


@tool
def scan_directories(target: str, extensions: str = "php,html,js,txt") -> str:
    """
    对目标进行目录和文件扫描
    
    Args:
        target: 目标 URL
        extensions: 文件扩展名，用逗号分隔
        
    Returns:
        str: JSON 格式的目录扫描结果
    """
    try:
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        ext_list = [ext.strip() for ext in extensions.split(",")]
        result = loop.run_until_complete(
            security_tools.gobuster.directory_scan(target, extensions=ext_list)
        )
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"目录扫描失败: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "found_paths": []
        }, ensure_ascii=False)


@tool
def enumerate_subdomains(domain: str) -> str:
    """
    枚举目标域名的子域名
    
    Args:
        domain: 目标域名
        
    Returns:
        str: JSON 格式的子域名枚举结果
    """
    try:
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            security_tools.subfinder.subdomain_scan(domain)
        )
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"子域名枚举失败: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "subdomains": []
        }, ensure_ascii=False)


@tool
def comprehensive_security_scan(target: str, strategy: str = "standard") -> str:
    """
    对目标进行综合安全扫描
    
    Args:
        target: 目标 URL、IP 地址或域名
        strategy: 扫描策略（quick、standard、comprehensive）
        
    Returns:
        str: JSON 格式的综合扫描结果
    """
    try:
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(
            security_tools.comprehensive_scan(target, strategy=strategy)
        )
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"综合扫描失败: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "results": {}
        }, ensure_ascii=False)


@tool
def get_available_security_tools() -> str:
    """
    获取当前可用的安全工具列表
    
    Returns:
        str: JSON 格式的可用工具信息
    """
    try:
        available_tools = security_tools.get_available_tools()
        tools_info = {}
        
        for tool_name, is_available in available_tools.items():
            tool_info = security_tools.get_tool_info(tool_name)
            if tool_info:
                tools_info[tool_name] = tool_info
        
        return json.dumps({
            "available_tools": available_tools,
            "tools_info": tools_info
        }, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"获取工具信息失败: {e}")
        return json.dumps({
            "error": str(e),
            "available_tools": {},
            "tools_info": {}
        }, ensure_ascii=False)


@tool
def generate_vulnerability_report(scan_results: str) -> str:
    """
    基于扫描结果生成漏洞报告
    
    Args:
        scan_results: JSON 格式的扫描结果
        
    Returns:
        str: 格式化的漏洞报告
    """
    try:
        # 解析扫描结果
        results = json.loads(scan_results)
        
        report = "# 安全扫描报告\n\n"
        
        # 添加扫描概要
        if "port_scan" in results:
            port_results = results["port_scan"]
            if port_results.get("success", False):
                open_ports = port_results.get("open_ports", [])
                report += f"## 端口扫描结果\n"
                report += f"发现 {len(open_ports)} 个开放端口:\n"
                for port in open_ports:
                    report += f"- 端口 {port['port']}/{port['protocol']}: {port['service']}\n"
                report += "\n"
        
        # 添加漏洞信息
        if "vulnerability_scan" in results:
            vuln_results = results["vulnerability_scan"]
            if vuln_results.get("success", False):
                vulnerabilities = vuln_results.get("vulnerabilities", [])
                report += f"## 漏洞扫描结果\n"
                report += f"发现 {len(vulnerabilities)} 个漏洞:\n"
                for vuln in vulnerabilities:
                    report += f"- **{vuln.get('info', {}).get('name', 'Unknown')}**\n"
                    report += f"  - 严重程度: {vuln.get('info', {}).get('severity', 'Unknown')}\n"
                    report += f"  - 描述: {vuln.get('info', {}).get('description', 'No description')}\n"
                report += "\n"
        
        # 添加目录扫描结果
        if "directory_scan" in results:
            dir_results = results["directory_scan"]
            if dir_results.get("success", False):
                found_paths = dir_results.get("found_paths", [])
                report += f"## 目录扫描结果\n"
                report += f"发现 {len(found_paths)} 个路径:\n"
                for path in found_paths:
                    report += f"- {path['path']} (状态码: {path['status_code']})\n"
                report += "\n"
        
        # 添加子域名枚举结果
        if "subdomain_scan" in results:
            subdomain_results = results["subdomain_scan"]
            if subdomain_results.get("success", False):
                subdomains = subdomain_results.get("subdomains", [])
                report += f"## 子域名枚举结果\n"
                report += f"发现 {len(subdomains)} 个子域名:\n"
                for subdomain in subdomains:
                    report += f"- {subdomain}\n"
                report += "\n"
        
        # 添加安全建议
        report += "## 安全建议\n"
        report += "1. 关闭不必要的开放端口\n"
        report += "2. 及时修复发现的漏洞\n"
        report += "3. 限制敏感目录的访问权限\n"
        report += "4. 定期进行安全扫描和评估\n"
        
        return report
        
    except Exception as e:
        logger.error(f"生成报告失败: {e}")
        return f"生成报告时发生错误: {str(e)}"


@tool
def analyze_security_risk(target: str, scan_results: str) -> str:
    """
    分析目标的安全风险等级
    
    Args:
        target: 目标地址
        scan_results: JSON 格式的扫描结果
        
    Returns:
        str: 安全风险分析报告
    """
    try:
        results = json.loads(scan_results)
        
        risk_score = 0
        risk_factors = []
        
        # 分析端口风险
        if "port_scan" in results:
            port_results = results["port_scan"]
            if port_results.get("success", False):
                open_ports = port_results.get("open_ports", [])
                high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
                
                for port in open_ports:
                    if port["port"] in high_risk_ports:
                        risk_score += 10
                        risk_factors.append(f"开放高风险端口: {port['port']}")
                    else:
                        risk_score += 5
                        risk_factors.append(f"开放端口: {port['port']}")
        
        # 分析漏洞风险
        if "vulnerability_scan" in results:
            vuln_results = results["vulnerability_scan"]
            if vuln_results.get("success", False):
                vulnerabilities = vuln_results.get("vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    severity = vuln.get("info", {}).get("severity", "").lower()
                    if severity == "critical":
                        risk_score += 50
                        risk_factors.append(f"严重漏洞: {vuln.get('info', {}).get('name', 'Unknown')}")
                    elif severity == "high":
                        risk_score += 30
                        risk_factors.append(f"高危漏洞: {vuln.get('info', {}).get('name', 'Unknown')}")
                    elif severity == "medium":
                        risk_score += 15
                        risk_factors.append(f"中危漏洞: {vuln.get('info', {}).get('name', 'Unknown')}")
                    elif severity == "low":
                        risk_score += 5
                        risk_factors.append(f"低危漏洞: {vuln.get('info', {}).get('name', 'Unknown')}")
        
        # 分析目录暴露风险
        if "directory_scan" in results:
            dir_results = results["directory_scan"]
            if dir_results.get("success", False):
                found_paths = dir_results.get("found_paths", [])
                sensitive_paths = ["/admin", "/backup", "/config", "/database", "/.env"]
                
                for path in found_paths:
                    if any(sensitive in path["path"].lower() for sensitive in sensitive_paths):
                        risk_score += 20
                        risk_factors.append(f"敏感目录暴露: {path['path']}")
                    else:
                        risk_score += 2
        
        # 确定风险等级
        if risk_score >= 100:
            risk_level = "极高"
        elif risk_score >= 70:
            risk_level = "高"
        elif risk_score >= 40:
            risk_level = "中"
        elif risk_score >= 20:
            risk_level = "低"
        else:
            risk_level = "极低"
        
        # 生成分析报告
        analysis = f"""# 安全风险分析报告

## 目标: {target}

### 风险等级: {risk_level}
### 风险评分: {risk_score}/100

### 风险因素:
"""
        
        for factor in risk_factors:
            analysis += f"- {factor}\n"
        
        analysis += f"""
### 风险评估说明:
- 极低 (0-19): 目标相对安全，建议定期监控
- 低 (20-39): 存在少量安全问题，建议及时处理
- 中 (40-69): 存在明显安全风险，需要尽快修复
- 高 (70-99): 存在严重安全威胁，必须立即处理
- 极高 (100+): 存在极严重安全威胁，需要紧急响应

### 建议措施:
1. 优先修复高危和严重漏洞
2. 关闭不必要的服务和端口
3. 加强访问控制和身份验证
4. 定期进行安全扫描和评估
5. 建立安全监控和响应机制
"""
        
        return analysis
        
    except Exception as e:
        logger.error(f"风险分析失败: {e}")
        return f"风险分析时发生错误: {str(e)}"


# 导出所有工具
vulun_tools = [
    scan_target_ports,
    scan_vulnerabilities,
    scan_directories,
    enumerate_subdomains,
    comprehensive_security_scan,
    get_available_security_tools,
    generate_vulnerability_report,
    analyze_security_risk,
    run_vulun_agent_scan,
]
