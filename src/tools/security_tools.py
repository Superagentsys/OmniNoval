"""
Security Tool Integration Module

Based on the OmniNoval AI design philosophy, 
this module integrates multiple security tools, 
supporting functions such as network scanning, 
web application testing, and vulnerability detection.
"""

import subprocess
import json
import logging
import asyncio
import tempfile
import os
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path

from src.config.loader import load_yaml_config
from src.utils.process_manager import process_manager
from src.engine.decision_engine import TargetProfile, TechnologyStack

logger = logging.getLogger(__name__)

DEFAULT_VULUN_CONFIG = Path(__file__).resolve().parents[2] / "vulun_agent_config.yaml"


def load_vulun_agent_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load VulunAgent specific configuration if available."""
    path = Path(config_path) if config_path else DEFAULT_VULUN_CONFIG
    if not path.exists():
        logger.debug("VulunAgent config not found at %s, using defaults", path)
        return {}

    config = load_yaml_config(str(path))
    if not config:
        return {}
    logger.info("Loaded VulunAgent config from %s", path)
    return config


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    output: str
    error: str
    return_code: int
    execution_time: float


class SecurityToolManager:
    """安全工具管理器"""
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[Union[str, Path]] = None,
    ):
        self.config = config if config is not None else load_vulun_agent_config(config_path)
        self.tools_config = self._build_default_tools_config()
        self.scan_strategies = self.config.get("SCAN_STRATEGIES", {})
        self.security_policies = self.config.get("SECURITY", {})
        self.reporting_config = self.config.get("REPORTING", {})
        cache_config = self.config.get("CACHE", {})
        
        # 缓存配置
        self.cache_settings = {
            "enabled": cache_config.get("enabled", True),
            "ttl": cache_config.get("ttl", 3600),
            "max_size": cache_config.get("max_size", 1000),
        }
        
        self._apply_config_overrides()
        self.available_tools = self._check_available_tools()
        logger.info(
            "可用安全工具: %s",
            [tool for tool, available in self.available_tools.items() if available],
        )

    def _build_default_tools_config(self) -> Dict[str, Dict[str, Any]]:
        """构建默认工具配置 - 迁移自 HexStrike AI 150+ 工具链"""
        return {
            # --- Essential Tools ---
            "nmap": {"binary": "nmap", "description": "网络发现和安全审计工具", "category": "essential"},
            "gobuster": {"binary": "gobuster", "description": "目录和文件暴力破解工具", "category": "essential", "default_args": ["dir", "-q"]},
            "dirb": {"binary": "dirb", "description": "Web 内容扫描器", "category": "essential"},
            "nikto": {"binary": "nikto", "description": "Web 服务器扫描器", "category": "essential"},
            "sqlmap": {"binary": "sqlmap", "description": "SQL 注入检测和利用工具", "category": "essential"},
            "hydra": {"binary": "hydra", "description": "网络登录破解工具", "category": "essential"},
            "john": {"binary": "john", "description": "密码破解工具", "category": "essential"},
            "hashcat": {"binary": "hashcat", "description": "高级密码恢复工具", "category": "essential"},

            # --- Network Tools ---
            "rustscan": {"binary": "rustscan", "description": "现代端口扫描器", "category": "network"},
            "masscan": {"binary": "masscan", "description": "高速端口扫描器", "category": "network"},
            "autorecon": {"binary": "autorecon", "description": "全面自动化侦察工具", "category": "network"},
            "nbtscan": {"binary": "nbtscan", "description": "NetBIOS 扫描器", "category": "network"},
            "arp-scan": {"binary": "arp-scan", "description": "ARP 网络发现工具", "category": "network"},
            "responder": {"binary": "responder", "description": "LLMNR/NBT-NS 毒化工具", "category": "network"},
            "nxc": {"binary": "nxc", "description": "NetExec 网络发现与利用工具", "category": "network"},
            "enum4linux-ng": {"binary": "enum4linux-ng", "description": "下一代 SMB 枚举工具", "category": "network"},
            "rpcclient": {"binary": "rpcclient", "description": "MS-RPC 客户端枚举工具", "category": "network"},
            "enum4linux": {"binary": "enum4linux", "description": "SMB 枚举工具", "category": "network"},

            # --- Web Security Tools ---
            "ffuf": {"binary": "ffuf", "description": "快速 Web 模糊测试工具", "category": "web"},
            "feroxbuster": {"binary": "feroxbuster", "description": "递归内容发现工具", "category": "web"},
            "dirsearch": {"binary": "dirsearch", "description": "高级 Web 路径扫描器", "category": "web"},
            "dotdotpwn": {"binary": "dotdotpwn", "description": "路径遍历检测工具", "category": "web"},
            "xsser": {"binary": "xsser", "description": "XSS 漏洞检测工具", "category": "web"},
            "wfuzz": {"binary": "wfuzz", "description": "Web 应用模糊测试工具", "category": "web"},
            "gau": {"binary": "gau", "description": "获取已知 URL 工具", "category": "web"},
            "waybackurls": {"binary": "waybackurls", "description": "Wayback Machine URL 提取器", "category": "web"},
            "arjun": {"binary": "arjun", "description": "HTTP 参数发现工具", "category": "web"},
            "paramspider": {"binary": "paramspider", "description": "参数挖掘工具", "category": "web"},
            "x8": {"binary": "x8", "description": "隐藏参数发现工具", "category": "web"},
            "jaeles": {"binary": "jaeles", "description": "高级漏洞扫描框架", "category": "web"},
            "dalfox": {"binary": "dalfox", "description": "XSS 扫描与分析器", "category": "web"},
            "httpx": {"binary": "httpx", "description": "高性能 HTTP 探测工具", "category": "web"},
            "wafw00f": {"binary": "wafw00f", "description": "WAF 指纹识别工具", "category": "web"},
            "burpsuite": {"binary": "burpsuite", "description": "专业级 Web 渗透套件", "category": "web"},
            "zaproxy": {"binary": "zaproxy", "description": "OWASP ZAP 扫描器", "category": "web"},
            "katana": {"binary": "katana", "description": "下一代 Web 爬虫", "category": "web"},
            "hakrawler": {"binary": "hakrawler", "description": "轻量级 Web 资产爬虫", "category": "web"},

            # --- Vulnerability Scanning ---
            "nuclei": {"binary": "nuclei", "description": "基于模板的漏洞扫描器", "category": "vulnerability"},
            "wpscan": {"binary": "wpscan", "description": "WordPress 漏洞扫描器", "category": "vulnerability"},
            "graphql-scanner": {"binary": "graphql-scanner", "description": "GraphQL 安全扫描器", "category": "vulnerability"},
            "jwt-analyzer": {"binary": "jwt-analyzer", "description": "JWT 令牌分析工具", "category": "vulnerability"},

            # --- Password Tools ---
            "medusa": {"binary": "medusa", "description": "并行网络登录爆破工具", "category": "password"},
            "patator": {"binary": "patator", "description": "多功能暴力破解工具", "category": "password"},
            "hash-identifier": {"binary": "hash-identifier", "description": "哈希类型识别工具", "category": "password"},
            "ophcrack": {"binary": "ophcrack", "description": "基于彩虹表的 Windows 密码破解", "category": "password"},
            "hashcat-utils": {"binary": "hashcat-utils", "description": "Hashcat 辅助工具集", "category": "password"},

            # --- Binary & Pwn Tools ---
            "gdb": {"binary": "gdb", "description": "GNU 调试器", "category": "binary"},
            "radare2": {"binary": "radare2", "description": "逆向工程框架", "category": "binary"},
            "binwalk": {"binary": "binwalk", "description": "固件分析与提取工具", "category": "binary"},
            "ropgadget": {"binary": "ROPgadget", "description": "ROP gadget 查找工具", "category": "binary"},
            "checksec": {"binary": "checksec", "description": "二进制安全特性检查", "category": "binary"},
            "objdump": {"binary": "objdump", "description": "对象文件反汇编工具", "category": "binary"},
            "ghidra": {"binary": "ghidra", "description": "NSA 逆向工程套件", "category": "binary"},
            "pwntools": {"binary": "python3", "description": "CTF 漏洞利用开发框架", "category": "binary"},
            "one-gadget": {"binary": "one_gadget", "description": "libc RCE gadget 查找工具", "category": "binary"},
            "ropper": {"binary": "ropper", "description": "ROP gadget 搜索工具", "category": "binary"},
            "angr": {"binary": "python3", "description": "二进制符号执行框架", "category": "binary"},
            "libc-database": {"binary": "libc-database", "description": "Libc 库指纹识别数据库", "category": "binary"},
            "pwninit": {"binary": "pwninit", "description": "CTF pwn 题目初始化工具", "category": "binary"},

            # --- Forensics Tools ---
            "volatility3": {"binary": "vol", "description": "内存取证框架 v3", "category": "forensics"},
            "steghide": {"binary": "steghide", "description": "隐写数据提取工具", "category": "forensics"},
            "hashpump": {"binary": "hashpump", "description": "哈希长度扩展攻击工具", "category": "forensics"},
            "foremost": {"binary": "foremost", "description": "文件恢复与挖掘工具", "category": "forensics"},
            "exiftool": {"binary": "exiftool", "description": "元数据处理工具", "category": "forensics"},
            "strings": {"binary": "strings", "description": "提取文件中的可打印字符串", "category": "forensics"},
            "xxd": {"binary": "xxd", "description": "十六进制转储工具", "category": "forensics"},
            "file": {"binary": "file", "description": "文件类型识别工具", "category": "forensics"},
            "photorec": {"binary": "photorec", "description": "数据恢复工具", "category": "forensics"},
            "testdisk": {"binary": "testdisk", "description": "分区恢复工具", "category": "forensics"},
            "scalpel": {"binary": "scalpel", "description": "高性能文件挖掘工具", "category": "forensics"},
            "bulk-extractor": {"binary": "bulk_extractor", "description": "数字取证证据提取", "category": "forensics"},
            "stegsolve": {"binary": "stegsolve", "description": "隐写图像分析工具", "category": "forensics"},
            "zsteg": {"binary": "zsteg", "description": "PNG/BMP 隐写检测", "category": "forensics"},
            "outguess": {"binary": "outguess", "description": "通用隐写工具", "category": "forensics"},

            # --- Cloud & Container ---
            "prowler": {"binary": "prowler", "description": "AWS 安全评估工具", "category": "cloud"},
            "scout-suite": {"binary": "scout", "description": "多云平台安全审计工具", "category": "cloud"},
            "trivy": {"binary": "trivy", "description": "容器与 IaC 漏洞扫描器", "category": "cloud"},
            "kube-hunter": {"binary": "kube-hunter", "description": "K8s 渗透测试工具", "category": "cloud"},
            "kube-bench": {"binary": "kube-bench", "description": "CIS K8s 基准检查", "category": "cloud"},
            "docker-bench-security": {"binary": "docker-bench-security", "description": "Docker 安全基准脚本", "category": "cloud"},
            "checkov": {"binary": "checkov", "description": "IaC 静态代码分析", "category": "cloud"},
            "terrascan": {"binary": "terrascan", "description": "IaC 安全扫描器", "category": "cloud"},
            "falco": {"binary": "falco", "description": "云原生运行时安全监控", "category": "cloud"},
            "clair": {"binary": "clairctl", "description": "容器静态漏洞分析", "category": "cloud"},

            # --- OSINT ---
            "amass": {"binary": "amass", "description": "子域名发现与攻击面测绘", "category": "osint"},
            "subfinder": {"binary": "subfinder", "description": "子域名枚举工具", "category": "osint"},
            "fierce": {"binary": "fierce", "description": "DNS 枚举与域传送检查", "category": "osint"},
            "dnsenum": {"binary": "dnsenum", "description": "多功能 DNS 枚举工具", "category": "osint"},
            "theharvester": {"binary": "theHarvester", "description": "OSINT 综合信息收集", "category": "osint"},
            "sherlock": {"binary": "sherlock", "description": "社交账号搜索工具", "category": "osint"},
            "social-analyzer": {"binary": "social-analyzer", "description": "社交媒体分析框架", "category": "osint"},
            "recon-ng": {"binary": "recon-ng", "description": "Web 侦察框架", "category": "osint"},
            "maltego": {"binary": "maltego", "description": "链接分析与 OSINT 工具", "category": "osint"},
            "spiderfoot": {"binary": "spiderfoot", "description": "自动化 OSINT 足迹收集", "category": "osint"},
            "have-i-been-pwned": {"binary": "python3", "description": "账号泄露检查", "category": "osint"},

            # --- Exploitation ---
            "metasploit": {"binary": "msfconsole", "description": "漏洞利用框架", "category": "exploitation"},
            "exploit-db": {"binary": "searchsploit", "description": "漏洞利用数据库", "category": "exploitation"},
            "searchsploit": {"binary": "searchsploit", "description": "本地漏洞库搜索工具", "category": "exploitation"},

            # --- API Tools ---
            "api-schema-analyzer": {"binary": "api-schema-analyzer", "description": "API Schema 安全分析", "category": "api"},
            "postman": {"binary": "newman", "description": "API 自动化测试工具", "category": "api"},
            "insomnia": {"binary": "insomnia", "description": "API 客户端", "category": "api"},
            "curl": {"binary": "curl", "description": "万能网络请求工具", "category": "api"},
            "httpie": {"binary": "http", "description": "现代命令行 HTTP 客户端", "category": "api"},
            "anew": {"binary": "anew", "description": "去重数据流处理工具", "category": "api"},
            "qsreplace": {"binary": "qsreplace", "description": "查询参数替换工具", "category": "api"},
            "uro": {"binary": "uro", "description": "URL 规范化与过滤工具", "category": "api"},

            # --- Wireless & Others ---
            "kismet": {"binary": "kismet", "description": "无线网络检测与嗅探", "category": "wireless"},
            "wireshark": {"binary": "tshark", "description": "网络协议分析器", "category": "wireless"},
            "tshark": {"binary": "tshark", "description": "命令行版 Wireshark", "category": "wireless"},
            "tcpdump": {"binary": "tcpdump", "description": "经典数据包捕获工具", "category": "wireless"},
            "smbmap": {"binary": "smbmap", "description": "SMB 共享枚举工具", "category": "additional"},
            "volatility": {"binary": "volatility", "description": "内存取证框架 v2", "category": "additional"},
            "sleuthkit": {"binary": "fls", "description": "文件系统取证工具集", "category": "additional"},
            "autopsy": {"binary": "autopsy", "description": "图形化数字取证平台", "category": "additional"},
            "evil-winrm": {"binary": "evil-winrm", "description": "Windows 远程管理利用工具", "category": "additional"},
            "msfvenom": {"binary": "msfvenom", "description": "Metasploit Payload 生成器", "category": "additional"},
        }

    def _apply_config_overrides(self):
        """应用配置文件中的工具设置"""
        security_config = self.config.get("SECURITY_TOOLS", {})
        for tool_name, overrides in security_config.items():
            if tool_name not in self.tools_config:
                continue
            tool_config = self.tools_config[tool_name]
            if "path" in overrides:
                tool_config["binary"] = overrides["path"]
            if "enabled" in overrides:
                tool_config["enabled"] = bool(overrides["enabled"])
            if "default_args" in overrides:
                tool_config["default_args"] = overrides["default_args"]
            if "templates_path" in overrides:
                tool_config["templates_path"] = overrides["templates_path"]
            if "default_extensions" in overrides:
                tool_config["default_extensions"] = overrides["default_extensions"]

    def is_tool_enabled(self, tool_name: str) -> bool:
        """检查工具是否启用"""
        return self.tools_config.get(tool_name, {}).get("enabled", True)

    def is_tool_ready(self, tool_name: str) -> bool:
        """检查工具是否启用且已安装"""
        return self.is_tool_enabled(tool_name) and self.available_tools.get(
            tool_name, False
        )
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """检查可用的安全工具"""
        available = {}
        for tool_name, config in self.tools_config.items():
            if not config.get("enabled", True):
                available[tool_name] = False
                continue
            try:
                result = subprocess.run(
                    ["which", config["binary"]], 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                available[tool_name] = result.returncode == 0
            except Exception as e:
                logger.warning(f"检查工具 {tool_name} 时出错: {e}")
                available[tool_name] = False
        
        return available
    
    async def run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> ToolResult:
        """
        异步执行安全工具，集成了增强型进程管理和缓存
        """
        if not self.is_tool_enabled(tool_name):
            return ToolResult(
                success=False,
                output="",
                error=f"工具 {tool_name} 未启用",
                return_code=-1,
                execution_time=0.0,
            )

        if tool_name not in self.available_tools or not self.available_tools[tool_name]:
            return ToolResult(
                success=False,
                output="",
                error=f"工具 {tool_name} 不可用",
                return_code=-1,
                execution_time=0.0
            )
        
        binary = self.tools_config[tool_name]["binary"]
        
        # 使用增强型进程管理器执行
        result = await process_manager.run_command_async(
            binary, 
            args, 
            timeout=timeout,
            use_cache=self.cache_settings.get("enabled", True)
        )
        
        return ToolResult(
            success=result.get("success", False),
            output=result.get("stdout", ""),
            error=result.get("stderr", result.get("error", "")),
            return_code=result.get("return_code", -1),
            execution_time=result.get("execution_time", 0.0)
        )

    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> List[str]:
        """迁移自 HexStrike 的参数优化逻辑"""
        context = context or {}
        args = list(self.tools_config.get(tool, {}).get("default_args", []))

        if tool == "nmap":
            # Force -sT (TCP Connect Scan) to avoid root requirements on macOS
            args.append("-sT")
            if "80" in str(profile.open_ports) or "443" in str(profile.open_ports):
                args.extend(["-sV", "-sC", "--script=http-title,http-headers"])
            if context.get("stealth"):
                args.append("-T2")
            else:
                args.append("-T4")
        
        elif tool == "gobuster":
            if TechnologyStack.PHP in profile.technologies:
                args.extend(["-x", "php,html,txt"])
            elif TechnologyStack.DOTNET in profile.technologies:
                args.extend(["-x", "aspx,asp,html"])
            
            if context.get("aggressive"):
                args.extend(["-t", "50"])
            else:
                args.extend(["-t", "20"])

        elif tool == "nuclei":
            if context.get("quick"):
                args.extend(["-severity", "critical,high"])
            else:
                args.extend(["-severity", "critical,high,medium"])
            
            if profile.cms_type == "WordPress":
                args.extend(["-tags", "wordpress"])

        return args


class NmapScanner:
    """Nmap 扫描器封装"""
    
    def __init__(self, tool_manager: SecurityToolManager):
        self.tool_manager = tool_manager
    
    async def port_scan(self, target: str, ports: str = "1-65535", scan_type: str = "syn") -> Dict[str, Any]:
        """
        端口扫描
        
        Args:
            target: 目标地址
            ports: 端口范围
            scan_type: 扫描类型 (syn, tcp, udp)
            
        Returns:
            Dict: 扫描结果
        """
        args = ["-p", ports, target]
        
        if scan_type == "syn":
            args.insert(0, "-sS")
        elif scan_type == "tcp":
            args.insert(0, "-sT")
        elif scan_type == "udp":
            args.insert(0, "-sU")
        
        # 添加输出格式
        args.extend(["-oX", "-"])  # XML 输出到标准输出
        
        result = await self.tool_manager.run_tool("nmap", args)
        
        return {
            "success": result.success,
            "raw_output": result.output,
            "error": result.error,
            "execution_time": result.execution_time,
            "open_ports": self._parse_nmap_output(result.output) if result.success else []
        }
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """解析 Nmap 输出"""
        # 简化的解析逻辑，实际应该解析 XML 输出
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    if len(port_info) >= 2:
                        open_ports.append({
                            "port": int(port_info[0]),
                            "protocol": port_info[1],
                            "state": parts[1],
                            "service": parts[2] if len(parts) > 2 else "unknown"
                        })
        
        return open_ports


class NucleiScanner:
    """Nuclei 漏洞扫描器封装"""
    
    def __init__(self, tool_manager: SecurityToolManager):
        self.tool_manager = tool_manager
    
    async def vulnerability_scan(self, target: str, templates: List[str] = None, severity: List[str] = None) -> Dict[str, Any]:
        """
        漏洞扫描
        
        Args:
            target: 目标 URL 或 IP
            templates: 模板列表
            severity: 严重程度过滤
            
        Returns:
            Dict: 扫描结果
        """
        args = ["-u", target, "-json"]
        
        if templates:
            args.extend(["-t", ",".join(templates)])
        
        if severity:
            args.extend(["-severity", ",".join(severity)])
        
        result = await self.tool_manager.run_tool("nuclei", args)
        
        vulnerabilities = []
        if result.success and result.output:
            for line in result.output.strip().split('\n'):
                if line.strip():
                    try:
                        vuln_data = json.loads(line)
                        vulnerabilities.append(vuln_data)
                    except json.JSONDecodeError:
                        continue
        
        return {
            "success": result.success,
            "vulnerabilities": vulnerabilities,
            "raw_output": result.output,
            "error": result.error,
            "execution_time": result.execution_time
        }


class GobusterScanner:
    """Gobuster 目录扫描器封装"""
    
    def __init__(self, tool_manager: SecurityToolManager):
        self.tool_manager = tool_manager
    
    async def directory_scan(self, target: str, wordlist: str = None, extensions: List[str] = None) -> Dict[str, Any]:
        """
        目录扫描
        
        Args:
            target: 目标 URL
            wordlist: 字典文件路径
            extensions: 文件扩展名列表
            
        Returns:
            Dict: 扫描结果
        """
        args = ["dir", "-u", target, "-q"]  # quiet mode
        
        if wordlist:
            args.extend(["-w", wordlist])
        else:
            # 使用默认字典
            default_wordlist = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(default_wordlist):
                args.extend(["-w", default_wordlist])
        
        if extensions:
            args.extend(["-x", ",".join(extensions)])
        
        result = await self.tool_manager.run_tool("gobuster", args)
        
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
        
        return {
            "success": result.success,
            "found_paths": found_paths,
            "raw_output": result.output,
            "error": result.error,
            "execution_time": result.execution_time
        }


class SubfinderScanner:
    """Subfinder 子域名扫描器封装"""
    
    def __init__(self, tool_manager: SecurityToolManager):
        self.tool_manager = tool_manager
    
    async def subdomain_scan(self, domain: str) -> Dict[str, Any]:
        """
        子域名扫描
        
        Args:
            domain: 目标域名
            
        Returns:
            Dict: 扫描结果
        """
        args = ["-d", domain, "-silent"]
        
        result = await self.tool_manager.run_tool("subfinder", args)
        
        subdomains = []
        if result.success:
            subdomains = [line.strip() for line in result.output.split('\n') if line.strip()]
        
        return {
            "success": result.success,
            "subdomains": subdomains,
            "count": len(subdomains),
            "raw_output": result.output,
            "error": result.error,
            "execution_time": result.execution_time
        }


class SecurityToolsIntegration:
    """安全工具集成类 - 增强版"""
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[Union[str, Path]] = None,
    ):
        self.tool_manager = SecurityToolManager(config=config, config_path=config_path)
        self.nmap = NmapScanner(self.tool_manager)
        self.nuclei = NucleiScanner(self.tool_manager)
        self.gobuster = GobusterScanner(self.tool_manager)
        self.subfinder = SubfinderScanner(self.tool_manager)
    
    async def run_smart_tool(self, tool_name: str, target: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """使用智能参数优化运行任意工具"""
        optimized_args = self.tool_manager.optimize_parameters(tool_name, profile, context)
        # 确保 target 在参数列表中
        args = optimized_args + [target]
        logger.info(f"Running smart tool {tool_name} with args: {args}")
        result = await self.tool_manager.run_tool(tool_name, args)
        return {
            "success": result.success,
            "stdout": result.output,
            "stderr": result.error,
            "execution_time": result.execution_time,
            "tool": tool_name
        }

    def get_available_tools(self) -> Dict[str, bool]:
        """获取可用工具列表"""
        return {
            name: self.tool_manager.is_tool_ready(name)
            for name in self.tool_manager.tools_config.keys()
        }
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """获取工具信息"""
        if tool_name in self.tool_manager.tools_config:
            config = dict(self.tool_manager.tools_config[tool_name])
            config["available"] = self.tool_manager.available_tools.get(tool_name, False)
            config["enabled"] = self.tool_manager.is_tool_enabled(tool_name)
            return config
        return None
    
    def _should_run_tool(self, tool_name: str, selected_tools: Optional[List[str]]) -> bool:
        if selected_tools and tool_name not in selected_tools:
            return False
        return self.tool_manager.is_tool_ready(tool_name)
    
    async def comprehensive_scan(self, target: str, strategy: Optional[str] = None) -> Dict[str, Any]:
        """
        综合扫描
        
        Args:
            target: 目标地址
            strategy: 预设扫描策略名称
            
        Returns:
            Dict: 综合扫描结果
        """
        results = {}
        strategy_name = strategy or "standard"
        strategy_config = self.tool_manager.scan_strategies.get(strategy_name, {})
        selected_tools = strategy_config.get("tools")
        port_range = strategy_config.get("port_range", "1-1000")
        nuclei_severity = strategy_config.get("nuclei_severity")
        
        # 端口扫描
        if self._should_run_tool("nmap", selected_tools):
            logger.info("执行端口扫描...")
            results["port_scan"] = await self.nmap.port_scan(target, ports=port_range)
        
        # 漏洞扫描
        if self._should_run_tool("nuclei", selected_tools):
            logger.info("执行漏洞扫描...")
            results["vulnerability_scan"] = await self.nuclei.vulnerability_scan(
                target, severity=nuclei_severity
            )
        
        # 目录扫描（如果是 HTTP/HTTPS 目标）
        if (
            target.startswith(("http://", "https://"))
            and self._should_run_tool("gobuster", selected_tools)
        ):
            logger.info("执行目录扫描...")
            results["directory_scan"] = await self.gobuster.directory_scan(target)
        
        # 子域名扫描（如果是域名）
        if (
            not target.startswith(("http://", "https://"))
            and "." in target
            and self._should_run_tool("subfinder", selected_tools)
        ):
            logger.info("执行子域名扫描...")
            results["subdomain_scan"] = await self.subfinder.subdomain_scan(target)
        
        results["strategy"] = strategy_name
        
        return results


# 创建全局实例
security_tools = SecurityToolsIntegration()
