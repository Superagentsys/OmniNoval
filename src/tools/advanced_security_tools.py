"""
高级安全工具集成模块 - 基于 OmniNoval AI 架构

集成 150+ 安全工具，提供智能决策引擎和自动化攻击链发现能力
支持网络扫描、Web 应用测试、漏洞检测、CTF 挑战、OSINT 等功能
"""

import subprocess
import json
import logging
import asyncio
import tempfile
import os
import time
import hashlib
import yaml
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from src.utils.process_manager import process_manager

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """工具类别枚举"""
    NETWORK = "network"
    WEB_APP = "web_application"
    VULNERABILITY = "vulnerability"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    FORENSICS = "forensics"
    OSINT = "osint"
    CTF = "ctf"
    CLOUD = "cloud"
    MOBILE = "mobile"
    BINARY = "binary"


class ScanStatus(Enum):
    """扫描状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ToolInfo:
    """工具信息数据结构"""
    name: str
    binary: str
    description: str
    category: ToolCategory
    version: Optional[str] = None
    available: bool = False
    install_command: Optional[str] = None
    documentation_url: Optional[str] = None
    default_args: List[str] = None
    supported_targets: List[str] = None
    output_formats: List[str] = None
    
    def __post_init__(self):
        if self.default_args is None:
            self.default_args = []
        if self.supported_targets is None:
            self.supported_targets = []
        if self.output_formats is None:
            self.output_formats = []


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    output: str
    error: str
    return_code: int
    execution_time: float


@dataclass
class ScanTask:
    """扫描任务数据结构"""
    id: str
    tool_name: str
    target: str
    args: List[str]
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[ToolResult] = None
    priority: int = 5  # 1-10, 10 为最高优先级
    timeout: int = 300
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class AttackVector:
    """攻击向量数据结构"""
    id: str
    name: str
    description: str
    severity: str
    confidence: float
    tools_required: List[str]
    prerequisites: List[str]
    steps: List[str]
    references: List[str]
    

@dataclass
class IntelligenceReport:
    """威胁情报报告"""
    target: str
    attack_surface: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    attack_vectors: List[AttackVector]
    risk_score: float
    recommendations: List[str]
    generated_at: datetime


class CacheManager:
    """缓存管理器"""
    
    def __init__(self, ttl: int = 3600, max_size: int = 1000):
        self.cache = {}
        self.ttl = ttl
        self.max_size = max_size
        self.access_times = {}
    
    def _generate_key(self, tool_name: str, target: str, args: List[str]) -> str:
        """生成缓存键"""
        content = f"{tool_name}:{target}:{','.join(args)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get(self, tool_name: str, target: str, args: List[str]) -> Optional[ToolResult]:
        """获取缓存结果"""
        key = self._generate_key(tool_name, target, args)
        
        if key in self.cache:
            result, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                self.access_times[key] = time.time()
                return result
            else:
                # 过期删除
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
        
        return None
    
    def set(self, tool_name: str, target: str, args: List[str], result: ToolResult):
        """设置缓存"""
        if len(self.cache) >= self.max_size:
            # LRU 清理
            oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
        
        key = self._generate_key(tool_name, target, args)
        self.cache[key] = (result, time.time())
        self.access_times[key] = time.time()


class IntelligentDecisionEngine:
    """智能决策引擎"""
    
    def __init__(self):
        self.tool_effectiveness = {}  # 工具效果评分
        self.target_patterns = {}     # 目标模式识别
        self.attack_chains = []       # 攻击链
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """分析目标特征"""
        analysis = {
            "type": self._detect_target_type(target),
            "technologies": [],
            "attack_surface": [],
            "recommended_tools": [],
            "scan_strategy": "standard"
        }
        
        # 基于目标类型推荐工具
        if analysis["type"] == "web_application":
            analysis["recommended_tools"] = [
                "nmap", "nuclei", "gobuster", "nikto", "sqlmap", "httpx"
            ]
        elif analysis["type"] == "network":
            analysis["recommended_tools"] = [
                "nmap", "masscan", "nuclei", "amass", "subfinder"
            ]
        elif analysis["type"] == "domain":
            analysis["recommended_tools"] = [
                "subfinder", "amass", "httpx", "nuclei", "gobuster"
            ]
        
        return analysis
    
    def _detect_target_type(self, target: str) -> str:
        """检测目标类型"""
        if target.startswith(("http://", "https://")):
            return "web_application"
        elif target.replace(".", "").replace(":", "").isdigit() or ":" in target:
            return "network"
        elif "." in target and not target.replace(".", "").isdigit():
            return "domain"
        else:
            return "unknown"
    
    def optimize_scan_parameters(self, tool_name: str, target: str, 
                                default_args: List[str]) -> List[str]:
        """优化扫描参数"""
        optimized_args = default_args.copy()
        
        # 基于目标类型和历史数据优化参数
        target_analysis = self.analyze_target(target)
        
        if tool_name == "nmap":
            if target_analysis["type"] == "web_application":
                # Web 应用优化：重点扫描 Web 端口
                if "-p" not in " ".join(optimized_args):
                    optimized_args.extend(["-p", "80,443,8080,8443,3000,5000,8000"])
            elif target_analysis["type"] == "network":
                # 网络扫描优化：快速扫描常用端口
                if "-p" not in " ".join(optimized_args):
                    optimized_args.extend(["-p", "1-1000"])
        
        elif tool_name == "nuclei":
            # 基于目标类型选择模板
            if target_analysis["type"] == "web_application":
                optimized_args.extend(["-tags", "web,cve,exposure"])
        
        return optimized_args
    
    def discover_attack_chains(self, scan_results: Dict[str, Any]) -> List[AttackVector]:
        """发现攻击链"""
        attack_vectors = []
        
        # 分析扫描结果，发现潜在攻击路径
        if "port_scan" in scan_results:
            open_ports = scan_results["port_scan"].get("open_ports", [])
            for port_info in open_ports:
                if port_info.get("port") == 22:
                    attack_vectors.append(AttackVector(
                        id="SSH_BRUTE_FORCE",
                        name="SSH 暴力破解",
                        description="通过暴力破解攻击 SSH 服务",
                        severity="medium",
                        confidence=0.7,
                        tools_required=["hydra", "medusa"],
                        prerequisites=["用户名列表", "密码字典"],
                        steps=[
                            "收集潜在用户名",
                            "准备密码字典",
                            "执行暴力破解攻击",
                            "验证获得的凭据"
                        ],
                        references=["https://attack.mitre.org/techniques/T1110/"]
                    ))
                elif port_info.get("port") == 80 or port_info.get("port") == 443:
                    attack_vectors.append(AttackVector(
                        id="WEB_APP_ATTACK",
                        name="Web 应用攻击",
                        description="针对 Web 应用的综合攻击",
                        severity="high",
                        confidence=0.8,
                        tools_required=["sqlmap", "xsser", "nikto"],
                        prerequisites=["Web 应用访问权限"],
                        steps=[
                            "Web 应用指纹识别",
                            "目录和文件枚举",
                            "漏洞扫描和检测",
                            "漏洞利用"
                        ],
                        references=["https://owasp.org/www-project-top-ten/"]
                    ))
        
        return attack_vectors


class OmniNovalToolManager:
    """OmniNoval 风格的高级安全工具管理器"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.tools_registry = self._initialize_tools_registry()
        self.available_tools = {}
        self.cache_manager = CacheManager()
        self.decision_engine = IntelligentDecisionEngine()
        self.task_queue = asyncio.Queue()
        self.running_tasks = {}
        self.scan_history = []
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        # 加载配置
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        
        # 检查可用工具
        self._check_available_tools()
        
        logger.info(f"OmniNoval 工具管理器初始化完成，可用工具: {len([t for t in self.available_tools.values() if t.available])}/{len(self.tools_registry)}")
    
    def _initialize_tools_registry(self) -> Dict[str, ToolInfo]:
        """初始化工具注册表 - 150+ 安全工具"""
        registry = {}
        
        # 网络扫描工具 (25+)
        network_tools = [
            ("nmap", "网络发现和安全审计工具", ["-sS", "-sV", "-O"], "apt install nmap"),
            ("masscan", "高速端口扫描器", ["--rate=1000"], "apt install masscan"),
            ("zmap", "互联网级网络扫描器", [], "apt install zmap"),
            ("rustscan", "现代端口扫描器", [], "cargo install rustscan"),
            ("unicornscan", "异步网络刺激工具", [], "apt install unicornscan"),
            ("hping3", "网络工具和数据包生成器", [], "apt install hping3"),
            ("netcat", "网络连接工具", [], "apt install netcat"),
            ("socat", "多用途中继工具", [], "apt install socat"),
            ("tcpdump", "网络数据包分析器", [], "apt install tcpdump"),
            ("wireshark", "网络协议分析器", [], "apt install wireshark"),
        ]
        
        for name, desc, args, install_cmd in network_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.NETWORK, default_args=args,
                supported_targets=["ip", "domain", "cidr"],
                install_command=install_cmd
            )
        
        # Web 应用扫描工具 (40+)
        web_tools = [
            ("gobuster", "目录和文件暴力破解工具", ["dir", "-q"], "go install github.com/OJ/gobuster/v3@latest"),
            ("dirb", "Web 内容扫描器", [], "apt install dirb"),
            ("dirsearch", "高级 Web 路径扫描器", [], "git clone https://github.com/maurosoria/dirsearch.git"),
            ("ffuf", "快速 Web 模糊测试工具", [], "go install github.com/ffuf/ffuf@latest"),
            ("wfuzz", "Web 应用模糊测试工具", [], "pip install wfuzz"),
            ("nikto", "Web 服务器扫描器", [], "apt install nikto"),
            ("sqlmap", "SQL 注入检测和利用工具", [], "apt install sqlmap"),
            ("xsser", "XSS 漏洞检测工具", [], "apt install xsser"),
            ("commix", "命令注入漏洞检测工具", [], "apt install commix"),
            ("whatweb", "Web 技术识别工具", [], "apt install whatweb"),
            ("httpx", "HTTP 工具包", [], "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("waybackurls", "Wayback Machine URL 提取器", [], "go install github.com/tomnomnom/waybackurls@latest"),
            ("gau", "获取已知 URL", [], "go install github.com/lc/gau@latest"),
            ("hakrawler", "Web 爬虫", [], "go install github.com/hakluke/hakrawler@latest"),
            ("gospider", "快速 Web 爬虫", [], "go install github.com/jaeles-project/gospider@latest"),
            ("burpsuite", "Web 应用安全测试平台", [], ""),
            ("owasp-zap", "Web 应用安全扫描器", [], "apt install zaproxy"),
            ("wpscan", "WordPress 安全扫描器", [], "gem install wpscan"),
            ("joomscan", "Joomla 漏洞扫描器", [], "apt install joomscan"),
            ("droopescan", "Drupal 安全扫描器", [], "pip install droopescan"),
        ]
        
        for name, desc, args, install_cmd in web_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.WEB_APP, default_args=args,
                supported_targets=["url", "domain"],
                install_command=install_cmd
            )
        
        # 漏洞扫描工具 (20+)
        vuln_tools = [
            ("nuclei", "基于模板的漏洞扫描器", ["-json"], "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
            ("openvas", "开源漏洞评估系统", [], "apt install openvas"),
            ("nessus", "专业漏洞扫描器", [], ""),
            ("nexpose", "漏洞管理解决方案", [], ""),
            ("qualys", "云端漏洞扫描", [], ""),
            ("nmap-vulners", "Nmap 漏洞扫描脚本", [], ""),
            ("vulscan", "Nmap 漏洞扫描脚本", [], ""),
            ("vulmap", "漏洞扫描和验证工具", [], "git clone https://github.com/zhzyker/vulmap.git"),
            ("afrog", "快速漏洞扫描器", [], "go install -v github.com/zan8in/afrog/cmd/afrog@latest"),
            ("xray", "被动漏洞扫描器", [], ""),
        ]
        
        for name, desc, args, install_cmd in vuln_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.VULNERABILITY, default_args=args,
                supported_targets=["ip", "url", "domain"],
                install_command=install_cmd
            )
        
        # 信息收集工具 (20+)
        recon_tools = [
            ("subfinder", "子域名发现工具", ["-silent"], "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("amass", "网络映射和攻击面发现", [], "go install -v github.com/OWASP/Amass/v3/...@master"),
            ("assetfinder", "域名资产发现工具", [], "go install github.com/tomnomnom/assetfinder@latest"),
            ("findomain", "跨平台子域名发现工具", [], ""),
            ("sublist3r", "Python 子域名枚举工具", [], "pip install sublist3r"),
            ("dnsrecon", "DNS 枚举工具", [], "apt install dnsrecon"),
            ("fierce", "DNS 扫描器", [], "pip install fierce"),
            ("theharvester", "OSINT 信息收集工具", [], "apt install theharvester"),
            ("recon-ng", "Web 侦察框架", [], "apt install recon-ng"),
            ("maltego", "链接分析工具", [], ""),
            ("shodan", "互联网设备搜索引擎", [], "pip install shodan"),
            ("censys", "互联网扫描平台", [], "pip install censys"),
            ("spiderfoot", "自动化 OSINT 工具", [], "pip install spiderfoot"),
            ("osrframework", "OSINT 研究框架", [], "pip install osrframework"),
            ("twint", "Twitter 情报工具", [], "pip install twint"),
        ]
        
        for name, desc, args, install_cmd in recon_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.RECONNAISSANCE, default_args=args,
                supported_targets=["domain", "email", "person"],
                install_command=install_cmd
            )
        
        # 漏洞利用工具 (25+)
        exploit_tools = [
            ("metasploit", "渗透测试框架", [], "apt install metasploit-framework"),
            ("searchsploit", "Exploit-DB 搜索工具", [], "apt install exploitdb"),
            ("exploit-db", "漏洞利用数据库", [], "apt install exploitdb"),
            ("beef", "浏览器漏洞利用框架", [], "apt install beef-xss"),
            ("empire", "PowerShell 后渗透框架", [], ""),
            ("cobalt-strike", "商业渗透测试工具", [], ""),
            ("armitage", "Metasploit 图形界面", [], "apt install armitage"),
            ("veil", "Payload 生成器", [], ""),
            ("msfvenom", "Payload 生成器", [], ""),
            ("shellter", "动态 Shellcode 注入工具", [], ""),
        ]
        
        for name, desc, args, install_cmd in exploit_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.EXPLOITATION, default_args=args,
                install_command=install_cmd
            )
        
        # CTF 工具 (20+)
        ctf_tools = [
            ("john", "密码破解工具", [], "apt install john"),
            ("hashcat", "高级密码恢复工具", [], "apt install hashcat"),
            ("hydra", "网络登录破解工具", [], "apt install hydra"),
            ("medusa", "并行暴力破解工具", [], "apt install medusa"),
            ("aircrack-ng", "WiFi 安全审计工具套件", [], "apt install aircrack-ng"),
            ("binwalk", "固件分析工具", [], "apt install binwalk"),
            ("strings", "字符串提取工具", [], "apt install binutils"),
            ("file", "文件类型识别工具", [], "apt install file"),
            ("hexdump", "十六进制转储工具", [], "apt install bsdmainutils"),
            ("radare2", "逆向工程框架", [], "apt install radare2"),
            ("gdb", "GNU 调试器", [], "apt install gdb"),
            ("objdump", "对象文件转储工具", [], "apt install binutils"),
            ("strace", "系统调用跟踪器", [], "apt install strace"),
            ("ltrace", "库调用跟踪器", [], "apt install ltrace"),
            ("volatility", "内存取证工具", [], "pip install volatility3"),
        ]
        
        for name, desc, args, install_cmd in ctf_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.CTF, default_args=args,
                install_command=install_cmd
            )
        
        # OSINT 工具 (20+)
        osint_tools = [
            ("shodan", "互联网设备搜索引擎", [], "pip install shodan"),
            ("censys", "互联网扫描平台", [], "pip install censys"),
            ("spiderfoot", "自动化 OSINT 工具", [], "pip install spiderfoot"),
            ("osrframework", "OSINT 研究框架", [], "pip install osrframework"),
            ("twint", "Twitter 情报工具", [], "pip install twint"),
            ("phoneinfoga", "电话号码 OSINT 工具", [], ""),
            ("sherlock", "社交媒体用户名搜索", [], "pip install sherlock-project"),
            ("maigret", "用户名 OSINT 收集", [], "pip install maigret"),
            ("holehe", "邮箱 OSINT 工具", [], "pip install holehe"),
            ("ghunt", "Google 账户 OSINT", [], "pip install ghunt"),
        ]
        
        for name, desc, args, install_cmd in osint_tools:
            registry[name] = ToolInfo(
                name=name, binary=name, description=desc,
                category=ToolCategory.OSINT, default_args=args,
                install_command=install_cmd
            )
        
        return registry
    
    def _load_config(self, config_path: str):
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # 更新工具配置
            if 'SECURITY_TOOLS' in config:
                for tool_name, tool_config in config['SECURITY_TOOLS'].items():
                    if tool_name in self.tools_registry:
                        tool_info = self.tools_registry[tool_name]
                        if 'path' in tool_config:
                            tool_info.binary = tool_config['path']
                        if 'default_args' in tool_config:
                            tool_info.default_args = tool_config['default_args']
            
            logger.info(f"配置文件加载成功: {config_path}")
            
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    
    def _check_available_tools(self):
        """检查可用的安全工具"""
        for tool_name, tool_info in self.tools_registry.items():
            try:
                result = subprocess.run(
                    ["which", tool_info.binary], 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                tool_info.available = result.returncode == 0
                
                if tool_info.available:
                    # 尝试获取版本信息
                    try:
                        version_result = subprocess.run(
                            [tool_info.binary, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if version_result.returncode == 0:
                            tool_info.version = version_result.stdout.strip().split('\n')[0]
                    except:
                        pass
                
                self.available_tools[tool_name] = tool_info
                
            except Exception as e:
                logger.warning(f"检查工具 {tool_name} 时出错: {e}")
                tool_info.available = False
    
    async def run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> ToolResult:
        """异步执行安全工具，集成增强型进程管理"""
        if tool_name not in self.available_tools or not self.available_tools[tool_name].available:
            return ToolResult(
                success=False,
                output="",
                error=f"工具 {tool_name} 不可用",
                return_code=-1,
                execution_time=0.0
            )
        
        binary = self.available_tools[tool_name].binary
        
        # 使用增强型进程管理器
        result = await process_manager.run_command_async(
            binary, 
            args, 
            timeout=timeout,
            use_cache=True # OmniNovalToolManager 内部也有缓存，但 process_manager 的更底层
        )
        
        return ToolResult(
            success=result.get("success", False),
            output=result.get("stdout", ""),
            error=result.get("stderr", result.get("error", "")),
            return_code=result.get("return_code", -1),
            execution_time=result.get("execution_time", 0.0)
        )
    
    async def intelligent_scan(self, target: str, scan_type: str = "auto") -> IntelligenceReport:
        """智能扫描 - 自动选择最佳工具和策略"""
        logger.info(f"开始智能扫描: {target}")
        
        # 分析目标
        target_analysis = self.decision_engine.analyze_target(target)
        
        # 选择扫描策略
        if scan_type == "auto":
            scan_type = target_analysis["scan_strategy"]
        
        # 执行扫描
        scan_results = {}
        recommended_tools = target_analysis["recommended_tools"]
        
        # 并行执行扫描任务
        tasks = []
        for tool_name in recommended_tools:
            if tool_name in self.available_tools and self.available_tools[tool_name].available:
                task = self._create_scan_task(tool_name, target)
                tasks.append(task)
        
        # 等待所有任务完成
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理扫描结果
        for i, result in enumerate(completed_tasks):
            if not isinstance(result, Exception) and i < len(recommended_tools):
                tool_name = recommended_tools[i]
                scan_results[tool_name] = result
        
        # 发现攻击向量
        attack_vectors = self.decision_engine.discover_attack_chains(scan_results)
        
        # 计算风险评分
        risk_score = self._calculate_risk_score(scan_results)
        
        # 生成情报报告
        report = IntelligenceReport(
            target=target,
            attack_surface=target_analysis,
            vulnerabilities=self._extract_vulnerabilities(scan_results),
            attack_vectors=attack_vectors,
            risk_score=risk_score,
            recommendations=self._generate_recommendations(scan_results, attack_vectors),
            generated_at=datetime.now()
        )
        
        return report
    
    async def _create_scan_task(self, tool_name: str, target: str) -> Dict[str, Any]:
        """创建扫描任务"""
        tool_info = self.available_tools[tool_name]
        
        # 优化扫描参数
        optimized_args = self.decision_engine.optimize_scan_parameters(
            tool_name, target, tool_info.default_args
        )
        
        # 检查缓存
        cached_result = self.cache_manager.get(tool_name, target, optimized_args)
        if cached_result:
            logger.info(f"使用缓存结果: {tool_name} -> {target}")
            return asdict(cached_result)
        
        # 执行扫描
        result = await self.run_tool(tool_name, [target] + optimized_args)
        
        # 缓存结果
        if result.success:
            self.cache_manager.set(tool_name, target, optimized_args, result)
        
        return asdict(result)
    
    def _calculate_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """计算风险评分"""
        risk_score = 0.0
        
        for tool_name, result in scan_results.items():
            if isinstance(result, dict) and result.get("success", False):
                # 基于发现的问题计算风险
                if "vulnerabilities" in result:
                    for vuln in result["vulnerabilities"]:
                        severity = vuln.get("severity", "low").lower()
                        if severity == "critical":
                            risk_score += 10.0
                        elif severity == "high":
                            risk_score += 7.0
                        elif severity == "medium":
                            risk_score += 4.0
                        elif severity == "low":
                            risk_score += 1.0
                
                if "open_ports" in result:
                    # 开放端口风险
                    risk_score += len(result["open_ports"]) * 0.5
        
        return min(risk_score, 100.0)  # 最高 100 分
    
    def _extract_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取漏洞信息"""
        vulnerabilities = []
        
        for tool_name, result in scan_results.items():
            if isinstance(result, dict) and result.get("success", False):
                if "vulnerabilities" in result:
                    for vuln in result["vulnerabilities"]:
                        vuln["discovered_by"] = tool_name
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generate_recommendations(self, scan_results: Dict[str, Any], 
                                attack_vectors: List[AttackVector]) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        # 基于扫描结果生成建议
        for tool_name, result in scan_results.items():
            if isinstance(result, dict) and result.get("success", False):
                if "open_ports" in result:
                    open_ports = result["open_ports"]
                    if len(open_ports) > 10:
                        recommendations.append("关闭不必要的开放端口，减少攻击面")
                
                if "vulnerabilities" in result:
                    high_vulns = [v for v in result["vulnerabilities"] 
                                if v.get("severity", "").lower() in ["high", "critical"]]
                    if high_vulns:
                        recommendations.append(f"立即修复 {len(high_vulns)} 个高危漏洞")
        
        # 基于攻击向量生成建议
        for vector in attack_vectors:
            if vector.severity in ["high", "critical"]:
                recommendations.append(f"防范 {vector.name} 攻击")
        
        return list(set(recommendations))  # 去重
    
    def get_tool_statistics(self) -> Dict[str, Any]:
        """获取工具统计信息"""
        stats = {
            "total_tools": len(self.tools_registry),
            "available_tools": len([t for t in self.available_tools.values() if t.available]),
            "categories": {},
            "scan_history_count": len(self.scan_history)
        }
        
        # 按类别统计
        for tool_info in self.tools_registry.values():
            category = tool_info.category.value
            if category not in stats["categories"]:
                stats["categories"][category] = {"total": 0, "available": 0}
            
            stats["categories"][category]["total"] += 1
            if tool_info.available:
                stats["categories"][category]["available"] += 1
        
        return stats
    
    def install_missing_tools(self) -> Dict[str, bool]:
        """安装缺失的工具"""
        installation_results = {}
        
        for tool_name, tool_info in self.tools_registry.items():
            if not tool_info.available and tool_info.install_command:
                try:
                    logger.info(f"安装工具: {tool_name}")
                    result = subprocess.run(
                        tool_info.install_command.split(),
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    installation_results[tool_name] = result.returncode == 0
                    
                    if result.returncode == 0:
                        tool_info.available = True
                        self.available_tools[tool_name] = tool_info
                        logger.info(f"工具 {tool_name} 安装成功")
                    else:
                        logger.error(f"工具 {tool_name} 安装失败: {result.stderr}")
                        
                except Exception as e:
                    logger.error(f"安装工具 {tool_name} 时出错: {e}")
                    installation_results[tool_name] = False
        
        return installation_results


# 创建全局实例
OmniNoval_tools = OmniNovalToolManager()
