"""
Intelligent Decision Engine for tool selection and strategy optimization.
Inspired by hexstrike-ai's IntelligentDecisionEngine.
"""

import logging
import re
import socket
import urllib.parse
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    DOMAIN = "domain"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: set[str] = set()
        self.risk_level: str = "unknown"

    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        self.success_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness ratings for different target types"""
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8,
                "gobuster": 0.9,
                "nuclei": 0.95,
                "nikto": 0.85,
                "sqlmap": 0.9,
                "ffuf": 0.9,
                "feroxbuster": 0.85,
                "katana": 0.88,
                "httpx": 0.85,
                "wpscan": 0.95,
                "dirsearch": 0.87,
                "gau": 0.82,
                "waybackurls": 0.8,
                "arjun": 0.9,
                "paramspider": 0.85,
                "x8": 0.88,
                "jaeles": 0.92,
                "dalfox": 0.93,
                "anew": 0.7,
                "qsreplace": 0.75,
                "uro": 0.7
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95,
                "masscan": 0.92,
                "rustscan": 0.9,
                "autorecon": 0.95,
                "enum4linux": 0.8,
                "enum4linux-ng": 0.88,
                "smbmap": 0.85,
                "rpcclient": 0.82,
                "nbtscan": 0.75,
                "arp-scan": 0.85,
                "responder": 0.88,
                "hydra": 0.8,
                "netexec": 0.85,
                "amass": 0.7
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9,
                "ffuf": 0.85,
                "arjun": 0.95,
                "paramspider": 0.88,
                "httpx": 0.9,
                "x8": 0.92,
                "katana": 0.85,
                "jaeles": 0.88,
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95,
                "scout-suite": 0.92,
                "cloudmapper": 0.88,
                "pacu": 0.85,
                "trivy": 0.9,
                "clair": 0.85,
                "kube-hunter": 0.9,
                "kube-bench": 0.88,
                "docker-bench-security": 0.85,
                "falco": 0.87,
                "checkov": 0.9,
                "terrascan": 0.88
            },
            TargetType.BINARY_FILE.value: {
                "ghidra": 0.95,
                "radare2": 0.9,
                "gdb": 0.85,
                "gdb-peda": 0.92,
                "angr": 0.88,
                "pwntools": 0.9,
                "ropgadget": 0.85,
                "ropper": 0.88,
                "one-gadget": 0.82,
                "libc-database": 0.8,
                "checksec": 0.75,
                "strings": 0.7,
                "objdump": 0.75,
                "binwalk": 0.8,
                "pwninit": 0.85
            }
        }

    def _initialize_technology_signatures(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize technology detection signatures"""
        return {
            "headers": {
                TechnologyStack.APACHE.value: ["Apache", "apache"],
                TechnologyStack.NGINX.value: ["nginx", "Nginx"],
                TechnologyStack.IIS.value: ["Microsoft-IIS", "IIS"],
                TechnologyStack.PHP.value: ["PHP", "X-Powered-By: PHP"],
                TechnologyStack.NODEJS.value: ["Express", "X-Powered-By: Express"],
                TechnologyStack.PYTHON.value: ["Django", "Flask", "Werkzeug"],
                TechnologyStack.JAVA.value: ["Tomcat", "JBoss", "WebLogic"],
                TechnologyStack.DOTNET.value: ["ASP.NET", "X-AspNet-Version"]
            },
            "content": {
                TechnologyStack.WORDPRESS.value: ["wp-content", "wp-includes", "WordPress"],
                TechnologyStack.DRUPAL.value: ["Drupal", "drupal", "/sites/default"],
                TechnologyStack.JOOMLA.value: ["Joomla", "joomla", "/administrator"],
                TechnologyStack.REACT.value: ["React", "react", "__REACT_DEVTOOLS"],
                TechnologyStack.ANGULAR.value: ["Angular", "angular", "ng-version"],
                TechnologyStack.VUE.value: ["Vue", "vue", "__VUE__"]
            }
        }

    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize common attack patterns for different scenarios"""
        return {
            "web_reconnaissance": [
                {"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
                {"tool": "httpx", "priority": 2, "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "priority": 3, "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "priority": 4, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 5, "params": {"get_versions": False}},
                {"tool": "nuclei", "priority": 6, "params": {"severity": "critical,high", "tags": "tech"}},
                {"tool": "dirsearch", "priority": 7, "params": {"extensions": "php,html,js,txt", "threads": 30}},
                {"tool": "gobuster", "priority": 8, "params": {"mode": "dir", "extensions": "php,html,js,txt"}}
            ],
            "api_testing": [
                {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True}},
                {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True}},
                {"tool": "x8", "priority": 3, "params": {"method": "GET", "wordlist": "/usr/share/wordlists/x8/params.txt"}},
                {"tool": "paramspider", "priority": 4, "params": {"level": 2}},
                {"tool": "nuclei", "priority": 5, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}},
                {"tool": "ffuf", "priority": 6, "params": {"mode": "parameter", "method": "POST"}}
            ],
            "network_discovery": [
                {"tool": "arp-scan", "priority": 1, "params": {"local_network": True}},
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "nmap", "priority": 3, "params": {"scan_type": "-sS", "os_detection": True, "version_detection": True}},
                {"tool": "masscan", "priority": 4, "params": {"rate": 1000, "ports": "1-65535", "banners": True}},
                {"tool": "enum4linux-ng", "priority": 5, "params": {"shares": True, "users": True, "groups": True}},
                {"tool": "nbtscan", "priority": 6, "params": {"verbose": True}},
                {"tool": "smbmap", "priority": 7, "params": {"recursive": True}},
                {"tool": "rpcclient", "priority": 8, "params": {"commands": "enumdomusers;enumdomgroups;querydominfo"}}
            ]
        }

    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        profile = TargetProfile(target=target)
        profile.target_type = self._determine_target_type(target)

        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)
            profile.technologies = self._detect_technologies(target)
            profile.cms_type = self._detect_cms(target)

        profile.attack_surface_score = self._calculate_attack_surface(profile)
        profile.risk_level = self._determine_risk_level(profile)
        profile.confidence_score = self._calculate_confidence(profile)

        logger.info(f"Target analyzed: {target} as {profile.target_type.value}, Risk: {profile.risk_level}")
        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION
        if target.endswith(('.exe', '.bin', '.elf', '.so', '.dll')):
            return TargetType.BINARY_FILE
        return TargetType.UNKNOWN

    def _resolve_domain(self, target: str) -> List[str]:
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urllib.parse.urlparse(target).hostname
            else:
                hostname = target
            if hostname:
                return [socket.gethostbyname(hostname)]
        except Exception:
            pass
        return []

    def _detect_technologies(self, target: str) -> List[TechnologyStack]:
        technologies = []
        target_lower = target.lower()
        if 'wordpress' in target_lower or 'wp-' in target_lower:
            technologies.append(TechnologyStack.WORDPRESS)
        if '.php' in target_lower:
            technologies.append(TechnologyStack.PHP)
        if '.asp' in target_lower:
            technologies.append(TechnologyStack.DOTNET)
        return technologies if technologies else [TechnologyStack.UNKNOWN]

    def _detect_cms(self, target: str) -> Optional[str]:
        target_lower = target.lower()
        if 'wordpress' in target_lower or 'wp-' in target_lower:
            return "WordPress"
        if 'drupal' in target_lower:
            return "Drupal"
        if 'joomla' in target_lower:
            return "Joomla"
        return None

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        score = 0.0
        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.0,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.BINARY_FILE: 4.0
        }
        score += type_scores.get(profile.target_type, 3.0)
        score += len(profile.technologies) * 0.5
        if profile.cms_type:
            score += 1.5
        return min(score, 10.0)

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        if profile.attack_surface_score >= 8.0: return "critical"
        if profile.attack_surface_score >= 6.0: return "high"
        if profile.attack_surface_score >= 4.0: return "medium"
        return "low"

    def _calculate_confidence(self, profile: TargetProfile) -> float:
        confidence = 0.5
        if profile.ip_addresses: confidence += 0.1
        if profile.technologies and profile.technologies[0] != TechnologyStack.UNKNOWN: confidence += 0.2
        if profile.target_type != TargetType.UNKNOWN: confidence += 0.1
        return min(confidence, 1.0)

    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        target_type = profile.target_type.value
        effectiveness_map = self.tool_effectiveness.get(target_type, {})
        base_tools = list(effectiveness_map.keys())

        if objective == "quick":
            sorted_tools = sorted(base_tools, key=lambda t: effectiveness_map.get(t, 0), reverse=True)
            selected_tools = sorted_tools[:3]
        elif objective == "stealth":
            stealth_tools = ["amass", "subfinder", "httpx", "nuclei"]
            selected_tools = [tool for tool in base_tools if tool in stealth_tools]
        else:
            selected_tools = [tool for tool in base_tools if effectiveness_map.get(tool, 0) > 0.7]

        return selected_tools

    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        chain = AttackChain(profile)
        pattern_key = "web_reconnaissance"
        if profile.target_type == TargetType.API_ENDPOINT:
            pattern_key = "api_testing"
        elif profile.target_type == TargetType.NETWORK_HOST:
            pattern_key = "network_discovery"
        
        pattern = self.attack_patterns.get(pattern_key, [])
        for step_config in pattern:
            tool = step_config["tool"]
            effectiveness = self.tool_effectiveness.get(profile.target_type.value, {}).get(tool, 0.5)
            step = AttackStep(
                tool=tool,
                parameters=step_config.get("params", {}),
                expected_outcome=f"Discover vulnerabilities using {tool}",
                success_probability=effectiveness * profile.confidence_score,
                execution_time_estimate=180
            )
            chain.add_step(step)
        
        chain.calculate_success_probability()
        chain.risk_level = profile.risk_level
        return chain

# Global instance
decision_engine = IntelligentDecisionEngine()

