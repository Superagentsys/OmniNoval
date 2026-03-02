"""
CTF Competition Framework — CTF 竞赛卓越框架

提供:
- 7 大类别 (Web/Crypto/Pwn/Forensics/Rev/Misc/OSINT) 专用工作流
- 挑战自动分析与工具推荐
- 并行任务识别
- 团队策略优化
- 自动解题尝试
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CTFChallenge:
    name: str
    category: str
    description: str = ""
    points: int = 0
    difficulty: str = "unknown"
    files: List[str] = field(default_factory=list)
    url: str = ""


CATEGORY_TOOLS: Dict[str, Dict[str, List[str]]] = {
    "web": {
        "recon": ["httpx", "katana", "gau", "waybackurls"],
        "vuln": ["sqlmap", "dalfox", "nikto", "wpscan"],
        "discovery": ["gobuster", "dirsearch", "feroxbuster"],
        "params": ["arjun", "paramspider"],
    },
    "crypto": {
        "hash": ["hashcat", "john", "hash-identifier"],
        "cipher": ["cipher-identifier", "frequency-analysis"],
        "rsa": ["rsatool", "factordb", "yafu"],
    },
    "pwn": {
        "analysis": ["checksec", "file", "strings", "objdump"],
        "exploit": ["pwntools", "ropper", "ropgadget", "one-gadget"],
        "debug": ["gdb-peda", "gdb-gef", "ltrace", "strace"],
    },
    "forensics": {
        "file": ["binwalk", "foremost", "photorec", "exiftool"],
        "image": ["steghide", "stegsolve", "zsteg", "outguess"],
        "memory": ["volatility", "volatility3"],
        "network": ["wireshark", "tcpdump"],
    },
    "rev": {
        "static": ["ghidra", "ida", "radare2", "strings"],
        "dynamic": ["gdb-peda", "ltrace", "strace"],
        "unpack": ["upx", "peid", "detect-it-easy"],
    },
    "misc": {
        "encoding": ["base64", "hex", "rot13"],
        "compression": ["zip", "7zip", "rar"],
        "esoteric": ["brainfuck", "whitespace", "piet"],
    },
    "osint": {
        "social": ["sherlock", "social-analyzer"],
        "domain": ["whois", "dig", "amass"],
        "search": ["shodan", "censys"],
    },
}


class CTFWorkflowManager:
    """CTF 竞赛工作流管理器"""

    def create_challenge_workflow(self, challenge: CTFChallenge) -> Dict[str, Any]:
        workflow: Dict[str, Any] = {
            "challenge": challenge.name,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "points": challenge.points,
            "tools": self._suggest_tools(challenge),
            "strategies": self._get_strategies(challenge.category),
            "workflow_steps": self._build_steps(challenge),
            "parallel_tasks": self._parallel_tasks(challenge.category),
            "estimated_time": self._estimate_time(challenge),
            "success_probability": self._success_prob(challenge),
        }
        return workflow

    def create_team_strategy(self, challenges: List[CTFChallenge], team_size: int = 4) -> Dict[str, Any]:
        efficiencies = []
        for ch in challenges:
            wf = self.create_challenge_workflow(ch)
            est = wf["estimated_time"] or 3600
            eff = (ch.points * wf["success_probability"]) / (est / 3600)
            efficiencies.append({"challenge": ch, "efficiency": eff, "workflow": wf})

        efficiencies.sort(key=lambda x: x["efficiency"], reverse=True)

        allocation: Dict[int, List[Dict]] = {i: [] for i in range(team_size)}
        workload = [0] * team_size
        expected_score = 0.0

        for item in efficiencies:
            member = workload.index(min(workload))
            allocation[member].append({
                "challenge": item["challenge"].name,
                "category": item["challenge"].category,
                "points": item["challenge"].points,
                "estimated_time": item["workflow"]["estimated_time"],
            })
            workload[member] += item["workflow"]["estimated_time"]
            expected_score += item["challenge"].points * item["workflow"]["success_probability"]

        return {
            "team_size": team_size,
            "assignments": allocation,
            "priority_order": [e["challenge"].name for e in efficiencies],
            "expected_score": round(expected_score),
            "estimated_total_time": max(workload),
        }

    def suggest_tools(self, description: str, category: str) -> List[str]:
        return self._suggest_tools(CTFChallenge(name="", category=category, description=description))

    # ---- internals ----

    def _suggest_tools(self, ch: CTFChallenge) -> List[str]:
        tools: List[str] = []
        cats = CATEGORY_TOOLS.get(ch.category, {})
        for subcat_tools in cats.values():
            tools.extend(subcat_tools[:2])

        dl = ch.description.lower()
        kw_map = {
            "sql": ["sqlmap"], "xss": ["dalfox"], "wordpress": ["wpscan"],
            "hash": ["hashcat", "john"], "rsa": ["rsatool", "factordb"],
            "buffer": ["pwntools", "gdb-peda", "ropper"], "heap": ["pwntools", "gdb-gef"],
            "image": ["exiftool", "steghide", "stegsolve"], "memory": ["volatility"],
            "pcap": ["wireshark", "tcpdump"], "packed": ["upx", "peid"],
        }
        for kw, tls in kw_map.items():
            if kw in dl:
                tools.extend(tls)

        return list(dict.fromkeys(tools))

    @staticmethod
    def _get_strategies(category: str) -> List[Dict[str, str]]:
        strategies: Dict[str, List[Dict[str, str]]] = {
            "web": [
                {"strategy": "source_code_analysis", "desc": "审查 HTML/JS 源码"},
                {"strategy": "directory_traversal", "desc": "路径遍历测试"},
                {"strategy": "sql_injection", "desc": "SQL 注入检测"},
                {"strategy": "xss_exploitation", "desc": "XSS 利用"},
            ],
            "crypto": [
                {"strategy": "frequency_analysis", "desc": "频率分析"},
                {"strategy": "weak_keys", "desc": "弱密钥测试"},
                {"strategy": "known_plaintext", "desc": "已知明文攻击"},
            ],
            "pwn": [
                {"strategy": "buffer_overflow", "desc": "缓冲区溢出"},
                {"strategy": "format_string", "desc": "格式化字符串"},
                {"strategy": "rop_chains", "desc": "ROP 链构建"},
            ],
            "forensics": [
                {"strategy": "file_carving", "desc": "文件恢复"},
                {"strategy": "steganography", "desc": "隐写分析"},
                {"strategy": "memory_analysis", "desc": "内存取证"},
            ],
            "rev": [
                {"strategy": "static_analysis", "desc": "静态分析"},
                {"strategy": "dynamic_analysis", "desc": "动态分析"},
                {"strategy": "algorithm_recovery", "desc": "算法还原"},
            ],
        }
        return strategies.get(category, [{"strategy": "generic", "desc": "通用分析"}])

    @staticmethod
    def _build_steps(ch: CTFChallenge) -> List[Dict[str, Any]]:
        generic = [
            {"step": 1, "action": "analysis", "desc": "分析挑战信息"},
            {"step": 2, "action": "research", "desc": "搜索相关技术"},
            {"step": 3, "action": "implementation", "desc": "实施攻击方案"},
            {"step": 4, "action": "testing", "desc": "测试解决方案"},
            {"step": 5, "action": "flag_extraction", "desc": "提取 Flag"},
        ]
        return generic

    @staticmethod
    def _parallel_tasks(category: str) -> List[Dict[str, Any]]:
        mapping: Dict[str, List[Dict[str, Any]]] = {
            "web": [{"group": "recon", "tasks": ["httpx", "katana", "gau"], "max": 3}],
            "crypto": [{"group": "cracking", "tasks": ["hashcat", "john"], "max": 2}],
            "pwn": [{"group": "analysis", "tasks": ["checksec", "file", "strings"], "max": 3}],
            "forensics": [{"group": "file_analysis", "tasks": ["binwalk", "foremost", "strings"], "max": 3}],
            "rev": [{"group": "initial", "tasks": ["file", "strings", "checksec"], "max": 3}],
        }
        return mapping.get(category, [])

    @staticmethod
    def _estimate_time(ch: CTFChallenge) -> int:
        base = {"easy": 1800, "medium": 3600, "hard": 7200, "insane": 14400, "unknown": 5400}
        mult = {"web": 1.0, "crypto": 1.3, "pwn": 1.5, "forensics": 1.2, "rev": 1.4, "misc": 0.8, "osint": 0.9}
        return int(base.get(ch.difficulty, 5400) * mult.get(ch.category, 1.0))

    @staticmethod
    def _success_prob(ch: CTFChallenge) -> float:
        return {"easy": 0.85, "medium": 0.65, "hard": 0.45, "insane": 0.25, "unknown": 0.55}.get(ch.difficulty, 0.55)


ctf_manager = CTFWorkflowManager()
