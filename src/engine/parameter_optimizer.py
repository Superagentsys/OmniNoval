"""
Parameter Optimizer for security tools.
Inspired by hexstrike-ai's ParameterOptimizer.
"""

import logging
from typing import Dict, List, Any, Optional
from .decision_engine import TargetProfile, TargetType

logger = logging.getLogger(__name__)

class ParameterOptimizer:
    """Intelligent parameter optimization for various security tools"""

    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> List[str]:
        """Optimize parameters for a specific tool based on target profile"""
        context = context or {}
        
        if tool == "nmap":
            return self._optimize_nmap(profile, context)
        elif tool == "gobuster":
            return self._optimize_gobuster(profile, context)
        elif tool == "nuclei":
            return self._optimize_nuclei(profile, context)
        elif tool == "sqlmap":
            return self._optimize_sqlmap(profile, context)
        
        # Default fallback
        return []

    def _optimize_nmap(self, profile: TargetProfile, context: Dict[str, Any]) -> List[str]:
        args = ["-sV"]
        
        if profile.target_type == TargetType.NETWORK_HOST:
            # Faster scan for network hosts
            args.extend(["-T4", "-F"])
        else:
            # Comprehensive scan for web apps/domains
            args.extend(["-T3", "-p", context.get("ports", "1-1000")])
            
        if context.get("stealth", False):
            args.append("-sS")
            
        return args

    def _optimize_gobuster(self, profile: TargetProfile, context: Dict[str, Any]) -> List[str]:
        args = ["dir", "-q"]
        
        # Wordlist selection based on tech
        if "wordpress" in profile.technologies:
            args.extend(["-w", "/usr/share/wordlists/dirb/common.txt"]) # Example
        else:
            args.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])
            
        if context.get("extensions"):
            args.extend(["-x", ",".join(context["extensions"])])
            
        return args

    def _optimize_nuclei(self, profile: TargetProfile, context: Dict[str, Any]) -> List[str]:
        args = ["-silent"]
        
        if context.get("severity"):
            args.extend(["-severity", ",".join(context["severity"])])
            
        if profile.technologies:
            # Add specific templates based on detected technologies
            for tech in profile.technologies:
                args.extend(["-t", f"technologies/{tech}"])
                
        return args

    def _optimize_sqlmap(self, profile: TargetProfile, context: Dict[str, Any]) -> List[str]:
        args = ["--batch", "--random-agent"]
        
        if context.get("level"):
            args.extend(["--level", str(context["level"])])
            
        if context.get("risk"):
            args.extend(["--risk", str(context["risk"])])
            
        return args

# Global instance
parameter_optimizer = ParameterOptimizer()

