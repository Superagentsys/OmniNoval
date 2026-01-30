"""
Enhanced Process Manager with resource monitoring and caching.
Inspired by hexstrike-ai's EnhancedProcessManager.
"""

import os
import subprocess
import threading
import time
import logging
import hashlib
import json
import asyncio
import re
from typing import Dict, List, Any, Optional, Union, Callable
from collections import OrderedDict
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"

@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds

class IntelligentErrorHandler:
    """Advanced error handling with automatic recovery strategies"""

    def __init__(self):
        self.error_patterns = {
            r"timeout|timed out": ErrorType.TIMEOUT,
            r"permission denied|access denied": ErrorType.PERMISSION_DENIED,
            r"network unreachable|connection refused": ErrorType.NETWORK_UNREACHABLE,
            r"rate limit|too many requests|429": ErrorType.RATE_LIMITED,
            r"command not found|not found": ErrorType.TOOL_NOT_FOUND,
            r"invalid argument|bad parameter": ErrorType.INVALID_PARAMETERS,
        }
        self.tool_alternatives = {
            "nmap": ["rustscan", "masscan"],
            "gobuster": ["dirsearch", "feroxbuster", "ffuf"],
            "nuclei": ["nikto", "jaeles"],
            "subfinder": ["amass", "assetfinder"],
        }

    def classify_error(self, error_message: str) -> ErrorType:
        for pattern, error_type in self.error_patterns.items():
            if re.search(pattern, error_message, re.IGNORECASE):
                return error_type
        return ErrorType.UNKNOWN

    def get_recovery_strategy(self, tool_name: str, error_type: ErrorType, attempt: int) -> RecoveryStrategy:
        if error_type == ErrorType.TIMEOUT:
            return RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"delay": 5}, 3, 2.0, 0.7, 30)
        if error_type == ErrorType.RATE_LIMITED:
            return RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"delay": 2}, 2, 1.0, 0.8, 60)
        if tool_name in self.tool_alternatives:
            return RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"alternatives": self.tool_alternatives[tool_name]}, 1, 1.0, 0.6, 60)
        return RecoveryStrategy(RecoveryAction.ABORT_OPERATION, {}, 1, 1.0, 0.0, 0)

class AdvancedCache:
    """Advanced caching system with intelligent TTL and LRU eviction"""

    def __init__(self, max_size=1000, default_ttl=3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.ttl_times = {}
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def _generate_key(self, tool: str, args: List[str]) -> str:
        key_data = f"{tool}:{json.dumps(args, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, tool: str, args: List[str]) -> Optional[Dict[str, Any]]:
        key = self._generate_key(tool, args)
        with self.lock:
            if key in self.cache:
                timestamp, result = self.cache[key]
                if time.time() - timestamp < self.ttl_times.get(key, self.default_ttl):
                    self.cache.move_to_end(key)
                    self.hits += 1
                    return result
                else:
                    del self.cache[key]
                    if key in self.ttl_times:
                        del self.ttl_times[key]
            self.misses += 1
            return None

    def set(self, tool: str, args: List[str], result: Dict[str, Any], ttl: int = None):
        key = self._generate_key(tool, args)
        with self.lock:
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            self.cache[key] = (time.time(), result)
            self.ttl_times[key] = ttl or self.default_ttl
            self.cache.move_to_end(key)

class ResourceMonitor:
    """Monitor system resources for smart execution"""
    
    @staticmethod
    def get_usage() -> Dict[str, float]:
        try:
            import psutil
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent
            }
        except ImportError:
            return {"cpu_percent": 0.0, "memory_percent": 0.0}

class EnhancedProcessManager:
    """Advanced process management for security tools"""

    def __init__(self):
        self.cache = AdvancedCache()
        self.error_handler = IntelligentErrorHandler()
        self.active_processes = {}
        self.lock = threading.Lock()
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0
        }

    async def run_command_async(
        self, 
        tool_name: str, 
        args: List[str], 
        timeout: int = 300, 
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """Execute command with resource awareness, caching and intelligent recovery"""
        
        if use_cache:
            cached = self.cache.get(tool_name, args)
            if cached:
                logger.info(f"Using cached result for {tool_name}")
                return cached

        attempt = 0
        max_attempts = 3
        current_args = list(args)

        while attempt < max_attempts:
            attempt += 1
            start_time = time.time()
            
            # Resource-aware execution
            usage = ResourceMonitor.get_usage()
            execution_args = [tool_name] + current_args
            if usage["cpu_percent"] > self.resource_thresholds["cpu_high"] and os.name != 'nt':
                execution_args = ["nice", "-n", "10"] + execution_args

            try:
                process = await asyncio.create_subprocess_exec(
                    *execution_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                with self.lock:
                    self.active_processes[process.pid] = {
                        "tool": tool_name,
                        "start_time": start_time,
                        "process": process
                    }

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), 
                        timeout=timeout
                    )
                    
                    execution_time = time.time() - start_time
                    result = {
                        "success": process.returncode == 0,
                        "stdout": stdout.decode('utf-8', errors='ignore'),
                        "stderr": stderr.decode('utf-8', errors='ignore'),
                        "return_code": process.returncode,
                        "execution_time": execution_time,
                        "attempt": attempt
                    }

                    if result["success"]:
                        if use_cache:
                            self.cache.set(tool_name, args, result)
                        return result
                    
                    # Handle failure
                    error_msg = result["stderr"] or result["stdout"]
                    logger.error(f"Command {tool_name} failed (attempt {attempt}). Stderr: {result['stderr']}")
                    error_type = self.error_handler.classify_error(error_msg)
                    strategy = self.error_handler.get_recovery_strategy(tool_name, error_type, attempt)
                    
                    if strategy.action == RecoveryAction.ABORT_OPERATION:
                        return result
                    
                    if strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                        delay = strategy.parameters.get("delay", 5) * (strategy.backoff_multiplier ** (attempt - 1))
                        logger.warning(f"Retrying {tool_name} after {delay}s delay...")
                        await asyncio.sleep(delay)
                        continue
                    
                    if strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                        alt_tools = strategy.parameters.get("alternatives", [])
                        if alt_tools:
                            logger.info(f"Switching from {tool_name} to alternative tool: {alt_tools[0]}")
                            return await self.run_command_async(alt_tools[0], args, timeout, use_cache)

                finally:
                    with self.lock:
                        if process.pid in self.active_processes:
                            del self.active_processes[process.pid]

            except asyncio.TimeoutError:
                logger.error(f"Command {tool_name} timed out")
                if attempt < max_attempts:
                    continue
                return {"success": False, "error": "Timeout", "execution_time": timeout}
            except Exception as e:
                logger.error(f"Error running {tool_name}: {e}")
                return {"success": False, "error": str(e), "execution_time": time.time() - start_time}

        return {"success": False, "error": "Max attempts reached", "execution_time": 0}

# Global instance
process_manager = EnhancedProcessManager()

