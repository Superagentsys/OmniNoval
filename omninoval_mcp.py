#!/usr/bin/env python3
"""
OmniNoval MCP Client - 适配高级多模态多智能体自动化渗透框架
基于 FastMCP 构建，实现 AI 智能体与 OmniNoval 后端的深度集成

架构: 基于 FastMCP 的工具编排接口
功能: 目标画像分析、自动化工作流执行、实时进程监控
"""

import sys
import os
import argparse
import logging
import requests
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# ============================================================================
# 视觉与颜色配置 (复刻 HexStrike 风格)
# ============================================================================

class OmniNovalColors:
    """视觉配色方案，保持与框架一致的红色黑客主题"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # 核心增强颜色
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    FIRE_RED = '\033[38;5;202m'
    BLOOD_RED = '\033[38;5;124m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # 状态颜色
    SUCCESS = MATRIX_GREEN
    WARNING = CYBER_ORANGE
    ERROR = HACKER_RED
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'
    INFO = NEON_BLUE

class ColoredFormatter(logging.Formatter):
    """增强型日志格式化器，支持颜色和表情符号"""
    COLORS = {
        'DEBUG': '\033[38;5;240m',
        'INFO': OmniNovalColors.SUCCESS,
        'WARNING': OmniNovalColors.WARNING,
        'ERROR': OmniNovalColors.ERROR,
        'CRITICAL': OmniNovalColors.CRITICAL
    }
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, OmniNovalColors.RESET)
        record.msg = f"{color}{emoji} {record.msg}{OmniNovalColors.RESET}"
        return super().format(record)

# ============================================================================
# 日志配置
# ============================================================================

def setup_logging(debug=False):
    handler = logging.StreamHandler(sys.stderr)
    formatter = ColoredFormatter(
        "[🚀 OmniNoval MCP] %(asctime)s [%(levelname)s] %(message)s", 
        datefmt="%H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    return logger

logger = logging.getLogger(__name__)

# ============================================================================
# 客户端实现
# ============================================================================

class OmniNovalClient:
    """与 OmniNoval FastAPI 后端通信的增强型客户端"""

    def __init__(self, server_url: str, timeout: int = 300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self._validate_connection()

    def _validate_connection(self):
        """验证与后端的连接并打印状态"""
        try:
            logger.info(f"🔗 正在尝试连接 OmniNoval 后端: {self.server_url}")
            response = self.session.get(f"{self.server_url}/health", timeout=5)
            response.raise_for_status()
            health = response.json()
            logger.info(f"🎯 连接成功! 后端版本: {health.get('version', '0.1.0')}")
            logger.info(f"🏥 后端状态: {health.get('status')} | 活跃进程: {health.get('process_stats', {}).get('active_count', 0)}")
            
            # 打印可用工具概览
            tools = health.get('tools_available', [])
            if tools:
                logger.info(f"🧰 后端已就绪，可用工具: {len(tools)} 个")
        except Exception as e:
            logger.warning(f"⚠️ 无法连接到 OmniNoval 后端 ({e})。")
            logger.warning(f"💡 请确保已在终端运行: `uv run server.py --port {self.server_url.split(':')[-1]}`")

    def safe_post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """线程安全的 POST 请求封装"""
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"📡 POST {url} | 数据: {data}")
            response = self.session.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"🚫 请求失败: {str(e)}")
            return {"success": False, "error": str(e)}

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """线程安全的 GET 请求封装"""
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"📡 GET {url} | 参数: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"🚫 请求失败: {str(e)}")
            return {"success": False, "error": str(e)}

# ============================================================================
# MCP 工具注册
# ============================================================================

def setup_mcp_server(client: OmniNovalClient) -> FastMCP:
    """初始化并配置 FastMCP 服务端工具集"""
    mcp = FastMCP("OmniNoval-Security-Suite")

    # --- 核心扫描与分析工具 ---

    @mcp.tool()
    def analyze_target_intelligence(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        调用智能决策引擎 (IDE) 对目标进行深度画像分析并推荐最佳工具组合。
        
        Args:
            target: 目标 URL (https://example.com), IP 地址 (192.168.1.1) 或 域名 (example.com)。
            objective: 扫描目标模式。'quick' (快速), 'comprehensive' (全面), 'stealth' (隐写)。
        """
        logger.info(f"🧠 正在分析目标画像: {OmniNovalColors.BOLD}{target}{OmniNovalColors.RESET} (模式: {objective})")
        result = client.safe_post("api/intelligence/analyze-target", {"target": target, "objective": objective})
        if result.get("success"):
            profile = result.get("target_profile", {})
            logger.info(f"✅ 画像完成 - 类型: {profile.get('target_type')} | 推荐工具: {len(result.get('recommended_tools', []))} 个")
        return result

    @mcp.tool()
    def execute_automated_workflow(user_input: str, debug: bool = False) -> Dict[str, Any]:
        """
        启动基于 LangGraph 的多智能体协同自动化渗透测试工作流。
        AI 将自动协调 BugBountyAgent, CTFAgent 和 CVEIntelAgent 来完成复杂的安全任务。
        
        Args:
            user_input: 给 Agent 的自然语言指令。例如: '对 http://test.com 进行全面扫描并查找 SQL 注入'。
            debug: 是否在控制台输出详细的图执行状态。
        """
        logger.info(f"{OmniNovalColors.FIRE_RED}🚀 启动自动化协同工作流: {OmniNovalColors.RESET}{user_input[:100]}...")
        return client.safe_post("workflow", {"user_input": user_input, "debug": debug})

    # --- 系统监控与资源管理 ---

    @mcp.tool()
    def get_server_health() -> Dict[str, Any]:
        """查看 OmniNoval API 服务器的健康状态、工具可用性清单以及进程统计信息。"""
        logger.info("🏥 正在查询服务器健康状态...")
        return client.safe_get("health")

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """列出当前后端正在执行的所有安全工具进程及其运行时长。"""
        logger.info("📊 正在获取活跃进程列表...")
        return client.safe_get("api/processes/list")

    @mcp.tool()
    def get_cache_statistics() -> Dict[str, Any]:
        """获取进程管理器的缓存命中率和存储情况。有助于了解任务加速效果。"""
        logger.info("💾 正在查询缓存统计...")
        return client.safe_get("api/cache/stats")

    return mcp

# ============================================================================
# 启动入口
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="OmniNoval AI MCP Server v6.0")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="OmniNoval API 服务地址 (默认: http://127.0.0.1:8000)")
    parser.add_argument("--timeout", type=int, default=300, help="API 请求超时时间 (秒)")
    parser.add_argument("--debug", action="store_true", help="启用调试日志")
    return parser.parse_args()

def main():
    args = parse_args()
    setup_logging(args.debug)
    
    logger.info(f"{OmniNovalColors.BOLD}{OmniNovalColors.HACKER_RED}===================================================={OmniNovalColors.RESET}")
    logger.info(f"{OmniNovalColors.BOLD}🚀 OmniNoval AI MCP Client v6.0 已启动{OmniNovalColors.RESET}")
    logger.info(f"{OmniNovalColors.BOLD}{OmniNovalColors.HACKER_RED}===================================================={OmniNovalColors.RESET}")

    try:
        # 初始化客户端
        client = OmniNovalClient(args.server, args.timeout)
        
        # 启动 MCP 服务
        mcp = setup_mcp_server(client)
        
        logger.info(f"🤖 MCP 工具集已就绪，正在接入 AI 智能体编排层...")
        mcp.run()
        
    except Exception as e:
        logger.error(f"💥 MCP 服务启动失败: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
