import argparse
import logging
import uvicorn
import os
import sys

# ============================================================================
# PATH CONFIGURATION
# ============================================================================
# 确保项目根目录在 sys.path 中，这样 'src' 模块才能被正确导入
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 验证 app 是否可导入
def check_app_import():
    """Verify that the FastAPI app can be imported correctly."""
    try:
        from src.api.app import app
        return True
    except ImportError as e:
        print(f"致命错误: 无法从 'src.api.app' 导入 'app' 实例。")
        print(f"详细错误信息: {e}")
        print(f"当前 Python 路径: {sys.path[:3]}...")
        return False

from src.tools.advanced_security_tools import OmniNoval_tools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

def print_banner():
    """Print the OmniNoval banner"""
    banner = r"""
    ========================================================================
       ____                 _ _   _                 _ 
      / __ \               (_) \ | |               | |
     | |  | |_ __ ___  _ __  _|  \| | _____   ____ _| |
     | |  | | '_ ` _ \| '_ \| | . ` |/ _ \ \ / / _` | |
     | |__| | | | | | | | | | | |\  | (_) \ V / (_| | |
      \____/|_| |_| |_|_| |_|_|_| \_|\___/ \_/ \__,_|_|
                                                        
      Advanced AI-Powered Cybersecurity Automation Platform
    ========================================================================
    """
    print(banner)

def main():
    """Run the API server with the specified arguments."""
    parser = argparse.ArgumentParser(description="Run the OmniNova API server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the server to")
    parser.add_argument("--port", default=8000, type=int, help="Port to bind the server to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--install-tools", action="store_true", help="Install missing security tools on startup")
    
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    print_banner()

    if args.install_tools:
        logger.info("Checking and installing missing security tools...")
        results = OmniNoval_tools.install_missing_tools()
        for tool, success in results.items():
            status = "Success" if success else "Failed"
            logger.info(f"Tool {tool}: {status}")

    # 启动前最后验证一次导入
    if not check_app_import():
        sys.exit(1)

    logger.info(f"Starting OmniNoval API server on {args.host}:{args.port}")
    
    # Run uvicorn
    try:
        uvicorn.run(
            "src.api.app:app", 
            host=args.host, 
            port=args.port, 
            reload=args.reload,
            app_dir=project_root, # 关键：显式指定应用根目录，解决 uvicorn 找不到模块的问题
            log_level="debug" if args.debug else "info"
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
