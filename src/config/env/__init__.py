import os
from dotenv import load_dotenv
from src.config.loader import load_yaml_config

# Load .env file if exists
load_dotenv()

# Load configuration
yaml_config = load_yaml_config()
USE_CONF = yaml_config.get("USE_CONF", False) if yaml_config else False

# Azure OpenAI settings
AZURE_API_BASE = os.getenv("AZURE_API_BASE")
AZURE_API_KEY = os.getenv("AZURE_API_KEY")
AZURE_API_VERSION = os.getenv("AZURE_API_VERSION", "2023-05-15")

# Reasoning LLM
REASONING_MODEL = None
REASONING_BASE_URL = os.getenv("REASONING_BASE_URL")
REASONING_API_KEY = os.getenv("REASONING_API_KEY")
REASONING_AZURE_DEPLOYMENT = os.getenv("REASONING_AZURE_DEPLOYMENT")

# Basic LLM
BASIC_MODEL = None
BASIC_BASE_URL = os.getenv("BASIC_BASE_URL")
BASIC_API_KEY = os.getenv("BASIC_API_KEY")
BASIC_AZURE_DEPLOYMENT = os.getenv("BASIC_AZURE_DEPLOYMENT")

# Vision-language LLM
VL_MODEL = None
VL_BASE_URL = os.getenv("VL_BASE_URL")
VL_API_KEY = os.getenv("VL_API_KEY")
VL_AZURE_DEPLOYMENT = os.getenv("VL_AZURE_DEPLOYMENT")

# Chrome configuration
CHROME_INSTANCE_PATH = os.getenv("CHROME_INSTANCE_PATH")
CHROME_HEADLESS = os.getenv("CHROME_HEADLESS", "False").lower() in ("true", "1", "t")
CHROME_PROXY_SERVER = os.getenv("CHROME_PROXY_SERVER")
CHROME_PROXY_USERNAME = os.getenv("CHROME_PROXY_USERNAME")
CHROME_PROXY_PASSWORD = os.getenv("CHROME_PROXY_PASSWORD")

# Override with YAML config if enabled
if USE_CONF and yaml_config:
    if "REASONING_MODEL" in yaml_config:
        REASONING_MODEL = yaml_config["REASONING_MODEL"]
    if "BASIC_MODEL" in yaml_config:
        BASIC_MODEL = yaml_config["BASIC_MODEL"]
    if "VISION_MODEL" in yaml_config:
        VL_MODEL = yaml_config["VISION_MODEL"] 