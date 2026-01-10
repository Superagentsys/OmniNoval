import os
import logging
from pathlib import Path
from typing import Dict, List, Union

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

def load_template(template_name: str) -> str:
    """Load a prompt template from the templates directory."""
    # 首先尝试加载 .txt 文件
    template_path = Path(__file__).parent / f"{template_name}.txt"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    
    # 如果没有 .txt 文件，尝试从 Python 模块加载
    try:
        if template_name == "vulun_agent":
            from .vulun_agent import get_vulun_agent_prompt
            return get_vulun_agent_prompt({})
        elif template_name == "bug_bounty_agent":
            from .bug_bounty_agent import get_bug_bounty_agent_prompt
            return get_bug_bounty_agent_prompt({})
        elif template_name == "ctf_agent":
            from .ctf_agent import get_ctf_agent_prompt
            return get_ctf_agent_prompt({})
        elif template_name == "cve_intel_agent":
            from .cve_intel_agent import get_cve_intel_agent_prompt
            return get_cve_intel_agent_prompt({})
        else:
            logger.warning(f"Template {template_name} not found at {template_path}")
            return ""
    except ImportError as e:
        logger.warning(f"Failed to import template {template_name}: {e}")
        return ""

def apply_prompt_template(template_name: str, state: Dict) -> List[BaseMessage]:
    """Apply a prompt template with the current state information."""
    # 特殊处理安全代理的提示词
    if template_name == "vulun_agent":
        try:
            from .vulun_agent import get_vulun_agent_prompt
            template = get_vulun_agent_prompt(state)
        except ImportError:
            template = load_template(template_name)
    elif template_name == "bug_bounty_agent":
        try:
            from .bug_bounty_agent import get_bug_bounty_agent_prompt
            template = get_bug_bounty_agent_prompt(state)
        except ImportError:
            template = load_template(template_name)
    elif template_name == "ctf_agent":
        try:
            from .ctf_agent import get_ctf_agent_prompt
            template = get_ctf_agent_prompt(state)
        except ImportError:
            template = load_template(template_name)
    elif template_name == "cve_intel_agent":
        try:
            from .cve_intel_agent import get_cve_intel_agent_prompt
            template = get_cve_intel_agent_prompt(state)
        except ImportError:
            template = load_template(template_name)
    else:
        template = load_template(template_name)
    
    if not template:
        return [SystemMessage(content="Error: Template not found")]
        
    # Extract relevant state information for the template
    messages = state.get("messages", [])
    team_members = state.get("TEAM_MEMBERS", [])
    team_config = state.get("TEAM_MEMBER_CONFIGRATIONS", {})
    full_plan = state.get("full_plan", "")
    
    # Create system message with template
    system_message = SystemMessage(content=template)
    
    # Create conversation history
    history = []
    for msg in messages:
        if isinstance(msg, BaseMessage):
            history.append(msg)
        elif isinstance(msg, dict):
            if msg.get("role") == "user":
                history.append(HumanMessage(content=msg.get("content", "")))
            elif msg.get("role") == "system":
                history.append(SystemMessage(content=msg.get("content", "")))
    
    # Return the full prompt
    return [system_message] + history

def apply_prompt_template_raw(template_name: str, state: Dict) -> str:
    """Apply a prompt template and return raw string (for non-chat models)."""
    messages = apply_prompt_template(template_name, state)
    return "\n\n".join([f"{msg.type}: {msg.content}" for msg in messages]) 