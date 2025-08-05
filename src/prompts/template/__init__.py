import os
import logging
from pathlib import Path
from typing import Dict, List, Union

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

def load_template(template_name: str) -> str:
    """Load a prompt template from the templates directory."""
    template_path = Path(__file__).parent / f"{template_name}.txt"
    if not template_path.exists():
        logger.warning(f"Template {template_name} not found at {template_path}")
        return ""
        
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def apply_prompt_template(template_name: str, state: Dict) -> List[BaseMessage]:
    """Apply a prompt template with the current state information."""
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