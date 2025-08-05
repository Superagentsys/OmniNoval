from enum import Enum
from typing import Dict, List, TypedDict, Union, Literal

from langchain_core.messages import BaseMessage

# Define the team members
TEAM_MEMBERS = ["researcher", "coder", "browser", "reporter"]


class Router(TypedDict):
    """Router schema for the agents graph."""

    next: Union[Literal["researcher", "coder", "browser", "reporter", "FINISH"], str]


class State(TypedDict):
    """State schema for the OmniNova workflow graph."""

    # Constants
    TEAM_MEMBERS: List[str]
    TEAM_MEMBER_CONFIGRATIONS: Dict

    # Variables
    messages: List[Union[BaseMessage, Dict]]
    next: str
    full_plan: str
    deep_thinking_mode: bool
    search_before_planning: bool 