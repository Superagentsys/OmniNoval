# Map agent types to their LLM type requirements
AGENT_LLM_MAP = {
    "coordinator": "basic",
    "planner": "reasoning",
    "supervisor": "reasoning",
    "researcher": "basic",
    "coder": "basic",
    "browser": "basic",
    "reporter": "basic",
    "vulun_agent": "reasoning",
    "bug_bounty_agent": "reasoning",
    "ctf_agent": "reasoning",
    "cve_intel_agent": "reasoning",
} 