from langgraph.prebuilt import create_react_agent

from src.prompts import apply_prompt_template
from src.tools import (
    bash_tool,
    browser_tool,
    crawl_tool,
    python_repl_tool,
    tavily_tool,
)
from src.tools.vulun_tools import vulun_tools

from src.llms.llm import get_llm_by_type
from src.config.agents import AGENT_LLM_MAP


# Create agents using configured LLM types
def create_agent(agent_type: str, tools: list, prompt_template: str):
    """Factory function to create agents with consistent configuration."""
    return create_react_agent(
        get_llm_by_type(AGENT_LLM_MAP[agent_type]),
        tools=tools,
        prompt=lambda state: apply_prompt_template(prompt_template, state),
    )


# Create agents using the factory function
research_agent = create_agent("researcher", [tavily_tool, crawl_tool], "researcher")
coder_agent = create_agent("coder", [python_repl_tool, bash_tool], "coder")
browser_agent = create_agent("browser", [browser_tool], "browser")
vulun_agent = create_agent("vulun_agent", vulun_tools, "vulun_agent")

# Specialized Security Agents inspired by hexstrike
bug_bounty_agent = create_agent("bug_bounty_agent", vulun_tools + [tavily_tool, browser_tool], "bug_bounty_agent")
ctf_agent = create_agent("ctf_agent", vulun_tools + [python_repl_tool, bash_tool], "ctf_agent")
cve_intel_agent = create_agent("cve_intel_agent", [tavily_tool, crawl_tool], "cve_intel_agent")
 