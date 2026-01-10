"""
CLI Entry point for the OmniNoval Framework.
Improved with specialized security command support.
"""

import argparse
import sys
import logging
from src.workflow import run_agent_workflow
from src.engine.decision_engine import decision_engine

def print_banner():
    """Print the OmniNoval CLI banner"""
    banner = r"""
    ========================================================================
       ____                 _ _   _                 _ 
      / __ \               (_) \ | |               | |
     | |  | |_ __ ___  _ __  _|  \| | _____   ____ _| |
     | |  | | '_ ` _ \| '_ \| | . ` |/ _ \ \ / / _` | |
     | |__| | | | | | | | | | | |\  | (_) \ V / (_| | |
      \____/|_| |_| |_|_| |_|_|_| \_|\___/ \_/ \__,_|_|
                                                        
      OmniNoval CLI - Advanced AI Cybersecurity Automation
    ========================================================================
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="OmniNoval CLI - Advanced Multi-Agent Framework")
    parser.add_argument("query", nargs="?", help="Your query or instruction for the agents")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--analyze", metavar="TARGET", help="Analyze a target using the Intelligent Decision Engine")
    
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    print_banner()

    if args.analyze:
        print(f"🧠 Analyzing target: {args.analyze}")
        profile = decision_engine.analyze_target(args.analyze)
        selected_tools = decision_engine.select_optimal_tools(profile)
        
        print("\n=== Target Profile ===")
        print(f"Target: {profile.target}")
        print(f"Type: {profile.target_type.value}")
        print(f"Risk Level: {profile.risk_level}")
        
        print("\n=== Recommended Tools ===")
        for i, tool in enumerate(selected_tools, 1):
            print(f"{i}. {tool}")
        return

    user_query = args.query
    if not user_query:
        user_query = input("Enter your query: ")

    if not user_query:
        print("Error: No query provided.")
        sys.exit(1)

    print(f"🚀 Running workflow for: {user_query}")
    result = run_agent_workflow(user_input=user_query, debug=args.debug)

    # Print the conversation history
    print("\n=== Workflow Results ===")
    for message in result.get("messages", []):
        role = getattr(message, "type", "unknown")
        print(f"\n[{role.upper()}]: {message.content}")

if __name__ == "__main__":
    main()
