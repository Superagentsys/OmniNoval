from langchain_core.tools import tool
from tavily import TavilyClient
import os


@tool("tavily_search")
def tavily_tool(query: str, max_results: int = 5) -> str:
    """Use Tavily search API to fetch web results and return a compact summary.

    Requires TAVILY_API_KEY in environment.
    """
    api_key = os.getenv("TAVILY_API_KEY")
    if not api_key:
        return "TAVILY_API_KEY not set."

    client = TavilyClient(api_key=api_key)
    try:
        result = client.search(query=query, max_results=max_results)
        items = result.get("results") or []
        if not items:
            return "No results found."
        lines = []
        for i, item in enumerate(items, start=1):
            title = item.get("title") or "(no title)"
            url = item.get("url") or ""
            snippet = (item.get("content") or "").strip().replace("\n", " ")
            snippet = snippet[:280]
            lines.append(f"{i}. {title}\n{url}\n{snippet}")
        return "\n\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"Search error: {exc}"


