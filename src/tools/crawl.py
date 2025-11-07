from langchain_core.tools import tool
from typing import Optional

import requests
from bs4 import BeautifulSoup


@tool("crawl")
def crawl_tool(url: str) -> str:
    """Fetch a URL and return the title and a text snippet.

    Args:
        url: The URL to fetch

    Returns:
        A string containing page title and first part of the text content
    """
    if not url:
        return "No URL provided."

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        title: Optional[str] = soup.title.string if soup.title else None
        text = soup.get_text(separator="\n")
        cleaned_lines = [line.strip() for line in text.splitlines() if line.strip()]
        snippet = "\n".join(cleaned_lines)[:2000]

        title_part = f"Title: {title}\n\n" if title else ""
        return f"{title_part}Content:\n{snippet}"
    except Exception as exc:  # noqa: BLE001
        return f"Failed to crawl {url}: {exc}"


