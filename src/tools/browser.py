from langchain_core.tools import tool
from playwright.sync_api import sync_playwright


@tool("browser")
def browser_tool(url: str, wait_ms: int = 1500) -> str:
    """Open a headless Chromium page and return title + first text snippet."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=30000)
            page.wait_for_timeout(wait_ms)
            title = page.title()
            content = page.content()
            browser.close()
            snippet = content[:2000]
            return f"Title: {title}\n\nHTML snippet:\n{snippet}"
    except Exception as exc:  # noqa: BLE001
        return f"Browser error: {exc}"


