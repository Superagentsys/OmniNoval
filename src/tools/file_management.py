from langchain_core.tools import tool
from pathlib import Path


@tool("write_file")
def write_file_tool(path: str, content: str) -> str:
    """Write text content to a file path, creating parent directories.

    Args:
        path: File path to write
        content: Text content to write

    Returns:
        A confirmation message with the file path
    """
    file_path = Path(path).expanduser().resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} chars to {file_path}"


