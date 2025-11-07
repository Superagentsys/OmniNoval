from langchain_core.tools import tool
import subprocess


@tool("bash")
def bash_tool(command: str) -> str:
    """Execute a bash command and return combined stdout/stderr.

    WARNING: This executes arbitrary commands. Use only in trusted contexts.
    """
    try:
        proc = subprocess.run(
            command, shell=True, check=False, capture_output=True, text=True
        )
        output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        return output.strip()
    except Exception as exc:  # noqa: BLE001
        return f"Bash error: {exc}"


