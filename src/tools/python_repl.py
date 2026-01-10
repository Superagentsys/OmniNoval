from langchain_core.tools import tool


@tool("python_repl")
def python_repl_tool(code: str) -> str:
    """Execute a small Python snippet and return stdout or repr of result.

    WARNING: This executes arbitrary code. Use only in trusted contexts.
    """
    global_namespace = {}
    local_namespace = {}
    try:
        exec(code, global_namespace, local_namespace)
        # Prefer explicit variable named `_` as convention for result
        if "_" in local_namespace:
            return repr(local_namespace["_"])
        return "Executed successfully."
    except Exception as exc:  # noqa: BLE001
        return f"Execution error: {exc}"


