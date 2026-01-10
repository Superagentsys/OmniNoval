import json
import logging
import json_repair

logger = logging.getLogger(__name__)

def repair_json_output(content: str) -> str:
    """
    Attempt to repair JSON output from LLM responses.
    
    Args:
        content: The content to repair
        
    Returns:
        Repaired content or original content if repair fails
    """
    # Check if content appears to contain JSON
    if not ("{" in content and "}" in content):
        return content
        
    try:
        # Try to find and repair JSON in content
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = content[json_start:json_end]
            try:
                # First try to parse as is
                json.loads(json_str)
                return content
            except json.JSONDecodeError:
                # If fails, try to repair
                repaired = json_repair.loads(json_str)
                repaired_str = json.dumps(repaired)
                return content[:json_start] + repaired_str + content[json_end:]
    except Exception as e:
        logger.debug(f"JSON repair failed: {e}")
        
    return content 