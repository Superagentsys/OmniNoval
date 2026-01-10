import os
from pathlib import Path

# Tavily search configuration
TAVILY_MAX_RESULTS = 5

# Browser configuration
BROWSER_HISTORY_DIR = Path(os.path.expanduser("~/.omninova/browser_history")).resolve() 