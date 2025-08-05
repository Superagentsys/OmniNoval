import os
import yaml
import logging

logger = logging.getLogger(__name__)

def load_yaml_config(config_path: str = "conf.yaml") -> dict:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the YAML config file
        
    Returns:
        Dict containing configuration or None if file doesn't exist
    """
    if not os.path.exists(config_path):
        logger.warning(f"Configuration file {config_path} not found")
        return None
        
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None 