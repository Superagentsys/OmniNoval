import os
import logging
from typing import Literal, Optional, Union, Dict, Any

from langchain_core.language_models import BaseLanguageModel
from langchain_community.chat_models import ChatLiteLLM

from src.config import (
    REASONING_MODEL,
    BASIC_MODEL,
    VL_MODEL,
)

logger = logging.getLogger(__name__)

# LLM type definitions
LLMType = Literal["reasoning", "basic", "vision"]

def get_llm_by_type(
    llm_type: Union[LLMType, str], 
    model_kwargs: Optional[Dict[str, Any]] = None
) -> BaseLanguageModel:
    """
    Get a language model instance by its type.
    
    Args:
        llm_type: The type of LLM to return
        model_kwargs: Additional model parameters to override defaults
        
    Returns:
        A language model instance
    """
    model_kwargs = model_kwargs or {}
    
    if llm_type == "reasoning":
        model_config = REASONING_MODEL
        if not model_config:
            logger.warning("Reasoning model not configured, falling back to basic model")
            return get_llm_by_type("basic", model_kwargs)
    elif llm_type == "basic":
        model_config = BASIC_MODEL
        if not model_config:
            logger.error("Basic model not configured")
            raise ValueError("Basic model configuration is required")
    elif llm_type == "vision":
        model_config = VL_MODEL
        if not model_config:
            logger.warning("Vision model not configured, falling back to basic model")
            return get_llm_by_type("basic", model_kwargs)
    else:
        # For agent-specific types, map to appropriate models
        from src.config.agents import AGENT_LLM_MAP
        if llm_type in AGENT_LLM_MAP:
            return get_llm_by_type(AGENT_LLM_MAP[llm_type], model_kwargs)
        else:
            logger.error(f"Unknown LLM type: {llm_type}")
            raise ValueError(f"Unknown LLM type: {llm_type}")
            
    # Merge model configs with any overrides
    final_kwargs = {**model_config, **model_kwargs}
    
    logger.debug(f"Creating LLM with config: {final_kwargs}")
    
    # Create LLM via litellm
    return ChatLiteLLM(**final_kwargs) 