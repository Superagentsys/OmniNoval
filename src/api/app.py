from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import time
import logging
from datetime import datetime

from src.workflow import run_agent_workflow
from src.utils.process_manager import process_manager
from src.engine.decision_engine import decision_engine
from src.tools.security_tools import security_tools

# Configure logging
logger = logging.getLogger(__name__)

app = FastAPI(
    title="OmniNoval API Server",
    description="Advanced multimodal multi-agent automation framework",
    version="0.1.0"
)

class WorkflowRequest(BaseModel):
    user_input: str
    debug: Optional[bool] = False

class AnalysisRequest(BaseModel):
    target: str
    objective: Optional[str] = "comprehensive"

@app.get("/health")
async def health_check():
    """Health check endpoint with tool availability information"""
    tools = security_tools.get_available_tools()
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "tools_available": tools,
        "process_stats": {
            "active_count": len(process_manager.active_processes),
            "cache_hits": process_manager.cache.hits,
            "cache_misses": process_manager.cache.misses
        }
    }

@app.post("/workflow")
async def execute_workflow(request: WorkflowRequest):
    """Execute a LangGraph agent workflow"""
    try:
        logger.info(f"Received workflow request: {request.user_input}")
        result = run_agent_workflow(request.user_input, debug=request.debug)
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        logger.error(f"Workflow execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/intelligence/analyze-target")
async def analyze_target(request: AnalysisRequest):
    """Analyze a target and create a profile using the Intelligent Decision Engine"""
    try:
        profile = decision_engine.analyze_target(request.target)
        selected_tools = decision_engine.select_optimal_tools(profile, objective=request.objective)
        attack_chain = decision_engine.create_attack_chain(profile, objective=request.objective)
        
        return {
            "success": True,
            "target_profile": profile.to_dict(),
            "recommended_tools": selected_tools,
            "attack_chain": attack_chain.to_dict(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Target analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/process/performance-dashboard")
async def get_performance_dashboard():
    """Get system performance metrics and cache statistics"""
    return {
        "cache_stats": {
            "hits": process_manager.cache.hits,
            "misses": process_manager.cache.misses,
            "size": len(process_manager.cache.cache)
        },
        "active_processes": len(process_manager.active_processes),
        "system_status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/processes/list")
async def list_processes():
    """List all active security tool processes"""
    processes = []
    with process_manager.lock:
        for pid, info in process_manager.active_processes.items():
            processes.append({
                "pid": pid,
                "tool": info["tool"],
                "start_time": datetime.fromtimestamp(info["start_time"]).isoformat(),
                "duration": time.time() - info["start_time"]
            })
    return {"processes": processes}

@app.get("/api/cache/stats")
async def cache_stats():
    """Get cache performance statistics"""
    return {
        "hits": process_manager.cache.hits,
        "misses": process_manager.cache.misses,
        "size": len(process_manager.cache.cache),
        "max_size": process_manager.cache.max_size
    }

