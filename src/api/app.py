from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import asyncio
from typing import Dict, Any, Optional
import time
import logging
import os
from datetime import datetime
from sqlalchemy.orm import Session

from src.workflow import run_agent_workflow
from src.utils.process_manager import process_manager
from src.engine.decision_engine import decision_engine
from src.tools.security_tools import security_tools
from src.db.database import get_db, engine, Base
from src.db.models.models import TaskStatus, Severity
from src.service.report_service import ScanService, ReportService

# Create database tables
Base.metadata.create_all(bind=engine)

# Configure logging
logger = logging.getLogger(__name__)

app = FastAPI(
    title="OmniNoval API Server",
    description="Advanced multimodal multi-agent automation framework",
    version="0.1.0"
)

# CORS (for separated frontend)
# - Default: allow all origins (no credentials)
# - Customize via env: OMNINOVAL_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:8080"
_origins_env = os.getenv("OMNINOVAL_CORS_ORIGINS", "").strip()
if _origins_env:
    _allow_origins = [o.strip() for o in _origins_env.split(",") if o.strip()]
else:
    _allow_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def read_root():
    return {
        "name": "OmniNoval API Server",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }

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
    """Execute a LangGraph agent workflow (Synchronous)"""
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

@app.get("/api/workflow/stream")
async def stream_workflow(user_input: str, debug: bool = False):
    """Stream LangGraph agent workflow progress via SSE"""
    from src.workflow import graph
    from src.config import TEAM_MEMBERS, TEAM_MEMBER_CONFIGRATIONS
    
    async def event_generator():
        try:
            # Initial state
            yield f"data: {json.dumps({'type': 'status', 'content': 'Starting workflow...'})}\n\n"
            
            inputs = {
                "TEAM_MEMBERS": TEAM_MEMBERS,
                "TEAM_MEMBER_CONFIGRATIONS": TEAM_MEMBER_CONFIGRATIONS,
                "messages": [{"role": "user", "content": user_input}],
                "deep_thinking_mode": True,
                "search_before_planning": True,
            }

            # Use stream to get updates from nodes
            # Note: LangGraph invoke is sync, but we can wrap it or use stream if compiled properly
            for update in graph.stream(inputs, stream_mode="updates"):
                for node_name, node_update in update.items():
                    # Extract the latest message or state change
                    content = f"Node {node_name} completed."
                    if "messages" in node_update and node_update["messages"]:
                        last_msg = node_update["messages"][-1]
                        # Handle Command objects or BaseMessage objects
                        if hasattr(last_msg, "content"):
                            content = last_msg.content
                        elif isinstance(last_msg, dict) and "content" in last_msg:
                            content = last_msg["content"]
                    
                    yield f"data: {json.dumps({'type': 'node_update', 'node': node_name, 'content': content})}\n\n"
                    await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'type': 'status', 'content': 'Workflow completed successfully.'})}\n\n"
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

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

class ToolRequest(BaseModel):
    tool_name: str
    target: str
    context: Optional[Dict[str, Any]] = None

class CommandRequest(BaseModel):
    command: str
    use_cache: Optional[bool] = True

@app.post("/api/tools/execute")
async def run_smart_tool(request: ToolRequest):
    """Execute a specific security tool with smart parameter optimization"""
    try:
        profile = decision_engine.analyze_target(request.target)
        result = await security_tools.run_smart_tool(
            request.tool_name, 
            request.target, 
            profile, 
            request.context
        )
        return result
    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/command")
async def run_raw_command(request: CommandRequest):
    """Execute an arbitrary shell command (restricted to allowed binaries)"""
    try:
        # Split command into binary and args
        parts = request.command.split()
        if not parts:
            raise HTTPException(status_code=400, detail="Empty command")
        
        binary = parts[0]
        args = parts[1:]
        
        result = await process_manager.run_command_async(
            binary, 
            args, 
            use_cache=request.use_cache
        )
        return result
    except Exception as e:
        logger.error(f"Command execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/intelligence/smart-scan")
async def smart_scan(request: AnalysisRequest, db: Session = Depends(get_db)):
    """Execute a series of optimized tools based on target profile and save results"""
    try:
        profile = decision_engine.analyze_target(request.target)
        
        # 1. Register target
        target = ScanService.create_target(db, request.target, profile.target_type.value)
        
        # 2. Create task
        task = ScanService.create_task(db, target.id, request.objective)
        
        tools = decision_engine.select_optimal_tools(profile, objective=request.objective)
        
        scan_results = []
        try:
            for tool in tools:
                res = await security_tools.run_smart_tool(tool, request.target, profile)
                scan_results.append(res)
                
                # 3. Save findings
                if res.get("status") == "success":
                    # For now, we save everything as an info-level finding
                    # In a production system, you would have a parser for each tool's output
                    ScanService.add_vulnerability(db, task.id, {
                        "name": f"Scan result from {tool}",
                        "severity": Severity.INFO,
                        "tool_name": tool,
                        "raw_output": str(res.get("stdout"))
                    })
            
            # 4. Update task status and generate report
            ScanService.update_task_status(db, task.id, TaskStatus.COMPLETED)
            report = ReportService.generate_report(db, task.id)
            
            return {
                "success": True,
                "target": request.target,
                "task_id": task.id,
                "report_id": report.id,
                "results": scan_results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as scan_err:
            ScanService.update_task_status(db, task.id, TaskStatus.FAILED)
            raise scan_err
            
    except Exception as e:
        logger.error(f"Smart scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports")
async def list_reports(db: Session = Depends(get_db)):
    """List all generated security reports"""
    from src.db.models.models import Report
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    return [{"id": r.id, "task_id": r.task_id, "title": r.title, "created_at": r.created_at} for r in reports]

@app.get("/api/reports/{report_id}")
async def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get detailed content of a specific report"""
    from src.db.models.models import Report
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": report.id,
        "title": report.title,
        "content": report.content,
        "created_at": report.created_at,
        "task_id": report.task_id
    }

@app.get("/api/analysis/summary")
async def get_analysis_summary(db: Session = Depends(get_db)):
    """Get system-wide security analysis statistics"""
    return ReportService.get_statistics(db)

@app.get("/api/tasks")
async def list_tasks(db: Session = Depends(get_db)):
    """List all scan tasks and their status"""
    from src.db.models.models import ScanTask
    tasks = db.query(ScanTask).order_by(ScanTask.start_time.desc()).all()
    return [
        {
            "id": t.id, 
            "target": t.target.address, 
            "status": t.status.value, 
            "scan_type": t.scan_type,
            "start_time": t.start_time,
            "end_time": t.end_time
        } for t in tasks
    ]

