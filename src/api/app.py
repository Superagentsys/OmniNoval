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

# ---- NEW: HexStrike 功能模块 ----
from src.intelligence.cve_intelligence import cve_intelligence
from src.intelligence.exploit_generator import exploit_generator
from src.intelligence.vulnerability_correlator import vulnerability_correlator
from src.intelligence.threat_intelligence import threat_intelligence
from src.tools.http_framework import http_framework
from src.tools.payload_generator import payload_generator
from src.tools.specialized_scanners import graphql_scanner, jwt_analyzer, api_schema_analyzer
from src.workflows.bug_bounty import bugbounty_manager, BugBountyTarget
from src.workflows.ctf_framework import ctf_manager, CTFChallenge

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

# ============================================================================
# CVE Intelligence API (from HexStrike)
# ============================================================================

class CVEMonitorRequest(BaseModel):
    hours: Optional[int] = 24
    severity_filter: Optional[str] = "HIGH,CRITICAL"
    keywords: Optional[str] = ""

class CVEAnalyzeRequest(BaseModel):
    cve_id: str

class ExploitGenerateRequest(BaseModel):
    cve_id: str
    target_arch: Optional[str] = "x64"
    evasion_level: Optional[str] = "none"

@app.post("/api/vuln-intel/cve-monitor")
async def cve_monitor(request: CVEMonitorRequest):
    """实时监控最新 CVE 漏洞并分析可利用性"""
    result = cve_intelligence.fetch_latest_cves(request.hours, request.severity_filter)
    if request.keywords and result.get("success"):
        kws = [k.strip().lower() for k in request.keywords.split(",") if k.strip()]
        result["cves"] = [c for c in result["cves"] if any(k in c.get("description", "").lower() for k in kws)]
        result["total_after_filter"] = len(result["cves"])
    return result

@app.post("/api/vuln-intel/cve-analyze")
async def cve_analyze(request: CVEAnalyzeRequest):
    """分析特定 CVE 的可利用性"""
    return cve_intelligence.analyze_exploitability(request.cve_id)

@app.post("/api/vuln-intel/exploit-search")
async def exploit_search(request: CVEAnalyzeRequest):
    """搜索 CVE 的已公开 Exploit (GitHub / Exploit-DB / Metasploit)"""
    return cve_intelligence.search_existing_exploits(request.cve_id)

@app.post("/api/vuln-intel/exploit-generate")
async def exploit_generate(request: ExploitGenerateRequest):
    """基于 CVE 数据自动生成 PoC exploit 脚本"""
    analysis = cve_intelligence.analyze_exploitability(request.cve_id)
    cve_data = {
        "cve_id": request.cve_id,
        "description": analysis.get("description", ""),
    }
    target_info = {"target_arch": request.target_arch, "evasion_level": request.evasion_level}
    return exploit_generator.generate_from_cve(cve_data, target_info)

# ============================================================================
# Vulnerability Correlator & Threat Intelligence (from HexStrike)
# ============================================================================

class AttackChainRequest(BaseModel):
    target: str
    scan_results: Optional[Dict[str, Any]] = None
    max_depth: Optional[int] = 3

class ThreatIntelRequest(BaseModel):
    indicators: list
    timeframe: Optional[str] = "30d"

@app.post("/api/vuln-intel/attack-chains")
async def discover_attack_chains(request: AttackChainRequest):
    """基于扫描结果发现多阶段攻击链"""
    return vulnerability_correlator.find_attack_chains(
        request.scan_results or {}, request.target, request.max_depth
    )

@app.post("/api/vuln-intel/threat-feeds")
async def aggregate_threat_feeds(request: ThreatIntelRequest):
    """多源威胁情报聚合与评分"""
    return threat_intelligence.correlate(request.indicators, request.timeframe)

# ============================================================================
# HTTP Testing Framework — Burp Suite Alternative (from HexStrike)
# ============================================================================

class HTTPFrameworkRequest(BaseModel):
    action: str = "request"
    url: Optional[str] = ""
    method: Optional[str] = "GET"
    data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 100
    rules: Optional[list] = None
    host: Optional[str] = ""
    include_subdomains: Optional[bool] = True
    params: Optional[list] = None
    payloads: Optional[list] = None
    max_requests: Optional[int] = 100

@app.post("/api/tools/http-framework")
async def http_framework_endpoint(request: HTTPFrameworkRequest):
    """HTTP 安全测试框架 (Burp Suite 替代): request / spider / intruder / repeater / proxy_history / set_scope / set_rules"""
    action = request.action

    if action == "request":
        if not request.url:
            raise HTTPException(400, "url required")
        return http_framework.intercept_request(request.url, request.method, request.data, request.headers, request.cookies)

    if action == "spider":
        if not request.url:
            raise HTTPException(400, "url required")
        return http_framework.spider_website(request.url, request.max_depth, request.max_pages)

    if action == "intruder":
        if not request.url:
            raise HTTPException(400, "url required")
        return http_framework.intruder_sniper(request.url, request.method, request.params, request.payloads, request.max_requests)

    if action == "repeater":
        return http_framework.send_custom_request({"url": request.url, "method": request.method, "data": request.data, "headers": request.headers})

    if action == "proxy_history":
        return {"history": http_framework.get_proxy_history(), "vulnerabilities": http_framework.get_vulnerabilities()}

    if action == "set_scope":
        if not request.host:
            raise HTTPException(400, "host required")
        http_framework.set_scope(request.host, request.include_subdomains)
        return {"success": True, "scope": http_framework.scope}

    if action == "set_rules":
        http_framework.set_match_replace_rules(request.rules or [])
        return {"success": True, "rules_count": len(request.rules or [])}

    raise HTTPException(400, f"Unknown action: {action}")

# ============================================================================
# Payload Generator (from HexStrike)
# ============================================================================

class PayloadRequest(BaseModel):
    attack_type: Optional[str] = "xss"
    complexity: Optional[str] = "basic"
    technology: Optional[str] = ""

@app.post("/api/ai/generate-payload")
async def generate_payload_endpoint(request: PayloadRequest):
    """AI 安全载荷生成 (XSS / SQLi / LFI / RCE / XXE / SSTI)"""
    return payload_generator.generate(request.attack_type, request.complexity, request.technology)

# ============================================================================
# Specialized Scanners — GraphQL / JWT / API Schema (from HexStrike)
# ============================================================================

class GraphQLScanRequest(BaseModel):
    endpoint: str
    query_depth: Optional[int] = 10

class JWTAnalyzeRequest(BaseModel):
    jwt_token: str
    target_url: Optional[str] = ""

class APISchemaScanRequest(BaseModel):
    schema_url: str

@app.post("/api/tools/graphql-scanner")
async def scan_graphql(request: GraphQLScanRequest):
    """GraphQL 端点安全扫描 (introspection / depth / batch)"""
    return graphql_scanner.scan(request.endpoint, request.query_depth)

@app.post("/api/tools/jwt-analyzer")
async def analyze_jwt(request: JWTAnalyzeRequest):
    """JWT Token 安全分析 (算法 / 过期 / none 攻击)"""
    return jwt_analyzer.analyze(request.jwt_token, request.target_url)

@app.post("/api/tools/api-schema-analyzer")
async def analyze_api_schema(request: APISchemaScanRequest):
    """OpenAPI / Swagger Schema 安全审计"""
    return api_schema_analyzer.analyze(request.schema_url)

# ============================================================================
# Bug Bounty Workflows (from HexStrike)
# ============================================================================

class BugBountyRequest(BaseModel):
    domain: str
    scope: Optional[list] = None
    out_of_scope: Optional[list] = None
    program_type: Optional[str] = "web"
    priority_vulns: Optional[list] = None
    include_osint: Optional[bool] = True
    include_business_logic: Optional[bool] = True

@app.post("/api/bugbounty/recon-workflow")
async def bb_recon(request: BugBountyRequest):
    """Bug Bounty 多阶段侦察工作流"""
    t = BugBountyTarget(domain=request.domain, scope=request.scope or [], program_type=request.program_type)
    return bugbounty_manager.create_reconnaissance_workflow(t)

@app.post("/api/bugbounty/hunting-workflow")
async def bb_hunting(request: BugBountyRequest):
    """Bug Bounty 漏洞猎杀工作流 (按影响排序)"""
    t = BugBountyTarget(domain=request.domain, priority_vulns=request.priority_vulns or ["rce", "sqli", "xss", "idor", "ssrf"])
    return bugbounty_manager.create_vulnerability_hunting_workflow(t)

@app.post("/api/bugbounty/business-logic")
async def bb_logic(request: BugBountyRequest):
    """Bug Bounty 业务逻辑测试工作流"""
    t = BugBountyTarget(domain=request.domain)
    return bugbounty_manager.create_business_logic_workflow(t)

@app.post("/api/bugbounty/osint")
async def bb_osint(request: BugBountyRequest):
    """Bug Bounty OSINT 情报收集工作流"""
    t = BugBountyTarget(domain=request.domain)
    return bugbounty_manager.create_osint_workflow(t)

class FileUploadTestRequest(BaseModel):
    target_url: str

@app.post("/api/bugbounty/file-upload-testing")
async def bb_upload(request: FileUploadTestRequest):
    """文件上传漏洞测试工作流"""
    return bugbounty_manager.create_file_upload_testing(request.target_url)

@app.post("/api/bugbounty/comprehensive")
async def bb_comprehensive(request: BugBountyRequest):
    """Bug Bounty 综合评估 (侦察+猎杀+业务逻辑+OSINT)"""
    t = BugBountyTarget(domain=request.domain, scope=request.scope or [], priority_vulns=request.priority_vulns or ["rce", "sqli", "xss", "idor", "ssrf"])
    return bugbounty_manager.create_comprehensive_assessment(t)

# ============================================================================
# CTF Competition Framework (from HexStrike)
# ============================================================================

class CTFChallengeRequest(BaseModel):
    name: str
    category: Optional[str] = "misc"
    difficulty: Optional[str] = "unknown"
    points: Optional[int] = 100
    description: Optional[str] = ""

class CTFTeamRequest(BaseModel):
    challenges: list
    team_size: Optional[int] = 4

class CTFToolSuggestRequest(BaseModel):
    description: str
    category: Optional[str] = "misc"

@app.post("/api/ctf/challenge-workflow")
async def ctf_workflow(request: CTFChallengeRequest):
    """为 CTF 挑战生成专业化解题工作流"""
    ch = CTFChallenge(name=request.name, category=request.category, difficulty=request.difficulty, points=request.points, description=request.description)
    return ctf_manager.create_challenge_workflow(ch)

@app.post("/api/ctf/team-strategy")
async def ctf_team(request: CTFTeamRequest):
    """CTF 团队策略优化 (按效率分配题目)"""
    challenges = [CTFChallenge(**c) for c in request.challenges]
    return ctf_manager.create_team_strategy(challenges, request.team_size)

@app.post("/api/ctf/suggest-tools")
async def ctf_tools(request: CTFToolSuggestRequest):
    """根据挑战描述推荐最佳 CTF 工具"""
    tools = ctf_manager.suggest_tools(request.description, request.category)
    return {"suggested_tools": tools, "category": request.category}