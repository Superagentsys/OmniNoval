OmniNoval 项目逻辑架构
系统总览
SecurityTools    │ │  FastAPI API  │
│ (IDE)        │ │ 150+ 工具管理     │ │  REST 接口    │
│ 目标画像      │ │ 参数优化          │ │  + SSE 流     │
│ 工具选择      │ │ 异步执行          │ │  + 数据库     │
│ 攻击链编排    │ │ 缓存/恢复         │ │              │
└──────────────┘ └───────┬
┌─────────────────────────────────────────────────────────┐│                  用户入口层                               ││  main.py (CLI)  |  server.py (FastAPI)  |  omninoval_mcp.py (MCP)  │└────────┬──────────────┬─────────────────────┬───────────┘         │              │                     │         ▼              ▼                     │┌──────────────────────────────────────┐      ││        LangGraph 工作流引擎           │      ││  coordinator → planner → supervisor  │      ││        ↓                             │      ││  ┌─────────────────────────────┐     │      ││  │     5 个专业化 Agent         │     │      ││  │ researcher | coder | browser│     │      ││  │ reporter   | vulun_agent    │     │      ││  └─────────────────────────────┘     │      │└────────────────┬─────────────────────┘      │                 │                            │         ┌───────┴───────┐                    │         ▼               ▼                    ▼┌──────────────┐ ┌──────────────────┐ ┌──────────────┐│ 智能决策引擎  │ │ SecurityTools    │ │  FastAPI API  ││ (IDE)        │ │ 150+ 工具管理     │ │  REST 接口    ││ 目标画像      │ │ 参数优化          │ │  + SSE 流     ││ 工具选择      │ │ 异步执行          │ │  + 数据库     ││ 攻击链编排    │ │ 缓存/恢复         │ │              │└──────────────┘ └───────┬──────────┘ └──────────────┘                         │                         ▼              ┌─────────────────────┐              │ EnhancedProcessMgr  │              │ 异步子进程执行        │              │ LRU+TTL 缓存        │              │ 错误分类+自动恢复     │              │ 资源感知 (CPU/Mem)   │              └─────────┬───────────┘                        ▼              ┌─────────────────────┐              │  150+ 外部安全工具    │              │  nmap, nuclei, ...  │              └─────────────────────┘
核心数据流
用户自然语言指令  → Coordinator (对话理解, 是否需要规划)    → Planner (深度思考+搜索, 生成 JSON 执行计划)      → Supervisor (路由分发给最合适的 Agent)        → Agent 执行 (researcher/coder/browser/reporter/vulun_agent)          → 工具调用: SecurityTools.run_smart_tool()            → DecisionEngine.analyze_target() + optimize_parameters()              → ProcessManager.run_command_async()                → 实际执行外部安全工具          → 结果返回 Supervisor        → Supervisor 决定下一步或 FINISH
各模块详细职责
模块	文件	职责
CLI 入口	main.py	交互式 CLI, --analyze 仅分析不执行
API 服务	server.py + src/api/app.py	FastAPI 服务器, 14 个 REST 端点
MCP 接口	omninoval_mcp.py	11 个 MCP tool, 桥接 AI Agent 与后端
工作流引擎	src/engine/builder.py	LangGraph StateGraph 构建
工作流节点	src/engine/nodes.py	8 个节点实现 (coordinator/planner/supervisor/5 agents)
状态定义	src/engine/types.py	State TypedDict + Router 路由
决策引擎	src/engine/decision_engine.py	目标画像/工具选择/攻击链, ~490 行
参数优化	src/engine/parameter_optimizer.py	工具参数智能调整
Agent 定义	src/agents/agents.py	7 个 Agent 的工厂函数 (含 bug_bounty/ctf/cve_intel)
VulunAgent	src/agents/vulun_agent.py	核心安全代理, 670 行, 端口/Web/漏洞/子域名扫描
安全工具	src/tools/security_tools.py	150+ 工具注册/检测/异步执行/参数优化, 654 行
高级工具	src/tools/advanced_security_tools.py	攻击链发现/情报报告/安装缺失工具, 765 行
进程管理	src/utils/process_manager.py	异步执行/LRU 缓存/错误恢复/资源监控, 262 行
数据库	src/db/	SQLAlchemy ORM (Target, ScanTask, Vulnerability, Report)
报告服务	src/service/report_service.py	扫描任务/漏洞/报告的 CRUD + 统计
提示词	src/prompts/template/	vulun_agent, bug_bounty, ctf, cve_intel 4 套专业提示词
前端	frontend/index.html	Bootstrap + Chart.js 静态仪表板
嵌入工具	vulmap/, dirsearch/	直接嵌入的 Python 安全工具源码
OmniNoval vs HexStrike 功能对比
OmniNoval 已实现的功能 (相对于 HexStrike)
功能领域	OmniNoval 状态	说明
智能决策引擎 (IDE)	✅ 已实现	目标画像、工具选择、攻击链
150+ 安全工具注册	✅ 已实现	两层架构: security_tools.py + advanced_security_tools.py
参数智能优化	✅ 已实现	nmap/gobuster/nuclei 等核心工具
异步进程管理	✅ 已实现	asyncio.create_subprocess_exec
LRU + TTL 缓存	✅ 已实现	进程管理器内置
错误分类与恢复	✅ 已实现	10 种错误类型, 6 种恢复策略
资源感知执行	✅ 已实现	CPU 高时自动 nice
REST API	✅ 已实现	FastAPI, 14 端点
MCP 接口	✅ 已实现	11 个 tool
数据库持久化	✅ OmniNoval 独有	SQLAlchemy ORM, HexStrike 无此功能
多 Agent 协同	✅ OmniNoval 独有	LangGraph 工作流, HexStrike 无
LLM 集成	✅ OmniNoval 独有	LiteLLM, 多模型支持
SSE 流式输出	✅ OmniNoval 独有	实时 workflow 进度
前端 Dashboard	✅ 已实现	静态 HTML, 前后端分离
嵌入工具源码	✅ OmniNoval 独有	vulmap + dirsearch 直接嵌入
OmniNoval 尚未实现的 HexStrike 功能
#	HexStrike 功能	重要性	说明
1	CVE 实时情报系统	🔴 高	HexStrike 对接 NVD API v2.0, 可实时拉取 CVE、分析可利用性、搜索 GitHub/Exploit-DB/Metasploit 上的 PoC。OmniNoval 的 cve_intel_agent 只定义了 Agent 和提示词, 没有实际的 CVE 查询/分析逻辑
2	AI Exploit 生成器	🔴 高	HexStrike 可根据 CVE 数据自动生成 Python exploit 脚本 (SQLi/XSS/RCE/XXE/LFI/反序列化/认证绕过/缓冲区溢出 8 种类型)。OmniNoval 完全缺失
3	HTTP 测试框架 (Burp Alternative)	🔴 高	HexStrike 实现了完整的 HTTP 拦截框架: 请求拦截、代理历史、Match & Replace 规则、Scope 控制、Repeater、Intruder (Sniper 模式)、自动漏洞检测。OmniNoval 完全缺失
4	浏览器安全代理 (BrowserAgent)	🟡 中	HexStrike 基于 Selenium 实现深度页面检查: Cookie/LocalStorage/SessionStorage 分析、表单/脚本提取、安全头检测、CSRF 检查、混合内容检测、反射 XSS 主动测试。OmniNoval 的 browser agent 只是 Playwright 通用浏览器, 无安全分析逻辑
5	Bug Bounty 专用工作流	🟡 中	HexStrike 有 BugBountyWorkflowManager: 4 阶段侦察工作流、漏洞猎杀工作流、业务逻辑测试、OSINT 工作流、文件上传测试框架。OmniNoval 有 bug_bounty_agent 但无独立工作流编排
6	CTF 竞赛框架	🟡 中	HexStrike 有 CTFWorkflowManager + CTFChallengeAutomator + CTFTeamCoordinator: 7 大类别专用工作流、并行任务、团队策略优化、自动解题、资源需求评估。OmniNoval 有 ctf_agent 但无独立 CTF 框架
7	漏洞关联分析器	🟡 中	HexStrike 的 VulnerabilityCorrelator 可发现多阶段攻击链 (初始访问→权限提升→持久化)。OmniNoval 的攻击链是预定义模式, 无基于扫描结果的动态关联
8	每工具独立 API 端点	🟡 中	HexStrike 为 nmap/gobuster/nuclei/sqlmap/hydra/john 等 40+ 工具各自提供专用 API 端点, 带工具特定参数校验。OmniNoval 用统一的 /api/tools/execute + /api/command, 缺少工具粒度的参数定义
9	AI Payload 生成器	🟡 中	HexStrike 的 AIPayloadGenerator 可生成 XSS/SQLi/LFI/RCE/XXE/SSTI 6 类载荷, 带上下文增强和风险评估。OmniNoval 完全缺失
10	高级参数优化体系	🟢 低	HexStrike 有 TechnologyDetector (主动 HTTP 探测技术栈)、RateLimitDetector (限速检测与时序调整)、PerformanceMonitor (基于资源的参数缩放)。OmniNoval 的参数优化较简单, 主要基于静态规则
11	进程池自动扩缩容	🟢 低	HexStrike 有 ProcessPool (min/max worker, 自动扩缩) + 后台监控线程。OmniNoval 使用 asyncio 单进程模型
12	终端美化引擎	🟢 低	HexStrike 有完整的 ModernVisualEngine (进度条、漏洞卡片、仪表板)。OmniNoval 仅 MCP 客户端有颜色输出
13	威胁情报聚合	🟡 中	HexStrike 的 /api/vuln-intel/threat-feeds 可聚合 CVE + IP 信誉 + 文件哈希, 计算综合威胁分数。OmniNoval 完全缺失
14	零日研究模拟	🟢 低	HexStrike 的 /api/vuln-intel/zero-day-research 提供研究模拟框架。OmniNoval 无
15	GraphQL/JWT 专项扫描	🟡 中	HexStrike 有 graphql_scanner (内省查询检测、深度限制、批量查询) 和 jwt_analyzer (算法分析、过期检查、none 攻击)。OmniNoval 无专项实现
OmniNoval 相比 HexStrike 的架构优势
维度	OmniNoval 优势
AI 原生	LangGraph 多 Agent 协同 + LLM 推理, HexStrike 无 AI 能力
代码质量	模块化清晰 (15+ 文件), HexStrike 是单文件 17000 行
数据持久化	SQLAlchemy ORM 完整数据模型, HexStrike 无持久化
异步原生	asyncio + FastAPI 全异步, HexStrike 用 Flask 同步
扩展性	Agent/Tool/Prompt 解耦, 易于添加新功能
LLM 支持	LiteLLM 多厂商模型, 支持 Azure/Volcengine 等
流式输出	SSE 实时 workflow 进度推送
建议优先实现的 Top 5
CVE 情报系统 — 对接 NVD API, 实现实时 CVE 查询、可利用性评估、PoC 搜索
HTTP 测试框架 — 实现请求拦截/代理/Repeater/Intruder, 作为 Burp 轻量替代
AI Exploit 生成 — 基于 CVE 数据让 LLM 生成针对性 exploit 脚本
Bug Bounty 工作流引擎 — 多阶段侦察→猎杀→OSINT 的独立编排
GraphQL/JWT 专项扫描 — 对 API 安全测试的深度支持