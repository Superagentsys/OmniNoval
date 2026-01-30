# 🚀 OmniNoval

OmniNoval 是一个基于 **LangGraph** 构建的高级多模态多智能体（Multi-Agent）自动化渗透测试框架。它将尖端的 AI 决策能力与 150+ 专业安全工具相结合，实现了从资产发现、漏洞扫描到攻击链研判的全流程自动化。

---

## 🌟 核心特性

- **🤖 智能决策引擎 (Intelligent Decision Engine)**: 
    - **自主画像**: 自动识别目标类型（Web、网络、域名、二进制文件等）。
    - **工具自选**: 基于目标特征自动从 150+ 工具库中筛选最优工具组合。
    - **动态参数优化**: 智能调整工具参数（如字典选择、扫描频率），最大化探测效果。
- **⚡ 增强型进程与缓存管理**: 
    - **资源感知**: 实时监控系统 CPU/内存，动态调整执行优先级。
    - **智能缓存**: 基于 LRU 和 TTL 机制缓存工具执行结果，大幅提升重复任务响应速度。
- **🛡️ 专门化安全智能体群**: 
    - **BugBountyAgent**: 专注于大规模资产发现与 Web 漏洞挖掘。
    - **CTFAgent**: 擅长逆向工程、密码学分析与二进制漏洞利用。
    - **CVEIntelAgent**: 实时搜寻漏洞情报、PoC 及修复方案。
    - **VulunAgent**: 核心协同代理，负责全流程安全评估。
- **🧰 150+ 安全工具库**: 集成 Nmap, Nuclei, Sqlmap, Gobuster, Metasploit 等涵盖网络、Web、云原生及二进制分析的全方位工具链。
- **🌐 高级 Web 自动化**: 集成 Playwright 和 Headless Chrome，支持动态内容抓取与复杂交互分析。

---

## 📋 目录结构

```text
OmniNoval/
├── src/
│   ├── agents/           # 专门化智能体定义 (BugBounty, CTF, CVE 等)
│   ├── api/              # FastAPI 接口定义与应用入口
│   ├── config/           # 智能体、模型与工具配置管理
│   ├── engine/           # 核心引擎 (IDE, 参数优化器, 工作流图)
│   ├── llms/             # LLM 抽象层 (支持 LiteLLM, langchain-litellm)
│   ├── prompts/          # 专门化安全提示词模板
│   ├── tools/            # 150+ 工具集成接口 (SecurityTools, AdvancedTools)
│   ├── utils/            # 增强型进程管理器与缓存工具
│   └── workflow.py       # LangGraph 工作流核心逻辑
├── main.py               # 增强型 CLI 入口
├── server.py             # 专业版 API 服务器启动脚本
├── frontend/             # ✅ 前端（纯静态 Dashboard，独立部署/启动）
├── vulun_agent_config.yaml # 安全工具与扫描策略配置
├── pyproject.toml        # 项目依赖与构建配置
└── README.md
```

---

## 🚀 快速开始

### 环境要求
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) 包管理器 (强烈推荐)

### 安装步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd OmniNoval
   ```

2. **安装依赖**
   ```bash
   # 使用 uv 同步环境
   uv sync
   
   # 安装浏览器内核
   uv run playwright install chromium --with-deps
   ```

3. **配置环境**
   复制配置文件并填写你的 API Keys：
   ```bash
   cp conf.yaml.example conf.yaml
   vim conf.yaml
   ```

---

## 📖 使用指南

### 1. 命令行模式 (CLI)
使用 `main.py` 进行交互或直接执行指令。

- **交互式/直接执行**:
  ```bash
  uv run main.py "对 https://example.com 进行全面的安全评估"
  ```
- **智能分析模式 (IDE)**:
  仅使用决策引擎分析目标并推荐工具，不执行实际扫描：
  ```bash
  uv run main.py --analyze "192.168.1.1/24"
  ```

### 2. API 模式
启动专业版后端服务，支持实时监控和工具自检。

```bash
# 启动服务器并自动安装缺失的工具
uv run server.py --host 0.0.0.0 --port 8000 --install-tools --reload
```

**关键 API 端点**:
- `GET /health`: 查看系统健康度、工具可用性及进程统计。
- `POST /workflow`: 提交自动化渗透测试任务。
- `POST /api/intelligence/analyze-target`: 调用决策引擎获取攻击建议。
- `GET /api/processes/list`: 监控实时运行的安全工具进程。

---

## 🧩 前后端分离（Dashboard）

本项目的 Dashboard 已从后端剥离为 **纯静态前端**：`frontend/index.html`。后端只提供 API，并通过 CORS 支持跨域（含 SSE `EventSource`）。

### 启动后端（API）

```bash
uv run server.py --host 0.0.0.0 --port 8000 --reload
```

如需限制允许的前端来源（推荐生产环境配置），设置环境变量（逗号分隔）：

```bash
export OMNINOVAL_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
uv run server.py --host 0.0.0.0 --port 8000 --reload
```

### 启动前端（静态托管）

任选一种方式启动静态服务器（示例用 Python 标准库）：

```bash
cd frontend
python3 -m http.server 5173
```

浏览器打开前端后，默认会请求 `http://localhost:8000`。

### 配置前端 API 地址（API_BASE）

前端支持两种方式指定后端地址：

- **URL 参数**：`?api=http://127.0.0.1:8000`（会自动写入 localStorage）
- **页面侧边栏**：点击 **Set API** 手动设置

---

## ⚙️ 核心配置

在 `vulun_agent_config.yaml` 中，你可以自定义扫描策略和工具路径：

```yaml
SCAN_STRATEGIES:
  quick:
    tools: ["nmap", "nuclei"]
    port_range: "1-1000"
  comprehensive:
    tools: ["nmap", "masscan", "nuclei", "gobuster", "nikto", "subfinder", "amass"]
    port_range: "1-65535"

CACHE:
  enabled: true
  ttl: 3600
```

---

## 🤝 贡献与参与

我们欢迎安全社区的贡献！
- **新增工具**: 在 `src/tools/` 中实现新的工具接口。
- **优化智能体**: 在 `src/prompts/template/` 中改进提示词逻辑。

---

## 📝 许可证

本项目基于 MIT 许可证开源。

---

**OmniNoval-VulunAgent** - 让 AI 成为你的网络安全专家 🚀
