# OmniNoval

OmniNoval 是一个先进的多模态多智能体自动化框架，基于 LangGraph 构建，支持复杂的智能体协作工作流。

## 🌟 特性

- **多智能体协作**: 支持多个专业智能体协同工作，每个智能体都有特定的角色和专长
- **多模态支持**: 集成视觉模型，支持图像理解和处理
- **灵活的工作流引擎**: 基于 LangGraph 构建的可扩展工作流系统
- **Web 自动化**: 集成 Playwright，支持网页浏览和自动化操作
- **RESTful API**: 提供完整的 API 接口，支持集成到现有系统
- **Docker 支持**: 提供完整的容器化部署方案
- **配置灵活**: 支持多种 LLM 提供商和配置选项

## 📋 目录结构

```
OmniNoval/
├── assets/                 # 静态资源文件
├── src/                    # 源代码目录
│   ├── agents/            # 智能体定义
│   ├── api/               # API 接口
│   ├── config/            # 配置管理
│   ├── engine/            # 工作流引擎
│   ├── llms/              # LLM 抽象层
│   ├── prompts/           # 提示词模板
│   ├── service/           # 服务层
│   ├── tools/             # 工具集
│   ├── utils/             # 工具函数
│   └── workflow.py        # 工作流入口
├── conf.yaml.example      # 配置文件示例
├── docker-compose.yml     # Docker Compose 配置
├── Dockerfile            # Docker 镜像配置
├── main.py               # CLI 入口
├── server.py             # API 服务器入口
├── pyproject.toml        # 项目配置
└── README.md             # 项目文档
```

## 🚀 快速开始

### 环境要求

- Python 3.12+
- uv 包管理器（推荐）

### 本地安装

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd OmniNoval
   ```

2. **安装依赖**
   ```bash
   # 使用 uv 安装依赖
   uv sync
   
   # 安装 Playwright 浏览器
   uv run playwright install chromium --with-deps
   ```

3. **配置环境**
   ```bash
   # 复制配置文件
   cp conf.yaml.example conf.yaml
   
   # 编辑配置文件，设置你的 API 密钥
   vim conf.yaml
   ```

4. **运行项目**
   ```bash
   # CLI 模式
   uv run main.py "你的查询"
   
   # API 服务器模式
   uv run server.py --reload
   ```

### 使用 Makefile

项目提供了便捷的 Makefile 命令：

```bash
# 初始设置
make setup

# 运行 CLI
make run

# 启动开发服务器
make dev

# 启动生产服务器
make api

# 运行测试
make test

# 清理环境
make clean
```

## 🐳 Docker 部署

### 使用 Docker Compose（推荐）

```bash
# 启动生产环境
docker-compose up api

# 启动开发环境（支持热重载）
docker-compose up dev
```

### 手动构建 Docker 镜像

```bash
# 构建镜像
docker build -t omninova .

# 运行容器
docker run -p 8000:8000 -v $(pwd)/.env:/app/.env -v $(pwd)/conf.yaml:/app/conf.yaml omninova
```

## ⚙️ 配置说明

### 配置文件结构

项目支持两种配置方式：
- `conf.yaml` 配置文件（推荐）
- `.env` 环境变量文件（兼容模式）

### LLM 配置

在 `conf.yaml` 中配置不同的 LLM 模型：

```yaml
# 推理模型
REASONING_MODEL:
  model: "volcengine/ep-xxxx"
  api_key: $REASONING_API_KEY
  api_base: $REASONING_BASE_URL

# 基础模型
BASIC_MODEL:
  model: "azure/gpt-4o-2024-08-06"
  api_base: $AZURE_API_BASE
  api_version: $AZURE_API_VERSION
  api_key: $AZURE_API_KEY

# 视觉模型
VISION_MODEL:
  model: "azure/gpt-4o-2024-08-06"
  api_base: $AZURE_API_BASE
  api_version: $AZURE_API_VERSION
  api_key: $AZURE_API_KEY
```

### 环境变量

创建 `.env` 文件设置敏感信息：

```bash
# API 密钥
REASONING_API_KEY=your_reasoning_api_key
AZURE_API_KEY=your_azure_api_key

# API 端点
REASONING_BASE_URL=https://api.example.com
AZURE_API_BASE=https://your-resource.openai.azure.com
AZURE_API_VERSION=2024-02-15-preview
```

## 📖 使用方法

### CLI 模式

```bash
# 直接运行
python main.py "帮我分析这个网页的内容"

# 交互模式
python main.py
# 然后输入你的查询
```

### API 模式

启动 API 服务器：

```bash
python server.py --host 0.0.0.0 --port 8000 --reload
```

API 端点：
- `GET /health` - 健康检查
- `POST /workflow` - 执行工作流
- `GET /docs` - API 文档（Swagger UI）

### 工作流示例

```python
from src.workflow import run_agent_workflow

# 执行工作流
result = run_agent_workflow(
    user_input="帮我分析这个网页的内容",
    debug=True
)

# 查看结果
print(result["messages"])
```

## 🔧 开发指南

### 项目结构说明

- **agents/**: 定义各种智能体角色和行为
- **engine/**: 工作流引擎，基于 LangGraph 构建
- **llms/**: LLM 抽象层，支持多种模型提供商
- **tools/**: 工具集，包括网页浏览、搜索等
- **api/**: RESTful API 接口

### 添加新的智能体

1. 在 `src/agents/` 目录下创建新的智能体文件
2. 在 `src/config/` 中注册智能体配置
3. 在工作流中集成新的智能体

### 添加新的工具

1. 在 `src/tools/` 目录下创建工具文件
2. 实现工具接口
3. 在智能体中注册和使用工具

### 代码规范

项目使用以下工具进行代码质量控制：

```bash
# 代码格式化
uv run black .

# 代码检查
uv run ruff check .

# 运行测试
uv run pytest
```

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📝 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🆘 常见问题

### Q: 如何切换不同的 LLM 提供商？
A: 在 `conf.yaml` 中修改模型配置，支持所有 LiteLLM 兼容的提供商。

### Q: 如何添加自定义工具？
A: 在 `src/tools/` 目录下创建新的工具类，并在智能体中注册使用。

### Q: 如何调试工作流？
A: 设置 `debug=True` 参数，或查看日志输出。

### Q: 支持哪些浏览器自动化功能？
A: 基于 Playwright，支持 Chromium 浏览器的所有功能。

## 📞 支持

如果你遇到问题或有建议，请：
1. 查看 [Issues](../../issues) 页面
2. 创建新的 Issue
3. 联系开发团队

---

**OmniNoval** - 让多智能体协作变得简单高效 🚀