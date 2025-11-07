# OmniNoval

OmniNoval is an advanced multimodal multi-agent automation framework, built on LangGraph, supporting complex agent collaboration workflows.

## 🌟 Features

- **Multi-agent Collaboration**: Supports multiple specialized agents working together, each with specific roles and expertise
- **Multimodal Support**: Integrated vision models, supporting image understanding and processing
- **Flexible Workflow Engine**: Extensible workflow system based on LangGraph
- **Web Automation**: Integrated Playwright, supporting web browsing and automation operations
- **RESTful API**: Provides complete API interfaces, supporting integration into existing systems
- **Docker Support**: Provides complete containerized deployment solutions
- **Flexible Configuration**: Supports multiple LLM providers and configuration options

## 📋 Directory Structure

```
OmniNoval/
├── assets/                 # Static resource files
├── src/                    # Source code directory
│   ├── agents/            # Agent definitions
│   ├── api/               # API interfaces
│   ├── config/            # Configuration management
│   ├── engine/            # Workflow engine
│   ├── llms/              # LLM abstraction layer
│   ├── prompts/           # Prompt templates
│   ├── service/           # Service layer
│   ├── tools/             # Toolset
│   ├── utils/             # Utility functions
│   └── workflow.py        # Workflow entry
├── conf.yaml.example      # Configuration file example
├── docker-compose.yml     # Docker Compose configuration
├── Dockerfile            # Docker image configuration
├── main.py               # CLI entry
├── server.py             # API server entry
├── pyproject.toml        # Project configuration
└── README.md             # Project documentation
```

## 🚀 Quick Start

### Environment Requirements

- Python 3.12+
- uv package manager (recommended)

### Local Installation

1. **Clone the Project**
   ```bash
   git clone <repository-url>
   cd OmniNoval
   ```

2. **Install Dependencies**
   ```bash
   # Install dependencies using uv
   uv sync
   
   # Install Playwright browser
   uv run playwright install chromium --with-deps
   ```

3. **Configure Environment**
   ```bash
   # Copy configuration file
   cp conf.yaml.example conf.yaml
   
   # Edit configuration file, set your API keys
   vim conf.yaml
   ```

4. **Run the Project**
   ```bash
   # CLI mode
   uv run main.py "Your query"
   
   # API server mode
   uv run server.py --reload
   ```

### Using Makefile

The project provides convenient Makefile commands:

```bash
# Initial setup
make setup

# Run CLI
make run

# Start development server
make dev

# Start production server
make api

# Run tests
make test

# Clean environment
make clean
```

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Start production environment
docker-compose up api

# Start development environment (supports hot reload)
docker-compose up dev
```

### Manual Docker Image Build

```bash
# Build image
docker build -t omninova .

# Run container
docker run -p 8000:8000 -v $(pwd)/.env:/app/.env -v $(pwd)/conf.yaml:/app/conf.yaml omninova
```

## ⚙️ Configuration Instructions

### Configuration File Structure

The project supports two configuration methods:
- `conf.yaml` configuration file (recommended)
- `.env` environment variable file (compatibility mode)

### LLM Configuration

Configure different LLM models in `conf.yaml`:

```yaml
# Reasoning Model
REASONING_MODEL:
  model: "volcengine/ep-xxxx"
  api_key: $REASONING_API_KEY
  api_base: $REASONING_BASE_URL

# Basic Model
BASIC_MODEL:
  model: "azure/gpt-4o-2024-08-06"
  api_base: $AZURE_API_BASE
  api_version: $AZURE_API_VERSION
  api_key: $AZURE_API_KEY

# Vision Model
VISION_MODEL:
  model: "azure/gpt-4o-2024-08-06"
  api_base: $AZURE_API_BASE
  api_version: $AZURE_API_VERSION
  api_key: $AZURE_API_KEY
```

### Environment Variables

Create `.env` file to set sensitive information:

```bash
# API Keys
REASONING_API_KEY=your_reasoning_api_key
AZURE_API_KEY=your_azure_api_key

# API Endpoints
REASONING_BASE_URL=https://api.example.com
AZURE_API_BASE=https://your-resource.openai.azure.com
AZURE_API_VERSION=2024-02-15-preview
```

## 📖 Usage

### CLI Mode

```bash
# Direct run
python main.py "Help me analyze the content of this webpage"

# Interactive mode
python main.py
# Then input your query
```

### API Mode

Start API server:

```bash
python server.py --host 0.0.0.0 --port 8000 --reload
```

API Endpoints:
- `GET /health` - Health check
- `POST /workflow` - Execute workflow
- `GET /docs` - API documentation (Swagger UI)

### Workflow Example

```python
from src.workflow import run_agent_workflow

# Execute workflow
result = run_agent_workflow(
    user_input="Help me analyze the content of this webpage",
    debug=True
)

# View result
print(result["messages"])
```

## 🔧 Development Guide

### Project Structure Explanation

- **agents/**: Defines various agent roles and behaviors
- **engine/**: Workflow engine, built on LangGraph
- **llms/**: LLM abstraction layer, supports multiple model providers
- **tools/**: Toolset, including web browsing, search, etc.
- **api/**: RESTful API interfaces

### Adding New Agents

1. Create new agent file in `src/agents/`
2. Register agent configuration in `src/config/`
3. Integrate new agent in workflow

### Adding New Tools

1. Create tool file in `src/tools/`
2. Implement tool interface
3. Register and use tool in agents

### Code Standards

The project uses the following tools for code quality control:

```bash
# Code formatting
uv run black .

# Code checking
uv run ruff check .

# Run tests
uv run pytest
```

## 🤝 Contribution Guide

1. Fork the project
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 FAQ

### Q: How to switch different LLM providers?
A: Modify model configuration in `conf.yaml`, supports all LiteLLM compatible providers.

### Q: How to add custom tools?
A: Create new tool class in `src/tools/` directory, and register use in agents.

### Q: How to debug workflow?
A: Set `debug=True` parameter, or check log output.

### Q: What browser automation features are supported?
A: Based on Playwright, supports all features of Chromium browser.

## 📞 Support

If you encounter problems or have suggestions, please:
1. Check [Issues](../../issues) page
2. Create new Issue
3. Contact development team

---

**OmniNoval** - Making multi-agent collaboration simple and efficient 🚀