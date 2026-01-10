FROM python:3.12-slim

WORKDIR /app

# 安装uv包管理器
RUN pip install uv

# 复制项目文件
COPY . /app/

# 安装依赖
RUN uv sync
RUN uv run playwright install chromium --with-deps

# 暴露API端口
EXPOSE 8000

# 启动命令
CMD ["python", "server.py", "--host", "0.0.0.0"]
