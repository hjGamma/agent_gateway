#!/bin/bash
# Agent Gateway - 启动脚本

set -e

echo "============================================"
echo "  Agent Gateway - 启动"
echo "============================================"

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found"
    exit 1
fi

# 安装依赖
if [ ! -d ".venv" ]; then
    echo "[1/3] 创建虚拟环境..."
    python3 -m venv .venv
fi

echo "[2/3] 安装依赖..."
. .venv/bin/activate
pip install -q -r requirements.txt

# 创建数据目录
mkdir -p /data

echo "[3/3] 启动网关..."
echo ""
echo "  端口: 8400"
echo "  API文档: http://localhost:8400/docs"
echo "  健康检查: http://localhost:8400/health"
echo ""
echo "  按 Ctrl+C 停止"
echo "============================================"

exec uvicorn app.main:app --host 0.0.0.0 --port 8400 --workers 1
