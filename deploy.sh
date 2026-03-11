#!/bin/bash
set -e

echo "CC Proxy Detector v9.0 - 一键部署"
echo "================================="

# 检测 Docker
if command -v docker &> /dev/null; then
    echo "[1/3] 检测到 Docker，使用容器部署..."
    docker build -t cc-proxy-detector .
    docker rm -f cc-detector 2>/dev/null || true
    docker run -d --name cc-detector -p 5000:5000 --restart unless-stopped cc-proxy-detector
    echo "[OK] 服务已启动: http://localhost:5000"
else
    echo "[1/3] 未检测到 Docker，使用直接部署..."

    # 安装依赖
    echo "[2/3] 安装 Python 依赖..."
    pip install -r requirements.txt

    # 启动服务
    echo "[3/3] 启动服务..."
    cd web && nohup python app.py > ../detector.log 2>&1 &
    echo "[OK] 服务已启动: http://localhost:5000"
    echo "     日志: tail -f detector.log"
fi
