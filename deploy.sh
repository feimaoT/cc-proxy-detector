#!/bin/bash
set -e

# ============================================================
# CC Proxy Detector v9.0 - 一键部署脚本
# 支持: Ubuntu/Debian, CentOS/RHEL/Fedora, macOS
# 功能: 自动检测系统 → 安装依赖 → 拉代码 → 部署启动
# ============================================================

REPO_URL="https://github.com/feimaoT/cc-proxy-detector.git"
INSTALL_DIR="cc-proxy-detector"
PORT=${PORT:-5000}

echo ""
echo "  CC Proxy Detector v9.0 - 一键部署"
echo "  ====================================="
echo ""

# ----------------------------------------------------------
# 1. 检测操作系统
# ----------------------------------------------------------
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MGR="brew"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        PKG_MGR="apt"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
        OS="rhel"
        if command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
    else
        OS="unknown"
        PKG_MGR="unknown"
    fi
    echo "[系统] 检测到: $OS (包管理器: $PKG_MGR)"
}

# ----------------------------------------------------------
# 2. 安装系统依赖 (Git + Python3 + pip + venv)
# ----------------------------------------------------------
install_deps() {
    echo ""
    echo "[1/5] 安装系统依赖..."

    case "$PKG_MGR" in
        apt)
            sudo apt update -qq
            sudo apt install -y -qq git python3 python3-pip python3-venv curl
            ;;
        dnf)
            sudo dnf install -y -q git python3 python3-pip python3-venv curl
            ;;
        yum)
            sudo yum install -y -q git python3 python3-pip curl
            # CentOS 7 没有 python3-venv，用 virtualenv 兜底
            if ! python3 -m venv --help &>/dev/null; then
                sudo pip3 install virtualenv
            fi
            ;;
        brew)
            # macOS: Homebrew
            if ! command -v brew &>/dev/null; then
                echo "  未检测到 Homebrew，请先安装: https://brew.sh"
                exit 1
            fi
            brew install git python3 2>/dev/null || true
            ;;
        *)
            echo "  [警告] 无法识别包管理器，跳过自动安装"
            echo "  请手动安装: git, python3, python3-pip, python3-venv"
            ;;
    esac

    echo "  [OK] 系统依赖安装完成"
}

# ----------------------------------------------------------
# 3. 检测 Python
# ----------------------------------------------------------
detect_python() {
    if command -v python3 &>/dev/null; then
        PYTHON=python3
    elif command -v python &>/dev/null; then
        PYTHON=python
    else
        echo "[ERROR] 未找到 Python，请手动安装 Python 3.8+"
        exit 1
    fi

    PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python: $PYTHON ($PY_VERSION)"
}

# ----------------------------------------------------------
# 4. 拉取/更新代码
# ----------------------------------------------------------
fetch_code() {
    echo ""
    echo "[2/5] 拉取代码..."

    # 如果脚本在项目目录内执行（已有代码），跳过 clone
    if [ -f "web/app.py" ] && [ -f "scripts/detect.py" ]; then
        echo "  检测到已有项目代码，尝试更新..."
        if [ -d ".git" ]; then
            git pull --ff-only 2>/dev/null || echo "  [提示] git pull 失败，使用本地代码继续"
        fi
        PROJECT_DIR="$(pwd)"
    elif [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/web/app.py" ]; then
        echo "  检测到已有目录 $INSTALL_DIR，尝试更新..."
        cd "$INSTALL_DIR"
        if [ -d ".git" ]; then
            git pull --ff-only 2>/dev/null || echo "  [提示] git pull 失败，使用本地代码继续"
        fi
        PROJECT_DIR="$(pwd)"
    else
        echo "  从 GitHub 克隆代码..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        PROJECT_DIR="$(pwd)"
    fi

    echo "  [OK] 代码目录: $PROJECT_DIR"
}

# ----------------------------------------------------------
# 5. 创建虚拟环境 + 安装 Python 依赖
# ----------------------------------------------------------
setup_venv() {
    echo ""
    echo "[3/5] 安装 Python 依赖..."

    cd "$PROJECT_DIR"

    # 创建虚拟环境（如果不存在）
    if [ ! -d "venv" ]; then
        echo "  创建虚拟环境..."
        $PYTHON -m venv venv
    else
        echo "  检测到已有虚拟环境"
    fi

    # 激活并安装依赖
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q

    echo "  [OK] Python 依赖安装完成"
}

# ----------------------------------------------------------
# 6. 停止旧进程（如果有）
# ----------------------------------------------------------
stop_old() {
    echo ""
    echo "[4/5] 检查旧进程..."

    # 尝试停止旧的 app.py 进程
    OLD_PID=$(pgrep -f "python.*app.py" 2>/dev/null || true)
    if [ -n "$OLD_PID" ]; then
        echo "  发现旧进程 (PID: $OLD_PID)，正在停止..."
        kill $OLD_PID 2>/dev/null || true
        sleep 1
        echo "  [OK] 旧进程已停止"
    else
        echo "  无旧进程"
    fi
}

# ----------------------------------------------------------
# 7. 启动服务
# ----------------------------------------------------------
start_service() {
    echo ""
    echo "[5/5] 启动服务..."

    cd "$PROJECT_DIR"

    # 用虚拟环境的 Python 启动
    VENV_PYTHON="$PROJECT_DIR/venv/bin/python"

    PORT=$PORT nohup "$VENV_PYTHON" web/app.py > detector.log 2>&1 &
    NEW_PID=$!

    # 等待 2 秒确认启动成功
    sleep 2
    if kill -0 $NEW_PID 2>/dev/null; then
        echo ""
        echo "  ========================================="
        echo "  [OK] 部署成功！"
        echo "  ========================================="
        echo ""
        echo "  访问地址: http://localhost:$PORT"
        echo "  外网访问: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '你的服务器IP'):$PORT"
        echo ""
        echo "  项目目录: $PROJECT_DIR"
        echo "  虚拟环境: $PROJECT_DIR/venv"
        echo "  进程 PID: $NEW_PID"
        echo "  查看日志: tail -f $PROJECT_DIR/detector.log"
        echo "  停止服务: kill $NEW_PID"
        echo ""
        echo "  提示: 如需外网访问，请确保防火墙放行 $PORT 端口"
        echo "        或配置 Nginx 反向代理（参考 README.md）"
        echo ""
    else
        echo "  [ERROR] 启动失败，请查看日志:"
        echo "  cat $PROJECT_DIR/detector.log"
        exit 1
    fi
}

# ----------------------------------------------------------
# Docker 部署（如果检测到 Docker）
# ----------------------------------------------------------
deploy_docker() {
    echo ""
    echo "[Docker] 使用容器部署..."

    cd "$PROJECT_DIR"

    echo "  构建镜像..."
    docker build -t cc-proxy-detector .

    echo "  停止旧容器..."
    docker rm -f cc-detector 2>/dev/null || true

    echo "  启动新容器..."
    docker run -d \
        --name cc-detector \
        -p $PORT:5000 \
        --restart unless-stopped \
        cc-proxy-detector

    echo ""
    echo "  ========================================="
    echo "  [OK] Docker 部署成功！"
    echo "  ========================================="
    echo ""
    echo "  访问地址: http://localhost:$PORT"
    echo "  外网访问: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '你的服务器IP'):$PORT"
    echo ""
    echo "  查看日志: docker logs -f cc-detector"
    echo "  停止服务: docker stop cc-detector"
    echo "  重启服务: docker restart cc-detector"
    echo ""
}

# ============================================================
# 主流程
# ============================================================

detect_os
install_deps
detect_python
fetch_code

# 判断部署方式: Docker 优先
if command -v docker &>/dev/null; then
    echo ""
    echo "  检测到 Docker，优先使用容器部署"
    echo "  如需直接部署，请运行: NO_DOCKER=1 ./deploy.sh"
    echo ""

    if [ "$NO_DOCKER" = "1" ]; then
        setup_venv
        stop_old
        start_service
    else
        deploy_docker
    fi
else
    setup_venv
    stop_old
    start_service
fi
