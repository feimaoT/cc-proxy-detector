# CC Proxy Detector v9.0

检测 Claude Code 中转站的真实后端来源 — 支持 Web UI 一键检测 + CLI 命令行

## 功能特点

- **七源检测**: Anthropic 官方 / AWS Bedrock 官转 / Kiro 逆向 / Google Vertex 逆向 / Azure 逆向 / OpenRouter 逆向 / 自定义逆向
- **全模型扫描**: 自动扫描所有 Claude 模型，检测混合渠道路由
- **偷鸡检测**: 检测代理是否用便宜模型冒充贵模型（速度 + 推理能力对比）
- **反绕过**: 金丝雀令牌、错误结构指纹、行为分析、SSE 边界攻击
- **Web Search 检测**: 识别原生 vs SearXNG/MCP 兜底搜索
- **缓存检测**: 识别逆向渠道自建的响应缓存
- **自动压缩检测**: 检测上下文自动压缩行为差异
- **Web UI**: 输入地址和 Key，一键检测，实时进度，可视化报告
- **低消耗模式**: 跳过高 token 场景（压缩 / Web Search / 偷鸡检测），节省约 80% token

## 检测逻辑

### 探测流程

```
1. Tool 指纹探测 (2轮)    → 提取 tool_use id 前缀、message id 格式
2. Thinking 签名探测      → 提取 thinking 签名类型、service_tier
3. SSE 流式探测           → 检测流式事件结构、TTFT、事件数
4. 多轮配对探测           → 检测 tool_result 配对一致性
5. 反绕过探测             → 金丝雀令牌 + 系统提示词 + 错误结构 + 行为指纹 + SSE 边界
6. 缓存检测               → 相同 prompt 二次请求，检测假缓存
7. Web Search 检测        → 检测 web_search 工具实现方式
8. 自动压缩检测           → 长上下文触发压缩，检测行为差异
9. 偷鸡检测               → 速度 + 推理能力验证模型真实性
10. Ratelimit 动态验证     → 多次请求检测 remaining 是否真实递减
11. 多维评分 + 判定        → 七源加权评分，置信度计算
```

### 判定逻辑

每个探测项会为七个来源 (Anthropic / AWS 官转 / Kiro / Google / Azure / OpenRouter / 自定义) 加减分。最终取最高分作为判定结果。

**置信度机制**:
- 置信度 >= 70%: 直接判定（如 "Anthropic 官方"）
- 置信度 50-70%: 加"大概率"前缀（如 "大概率 Anthropic 官方"）
- 置信度 < 50%: 加"疑似"前缀（如 "疑似 Anthropic 官方 (置信度不足)"）

### 指纹矩阵

| 指纹 | Anthropic 官方 | Bedrock 官转/Kiro | Vertex/Google | 逆向渠道 |
|------|---------------|-------------------|---------------|---------|
| tool_use id | `toolu_` | `tooluse_` | `tooluse_`/`tool_N` | 可能伪造 |
| message id | `msg_<base62>` | UUID/`msg_<UUID>` | `req_vrtx_` | 可能伪造 |
| thinking sig | 长度 200+ | 长度 200+/截断 | `claude#` 前缀 | 可能截断 |
| service_tier | 存在 | 不存在 | 不存在 | 可能注入 |
| inference_geo | 存在 | 不存在 | 不存在 | 难以伪造 |
| ratelimit | 动态递减 | 不存在 | 不存在 | 可能注入固定值 |
| web_search | srvtoolu_ + encrypted_url | 不同 | 不同 | MCP/SearXNG |

## 快速开始

### Web UI 模式（推荐）

```bash
# 安装依赖
pip install -r requirements.txt

# 启动 Web 服务
cd web && python app.py

# 浏览器打开 http://localhost:5000
# 输入目标地址和 API Key，点击检测
```

### CLI 命令行模式

```bash
# 自动检测 (单模型)
python scripts/detect.py

# 扫描所有模型 (推荐)
python scripts/detect.py --scan-all --rounds 2

# 完整检测 (所有探测项)
python scripts/detect.py --scan-all --streaming --multiturn --anti-bypass --parallel

# 指定模型
python scripts/detect.py --scan-models "claude-opus-4-6,claude-sonnet-4-5-20250929"

# 自定义地址
python scripts/detect.py --base-url https://your-proxy.com --api-key sk-xxx

# JSON 输出
python scripts/detect.py --scan-all --json --output report.json
```

### 环境变量

| 变量 | 说明 |
|------|------|
| `ANTHROPIC_BASE_URL` | 中转站地址 |
| `ANTHROPIC_AUTH_TOKEN` | API Key (优先) |
| `FACTORY_API_KEY` | API Key (备选) |

## 服务器部署

### 直接部署

```bash
# 1. 克隆代码
git clone https://github.com/feimaoT/cc-proxy-detector.git
cd cc-proxy-detector

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动服务 (默认端口 5000)
cd web && python app.py

# 自定义端口
PORT=8080 python app.py
```

生产环境会自动使用 `waitress` 多线程 WSGI 服务器（16 线程并发），支持多人同时使用。

### 反向代理 (Nginx)

```nginx
server {
    listen 80;
    server_name detect.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # SSE 支持 (实时进度)
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

### Systemd 服务

```ini
# /etc/systemd/system/cc-detector.service
[Unit]
Description=CC Proxy Detector Web UI
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/cc-proxy-detector/web
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=5
Environment=PORT=5000

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable cc-detector
sudo systemctl start cc-detector
```

## Docker 部署

### Dockerfile

在项目根目录创建 `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ scripts/
COPY web/ web/

EXPOSE 5000

CMD ["python", "web/app.py"]
```

### 构建和运行

```bash
# 构建镜像
docker build -t cc-proxy-detector .

# 运行容器
docker run -d \
  --name cc-detector \
  -p 5000:5000 \
  --restart unless-stopped \
  cc-proxy-detector

# 自定义端口
docker run -d -p 8080:5000 -e PORT=5000 cc-proxy-detector
```

### Docker Compose

创建 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  detector:
    build: .
    ports:
      - "5000:5000"
    restart: unless-stopped
    environment:
      - PORT=5000
```

```bash
# 一键启动
docker compose up -d

# 查看日志
docker compose logs -f
```

## 一键部署脚本

在项目根目录创建 `deploy.sh`:

```bash
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
```

```bash
# 使用
chmod +x deploy.sh
./deploy.sh
```

## API 接口

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | Web UI 页面 |
| `/api/detect` | POST | 启动检测任务 |
| `/api/progress/<task_id>` | GET | SSE 实时进度流 |
| `/api/report/<task_id>` | GET | 获取检测报告 (JSON) |
| `/api/stop/<task_id>` | POST | 停止检测任务 |
| `/api/check-models` | POST | 模型可用性检查 |

**限流**: 同一 IP 每分钟最多 6 次请求。

## 项目结构

```
cc-proxy-detector/
├── scripts/
│   └── detect.py          # 核心检测引擎 (所有探测 + 评分 + 报告)
├── web/
│   ├── app.py             # Flask Web 应用 (API + SSE + 并发)
│   └── templates/
│       └── index.html     # 前端页面 (单文件，内嵌 CSS/JS)
├── requirements.txt       # Python 依赖
├── Dockerfile             # Docker 构建文件
├── docker-compose.yml     # Docker Compose 配置
├── deploy.sh              # 一键部署脚本
└── README.md
```

## License

MIT
