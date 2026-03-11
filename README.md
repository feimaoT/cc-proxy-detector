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

## 部署指南

### 方式一：一键部署（最简单）

只需一行命令，脚本会自动完成所有步骤：检测系统 → 安装 Git/Python → 拉取代码 → 创建虚拟环境 → 安装依赖 → 启动服务。

**支持系统**: Ubuntu/Debian, CentOS/RHEL/Fedora, macOS

```bash
# 方法 A：全新服务器，一行命令从零部署（推荐）
curl -fsSL https://raw.githubusercontent.com/feimaoT/cc-proxy-detector/main/deploy.sh -o deploy.sh && chmod +x deploy.sh && ./deploy.sh

# 方法 B：已有代码，在项目目录内执行
git clone https://github.com/feimaoT/cc-proxy-detector.git && cd cc-proxy-detector && chmod +x deploy.sh && ./deploy.sh
```

脚本会自动完成：

| 步骤 | 说明 |
|------|------|
| 1. 检测系统 | 自动识别 Ubuntu/CentOS/macOS，选择对应包管理器 |
| 2. 安装依赖 | 自动安装 Git、Python3、pip、venv（跳过已有的） |
| 3. 拉取代码 | 自动 git clone（如果在项目目录内则 git pull 更新） |
| 4. Python 环境 | 自动创建虚拟环境 `venv/`，在其中安装依赖（兼容 Ubuntu 22.04+ PEP 668）|
| 5. 启动服务 | 后台启动，自动输出访问地址、PID、日志路径 |

**Docker 用户**：脚本检测到 Docker 会自动用容器部署。如需强制直接部署：

```bash
NO_DOCKER=1 ./deploy.sh
```

**自定义端口**：

```bash
PORT=8080 ./deploy.sh
```

部署完成后访问 `http://你的服务器IP:5000` 即可使用。

> 如果需要外网访问，记得在服务器安全组/防火墙放行端口，或配置 Nginx 反向代理（见下方）。

---

### 方式二：手动部署（推荐生产环境）

#### 第一步：拉取代码

```bash
git clone https://github.com/feimaoT/cc-proxy-detector.git
cd cc-proxy-detector
```

#### 第二步：安装依赖

```bash
pip install -r requirements.txt
```

依赖说明：
- `requests` — HTTP 请求
- `flask` — Web 框架
- `waitress` — 生产级 WSGI 服务器（16 线程并发，支持多人同时使用）

#### 第三步：启动服务

```bash
# 前台启动（调试用）
cd web && python app.py

# 后台启动（生产用）
cd web && nohup python app.py > ../detector.log 2>&1 &

# 自定义端口
PORT=8080 python app.py
```

启动后终端会显示：
```
CC Proxy Detector v9.0 - Web UI
http://localhost:5000
Server: waitress (多线程并发)
```

#### 第四步：配置 Nginx 反向代理

将服务通过域名对外暴露，避免直接暴露端口：

```bash
# 安装 Nginx（如果没有）
sudo apt install -y nginx
```

创建配置文件 `/etc/nginx/sites-available/cc-detector`：

```nginx
server {
    listen 80;
    server_name detect.yourdomain.com;  # 改成你的域名

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # SSE 实时进度必须关闭缓冲，否则进度条不动
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

启用配置：

```bash
# 创建软链接启用站点
sudo ln -s /etc/nginx/sites-available/cc-detector /etc/nginx/sites-enabled/

# 测试配置是否正确
sudo nginx -t

# 重载 Nginx
sudo nginx -s reload
```

现在访问 `http://detect.yourdomain.com` 即可。

#### 第五步（可选）：配置 HTTPS

```bash
# 安装 Certbot
sudo apt install -y certbot python3-certbot-nginx

# 自动申请证书并配置 Nginx
sudo certbot --nginx -d detect.yourdomain.com
```

#### 第六步（可选）：设置开机自启

创建 Systemd 服务文件 `/etc/systemd/system/cc-detector.service`：

```ini
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
# 把项目放到 /opt（如果还没有）
sudo cp -r /path/to/cc-proxy-detector /opt/cc-proxy-detector

# 启用并启动服务
sudo systemctl daemon-reload
sudo systemctl enable cc-detector
sudo systemctl start cc-detector

# 查看状态
sudo systemctl status cc-detector

# 查看日志
sudo journalctl -u cc-detector -f
```

---

### 方式三：Docker 部署

#### 快速启动

```bash
# 1. 拉取代码
git clone https://github.com/feimaoT/cc-proxy-detector.git
cd cc-proxy-detector

# 2. 构建镜像
docker build -t cc-proxy-detector .

# 3. 运行容器
docker run -d \
  --name cc-detector \
  -p 5000:5000 \
  --restart unless-stopped \
  cc-proxy-detector
```

#### Docker Compose（推荐）

```bash
# 1. 拉取代码
git clone https://github.com/feimaoT/cc-proxy-detector.git
cd cc-proxy-detector

# 2. 一键启动
docker compose up -d

# 3. 查看日志
docker compose logs -f

# 4. 停止服务
docker compose down
```

#### Docker + Nginx

Docker 启动后，Nginx 反向代理配置和上面一样，`proxy_pass` 指向 `http://127.0.0.1:5000`。

---

### 部署后验证

无论哪种方式部署，部署完成后：

1. 浏览器打开 `http://你的服务器IP:5000`（或你配置的域名）
2. 输入要检测的中转站地址和 API Key
3. 点击"开始检测"或"低消耗检测"
4. 等待检测完成，查看报告

### 常见问题

| 问题 | 解决方案 |
|------|---------|
| 访问不了页面 | 检查防火墙/安全组是否放行端口 |
| SSE 进度不动 | Nginx 需要加 `proxy_buffering off` |
| 502 Bad Gateway | 检查后端服务是否在运行：`curl http://127.0.0.1:5000` |
| 权限不足 | `chmod +x deploy.sh`，或用 `sudo` 执行 |

## API 接口

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | Web UI 页面 |
| `/api/detect` | POST | 启动检测任务 |
| `/api/progress/<task_id>` | GET | SSE 实时进度流 |
| `/api/report/<task_id>` | GET | 获取检测报告 (JSON) |
| `/api/stop/<task_id>` | POST | 停止检测任务 |
| `/api/check-models` | POST | 模型可用性检查 |

**限流**: 同一 IP 每分钟最多 6 次请求，全局最大并发 5 个检测任务。

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
