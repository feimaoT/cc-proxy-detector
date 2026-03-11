#!/usr/bin/env python3
"""
CC Proxy Detector v9.0 - Web UI
Flask 应用：输入地址和 Key，一键检测，实时进度，出报告
支持多人并发使用，waitress 生产服务器
"""
import json
import os
import sys
import threading
import time
import uuid
from collections import defaultdict

from flask import Flask, render_template, request, jsonify, Response

# 将 scripts 目录加入 path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import detect

app = Flask(__name__)

# 任务存储 (线程安全)
tasks = {}
tasks_lock = threading.Lock()

# ── 全局并发控制 ──────────────────────────────────────────
MAX_CONCURRENT_TASKS = 5  # 最大同时运行的检测任务数


def get_running_task_count():
    """获取当前正在运行的任务数"""
    with tasks_lock:
        return sum(1 for t in tasks.values() if t.status in ("pending", "running"))


# ── IP 限流 ──────────────────────────────────────────────
RATE_LIMIT_WINDOW = 60  # 秒
RATE_LIMIT_MAX = 6      # 每窗口最大请求数
rate_limit_data = defaultdict(list)  # ip -> [timestamp, ...]
rate_limit_lock = threading.Lock()


def get_client_ip():
    """获取客户端真实 IP (支持反代)"""
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or request.remote_addr
            or "unknown")


def check_rate_limit(ip):
    """检查 IP 限流，返回 (allowed, remaining, retry_after)"""
    now = time.time()
    with rate_limit_lock:
        # 清理过期记录
        rate_limit_data[ip] = [t for t in rate_limit_data[ip]
                               if now - t < RATE_LIMIT_WINDOW]
        count = len(rate_limit_data[ip])
        if count >= RATE_LIMIT_MAX:
            oldest = rate_limit_data[ip][0]
            retry_after = int(RATE_LIMIT_WINDOW - (now - oldest)) + 1
            return False, 0, retry_after
        rate_limit_data[ip].append(now)
        return True, RATE_LIMIT_MAX - count - 1, 0


# 过期任务清理
TASK_EXPIRE_SECONDS = 30 * 60


def cleanup_expired_tasks():
    while True:
        time.sleep(60)
        now = time.time()
        expired = []
        with tasks_lock:
            for tid, task in tasks.items():
                if now - task.last_update > TASK_EXPIRE_SECONDS:
                    expired.append(tid)
            for tid in expired:
                del tasks[tid]
        # 清理限流过期数据
        with rate_limit_lock:
            stale_ips = [ip for ip, ts in rate_limit_data.items()
                         if all(now - t > RATE_LIMIT_WINDOW for t in ts)]
            for ip in stale_ips:
                del rate_limit_data[ip]


_cleanup_thread = threading.Thread(target=cleanup_expired_tasks, daemon=True)
_cleanup_thread.start()


class DetectTask:
    def __init__(self, base_url, api_key, options):
        self.id = str(uuid.uuid4())[:8]
        self.base_url = base_url
        self.api_key = api_key
        self.options = options
        self.status = "pending"
        self.progress = 0
        self.progress_msg = ""
        self.logs = []
        self.result = None
        self.error_msg = ""
        self.last_update = time.time()
        self.stop_event = threading.Event()

    def add_log(self, msg):
        self.logs.append({"time": time.time(), "msg": msg})
        self.last_update = time.time()

    def set_progress(self, step, total, msg):
        self.progress = int(step / total * 100) if total > 0 else 0
        self.progress_msg = msg
        self.add_log(msg)
        self.last_update = time.time()

    def is_stopped(self):
        return self.stop_event.is_set()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/detect", methods=["POST"])
def start_detect():
    # 并发检查
    running = get_running_task_count()
    if running >= MAX_CONCURRENT_TASKS:
        return jsonify({
            "error": f"当前有 {running} 个检测任务正在运行，服务器繁忙，请稍后再试 (最大并发 {MAX_CONCURRENT_TASKS})"
        }), 429

    # 限流检查
    ip = get_client_ip()
    allowed, remaining, retry_after = check_rate_limit(ip)
    if not allowed:
        return jsonify({
            "error": f"请求过于频繁，请 {retry_after} 秒后重试 (每分钟最多 {RATE_LIMIT_MAX} 次)"
        }), 429

    data = request.get_json()
    base_url = (data.get("base_url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()

    if not base_url:
        return jsonify({"error": "需要填写目标地址"}), 400
    if not api_key:
        return jsonify({"error": "需要填写 API Key"}), 400

    options = {
        "scan_all": data.get("scan_all", True),
        "parallel": data.get("parallel", True),
        "streaming": data.get("streaming", True),
        "multiturn": data.get("multiturn", True),
        "anti_bypass": data.get("anti_bypass", True),
        "rounds": data.get("rounds", 2),
        "model": data.get("model") or None,
        "scan_models": data.get("scan_models") or None,
        "lite": data.get("lite", False),
    }

    task = DetectTask(base_url, api_key, options)
    with tasks_lock:
        tasks[task.id] = task

    thread = threading.Thread(target=_run_detect, args=(task,), daemon=True)
    thread.start()

    resp = jsonify({"task_id": task.id})
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp


@app.route("/api/check-models", methods=["POST"])
def check_models():
    """只检测模型可用性，不做完整扫描"""
    # 限流检查
    ip = get_client_ip()
    allowed, remaining, retry_after = check_rate_limit(ip)
    if not allowed:
        return jsonify({
            "error": f"请求过于频繁，请 {retry_after} 秒后重试 (每分钟最多 {RATE_LIMIT_MAX} 次)"
        }), 429

    data = request.get_json()
    base_url = (data.get("base_url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    scan_models_str = data.get("scan_models") or None

    if not base_url:
        return jsonify({"error": "需要填写目标地址"}), 400
    if not api_key:
        return jsonify({"error": "需要填写 API Key"}), 400

    # 确定要检查的模型列表
    if scan_models_str:
        target_models = [m.strip() for m in scan_models_str.split(",") if m.strip()]
    else:
        target_models = list(detect.SCAN_MODELS)

    task_id = str(uuid.uuid4())[:8]

    def run_check():
        results = {}
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(target_models), 8)) as pool:
            future_map = {
                pool.submit(detect.check_model_available, base_url, api_key, m): m
                for m in target_models
            }
            for fut in concurrent.futures.as_completed(future_map):
                m = future_map[fut]
                try:
                    results[m] = fut.result()
                except Exception:
                    results[m] = False
        return results

    # 同步执行 (模型可用性检查很快，不需要异步)
    model_results = run_check()

    available = [m for m, ok in model_results.items() if ok]
    unavailable = [m for m, ok in model_results.items() if not ok]

    # 按原始顺序排列
    available.sort(key=lambda m: target_models.index(m) if m in target_models else 999)
    unavailable.sort(key=lambda m: target_models.index(m) if m in target_models else 999)

    resp = jsonify({
        "total": len(target_models),
        "available": available,
        "unavailable": unavailable,
        "available_count": len(available),
        "unavailable_count": len(unavailable),
        "models": {m: ("available" if ok else "unavailable") for m, ok in model_results.items()},
    })
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    return resp


def _run_detect(task):
    task.status = "running"
    task.add_log(f"开始检测 {task.base_url}")

    def progress_cb(step, total, msg):
        if task.is_stopped():
            raise InterruptedError("用户停止了检测")
        task.set_progress(step, total, msg)

    try:
        result = detect.detect_full(
            task.base_url,
            task.api_key,
            options=task.options,
            progress_callback=progress_cb,
        )
        if task.is_stopped():
            task.status = "stopped"
            task.add_log("检测已停止")
            return
        task.result = result
        task.status = "done"
        task.progress = 100
        task.add_log("检测完成")
    except InterruptedError:
        task.status = "stopped"
        task.add_log("检测已停止")
    except Exception as e:
        if task.is_stopped():
            task.status = "stopped"
            task.add_log("检测已停止")
        else:
            task.status = "error"
            task.error_msg = str(e)
            task.add_log(f"检测失败: {e}")


@app.route("/api/stop/<task_id>", methods=["POST"])
def stop_detect(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    if task.status not in ("pending", "running"):
        return jsonify({"error": "任务已结束", "status": task.status}), 400
    task.stop_event.set()
    task.add_log("正在停止检测...")
    return jsonify({"ok": True})


@app.route("/api/progress/<task_id>")
def progress_stream(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    def generate():
        last_log_idx = 0
        last_sent_progress = -1
        while True:
            while last_log_idx < len(task.logs):
                log = task.logs[last_log_idx]
                data = json.dumps({
                    "type": "log",
                    "msg": log["msg"],
                    "progress": task.progress,
                }, ensure_ascii=False)
                yield f"data: {data}\n\n"
                last_sent_progress = task.progress
                last_log_idx += 1

            if task.status == "done":
                data = json.dumps({"type": "done", "progress": 100}, ensure_ascii=False)
                yield f"data: {data}\n\n"
                return
            elif task.status == "stopped":
                data = json.dumps({"type": "stopped", "msg": "检测已停止"}, ensure_ascii=False)
                yield f"data: {data}\n\n"
                return
            elif task.status == "error":
                data = json.dumps({"type": "error", "msg": task.error_msg}, ensure_ascii=False)
                yield f"data: {data}\n\n"
                return

            if task.progress != last_sent_progress:
                data = json.dumps({
                    "type": "log",
                    "msg": task.progress_msg or "检测中...",
                    "progress": task.progress,
                }, ensure_ascii=False)
                yield f"data: {data}\n\n"
                last_sent_progress = task.progress

            time.sleep(0.5)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/report/<task_id>")
def get_report(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    if task.status == "error":
        return jsonify({"error": task.error_msg}), 500
    if task.status != "done":
        return jsonify({"error": "任务尚未完成", "status": task.status}), 202
    return jsonify(task.result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  CC Proxy Detector v9.0 - Web UI")
    print(f"  http://localhost:{port}")

    try:
        from waitress import serve
        print(f"  Server: waitress (多线程并发)\n")
        serve(app, host="0.0.0.0", port=port, threads=16)
    except ImportError:
        print(f"  Server: Flask dev (建议 pip install waitress 获得并发支持)\n")
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
