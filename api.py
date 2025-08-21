import time
from dotenv import load_dotenv
import psutil
import requests

load_dotenv("conf/.env")

import atexit
import json
import os
import traceback
from datetime import datetime
from urllib.parse import urljoin, urlparse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask, request, jsonify

from biz.gitlab.webhook_handler import slugify_url
from biz.queue.worker import (
    handle_merge_request_event, handle_merge_request_event_v2, handle_push_event, 
    handle_github_pull_request_event, handle_github_push_event
)
from biz.service.review_service import ReviewService
from biz.utils.im import notifier
from biz.utils.log import logger
from biz.utils.queue import handle_queue
from biz.utils.reporter import Reporter

from biz.utils.config_checker import check_config

# 初始化 Flask 应用
api_app = Flask(__name__)
# 配置：推送评审功能开关
push_review_enabled = os.environ.get('PUSH_REVIEW_ENABLED', '0') == '1'
# 全局状态：调度器状态（用于存活检查）
scheduler_status = {
    "initialized": False,
    "start_time": None,
    "error": None
}
# 全局状态：服务就绪检查依赖状态
service_status = {
    "queue": {"backlog": 0, "max_backlog": 50},  # 任务队列最大积压阈值
    "start_time": datetime.now().timestamp()
}


# ---------------------- 原有业务路由 ----------------------
@api_app.route('/')
def home():
    return """<h2>The code review api server is running.</h2>
              <p>GitHub project address: <a href="https://github.com/sunmh207/AI-Codereview-Gitlab" target="_blank">
              https://github.com/sunmh207/AI-Codereview-Gitlab</a></p>
              <p>Gitee project address: <a href="https://gitee.com/sunminghui/ai-codereview-gitlab" target="_blank">
              https://gitee.com/sunminghui/ai-codereview-gitlab</a></p>
              """


@api_app.route('/review/daily_report', methods=['GET'])
def daily_report():
    # 获取当前日期0点和23点59分59秒的时间戳
    start_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    end_time = datetime.now().replace(hour=23, minute=59, second=59, microsecond=0).timestamp()

    try:
        if push_review_enabled:
            df = ReviewService().get_push_review_logs(updated_at_gte=start_time, updated_at_lte=end_time)
        else:
            df = ReviewService().get_mr_review_logs(updated_at_gte=start_time, updated_at_lte=end_time)

        if df.empty:
            logger.info("No data to process.")
            return jsonify({'message': 'No data to process.'}), 200
        # 去重：基于 (author, message) 组合
        df_unique = df.drop_duplicates(subset=["author", "commit_messages"])
        # 按照 author 排序
        df_sorted = df_unique.sort_values(by="author")
        # 转换为适合生成日报的格式
        commits = df_sorted.to_dict(orient="records")
        # 生成日报内容
        report_txt = Reporter().generate_report(json.dumps(commits))
        # 发送钉钉通知
        notifier.send_notification(content=report_txt, msg_type="markdown", title="代码提交日报")

        # 返回生成的日报内容
        return json.dumps(report_txt, ensure_ascii=False, indent=4)
    except Exception as e:
        logger.error(f"Failed to generate daily report: {e}")
        return jsonify({'message': f"Failed to generate daily report: {e}"}), 500


# ---------------------- 定时任务调度器 ----------------------
def setup_scheduler():
    """配置并启动定时任务调度器（更新全局调度器状态）"""
    try:
        scheduler = BackgroundScheduler()
        crontab_expression = os.getenv('REPORT_CRONTAB_EXPRESSION', '0 18 * * 1-5')
        cron_parts = crontab_expression.split()
        cron_minute, cron_hour, cron_day, cron_month, cron_day_of_week = cron_parts

        # 添加定时日报任务
        scheduler.add_job(
            daily_report,
            trigger=CronTrigger(
                minute=cron_minute,
                hour=cron_hour,
                day=cron_day,
                month=cron_month,
                day_of_week=cron_day_of_week
            )
        )

        # Start the scheduler
        scheduler.start()
        logger.info("Scheduler started successfully.")
        # 更新调度器状态为成功
        scheduler_status["initialized"] = True
        scheduler_status["start_time"] = datetime.now().timestamp()
        scheduler_status["error"] = None

        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())
    except Exception as e:
        err_msg = f"Error setting up scheduler: {str(e)}"
        logger.error(err_msg)
        logger.error(traceback.format_exc())
        # 更新调度器状态为失败
        scheduler_status["initialized"] = False
        scheduler_status["error"] = err_msg


# ---------------------- Webhook 处理逻辑 ----------------------
@api_app.route('/review/webhook', methods=['POST'])
def handle_webhook():
    # 获取请求的JSON数据
    if request.is_json:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        # 判断是GitLab还是GitHub的webhook
        webhook_source = request.headers.get('X-GitHub-Event')

        if webhook_source:  # GitHub webhook
            return handle_github_webhook(webhook_source, data)
        else:  # GitLab webhook
            return handle_gitlab_webhook(data)
    else:
        return jsonify({'message': 'Invalid data format'}), 400


def handle_github_webhook(event_type, data):
    # 获取GitHub配置
    github_token = os.getenv('GITHUB_ACCESS_TOKEN') or request.headers.get('X-GitHub-Token')
    if not github_token:
        return jsonify({'message': 'Missing GitHub access token'}), 400

    github_url = os.getenv('GITHUB_URL') or 'https://github.com'
    github_url_slug = slugify_url(github_url)

    # 打印整个payload数据
    logger.info(f'Received GitHub event: {event_type}')
    logger.info(f'Payload: {json.dumps(data)}')

    # 处理支持的事件类型
    if event_type == "pull_request":
        # 使用handle_queue进行异步处理
        handle_queue(handle_github_pull_request_event, data, github_token, github_url, github_url_slug)
        # 立马返回响应
        return jsonify(
            {'message': f'GitHub request received(event_type={event_type}), will process asynchronously.'}), 200
    elif event_type == "push":
        # 使用handle_queue进行异步处理
        handle_queue(handle_github_push_event, data, github_token, github_url, github_url_slug)
        # 立马返回响应
        return jsonify(
            {'message': f'GitHub request received(event_type={event_type}), will process asynchronously.'}), 200
    else:
        error_message = f'Only pull_request and push events are supported for GitHub webhook, but received: {event_type}.'
        logger.error(error_message)
        return jsonify(error_message), 400


def handle_gitlab_webhook(data):
    object_kind = data.get("object_kind")

    # 获取GitLab URL（优先级：请求头 > 环境变量 > 事件数据）
    gitlab_url = os.getenv('GITLAB_URL') or request.headers.get('X-Gitlab-Instance')
    if not gitlab_url:
        repository = data.get('repository')
        if not repository:
            return jsonify({'message': 'Missing GitLab URL'}), 400
        homepage = repository.get("homepage")
        if not homepage:
            return jsonify({'message': 'Missing GitLab URL'}), 400
        try:
            parsed_url = urlparse(homepage)
            gitlab_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        except Exception as e:
            return jsonify({"error": f"Failed to parse homepage URL: {str(e)}"}), 400

    # 获取GitLab Token（优先级：请求头 > 环境变量 ）
    gitlab_token = request.headers.get('X-Gitlab-Token') or os.getenv('GITLAB_ACCESS_TOKEN')
    # 如果gitlab_token为空，返回错误
    if not gitlab_token:
        return jsonify({'message': 'Missing GitLab access token'}), 400

    gitlab_url_slug = slugify_url(gitlab_url)
    # 打印日志
    logger.info(f'Received event: {object_kind}')
    logger.info(f'Payload: {json.dumps(data)}')

    # 处理支持的事件类型
    if object_kind == "merge_request":
        # 创建一个新进程进行异步处理
        handle_queue(handle_merge_request_event_v2, data, gitlab_token, gitlab_url, gitlab_url_slug)
        # 立马返回响应
        return jsonify(
            {'message': f'Request received(object_kind={object_kind}), will process asynchronously.'}), 200
    elif object_kind == "push":
        # 创建一个新进程进行异步处理
        # TODO check if PUSH_REVIEW_ENABLED is needed here
        handle_queue(handle_push_event, data, gitlab_token, gitlab_url, gitlab_url_slug)
        # 立马返回响应
        return jsonify(
            {'message': f'Request received(object_kind={object_kind}), will process asynchronously.'}), 200
    else:
        error_message = f'Only merge_request and push events are supported (both Webhook and System Hook), but received: {object_kind}.'
        logger.error(error_message)
        return jsonify(error_message), 400


# ---------------------- 存活探针（livenessProbe） ----------------------
@api_app.route('/health/liveness', methods=['GET'])
def liveness_check():
    """存活探针：检查服务核心进程状态（不依赖外部服务）"""
    # 1. 检查Flask应用实例是否正常
    if not isinstance(api_app, Flask):
        return jsonify({
            "status": "dead",
            "reason": "Flask 应用实例未初始化",
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 500

    # 2. 检查定时调度器是否启动成功
    if not scheduler_status["initialized"]:
        return jsonify({
            "status": "dead",
            "reason": f"定时调度器初始化失败: {scheduler_status.get('error', '未知错误')}",
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 500

    # 3. 检查核心业务依赖是否可导入（避免代码缺失）
    try:
        from biz.service.review_service import ReviewService
        from biz.utils.queue import handle_queue
        logger.debug("Core business dependencies are available.")
    except ImportError as e:
        return jsonify({
            "status": "dead",
            "reason": f"核心业务依赖导入失败: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 500

    # 4. 检查内存使用率（避免OOM假死）
    def get_memory_usage():
        process = psutil.Process()
        return round(process.memory_percent(), 2)
    
    memory_usage = get_memory_usage()
    memory_threshold = 95  # 可根据服务资源配置调整
    if memory_usage > memory_threshold:
        return jsonify({
            "status": "dead",
            "reason": f"内存使用率超过阈值 {memory_threshold}%，当前: {memory_usage}%",
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 500

    # 5. 所有检查通过：返回存活状态
    return jsonify({
        "status": "alive",
        "uptime_seconds": int(datetime.now().timestamp() - scheduler_status["start_time"]),
        "scheduler_status": "running",
        "memory_usage": f"{memory_usage}%",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    }), 200


# ---------------------- 就绪探针（readinessProbe） ----------------------
def check_vcs_api():
    """检查 GitLab/GitHub API 可用性（必须返回含 "status" 键的字典）"""
    # 初始化返回结构：默认包含 "status" 和 "error" 键
    vcs_status = {
        "status": "unavailable",  # 默认未就绪，后续根据检查结果更新
        "error": None,
        "gitlab": "unavailable",  # 可选：保留子依赖状态，便于调试
        "github": "unavailable"
    }
    timeout = 5  # 超时时间，避免阻塞探针

    # 1. 检查 GitLab API
    gitlab_url = os.getenv('GITLAB_URL')
    gitlab_token = os.getenv('GITLAB_ACCESS_TOKEN')
    if gitlab_url and gitlab_token:
        try:
            gitlab_api_url = urljoin(gitlab_url, "/api/v4/projects")
            headers = {"Private-Token": gitlab_token}
            response = requests.head(gitlab_api_url, headers=headers, timeout=timeout)
            # 更新 GitLab 子状态
            if response.status_code == 200:
                vcs_status["gitlab"] = "available"
            elif response.status_code == 401:
                vcs_status["gitlab"] = "token_invalid"
                vcs_status["error"] = "GitLab Token 无效"
        except Exception as e:
            vcs_status["gitlab"] = "unavailable"
            vcs_status["error"] = f"GitLab 检查失败: {str(e)}"

    # 2. 检查 GitHub API
    github_token = os.getenv('GITHUB_ACCESS_TOKEN')
    if github_token:
        try:
            github_api_url = urljoin(os.getenv('GITHUB_URL', 'https://github.com'), "/api/v3/user")
            headers = {"Authorization": f"token {github_token}"}
            response = requests.head(github_api_url, headers=headers, timeout=timeout)
            # 更新 GitHub 子状态
            if response.status_code == 200:
                vcs_status["github"] = "available"
            elif response.status_code == 401:
                vcs_status["github"] = "token_invalid"
                if not vcs_status["error"]:  # 优先保留先出现的错误
                    vcs_status["error"] = "GitHub Token 无效"
        except Exception as e:
            vcs_status["github"] = "unavailable"
            if not vcs_status["error"]:
                vcs_status["error"] = f"GitHub 检查失败: {str(e)}"

    # 3. 确定整体 status（只要有一个 VCS 可用，整体视为可用；若 Token 无效，按实际场景调整）
    if vcs_status["gitlab"] in ["available", "token_invalid"] or vcs_status["github"] in ["available", "token_invalid"]:
        # 若 Token 无效，可根据需求调整 status（如 "token_invalid"，需在后续判断中兼容）
        vcs_status["status"] = "available" if (vcs_status["gitlab"] == "available" or vcs_status["github"] == "available") else "token_invalid"
    
    # 最终返回：确保包含 "status" 键
    return vcs_status


@api_app.route('/health/readiness', methods=['GET'])
def readiness_check():
    """就绪探针：检查服务能否处理核心业务（Webhook/评审/日报）"""
    # 1. 基础存活检查（复用liveness核心逻辑，避免重复）
    base_error = None
    if not isinstance(api_app, Flask):
        base_error = "Flask 应用实例未初始化"
    elif not scheduler_status["initialized"]:
        base_error = f"定时调度器未启动：{scheduler_status['error']}"
    
    if base_error:
        return jsonify({
            "status": "not_ready",
            "reason": base_error,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 503

    # 2. 检查所有关键业务依赖
    dependencies = {
        "vcs_api": check_vcs_api(),          # GitLab/GitHub API（Webhook处理）
        "scheduler": {"status": "available" if scheduler_status["initialized"] else "unavailable", "error": scheduler_status["error"]}
    }

    # 3. 检查必要配置完整性
    required_env = []
    if os.getenv('GITLAB_URL') and not os.getenv('GITLAB_ACCESS_TOKEN'):
        required_env.append("GITLAB_ACCESS_TOKEN")
    if os.getenv('GITHUB_URL') and not os.getenv('GITHUB_ACCESS_TOKEN'):
        required_env.append("GITHUB_ACCESS_TOKEN")
    if not os.getenv('SERVER_PORT'):
        required_env.append("SERVER_PORT")
    
    if required_env:
        dependencies["config"] = {"status": "unavailable", "error": f"缺失必要配置：{', '.join(required_env)}"}
    else:
        dependencies["config"] = {"status": "available", "error": None}

    # 4. 判断是否存在不可用依赖
    unavailable_deps = [name for name, dep in dependencies.items() if dep["status"] not in ["available", "token_invalid"]]
    if unavailable_deps:
        fail_reasons = [f"{name}: {dependencies[name]['error']}" for name in unavailable_deps]
        return jsonify({
            "status": "not_ready",
            "reason": f"关键依赖不可用：{'; '.join(fail_reasons)}",
            "dependencies": {name: dep["status"] for name, dep in dependencies.items()},
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }), 503

    # 5. 特殊提示：Token无效（不阻塞服务，但需告警）
    token_invalid_deps = [name for name, dep in dependencies.items() if dep["status"] == "token_invalid"]
    if token_invalid_deps:
        logger.warning(f"部分VCS Token无效：{', '.join(token_invalid_deps)}，请检查配置")

    # 6. 所有检查通过：返回就绪状态
    return jsonify({
        "status": "ready",
        "uptime_seconds": int(datetime.now().timestamp() - service_status["start_time"]),
        "dependencies": {name: dep["status"] for name, dep in dependencies.items()},
        "queue_backlog": service_status["queue"]["backlog"],
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    }), 200


# ---------------------- 应用启动入口 ----------------------
if __name__ == '__main__':
    check_config()
    # 启动定时任务调度器
    setup_scheduler()
    # 启动Flask服务
    port = int(os.environ.get('SERVER_PORT', 5001))
    api_app.run(host='0.0.0.0', port=port, debug=False)  # 生产环境禁用debug