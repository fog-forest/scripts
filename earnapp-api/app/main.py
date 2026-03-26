#!/usr/bin/python3
# coding=utf8
"""EarnApp设备注册API服务入口"""
import logging
import os
import threading

from flask import Flask

from api.routes import bp
from config import (
    ACCOUNTS, ALARM_ENABLED, PROXY_HOST, PROXY_PORT,
    PROXY_USER_TPL, PROXY_PASS_TPL,
    API_CALL_INTERVAL, MAX_PROXY_RETRY_COUNT, TOKEN_EXPIRE_ALERT_THRESHOLD,
    REPORT_HOURS, DELETE_BANNED_INTERVAL
)
from core.queue_processor import process_uuids, uuid_queue
from jobs.scheduler import start_scheduler
from utils.notify import send_startup_notification
from utils.persistence import ensure_data_dir_exists, load_uuid_status, uuid_status

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.register_blueprint(bp)

if __name__ == "__main__":
    try:
        ensure_data_dir_exists()
        load_uuid_status()

        send_startup_notification(
            queue_size=uuid_queue.qsize(),
            recorded_uuids=len(uuid_status)
        )

        logger.info(f"账号数: {len(ACCOUNTS)} | 告警: {'开启' if ALARM_ENABLED else '关闭'}")

        if all([PROXY_HOST, PROXY_PORT]):
            if PROXY_USER_TPL and PROXY_PASS_TPL:
                auth_info = "用户名+密码"
            elif PROXY_USER_TPL:
                auth_info = "仅用户名"
            elif PROXY_PASS_TPL:
                auth_info = "仅密码"
            else:
                auth_info = "无认证"
            logger.info(f"代理: {PROXY_HOST}:{PROXY_PORT} | 认证: {auth_info}")
        else:
            logger.info("未配置代理")

        threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()
        start_scheduler()

        port = int(os.getenv("PORT", 5000))
        logger.info(
            f"服务启动 | 0.0.0.0:{port} | "
            f"API间隔: {API_CALL_INTERVAL}s | 429重试: {MAX_PROXY_RETRY_COUNT}次 | "
            f"403阈值: {TOKEN_EXPIRE_ALERT_THRESHOLD}次 | "
            f"日报时间: {REPORT_HOURS} | 自动删除间隔: {DELETE_BANNED_INTERVAL}分钟"
        )
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

    except Exception as e:
        logger.error(f"服务启动失败: {e}")
        exit(1)
