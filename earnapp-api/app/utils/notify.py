#!/usr/bin/python3
# coding=utf8
"""通知模块 - QMSG推送"""
import logging
from datetime import datetime

import requests
from config import (
    ALARM_ENABLED, QMSG_TOKEN, QMSG_QQ, QMSG_BOT, QMSG_API,
    ACCOUNTS, API_CALL_INTERVAL, MAX_PROXY_RETRY_COUNT,
    PROXY_HOST, PROXY_PORT, PROXY_USER_TPL, PROXY_PASS_TPL
)

logger = logging.getLogger(__name__)


def send_qmsg_notification(message: str) -> bool:
    """发送QMSG通知"""
    if not ALARM_ENABLED:
        logger.debug("告警已关闭，跳过通知")
        return False
    if not all([QMSG_TOKEN, QMSG_QQ, QMSG_BOT]):
        logger.warning("QMSG配置不完整，跳过通知")
        return False
    try:
        resp = requests.post(
            QMSG_API,
            json={"msg": message, "qq": QMSG_QQ, "bot": QMSG_BOT},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            logger.info(f"QMSG通知发送成功: {message[:50]}...")
            return True
        logger.error(f"QMSG通知失败 | 状态码: {resp.status_code} | {resp.text}")
        return False
    except Exception as e:
        logger.error(f"QMSG通知异常: {e}")
        return False


def send_startup_notification(queue_size: int, recorded_uuids: int) -> None:
    """服务启动通知"""
    proxy_status = "已配置" if all([PROXY_HOST, PROXY_PORT]) else "未配置"
    if PROXY_USER_TPL and PROXY_PASS_TPL:
        proxy_auth = "用户名+密码"
    elif PROXY_USER_TPL:
        proxy_auth = "仅用户名"
    elif PROXY_PASS_TPL:
        proxy_auth = "仅密码"
    else:
        proxy_auth = "无认证"

    send_qmsg_notification(
        f"🚀 EarnApp注册服务已启动\n"
        f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"队列长度: {queue_size} | 已记录UUID: {recorded_uuids}\n"
        f"配置账号数: {len(ACCOUNTS)}\n"
        f"API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次\n"
        f"代理: {proxy_status} ({proxy_auth})\n"
        f"告警功能: {'开启' if ALARM_ENABLED else '关闭'}"
    )


def send_account_403_alert(account_name: str, count: int) -> None:
    """账号403 Token过期告警"""
    send_qmsg_notification(
        f"⚠️ EarnApp账号Token过期告警\n"
        f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"账号: {account_name}\n"
        f"连续403次数: {count}\n"
        f"请及时更新该账号Cookie！"
    )
