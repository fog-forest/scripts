#!/usr/bin/python3
# coding=utf8
"""定时任务 - 日报推送 + 定时删除被ban设备"""
import logging
import threading
import time
from datetime import datetime
from typing import List, Dict

from config import ACCOUNTS, REPORT_HOURS, DELETE_BANNED_INTERVAL
from core.earnapp_api import get_devices, get_money
from jobs.delete_devices import run_delete
from utils.notify import send_qmsg_notification

logger = logging.getLogger(__name__)

# 日报推送小时列表和删除间隔均从配置文件读取
NOTIFY_HOURS: List[int] = REPORT_HOURS


# ── 日报 ──────────────────────────────────────────────────────

def _build_account_report(account: Dict) -> str:
    name = account['name']
    lines = [f"📋 账号: {name}"]

    devices = get_devices(account)
    if devices is None:
        lines.append("  设备列表: 查询失败")
    else:
        total = len(devices)
        banned = sum(1 for d in devices if d.get('banned'))
        lines.append(f"  设备总数: {total}  (正常: {total - banned} | 被封: {banned})")

    money = get_money(account)
    if not money['ok']:
        err = money['error']
        if err == 'token_expired':
            lines.append("  收益查询: ⚠️ Token过期或账号已封禁，请及时更新Cookie")
        elif err == 'ip_banned':
            lines.append("  收益查询: 🚫 查询IP已被封禁")
        else:
            lines.append(f"  收益查询: 失败 ({err})")
    else:
        d = money['data']
        email = d.get('redeem_details', {}).get('email', '未知')
        payment = d.get('redeem_details', {}).get('payment_method', '未知')
        lines.append(f"  提现账户: {email} ({payment})")
        lines.append(f"  当前余额: ${d.get('balance', 0):.3f}")
        lines.append(f"  累计收益: ${d.get('earnings_total', 0):.3f}")

    return "\n".join(lines)


def send_daily_report() -> None:
    """组装并推送全账号日报"""
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info(f"推送日报 | {now_str}")
    sections = [f"📊 EarnApp 账号日报\n🕐 时间: {now_str}\n"]
    for account in ACCOUNTS:
        try:
            sections.append(_build_account_report(account))
        except Exception as e:
            logger.error(f"账号 {account['name']} 日报生成异常: {e}")
            sections.append(f"📋 账号: {account['name']}\n  ❌ 数据获取异常: {e}")
    send_qmsg_notification("\n\n".join(sections))
    logger.info("日报推送完毕")


# ── 调度循环 ──────────────────────────────────────────────────

def _scheduler_loop() -> None:
    """
    调度主循环，每30秒检查一次：
    - 日报：命中 NOTIFY_HOURS 中的整点小时时推送，每天每个小时只触发一次
    - 自动删除被ban设备：按 DELETE_BANNED_INTERVAL 分钟间隔执行，服务启动后首次立即触发
    """
    triggered_reports = set()  # 已推送日报的小时 key，格式: 'report_9'，防止同一小时重复推送
    last_day = datetime.now().day
    last_delete_time = 0.0  # 上次执行删除的时间戳，0 表示从未执行（服务启动后首次立即触发）
    delete_interval_sec = DELETE_BANNED_INTERVAL * 60
    logger.info(f"定时器已启动 | 日报时间: {NOTIFY_HOURS} | 自动删除间隔: {DELETE_BANNED_INTERVAL}分钟")

    while True:
        try:
            now = datetime.now()
            now_ts = time.time()

            # 跨零点重置日报触发记录
            if now.day != last_day:
                triggered_reports.clear()
                last_day = now.day
                logger.debug("日期切换，重置日报触发记录")

            # 日报：整点命中时推送
            if now.minute == 0:
                report_key = f"report_{now.hour}"
                if now.hour in NOTIFY_HOURS and report_key not in triggered_reports:
                    triggered_reports.add(report_key)
                    threading.Thread(
                        target=send_daily_report,
                        name=f"DailyReport-{now.hour:02d}",
                        daemon=True
                    ).start()

            # 自动删除被ban设备：按间隔触发
            if now_ts - last_delete_time >= delete_interval_sec:
                last_delete_time = now_ts
                threading.Thread(
                    target=run_delete,
                    args=('banned',),
                    name=f"DeleteBanned-{now.strftime('%H%M')}",
                    daemon=True
                ).start()

        except Exception as e:
            logger.error(f"调度循环异常: {e}")

        time.sleep(30)


def start_scheduler() -> None:
    """启动定时调度后台线程"""
    t = threading.Thread(target=_scheduler_loop, name="Scheduler", daemon=True)
    t.start()
    logger.info("定时调度器已启动")
