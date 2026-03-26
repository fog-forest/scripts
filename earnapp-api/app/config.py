#!/usr/bin/python3
# coding=utf8
"""全局配置加载"""
import logging
import os
import threading
from typing import Dict

import yaml

logger = logging.getLogger(__name__)

CONFIG_FILE = "/data/config.yaml"  # 配置文件路径（容器内挂载）
DATA_DIR = "/data"  # 数据目录
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")  # UUID状态持久化文件

# 接口调用
API_CALL_INTERVAL = 5  # 每次注册请求后的等待间隔（秒），避免频繁调用
MAX_PROXY_RETRY_COUNT = 2  # 遇到429限流时的最大重试次数
TOKEN_EXPIRE_ALERT_THRESHOLD = 5  # 账号连续403次数达到此阈值时触发告警

# 统一响应码，供 routes.py 使用
RESPONSE_CODES = {
    "SUCCESS": 0,
    "INVALID_PARAM": 1001,
    "UNAUTHORIZED": 1002,
    "UUID_NOT_FOUND": 1003,
    "DUPLICATE_UUID": 1004,
    "SYSTEM_ERROR": 9999
}


def load_config() -> Dict:
    """读取并解析 YAML 配置文件，失败时抛出异常"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_FILE}")
    with open(CONFIG_FILE, 'r', encoding='utf8') as f:
        try:
            config = yaml.safe_load(f)
            logger.info(f"加载配置文件成功: {CONFIG_FILE}")
            return config
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"配置文件解析错误: {str(e)}")


_config = load_config()

AUTH_TOKEN: str = _config.get('global', {}).get('auth_token', '')
if not AUTH_TOKEN:
    raise ValueError("global.auth_token 未配置")

ACCOUNT_VERSION: str = _config.get('global', {}).get('account_version', '')
if not ACCOUNT_VERSION:
    logger.warning("global.account_version 未配置，建议填写随机字符串标识账号版本")

ACCOUNTS = _config.get('accounts', [])
if not ACCOUNTS:
    raise ValueError("accounts 列表为空，请至少配置一个账号")

# 定时任务
_scheduler_cfg = _config.get('scheduler', {})
# 日报推送小时列表，默认 9、15、20 点整点触发
REPORT_HOURS: list = _scheduler_cfg.get('report_hours', [9, 15, 20])
# 自动删除被ban设备的执行间隔（分钟），默认 120 分钟（2小时）
DELETE_BANNED_INTERVAL: int = int(_scheduler_cfg.get('delete_banned_interval_minutes', 120))

# 告警
ALARM_ENABLED: bool = _config.get('alarm', {}).get('enabled', False)
QMSG_CONFIG = _config.get('alarm', {}).get('qmsg', {})
QMSG_TOKEN: str = QMSG_CONFIG.get('token', '')
QMSG_QQ: str = str(QMSG_CONFIG.get('qq', ''))
QMSG_BOT: str = str(QMSG_CONFIG.get('bot_id', ''))
QMSG_API: str = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else ''

# 代理
PROXY_CONFIG = _config.get('proxy', {})
PROXY_HOST: str = PROXY_CONFIG.get('host', '')
PROXY_PORT = PROXY_CONFIG.get('port')
PROXY_USER_TPL: str = PROXY_CONFIG.get('user_template', '')
PROXY_PASS_TPL: str = PROXY_CONFIG.get('password_template', '')
RND_CHARSET: str = PROXY_CONFIG.get('random_charset', 'abcdefghijklmnopqrstuvwxyz0123456789')

# 账号轮询（线程安全）
_account_index = 0
account_lock = threading.Lock()  # 保护 _account_index 的轮询锁
notify_lock = threading.Lock()  # 保护 403 告警状态的锁，防止重复发送通知

# 每个账号的 403 计数与告警状态，格式: {account_name: {count, notified}}
account_403_status: Dict[str, Dict] = {
    account['name']: {'count': 0, 'notified': False} for account in ACCOUNTS
}


def get_next_account() -> Dict:
    """轮询获取下一个账号"""
    global _account_index
    with account_lock:
        account = ACCOUNTS[_account_index]
        _account_index = (_account_index + 1) % len(ACCOUNTS)
        return account
