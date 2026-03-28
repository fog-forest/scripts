#!/usr/bin/python3
# coding=utf8
"""EarnApp API封装 - 设备注册、列表查询、收益查询"""
import logging
from typing import Dict, List, Optional

import requests
from config import (
    MAX_PROXY_RETRY_COUNT, TOKEN_EXPIRE_ALERT_THRESHOLD,
    account_403_status, notify_lock, get_next_account
)
from utils.notify import send_account_403_alert
from utils.proxy import get_proxy_dict

logger = logging.getLogger(__name__)

API_BASE = "https://earnapp.com/dashboard/api"
API_LINK_DEVICE = f"{API_BASE}/link_device"
API_LIST_DEVICES = f"{API_BASE}/devices"
API_MONEY = f"{API_BASE}/money"
REQUEST_TIMEOUT = 15


def _build_auth(account: Dict):
    """从账号配置提取认证头和Cookie"""
    cookie_cfg = account.get('cookie', {})
    xsrf_token = cookie_cfg.get('xsrf_token', '')
    brd_sess_id = cookie_cfg.get('brd_sess_id', '')
    headers = {"Xsrf-Token": xsrf_token}
    cookies = {"xsrf-token": xsrf_token, "brd_sess_id": brd_sess_id}
    return xsrf_token, brd_sess_id, headers, cookies


def _reset_403(account_name: str) -> None:
    """请求成功后重置账号的403计数和告警标记"""
    with notify_lock:
        if account_403_status[account_name]['count'] > 0:
            account_403_status[account_name]['count'] = 0
        account_403_status[account_name]['notified'] = False


def _handle_403(label: str, account_name: str) -> Dict:
    """处理403：计数并在达到阈值时告警"""
    with notify_lock:
        account_403_status[account_name]['count'] += 1
        count = account_403_status[account_name]['count']
        logger.warning(f"{label} | 账号 {account_name} | 403 Token过期 | 计数: {count}/{TOKEN_EXPIRE_ALERT_THRESHOLD}")
        if count >= TOKEN_EXPIRE_ALERT_THRESHOLD and not account_403_status[account_name]['notified']:
            logger.error(f"账号 {account_name} 连续{TOKEN_EXPIRE_ALERT_THRESHOLD}次403，触发告警")
            send_account_403_alert(account_name, count)
            account_403_status[account_name]['notified'] = True
    return {"error": f"Account {account_name} Token expired (403)", "account": account_name}


# ── 设备注册 ──────────────────────────────────────────────────

def register_device(uuid: str) -> Dict:
    """注册设备，支持429重试和403检测，轮询账号。遇到429时同时切换账号+代理重试"""
    account = get_next_account()
    account_name = account['name']
    xsrf_token, brd_sess_id, headers, cookies = _build_auth(account)

    if not xsrf_token:
        return {"error": f"Account {account_name} missing xsrf_token", "account": account_name}
    if not brd_sess_id:
        return {"error": f"Account {account_name} missing brd_sess_id", "account": account_name}

    # 最多重试 MAX_PROXY_RETRY_COUNT 次，每次同时切换账号和代理
    for retry_idx in range(MAX_PROXY_RETRY_COUNT + 1):
        try:
            proxies = get_proxy_dict()
            response = requests.post(
                API_LINK_DEVICE,
                json={"uuid": uuid},
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 403:
                return _handle_403(f"UUID {uuid}", account_name)

            _reset_403(account_name)

            if response.status_code == 429:
                if retry_idx >= MAX_PROXY_RETRY_COUNT:
                    logger.error(f"UUID {uuid} | 账号 {account_name} | 429重试{MAX_PROXY_RETRY_COUNT}次失败")
                    return {
                        "error": f"Account {account_name} Too many requests (429), failed after {MAX_PROXY_RETRY_COUNT} retries",
                        "account": account_name}
                # 429 时切换账号+代理重试，避免同一账号持续被限流
                account = get_next_account()
                account_name = account['name']
                xsrf_token, brd_sess_id, headers, cookies = _build_auth(account)
                logger.warning(f"UUID {uuid} | 429限流 | 第{retry_idx + 1}次重试 | 切换至账号 {account_name}")
                continue

            if response.status_code == 200:
                result = response.json()
                result['account'] = account_name
                return result

            logger.error(f"UUID {uuid} | 账号 {account_name} | 状态码: {response.status_code}")
            return {"error": f"Account {account_name} Request failed, status: {response.status_code}",
                    "account": account_name}

        except requests.exceptions.Timeout:
            _reset_403(account_name)
            logger.error(f"UUID {uuid} | 账号 {account_name} | 请求超时")
            return {"error": f"Account {account_name} Request timeout", "account": account_name}
        except requests.exceptions.ConnectionError:
            _reset_403(account_name)
            logger.error(f"UUID {uuid} | 账号 {account_name} | 连接失败")
            return {"error": f"Account {account_name} Connection error", "account": account_name}
        except Exception as e:
            _reset_403(account_name)
            logger.error(f"UUID {uuid} | 账号 {account_name} | 异常: {e}")
            return {"error": f"Account {account_name} {e}", "account": account_name}

    return {"error": f"Account {account_name} Unknown error", "account": account_name}


# ── 设备列表查询 ──────────────────────────────────────────────

def get_devices(account: Dict) -> Optional[List[Dict]]:
    """获取指定账号的设备列表"""
    account_name = account['name']
    xsrf_token, brd_sess_id, _, _ = _build_auth(account)
    # get_devices 不走代理，直接用账号 Cookie 请求
    headers = {
        "xsrf-token": xsrf_token,
        "cookie": f"xsrf-token={xsrf_token}; brd_sess_id={brd_sess_id}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(API_LIST_DEVICES, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        devices = resp.json()
        if not isinstance(devices, list):
            logger.error(f"账号 {account_name} 设备列表格式异常")
            return None
        return devices
    except Exception as e:
        logger.error(f"账号 {account_name} 获取设备列表失败: {e}")
        return None


# ── 收益查询 ──────────────────────────────────────────────────

def get_money(account: Dict) -> Dict:
    """
    查询账号收益。
    返回: {'ok': True, 'data': {...}} 或 {'ok': False, 'error': 'token_expired'|'ip_banned'|...}
    """
    account_name = account['name']
    xsrf_token, brd_sess_id, _, _ = _build_auth(account)
    headers = {
        "xsrf-token": xsrf_token,
        "cookie": f"xsrf-token={xsrf_token}; brd_sess_id={brd_sess_id}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(API_MONEY, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 403:
            logger.warning(f"账号 {account_name} 收益查询403")
            return {'ok': False, 'error': 'token_expired'}
        if resp.status_code == 406:
            logger.warning(f"账号 {account_name} 收益查询406: IP被封禁")
            return {'ok': False, 'error': 'ip_banned'}
        if resp.status_code == 200:
            return {'ok': True, 'data': resp.json()}
        logger.error(f"账号 {account_name} 收益查询失败 | 状态码: {resp.status_code}")
        return {'ok': False, 'error': 'request_failed', 'status_code': resp.status_code}
    except Exception as e:
        logger.error(f"账号 {account_name} 收益查询异常: {e}")
        return {'ok': False, 'error': str(e)}
