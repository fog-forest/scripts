#!/usr/bin/python3
# coding=utf8
"""
EarnApp设备批量删除
- 支持 --all / --banned 参数静默运行
- 也可作为模块被scheduler调用
- 被ban设备删除时同步更新 uuid_status.json
"""
import json
import os
import sys
import time
from typing import Dict, List, Optional

import requests
import yaml

from config import CONFIG_FILE, STATUS_FILE

REQUEST_TIMEOUT = 15
REQUEST_INTERVAL = 1  # 同账号设备间隔(秒)
ACCOUNT_INTERVAL = 3  # 账号间隔(秒)

API_BASE = "https://earnapp.com/dashboard/api"
API_LIST_DEVICES = f"{API_BASE}/devices"
API_DELETE_DEVICE = f"{API_BASE}/device/"


# ── 状态文件 ──────────────────────────────────────────────────

def load_uuid_status() -> Dict:
    if not os.path.exists(STATUS_FILE):
        return {}
    try:
        with open(STATUS_FILE, 'r', encoding='utf8') as f:
            return json.load(f).get('uuid_status', {})
    except Exception as e:
        print(f"[WARNING] 加载UUID状态失败: {e}")
        return {}


def save_uuid_status(uuid_status: Dict) -> None:
    try:
        temp = f"{STATUS_FILE}.tmp"
        with open(temp, 'w', encoding='utf8') as f:
            json.dump({'uuid_status': uuid_status}, f, ensure_ascii=False, indent=2)
        os.replace(temp, STATUS_FILE)
    except Exception as e:
        print(f"[WARNING] 保存UUID状态失败: {e}")


def mark_uuid_banned(uuid: str, ban_reason: str, uuid_status: Dict) -> None:
    msg = f"Device banned: {ban_reason}"
    if uuid not in uuid_status:
        uuid_status[uuid] = {}
    uuid_status[uuid]['status'] = 'banned'
    uuid_status[uuid]['message'] = msg
    print(f"  [STATUS] {uuid} 已标记为 banned | {msg}")


# ── 配置加载 ──────────────────────────────────────────────────

def load_config() -> Optional[Dict]:
    try:
        if not os.path.exists(CONFIG_FILE):
            print(f"[ERROR] 配置文件不存在: {CONFIG_FILE}")
            return None
        with open(CONFIG_FILE, 'r', encoding='utf8') as f:
            config = yaml.safe_load(f)
        if not isinstance(config.get('accounts'), list):
            print("[ERROR] accounts字段错误")
            return None
        valid = [
            a for a in config['accounts']
            if a.get('name') and a.get('cookie', {}).get('xsrf_token') and a.get('cookie', {}).get('brd_sess_id')
        ]
        if not valid:
            print("[ERROR] 无有效账号")
            return None
        config['accounts'] = valid
        return config
    except Exception as e:
        print(f"[ERROR] 加载配置失败: {e}")
        return None


# ── 请求工具 ──────────────────────────────────────────────────

def _headers(xsrf_token: str, brd_sess_id: str) -> Dict:
    return {
        "xsrf-token": xsrf_token,
        "cookie": f"xsrf-token={xsrf_token}; brd_sess_id={brd_sess_id}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }


# ── 设备操作 ──────────────────────────────────────────────────

def get_target_devices(account: Dict, mode: str) -> List[Dict]:
    """获取待删除设备列表，返回 [{'uuid', 'ban_reason', 'ban_ip'}, ...]"""
    name = account['name']
    xsrf_token = account['cookie']['xsrf_token']
    brd_sess_id = account['cookie']['brd_sess_id']
    print(f"\n[{name}] 获取设备列表 (模式: {mode})...")
    try:
        resp = requests.get(API_LIST_DEVICES, headers=_headers(xsrf_token, brd_sess_id), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        devices = resp.json()
        if not isinstance(devices, list):
            print(f"[{name}] [ERROR] 设备列表格式异常")
            return []

        targets = []
        for device in devices:
            uuid = device.get('uuid')
            if not uuid:
                continue
            ban_info = device.get('banned', {})
            ban_reason = ban_info.get('reason', '未知') if ban_info else ''
            if mode == 'banned':
                if ban_info:
                    print(f"[{name}] [BANNED] {uuid} - 原因: {ban_reason}")
                    targets.append({'uuid': uuid, 'ban_reason': ban_reason})
            else:
                targets.append({'uuid': uuid, 'ban_reason': ban_reason})

        print(f"[{name}] 待删除设备数: {len(targets)}")
        return targets
    except Exception as e:
        print(f"[{name}] [ERROR] 获取设备列表失败: {e}")
        return []


def delete_device(account_name: str, uuid: str, xsrf_token: str, brd_sess_id: str, mode: str) -> bool:
    try:
        resp = requests.delete(
            f"{API_DELETE_DEVICE}{uuid}",
            headers=_headers(xsrf_token, brd_sess_id),
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        if resp.json().get('status') == 'ok':
            print(f"[{account_name}] [SUCCESS] 删除({mode}): {uuid}")
            return True
        print(f"[{account_name}] [FAILED] 删除({mode}) {uuid}: {resp.json()}")
        return False
    except Exception as e:
        print(f"[{account_name}] [FAILED] 删除({mode}) {uuid}: {e}")
        return False


def process_account(account: Dict, mode: str, uuid_status: Dict) -> Dict:
    """处理单个账号的设备删除，返回统计"""
    name = account['name']
    xsrf_token = account['cookie']['xsrf_token']
    brd_sess_id = account['cookie']['brd_sess_id']

    targets = get_target_devices(account, mode)
    if not targets:
        print(f"[{name}] 无待删除设备")
        return {'total': 0, 'success': 0, 'fail': 0}

    print(f"\n[{name}] 开始删除 {len(targets)} 个设备...")
    success = fail = 0
    status_dirty = False

    for idx, target in enumerate(targets, 1):
        uuid = target['uuid']
        ban_reason = target.get('ban_reason', '')
        print(f"\n[{name}] [{idx}/{len(targets)}] 处理: {uuid}")

        if ban_reason:
            mark_uuid_banned(uuid, ban_reason, uuid_status)
            status_dirty = True

        if delete_device(name, uuid, xsrf_token, brd_sess_id, mode):
            success += 1
        else:
            fail += 1

        if idx < len(targets):
            time.sleep(REQUEST_INTERVAL)

    if status_dirty:
        save_uuid_status(uuid_status)
        print(f"[{name}] UUID状态文件已更新")

    return {'total': len(targets), 'success': success, 'fail': fail}


# ── 主流程 ────────────────────────────────────────────────────

def run_delete(mode: str) -> None:
    """
    执行批量删除，可被scheduler直接调用，也可作为CLI入口。
    作为模块调用时，优先使用 persistence 模块的内存状态和锁，
    避免与 queue_processor 并发写磁盘时互相覆盖。
    """
    print(f"===== EarnApp 设备批量删除 (模式: {mode}) =====")
    config = load_config()
    if not config:
        print("[ERROR] 配置加载失败")
        return

    accounts = config['accounts']

    # 尝试复用 persistence 模块的内存状态（服务内调用时），
    # 独立运行时（CLI）fallback 到从磁盘读取
    try:
        import utils.persistence as _persistence
        _use_persistence = True
        with _persistence.status_lock:
            uuid_status = dict(_persistence.uuid_status)  # 浅拷贝用于本次操作
        print(f"[INFO] 账号数: {len(accounts)} | UUID状态记录（内存）: {len(uuid_status)}")
    except Exception:
        _use_persistence = False
        uuid_status = load_uuid_status()
        print(f"[INFO] 账号数: {len(accounts)} | UUID状态记录（磁盘）: {len(uuid_status)}")

    totals = {'devices': 0, 'success': 0, 'fail': 0}
    for idx, account in enumerate(accounts, 1):
        print(f"\n[{idx}/{len(accounts)}] 账号: {account['name']}")
        stats = process_account(account, mode, uuid_status)
        totals['devices'] += stats['total']
        totals['success'] += stats['success']
        totals['fail'] += stats['fail']
        if idx < len(accounts):
            print(f"等待{ACCOUNT_INTERVAL}秒...")
            time.sleep(ACCOUNT_INTERVAL)

    # 将 banned 状态同步回 persistence 内存，再统一持久化
    if _use_persistence:
        with _persistence.status_lock:
            for uuid, info in uuid_status.items():
                if info.get('status') == 'banned':
                    _persistence.uuid_status[uuid] = info
        _persistence.save_uuid_status()
        print("[INFO] banned状态已同步至内存并持久化")

    print("\n" + "=" * 50)
    print(f"账号总数: {len(accounts)} | 设备总数: {totals['devices']}")
    print(f"成功: {totals['success']} | 失败: {totals['fail']}")
    print("=" * 50)


# ── CLI入口 ───────────────────────────────────────────────────

def _parse_args() -> Optional[str]:
    if len(sys.argv) != 2:
        return None
    arg = sys.argv[1].lower()
    if arg in ['--all', '-a']:
        return 'all'
    if arg in ['--banned', '-b']:
        return 'banned'
    print("[ERROR] 无效参数，支持: --all/-a (删除全部) | --banned/-b (仅删被ban)")
    return None


def main():
    mode = _parse_args()
    if not mode:
        print("请选择删除模式:")
        print("  1. --all/-a   删除全部设备")
        print("  2. --banned/-b 仅删除被ban设备")
        while True:
            choice = input("\n输入选择(1/2): ").strip()
            if choice == '1':
                mode = 'all'
                break
            elif choice == '2':
                mode = 'banned'
                break
            print("[ERROR] 请输入 1 或 2")
    else:
        print(f"[INFO] 静默模式: {mode}")

    run_delete(mode)


if __name__ == '__main__':
    main()
