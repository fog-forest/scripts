#!/usr/bin/python3
# coding=utf8
# EarnApp设备批量删除工具：支持参数运行（--all/--banned），静默模式无交互
import os
import sys
import time
from typing import List, Dict, Optional

import requests
import yaml

# 配置
CONFIG_FILE_PATH = "data/config.yaml"
REQUEST_TIMEOUT = 15  # 请求超时(秒)
REQUEST_INTERVAL = 1  # 单账号设备删除间隔(秒)
ACCOUNT_INTERVAL = 3  # 账号间操作间隔(秒)

# API地址
API_BASE_URL = "https://earnapp.com/dashboard/api"
API_LIST_DEVICES = f"{API_BASE_URL}/devices"
API_DELETE_DEVICE = f"{API_BASE_URL}/device/"


def load_config() -> Optional[Dict]:
    """加载配置文件，返回有效账号列表"""
    try:
        if not os.path.exists(CONFIG_FILE_PATH):
            print(f"[ERROR] 配置文件不存在: {CONFIG_FILE_PATH}")
            return None

        with open(CONFIG_FILE_PATH, 'r', encoding='utf8') as f:
            config = yaml.safe_load(f)

        if "accounts" not in config or not isinstance(config["accounts"], list):
            print("[ERROR] 配置文件accounts字段错误")
            return None

        # 过滤有效账号（含name、cookie.xsrf_token、cookie.brd_sess_id）
        valid_accounts = []
        for account in config["accounts"]:
            if (account.get("name") and account.get("cookie") and
                    account["cookie"].get("xsrf_token") and account["cookie"].get("brd_sess_id")):
                valid_accounts.append(account)
            else:
                print(f"[WARNING] 跳过无效账号: {account.get('name', '未知')}")

        if not valid_accounts:
            print("[ERROR] 无有效账号配置")
            return None

        config["accounts"] = valid_accounts
        return config

    except Exception as e:
        print(f"[ERROR] 加载配置失败: {str(e)}")
        return None


def get_request_headers(xsrf_token: str, brd_sess_id: str) -> Dict[str, str]:
    """构建请求头（含认证信息）"""
    cookie = f"xsrf-token={xsrf_token}; brd_sess_id={brd_sess_id}"
    return {
        "xsrf-token": xsrf_token,
        "cookie": cookie,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }


def get_device_uuids(account_name: str, xsrf_token: str, brd_sess_id: str, delete_mode: str) -> List[str]:
    """
    获取待删除设备UUID列表
    :param delete_mode: all(全部设备)/banned(仅被ban设备)
    :return: 设备UUID列表
    """
    print(f"\n[{account_name}] 获取{delete_mode}设备列表...")
    try:
        headers = get_request_headers(xsrf_token, brd_sess_id)
        response = requests.get(API_LIST_DEVICES, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        devices = response.json()
        if not isinstance(devices, list):
            print(f"[{account_name}] [ERROR] 设备列表格式异常")
            return []

        target_uuids = []
        for device in devices:
            if not device.get("uuid"):
                continue

            # 筛选被ban设备
            if delete_mode == "banned":
                if "banned" in device:
                    target_uuids.append(device["uuid"])
                    ban_reason = device["banned"].get("reason", "未知")
                    ban_ip = device["banned"].get("ip", "未知")
                    print(f"[{account_name}] [BANNED] {device['uuid']} - 原因: {ban_reason} | IP: {ban_ip}")
            else:
                target_uuids.append(device["uuid"])

        print(f"[{account_name}] [INFO] 待删除设备数: {len(target_uuids)}")
        return target_uuids

    except Exception as e:
        print(f"[{account_name}] [ERROR] 获取设备列表失败: {str(e)}")
        return []


def delete_single_device(account_name: str, uuid: str, xsrf_token: str, brd_sess_id: str, delete_mode: str) -> bool:
    """删除单个设备，返回删除结果"""
    delete_url = f"{API_DELETE_DEVICE}{uuid}"
    try:
        headers = get_request_headers(xsrf_token, brd_sess_id)
        response = requests.delete(delete_url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        result = response.json()
        if result.get("status") == "ok":
            print(f"[{account_name}] [SUCCESS] 删除{delete_mode}设备: {uuid}")
            return True
        else:
            print(f"[{account_name}] [FAILED] 删除{delete_mode}设备 {uuid} 失败: {result}")
            return False

    except Exception as e:
        print(f"[{account_name}] [FAILED] 删除{delete_mode}设备 {uuid} 出错: {str(e)}")
        return False


def batch_delete_devices_for_account(account: Dict, delete_mode: str) -> Dict[str, int]:
    """删除单个账号设备，返回统计结果"""
    account_name = account["name"]
    xsrf_token = account["cookie"]["xsrf_token"]
    brd_sess_id = account["cookie"]["brd_sess_id"]

    # 获取待删除设备
    target_uuids = get_device_uuids(account_name, xsrf_token, brd_sess_id, delete_mode)
    if not target_uuids:
        print(f"[{account_name}] [WARNING] 无待删除设备")
        return {"total": 0, "success": 0, "fail": 0}

    # 批量删除
    print(f"\n[{account_name}] [INFO] 开始删除{len(target_uuids)}个{delete_mode}设备...")
    success_count = 0
    fail_count = 0

    for idx, uuid in enumerate(target_uuids, 1):
        print(f"\n[{account_name}] [{idx}/{len(target_uuids)}] 处理: {uuid}")
        if delete_single_device(account_name, uuid, xsrf_token, brd_sess_id, delete_mode):
            success_count += 1
        else:
            fail_count += 1

        if idx < len(target_uuids):
            time.sleep(REQUEST_INTERVAL)

    return {"total": len(target_uuids), "success": success_count, "fail": fail_count}


def parse_args() -> Optional[str]:
    """解析命令行参数，返回删除模式（all/banned/None）"""
    if len(sys.argv) != 2:
        return None

    arg = sys.argv[1].lower()
    if arg in ["--all", "-a"]:
        return "all"
    elif arg in ["--banned", "-b"]:
        return "banned"
    else:
        print("[ERROR] 无效参数！支持：--all/-a(删除全部)、--banned/-b(仅删被ban)")
        return None


def main():
    """主入口：支持参数静默运行/交互运行"""
    print("===== EarnApp 设备批量删除工具 =====")

    # 加载配置
    config = load_config()
    if not config:
        print("[ERROR] 配置加载失败，退出")
        return
    accounts = config["accounts"]
    print(f"[INFO] 加载{len(accounts)}个有效账号")

    # 解析命令行参数
    delete_mode = parse_args()
    if not delete_mode:
        # 无参数，交互选择模式
        print("\n请选择删除模式:")
        print("  1. --all/-a  删除全部设备")
        print("  2. --banned/-b  仅删除被ban设备")
        while True:
            choice = input("\n输入选择(1/2): ").strip()
            if choice == "1":
                delete_mode = "all"
                break
            elif choice == "2":
                delete_mode = "banned"
                break
            else:
                print("[ERROR] 仅支持输入1/2！")
    else:
        # 有参数，静默模式（无交互确认）
        print(f"\n[INFO] 静默模式 - 执行{delete_mode}设备删除")

    # 统计初始化
    global_stats = {"total_accounts": len(accounts), "total_devices": 0, "total_success": 0, "total_fail": 0}

    # 批量处理账号
    print("\n" + "=" * 50)
    for idx, account in enumerate(accounts, 1):
        account_name = account["name"]
        print(f"\n[{idx}/{len(accounts)}] 处理账号: {account_name}")

        # 删除设备
        account_stats = batch_delete_devices_for_account(account, delete_mode)
        global_stats["total_devices"] += account_stats["total"]
        global_stats["total_success"] += account_stats["success"]
        global_stats["total_fail"] += account_stats["fail"]

        # 账号间间隔
        if idx < len(accounts):
            print(f"\n[{account_name}] 等待{ACCOUNT_INTERVAL}秒处理下一个账号...")
            time.sleep(ACCOUNT_INTERVAL)

    # 输出统计
    print("\n" + "=" * 50)
    print("========== 处理完成 ==========")
    print(f"账号总数: {global_stats['total_accounts']}")
    print(f"设备总数: {global_stats['total_devices']}")
    print(f"成功删除: {global_stats['total_success']}")
    print(f"删除失败: {global_stats['total_fail']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
