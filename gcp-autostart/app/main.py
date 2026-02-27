#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/02/08
# @Desc  : GCP 抢占式实例自动开机
import json
import os
import time
from typing import Dict, List

from google.api_core.exceptions import GoogleAPICallError, RetryError
from google.cloud import compute_v1

# 环境变量配置
KEY_PATH = os.getenv("GCP_KEY_PATH", "/app/key")
LOOP_INTERVAL = int(os.getenv("GCP_LOOP_INTERVAL", "300"))  # 循环间隔秒数
DEFAULT_TIMEOUT = int(os.getenv("GCP_TIMEOUT", "30"))


def load_gcp_credentials() -> List[Dict]:
    """加载并验证GCP凭证文件"""
    cred_list = []

    # 处理目录或单个文件
    if os.path.isdir(KEY_PATH):
        for file in os.listdir(KEY_PATH):
            if file.endswith('.json'):
                file_path = os.path.join(KEY_PATH, file)
                try:
                    with open(file_path, 'r') as f:
                        cred = json.load(f)
                        if 'project_id' in cred:
                            cred['file_path'] = file_path
                            cred_list.append(cred)
                except (json.JSONDecodeError, PermissionError):
                    continue
    elif os.path.isfile(KEY_PATH) and KEY_PATH.endswith('.json'):
        try:
            with open(KEY_PATH, 'r') as f:
                cred = json.load(f)
                if 'project_id' in cred:
                    cred['file_path'] = KEY_PATH
                    cred_list.append(cred)
        except (json.JSONDecodeError, PermissionError):
            pass

    return cred_list


def start_instance_if_not_running(project_id: str, zone: str, instance_name: str) -> str:
    """启动指定实例（如果未运行）"""
    try:
        instance_client = compute_v1.InstancesClient()
        instance = instance_client.get(project=project_id, zone=zone, instance=instance_name)

        if instance.status != "RUNNING":
            operation = instance_client.start(project=project_id, zone=zone, instance=instance_name)
            wait_for_operation(project_id, zone, instance_name, operation.name)
            return "RUNNING"
        return "RUNNING"
    except (GoogleAPICallError, RetryError) as e:
        print(f"[{project_id}] {instance_name} 启动失败: {str(e)}")
        return "ERROR"


def wait_for_operation(project_id: str, zone: str, instance_name: str, operation_name: str) -> None:
    """等待云操作完成"""
    operation_client = compute_v1.ZoneOperationsClient()
    start_time = time.time()

    while time.time() - start_time < DEFAULT_TIMEOUT:
        operation = operation_client.get(project=project_id, zone=zone, operation=operation_name)
        if operation.status == "RUNNING":
            return
        if operation.status == "DONE":
            if operation.error:
                raise RuntimeError(f"操作失败: {operation.error}")
            return
        time.sleep(5)
    raise TimeoutError("操作超时")


def process_account(cred: Dict):
    """处理单个账号"""
    project_id = cred['project_id']
    try:
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = cred['file_path']
        compute = compute_v1.InstancesClient()
        zones_client = compute_v1.ZonesClient()

        print(f"\n🔍 开始处理项目: {project_id}")
        for zone in zones_client.list(project=project_id):
            instances = compute.list(project=project_id, zone=zone.name)
            for instance in instances:
                status = start_instance_if_not_running(project_id, zone.name, instance.name)
                print(f"  {instance.name} ({zone.name}): {'✅' if status == 'RUNNING' else '❌'}")

    finally:
        if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
            del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
        print(f"🏁 项目 {project_id} 处理完成\n")  # 新增完成提示


if __name__ == "__main__":
    print("🚀 GCP 抢占式实例自动维护服务启动")
    print(f"📁 凭证路径: {KEY_PATH}")
    print(f"⏱ 循环间隔: {LOOP_INTERVAL}秒")

    try:
        while True:
            start_time = time.time()
            credentials = load_gcp_credentials()

            if not credentials:
                print("⚠️ 未找到有效凭证文件")
                time.sleep(LOOP_INTERVAL)
                continue

            print(f"\n🔄 发现 {len(credentials)} 个账号")
            for cred in credentials:
                try:
                    process_account(cred)
                except Exception as e:
                    print(f"❌ 处理账号 {cred.get('project_id', '未知')} 失败: {str(e)}")

            print("🎉 所有项目处理完成，等待下次轮询")
            sleep_time = LOOP_INTERVAL - (time.time() - start_time)
            if sleep_time > 0:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n🛑 用户中断操作")
    except Exception as e:
        print(f"💥 严重错误: {str(e)}")
    finally:
        print("🔚 服务已停止")
