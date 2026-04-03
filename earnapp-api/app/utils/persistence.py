#!/usr/bin/python3
# coding=utf8
"""数据持久化 - UUID注册状态读写"""
import copy
import json
import logging
import os
import threading

from config import DATA_DIR, STATUS_FILE

logger = logging.getLogger(__name__)

uuid_status = {}  # 全局 UUID 状态字典，key 为 uuid，value 为状态信息
status_lock = threading.Lock()  # 保护 uuid_status 读写的互斥锁


def ensure_data_dir_exists() -> None:
    """确保数据目录存在，不存在则创建（权限 755）"""
    try:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, mode=0o755)
            logger.info(f"创建数据目录: {DATA_DIR}")
        else:
            logger.info(f"数据目录已存在: {DATA_DIR}")
    except Exception as e:
        raise RuntimeError(f"无法创建数据目录 {DATA_DIR}: {e}")


def load_uuid_status() -> None:
    """从文件加载UUID状态"""
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f).get('uuid_status', {})
            uuid_status.update(data)
            logger.info(f"加载UUID状态成功，共{len(uuid_status)}条记录")
        else:
            logger.info("UUID状态文件不存在，初始化空状态")
    except Exception as e:
        logger.error(f"加载UUID状态失败: {e}")


def save_uuid_status() -> None:
    """原子写入UUID状态：先写临时文件再 replace，避免写入中途崩溃导致文件损坏"""
    try:
        with status_lock:
            data = {'uuid_status': copy.deepcopy(uuid_status)}
        temp = f"{STATUS_FILE}.tmp"
        with open(temp, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp, STATUS_FILE)
        logger.info(f"UUID状态保存成功 | 记录数: {len(uuid_status)} | 文件: {STATUS_FILE}")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {e}")


def update_uuid_field(uuid: str, **kwargs) -> None:
    """线程安全地更新指定UUID的字段并持久化"""
    with status_lock:
        if uuid not in uuid_status:
            uuid_status[uuid] = {}
        uuid_status[uuid].update(kwargs)
    save_uuid_status()
