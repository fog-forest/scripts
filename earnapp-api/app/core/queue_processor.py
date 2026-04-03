#!/usr/bin/python3
# coding=utf8
"""UUID注册队列处理器"""
import logging
import queue
import threading
import time

from config import API_CALL_INTERVAL
from core.earnapp_api import register_device
from utils.persistence import uuid_status, status_lock, save_uuid_status

logger = logging.getLogger(__name__)

uuid_queue: queue.Queue = queue.Queue()  # 待处理的 UUID 队列
queue_set: set = set()  # 队列中 UUID 的快速查重集合
queue_lock = threading.Lock()  # 保护 queue_set 与 uuid_queue 的互斥锁


def is_uuid_in_queue(uuid: str) -> bool:
    """判断 UUID 是否已在队列中（O(1) 查找）"""
    with queue_lock:
        return uuid in queue_set


def add_uuid_to_queue(uuid: str) -> int:
    """将 UUID 加入队列和查重集合，返回当前队列长度"""
    with queue_lock:
        uuid_queue.put(uuid)
        queue_set.add(uuid)
    return uuid_queue.qsize()


def remove_uuid_from_queue(uuid: str) -> None:
    """处理完成后从查重集合中移除 UUID"""
    with queue_lock:
        queue_set.discard(uuid)


def process_uuids() -> None:
    """UUID处理线程主函数"""
    logger.info("UUID处理线程已启动")
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                logger.info(f"开始处理UUID: {uuid}")

                with status_lock:
                    # 已成功注册的 UUID 无需重复处理
                    if uuid in uuid_status and uuid_status[uuid]['status'] == 'success':
                        logger.info(f"UUID {uuid} 已成功注册，跳过")
                        remove_uuid_from_queue(uuid)
                        uuid_queue.task_done()
                        time.sleep(API_CALL_INTERVAL)
                        continue

                    # 更新或初始化状态为 processing
                    if uuid in uuid_status:
                        uuid_status[uuid]['status'] = 'processing'
                        uuid_status[uuid]['message'] = "UUID is being processed"
                    else:
                        uuid_status[uuid] = {
                            'status': 'processing',
                            'create_time': time.time(),
                            'message': "UUID is being processed"
                        }
                save_uuid_status()

                start_time = time.time()
                response = register_device(uuid)
                process_time = round(time.time() - start_time, 2)
                used_account = response.get('account')

                with status_lock:
                    if "error" in response:
                        err = response['error']
                        if "already linked" in err or "already registered" in err:
                            logger.info(f"UUID {uuid} | 账号 {used_account} | 已注册 | 耗时: {process_time}s")
                            uuid_status[uuid]['status'] = 'success'
                            uuid_status[uuid]['message'] = "UUID already registered (duplicate)"
                        else:
                            logger.error(f"UUID {uuid} | 账号 {used_account} | 失败 | 耗时: {process_time}s | {err}")
                            uuid_status[uuid]['status'] = 'failed'
                            uuid_status[uuid]['message'] = err
                    else:
                        logger.info(f"UUID {uuid} | 账号 {used_account} | 注册成功 | 耗时: {process_time}s")
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['message'] = "UUID registered successfully"

                save_uuid_status()
                remove_uuid_from_queue(uuid)
                uuid_queue.task_done()
                time.sleep(API_CALL_INTERVAL)
            else:
                time.sleep(1)
        except Exception as e:
            logger.error(f"UUID处理线程异常: {e}")
            time.sleep(API_CALL_INTERVAL)
