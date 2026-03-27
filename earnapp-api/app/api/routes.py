#!/usr/bin/python3
# coding=utf8
"""Flask路由定义"""
import logging
import time
from datetime import datetime
from functools import wraps

from flask import Blueprint, request, jsonify

from config import AUTH_TOKEN, ACCOUNT_VERSION, ACCOUNTS, ALARM_ENABLED, PROXY_HOST, PROXY_PORT, RESPONSE_CODES
from core.queue_processor import uuid_queue, queue_set, queue_lock, is_uuid_in_queue, add_uuid_to_queue
from utils.persistence import uuid_status, status_lock, save_uuid_status

logger = logging.getLogger(__name__)
bp = Blueprint('api', __name__)


# ── 工具 ──────────────────────────────────────────────────────

def build_response(code, message, data=None):
    """构造统一格式的 JSON 响应，data 为 None 时不包含 data 字段"""
    resp = {'code': code, 'message': message}
    if data is not None:
        resp['data'] = data
    return jsonify(resp)


def auth_required(f):
    """接口鉴权装饰器"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        auth_header = request.headers.get('Authorization', '')
        token = None
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = request.headers.get('X-Auth-Token')

        if not token:
            logger.warning(f"[{client_ip}] 未提供认证Token")
            return build_response(RESPONSE_CODES['UNAUTHORIZED'], "Missing authentication token"), 401
        if token != AUTH_TOKEN:
            # 只打印前10位，避免完整 token 泄露到日志
            logger.warning(f"[{client_ip}] 无效Token: {token[:10]}...")
            return build_response(RESPONSE_CODES['UNAUTHORIZED'], "Invalid authentication token"), 401

        logger.info(f"[{client_ip}] 鉴权成功")
        return f(*args, **kwargs)

    return wrapper


# ── 接口 ──────────────────────────────────────────────────────

@bp.route('/api/register', methods=['POST'])
@auth_required
def register_uuid():
    """UUID注册"""
    client_ip = request.remote_addr
    if not request.is_json:
        return build_response(RESPONSE_CODES['INVALID_PARAM'], "Request must be JSON"), 400

    uuid = request.get_json().get('uuid')
    if not uuid:
        return build_response(RESPONSE_CODES['INVALID_PARAM'], "Missing required field: uuid"), 400

    if is_uuid_in_queue(uuid):
        logger.info(f"[{client_ip}] UUID {uuid} 已在队列中")
        return build_response(
            RESPONSE_CODES['DUPLICATE_UUID'],
            "UUID is already in processing queue",
            {'uuid': uuid, 'status': 'in_queue'}
        ), 200

    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            # 已注册成功直接返回，无需重新入队
            if status == 'success':
                return build_response(RESPONSE_CODES['SUCCESS'], "UUID already registered",
                                      {'uuid': uuid, 'status': 'success'}), 200
            # 设备已被封禁，直接返回 banned 状态，不允许重新入队
            if status == 'banned':
                msg = uuid_status[uuid].get('message', 'Device has been banned')
                logger.warning(f"[{client_ip}] UUID {uuid} 已被封禁，拒绝重新注册")
                return build_response(RESPONSE_CODES['SUCCESS'], "UUID is banned",
                                      {'uuid': uuid, 'status': 'banned', 'message': msg}), 200
            # 正在处理中，返回当前状态
            if status in ('processing', 'pending'):
                return build_response(RESPONSE_CODES['SUCCESS'], f"UUID status: {status}",
                                      {'uuid': uuid, 'status': status}), 202

        # 新 UUID 或 failed 状态，初始化为 pending 重新入队
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': time.time(),
            'message': "UUID received, waiting for processing"
        }

    queue_size = add_uuid_to_queue(uuid)
    save_uuid_status()
    logger.info(f"[{client_ip}] UUID {uuid} 加入队列 | 队列长度: {queue_size}")
    return build_response(
        RESPONSE_CODES['SUCCESS'],
        "UUID received, processing will start shortly",
        {'uuid': uuid, 'queue_position': queue_size, 'status': 'pending'}
    ), 202


@bp.route('/api/uuid/status/<uuid>', methods=['GET'])
@auth_required
def get_uuid_status(uuid):
    """UUID状态查询"""
    client_ip = request.remote_addr
    with status_lock:
        if uuid not in uuid_status:
            if is_uuid_in_queue(uuid):
                return build_response(RESPONSE_CODES['SUCCESS'], "UUID status query successful",
                                      {'status': 'pending', 'message': 'UUID is in processing queue',
                                       'account_version': ACCOUNT_VERSION}), 200
            logger.warning(f"[{client_ip}] 查询不存在的UUID: {uuid}")
            return build_response(RESPONSE_CODES['UUID_NOT_FOUND'], "UUID not found",
                                  {'status': 'not_found', 'account_version': ACCOUNT_VERSION}), 200

        status_info = {
            'status': uuid_status[uuid]['status'],
            'message': uuid_status[uuid].get('message', ''),
            'account_version': ACCOUNT_VERSION
        }
        is_banned = uuid_status[uuid]['status'] == 'banned'

    logger.info(f"[{client_ip}] UUID {uuid} 状态: {status_info['status']}")
    if is_banned:
        return build_response(RESPONSE_CODES['SUCCESS'], "UUID is banned", status_info), 200
    return build_response(RESPONSE_CODES['SUCCESS'], "UUID status query successful", status_info), 200


@bp.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    with queue_lock:
        queue_unique = len(queue_set)
    return build_response(
        RESPONSE_CODES['SUCCESS'],
        "Service is running normally",
        {
            'service': 'earnapp-uuid-register',
            'status': 'running',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'queue_size': uuid_queue.qsize(),
            'queue_unique_count': queue_unique,
            'recorded_uuids': len(uuid_status),
            'proxy_configured': all([PROXY_HOST, PROXY_PORT]),
            'account_count': len(ACCOUNTS),
            'alarm_enabled': ALARM_ENABLED
        }
    ), 200
