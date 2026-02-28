#!/usr/bin/python3
# coding=utf8
import json
import logging
import os
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime

import requests
from flask import Flask, request, jsonify

# 日志配置（简化格式）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# QMSG配置（从环境变量获取）
QMSG_TOKEN = os.getenv('QMSG_TOKEN')
QMSG_QQ = os.getenv('QMSG_QQ')
QMSG_BOT = os.getenv('QMSG_BOT')
QMSG_API = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else None

app = Flask(__name__)

# 核心配置
uuid_queue = queue.Queue()  # 主处理队列
retry_queue = defaultdict(lambda: [0, None, None])  # 失败重试队列
uuid_status = {}  # UUID状态追踪
MAX_RETRY_COUNT = 3  # 最大重试次数
RETRY_INTERVALS = [5, 15, 30]  # 重试间隔（秒）
DATA_DIR = "/data"  # 数据目录
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")  # 状态文件
status_lock = threading.Lock()  # 状态锁
retry_lock = threading.Lock()  # 重试队列锁

# 鉴权Token（必填）
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
if not AUTH_TOKEN:
    raise ValueError("环境变量 AUTH_TOKEN 未配置，请设置后启动服务！")

# 重复提醒控制
token_expired_notified = False
notify_lock = threading.Lock()


# 工具函数
def ensure_data_dir_exists():
    # 创建/data目录
    try:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, mode=0o755)
            logger.info(f"创建目录: {DATA_DIR}")
        else:
            logger.info(f"目录已存在: {DATA_DIR}")
    except Exception as e:
        logger.error(f"创建/data目录失败: {str(e)}")
        raise RuntimeError(f"无法创建必要的/data目录: {str(e)}")


def load_uuid_status():
    # 加载UUID状态（防止重启丢失）
    global uuid_status, retry_queue
    ensure_data_dir_exists()

    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f)
                uuid_status = data.get('uuid_status', {})
                retry_data = data.get('retry_queue', {})
                for uuid, info in retry_data.items():
                    retry_queue[uuid] = info
                logger.info(f"加载UUID状态: {len(uuid_status)}个UUID，{len(retry_queue)}个待重试")
        else:
            logger.info(f"{STATUS_FILE}不存在，初始化空状态")
            uuid_status = {}
            retry_queue = defaultdict(lambda: [0, None, None])
    except Exception as e:
        logger.error(f"加载UUID状态失败: {str(e)}")


def save_uuid_status():
    # 保存UUID状态（持久化）
    ensure_data_dir_exists()

    try:
        with status_lock:
            data = {
                'uuid_status': uuid_status,
                'retry_queue': dict(retry_queue)
            }
        temp_file = f"{STATUS_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, STATUS_FILE)
        logger.debug(f"保存UUID状态到: {STATUS_FILE}")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {str(e)}")


def send_qmsg_notification(message):
    # 发送QQ消息提醒
    if not all([QMSG_TOKEN, QMSG_QQ, QMSG_BOT]):
        logger.warning("QMSG配置不完整，跳过消息发送")
        return False

    try:
        payload = {
            "msg": message,
            "qq": QMSG_QQ,
            "bot": QMSG_BOT
        }
        response = requests.post(
            QMSG_API,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            logger.info(f"QMSG发送成功: {message[:50]}...")
            return True
        else:
            logger.error(f"QMSG发送失败 | 状态码: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"QMSG发送异常: {str(e)}")
        return False


def check_pending_uuid():
    # 检查长时间未处理的UUID并告警
    while True:
        try:
            now = time.time()
            pending_uuids = []
            with status_lock:
                for uuid, status_info in uuid_status.items():
                    if status_info['status'] == 'pending' and now - status_info['create_time'] > 300:
                        pending_uuids.append(uuid)

            if pending_uuids:
                msg = f"⚠️ {len(pending_uuids)}个UUID长时间未处理 ⚠️\nUUID列表: {pending_uuids[:10]}..."
                send_qmsg_notification(msg)
                logger.warning(f"长时间未处理UUID: {pending_uuids}")

            time.sleep(60)
        except Exception as e:
            logger.error(f"检查待处理UUID异常: {str(e)}")


# 鉴权装饰器
def auth_required(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        custom_auth_header = request.headers.get('X-Auth-Token')
        client_ip = request.remote_addr

        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif custom_auth_header:
            token = custom_auth_header

        if not token:
            logger.warning(f"[{client_ip}] 无认证Token")
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid authentication token, please carry the correct Token in the request header"
            }), 401
        elif token != AUTH_TOKEN:
            logger.warning(f"[{client_ip}] 无效Token: {token[:10]}...")
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid authentication token, please carry the correct Token in the request header"
            }), 401

        logger.info(f"[{client_ip}] 认证成功")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# 重试处理线程
def process_retry_queue():
    # 处理失败重试的UUID
    logger.info("重试队列处理线程启动")
    while True:
        try:
            now = time.time()
            need_retry_uuids = []

            with retry_lock:
                for uuid, (retry_count, last_fail_time, fail_reason) in list(retry_queue.items()):
                    # 未到重试时间
                    if last_fail_time and now - last_fail_time < RETRY_INTERVALS[
                        min(retry_count - 1, len(RETRY_INTERVALS) - 1)]:
                        continue

                    # 超过最大重试次数
                    if retry_count >= MAX_RETRY_COUNT:
                        with status_lock:
                            if uuid in uuid_status:
                                uuid_status[uuid]['status'] = 'failed'
                                uuid_status[uuid]['fail_reason'] = fail_reason
                                uuid_status[uuid]['retry_count'] = retry_count
                        msg = f"❌ UUID永久失败 ❌\nUUID: {uuid}\n原因: {fail_reason}\n重试: {retry_count}次"
                        send_qmsg_notification(msg)
                        logger.error(f"UUID {uuid} 重试{retry_count}次失败，放弃")
                        del retry_queue[uuid]
                        save_uuid_status()
                        continue

                    need_retry_uuids.append(uuid)

            # 执行重试
            for uuid in need_retry_uuids:
                with retry_lock:
                    retry_count = retry_queue[uuid][0] + 1
                    retry_queue[uuid] = [retry_count, now, retry_queue[uuid][2]]

                logger.info(f"重试UUID: {uuid} | 第{retry_count}次")
                uuid_queue.put(uuid)
                with status_lock:
                    if uuid in uuid_status:
                        uuid_status[uuid]['status'] = 'retrying'
                        uuid_status[uuid]['retry_count'] = retry_count

            save_uuid_status()
            time.sleep(2)
        except Exception as e:
            logger.error(f"重试队列处理异常: {str(e)}")


# 主处理线程
def process_uuids():
    # 消费队列中的UUID并调用注册API
    logger.info("UUID主处理线程启动")
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                logger.info(f"处理UUID: {uuid}")

                # 更新状态为处理中
                with status_lock:
                    if uuid in uuid_status:
                        uuid_status[uuid]['status'] = 'processing'
                        uuid_status[uuid]['process_time'] = time.time()
                    else:
                        uuid_status[uuid] = {
                            'status': 'processing',
                            'create_time': uuid_status.get(uuid, {}).get('create_time', time.time()),
                            'process_time': time.time(),
                            'retry_count': 0
                        }
                save_uuid_status()

                start_time = time.time()
                response = call_api(uuid)
                process_time = round(time.time() - start_time, 2)

                if "error" in response:
                    logger.error(f"UUID {uuid} 处理失败 | 耗时 {process_time}s | 错误: {response['error']}")

                    # 加入重试队列
                    with retry_lock:
                        retry_queue[uuid] = [
                            retry_queue[uuid][0],
                            time.time(),
                            response['error']
                        ]

                    with status_lock:
                        uuid_status[uuid]['status'] = 'failed'
                        uuid_status[uuid]['fail_reason'] = response['error']

                    save_uuid_status()
                else:
                    logger.info(f"UUID {uuid} 处理成功 | 耗时 {process_time}s")

                    # 处理成功，移除重试队列
                    with retry_lock:
                        if uuid in retry_queue:
                            del retry_queue[uuid]

                    with status_lock:
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['result'] = response
                        uuid_status[uuid]['complete_time'] = time.time()

                    save_uuid_status()

                uuid_queue.task_done()
                time.sleep(3)
            else:
                time.sleep(1)
        except Exception as e:
            logger.error(f"UUID主处理线程异常: {str(e)}")


# API调用函数
def call_api(uuid):
    # 调用EarnAPP设备注册API
    global token_expired_notified
    url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    xsrf_token = os.getenv('XSRF_TOKEN')
    brd_sess_id = os.getenv('BRD_SESS_ID')

    # 检查必要参数
    if not xsrf_token:
        logger.error("XSRF_TOKEN未配置")
        return {"error": "XSRF_TOKEN not configured"}
    if not brd_sess_id:
        logger.error("BRD_SESS_ID未配置")
        return {"error": "BRD_SESS_ID not configured"}

    headers = {"Xsrf-Token": xsrf_token}
    cookies = {
        "xsrf-token": xsrf_token,
        "brd_sess_id": brd_sess_id
    }

    try:
        response = requests.post(
            url,
            json={"uuid": uuid},
            headers=headers,
            cookies=cookies,
            timeout=10
        )

        # Token过期处理
        if response.status_code == 403:
            with notify_lock:
                if not token_expired_notified:
                    logger.error(f"EarnApp Token过期 | UUID: {uuid}")
                    notify_msg = f"⚠️ EarnApp Token过期 ⚠️\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nUUID: {uuid}"
                    send_qmsg_notification(notify_msg)
                    token_expired_notified = True

            return {"error": "EarnApp Token过期，已发送提醒，请更新认证信息"}

        if response.status_code == 200:
            with notify_lock:
                token_expired_notified = False
            return response.json()
        else:
            error_msg = f"请求失败，状态码: {response.status_code}"
            logger.error(error_msg)
            return {"error": error_msg}
    except requests.exceptions.Timeout:
        logger.error(f"API超时 | UUID: {uuid}")
        return {"error": "Request timeout"}
    except requests.exceptions.ConnectionError:
        logger.error(f"API连接失败 | UUID: {uuid}")
        return {"error": "Connection error"}
    except Exception as e:
        logger.error(f"API调用异常 | UUID: {uuid} | 错误: {str(e)}")
        return {"error": str(e)}


# 注册接口
@app.route('/api/register', methods=['POST'])
@auth_required
def get_request_result():
    # 接收UUID并加入处理队列
    client_ip = request.remote_addr
    data = request.json
    if not data:
        logger.warning(f"[{client_ip}] 无JSON数据")
        return jsonify({"error": "JSON data is required"}), 400

    uuid = data.get('uuid')
    if not uuid:
        logger.warning(f"[{client_ip}] 缺少UUID参数")
        return jsonify({"error": "UUID is required"}), 400

    # 记录UUID状态
    now = time.time()
    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            if status == 'success':
                logger.info(f"UUID {uuid} 已注册成功")
                return jsonify({
                    "message": "UUID already registered successfully",
                    "uuid": uuid,
                    "status": "success"
                }), 200
            elif status in ['processing', 'retrying']:
                logger.info(f"UUID {uuid} 正在处理中")
                return jsonify({
                    "message": "UUID is being processed",
                    "uuid": uuid,
                    "status": "processing"
                }), 202
        # 新增UUID
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': now,
            'client_ip': client_ip,
            'retry_count': 0
        }

    # 加入队列
    uuid_queue.put(uuid)
    queue_size = uuid_queue.qsize()
    save_uuid_status()

    logger.info(f"UUID {uuid} 加入队列 | 队列长度: {queue_size}")
    return jsonify({
        "message": "UUID received, processing will start shortly.",
        "uuid": uuid,
        "queue_position": queue_size,
        "status": "pending"
    }), 202


# 查询UUID状态接口
@app.route('/api/uuid/status/<uuid>', methods=['GET'])
@auth_required
def get_uuid_status(uuid):
    # 查询UUID注册状态
    with status_lock:
        if uuid not in uuid_status:
            return jsonify({"error": "UUID not found"}), 404

        status_info = uuid_status[uuid].copy()
        # 转换时间戳为可读格式
        for time_key in ['create_time', 'process_time', 'complete_time']:
            if time_key in status_info and status_info[time_key]:
                status_info[time_key] = datetime.fromtimestamp(status_info[time_key]).strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({
        "uuid": uuid,
        "status": status_info
    }), 200


# 主函数
if __name__ == "__main__":
    # 加载历史状态
    load_uuid_status()

    # 检查必要环境变量
    required_envs = ['XSRF_TOKEN', 'BRD_SESS_ID']
    missing_envs = [env for env in required_envs if not os.getenv(env)]
    if missing_envs:
        logger.warning(f"未配置环境变量: {', '.join(missing_envs)}")

    # 启动线程
    threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()
    threading.Thread(target=process_retry_queue, name="Retry-Processor", daemon=True).start()
    threading.Thread(target=check_pending_uuid, name="Pending-Checker", daemon=True).start()

    # 启动Flask服务
    port = int(os.getenv("PORT", 5000))
    logger.info(f"Flask服务启动 | 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
