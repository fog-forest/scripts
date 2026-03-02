#!/usr/bin/python3
# coding=utf8
"""
EarnApp设备注册API
- 串行处理UUID，兼容EarnApp官方返回
- 429错误按15/30/60秒阶梯重试
- 启动/Token异常发送告警通知，确保关键状态及时感知
- 提供注册和状态查询接口，鉴权保护
"""

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime

import requests
from flask import Flask, request, jsonify

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Flask实例
app = Flask(__name__)

# QMSG配置
QMSG_TOKEN = os.getenv('QMSG_TOKEN')
QMSG_QQ = os.getenv('QMSG_QQ')
QMSG_BOT = os.getenv('QMSG_BOT')
QMSG_API = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else None

# 鉴权Token（必填）
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
if not AUTH_TOKEN:
    raise ValueError("环境变量 AUTH_TOKEN 未配置！")

# 核心配置
uuid_queue = queue.Queue()
uuid_status = {}
DATA_DIR = "/data"
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")
API_CALL_INTERVAL = 5  # API调用间隔（秒）
TOO_MANY_REQUESTS_RETRIES = [15, 30, 60]  # 429错误重试间隔
MAX_429_RETRY_COUNT = len(TOO_MANY_REQUESTS_RETRIES)  # 最大429重试次数

# 线程锁
status_lock = threading.Lock()
notify_lock = threading.Lock()

# 通知控制
token_expired_notified = False

# 统一响应码
RESPONSE_CODES = {
    "SUCCESS": 0,  # 成功
    "INVALID_PARAM": 1001,  # 参数错误
    "UNAUTHORIZED": 1002,  # 未授权
    "UUID_NOT_FOUND": 1003,  # UUID不存在
    "SYSTEM_ERROR": 9999  # 系统错误
}


def ensure_data_dir_exists():
    try:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, mode=0o755)
            logger.info(f"创建目录: {DATA_DIR}")
        else:
            logger.info(f"目录已存在: {DATA_DIR}")
    except Exception as e:
        logger.error(f"创建目录失败: {str(e)}")
        raise RuntimeError(f"无法创建必要目录: {str(e)}")


def load_uuid_status():
    global uuid_status
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f)
                uuid_status = data.get('uuid_status', {})
                logger.info(f"加载{len(uuid_status)}个UUID状态记录")
        else:
            logger.info(f"{STATUS_FILE}不存在，初始化空状态")
            uuid_status = {}
    except Exception as e:
        logger.error(f"加载UUID状态失败: {str(e)}")


def save_uuid_status():
    try:
        with status_lock:
            data = {'uuid_status': uuid_status}

        temp_file = f"{STATUS_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, STATUS_FILE)
        logger.debug(f"保存UUID状态到: {STATUS_FILE}")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {str(e)}")


def send_qmsg_notification(message):
    if not all([QMSG_TOKEN, QMSG_QQ, QMSG_BOT]):
        logger.warning("QMSG配置不完整，跳过通知发送")
        return False

    try:
        payload = {"msg": message, "qq": QMSG_QQ, "bot": QMSG_BOT}
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


def send_startup_notification():
    startup_msg = f"""🚀 EarnApp UUID注册服务已启动 🚀
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
队列长度: {uuid_queue.qsize()}
已记录UUID数: {len(uuid_status)}
API调用间隔: {API_CALL_INTERVAL}秒
429重试策略: {TOO_MANY_REQUESTS_RETRIES}秒"""
    send_qmsg_notification(startup_msg)


def build_response(code, message, data=None):
    """构建统一API响应格式"""
    response = {"code": code, "message": message}
    if data is not None:
        response["data"] = data
    return jsonify(response)


def auth_required(f):
    """接口鉴权装饰器"""

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
            logger.warning(f"[{client_ip}] 未提供认证Token")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token, please provide a valid token in request header",
                None
            ), 401
        elif token != AUTH_TOKEN:
            logger.warning(f"[{client_ip}] 无效Token: {token[:10]}...")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token",
                None
            ), 401

        logger.info(f"[{client_ip}] 认证成功")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


def call_api_with_429_retry(uuid):
    """调用API并处理429错误重试"""
    global token_expired_notified
    url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    xsrf_token = os.getenv('XSRF_TOKEN')
    brd_sess_id = os.getenv('BRD_SESS_ID')

    if not xsrf_token:
        logger.error("XSRF_TOKEN未配置")
        return {"error": "XSRF_TOKEN not configured"}
    if not brd_sess_id:
        logger.error("BRD_SESS_ID未配置")
        return {"error": "BRD_SESS_ID not configured"}

    headers = {"Xsrf-Token": xsrf_token}
    cookies = {"xsrf-token": xsrf_token, "brd_sess_id": brd_sess_id}

    for retry_idx in range(MAX_429_RETRY_COUNT + 1):
        try:
            response = requests.post(
                url,
                json={"uuid": uuid},
                headers=headers,
                cookies=cookies,
                timeout=10
            )

            if response.status_code == 403:
                with notify_lock:
                    if not token_expired_notified:
                        logger.error(f"EarnApp Token过期 | UUID: {uuid}")
                        notify_msg = f"⚠️ EarnApp Token过期 ⚠️\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nUUID: {uuid}"
                        send_qmsg_notification(notify_msg)
                        token_expired_notified = True
                return {"error": "EarnApp Token expired, notification sent, please update authentication info"}

            if response.status_code == 429:
                if retry_idx >= MAX_429_RETRY_COUNT:
                    error_msg = f"请求过于频繁（429），重试{MAX_429_RETRY_COUNT}次失败"
                    logger.error(f"UUID {uuid} | {error_msg}")
                    return {"error": f"Too many requests (429), failed after {MAX_429_RETRY_COUNT} retries"}

                wait_time = TOO_MANY_REQUESTS_RETRIES[retry_idx]
                logger.warning(f"UUID {uuid} | 请求过于频繁（429），第{retry_idx + 1}次重试，等待{wait_time}秒")
                time.sleep(wait_time)
                continue

            if response.status_code == 200:
                with notify_lock:
                    token_expired_notified = False
                return response.json()

            error_msg = f"请求失败 | 状态码: {response.status_code}"
            logger.error(f"UUID {uuid} | {error_msg}")
            return {"error": f"Request failed | Status code: {response.status_code}"}

        except requests.exceptions.Timeout:
            logger.error(f"API超时 | UUID: {uuid}")
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            logger.error(f"API连接失败 | UUID: {uuid}")
            return {"error": "Connection error"}
        except Exception as e:
            logger.error(f"API调用异常 | UUID: {uuid} | 错误: {str(e)}")
            return {"error": str(e)}

    return {"error": "Unknown error"}


def process_uuids():
    """串行处理队列中的UUID"""
    logger.info("UUID主处理线程启动（串行模式）")
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                logger.info(f"开始处理UUID: {uuid}")

                with status_lock:
                    if uuid in uuid_status and uuid_status[uuid]['status'] == 'success':
                        logger.info(f"UUID {uuid} 已成功，无需重复处理")
                        uuid_queue.task_done()
                        time.sleep(API_CALL_INTERVAL)
                        continue

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
                response = call_api_with_429_retry(uuid)
                process_time = round(time.time() - start_time, 2)

                if "error" in response:
                    if response['error'] == "This device was already linked":
                        logger.info(f"UUID {uuid} 已注册成功（重复注册） | 耗时 {process_time}秒")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'success'
                            uuid_status[uuid]['message'] = "UUID already registered (duplicate)"
                        save_uuid_status()
                    else:
                        logger.error(f"UUID {uuid} 处理失败 | 耗时 {process_time}秒 | 错误: {response['error']}")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'failed'
                            uuid_status[uuid]['message'] = response['error']
                        save_uuid_status()
                else:
                    logger.info(f"UUID {uuid} 处理成功 | 耗时 {process_time}秒")
                    with status_lock:
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['message'] = "UUID registered successfully"
                    save_uuid_status()

                uuid_queue.task_done()
                time.sleep(API_CALL_INTERVAL)
            else:
                time.sleep(1)
        except Exception as e:
            logger.error(f"UUID主处理线程异常: {str(e)}")
            time.sleep(API_CALL_INTERVAL)


@app.route('/api/register', methods=['POST'])
@auth_required
def register_uuid():
    """接收UUID并加入处理队列"""
    client_ip = request.remote_addr

    if not request.is_json:
        logger.warning(f"[{client_ip}] 请求数据不是JSON格式")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Request format error, please submit data in JSON format",
            None
        ), 400

    data = request.get_json()
    uuid = data.get('uuid')

    if not uuid:
        logger.warning(f"[{client_ip}] 缺少UUID参数")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Parameter error, missing required UUID field",
            None
        ), 400

    now = time.time()
    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            if status == 'success':
                logger.info(f"[{client_ip}] UUID {uuid} 已注册成功")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    "UUID already registered successfully",
                    {
                        "uuid": uuid,
                        "status": "success"
                    }
                ), 200
            elif status in ['processing', 'pending']:
                logger.info(f"[{client_ip}] UUID {uuid} 正在处理中/等待处理")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    f"UUID current status: {status}",
                    {
                        "uuid": uuid,
                        "status": status
                    }
                ), 202
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': now,
            'message': "UUID received, waiting for processing"
        }

    uuid_queue.put(uuid)
    queue_size = uuid_queue.qsize()
    save_uuid_status()

    logger.info(f"[{client_ip}] UUID {uuid} 加入队列 | 队列长度: {queue_size}")
    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "UUID received, processing will start shortly",
        {
            "uuid": uuid,
            "queue_position": queue_size,
            "status": "pending"
        }
    ), 202


@app.route('/api/uuid/status/<uuid>', methods=['GET'])
@auth_required
def get_uuid_status(uuid):
    """查询UUID注册状态"""
    client_ip = request.remote_addr
    with status_lock:
        if uuid not in uuid_status:
            logger.warning(f"[{client_ip}] 查询不存在的UUID: {uuid}")
            return build_response(
                RESPONSE_CODES["UUID_NOT_FOUND"],
                "UUID not found",
                None
            ), 404

        status_info = {
            "status": uuid_status[uuid]['status'],
            "message": uuid_status[uuid].get('message', 'No detailed information')
        }

    logger.info(f"[{client_ip}] 查询UUID {uuid} 状态: {status_info['status']}")
    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "UUID status query successful",
        status_info
    ), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """服务健康检查接口"""
    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "Service is running normally",
        {
            "service": "earnapp-uuid-register",
            "status": "running",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "queue_size": uuid_queue.qsize(),
            "recorded_uuids": len(uuid_status)
        }
    ), 200


if __name__ == "__main__":
    # 初始化
    ensure_data_dir_exists()
    load_uuid_status()

    # 发送启动通知
    send_startup_notification()

    # 检查必要环境变量
    required_envs = ['XSRF_TOKEN', 'BRD_SESS_ID']
    missing_envs = [env for env in required_envs if not os.getenv(env)]
    if missing_envs:
        logger.warning(f"未配置环境变量: {', '.join(missing_envs)}")

    # 启动处理线程
    threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()

    # 启动服务
    port = int(os.getenv("PORT", 5000))
    logger.info(
        f"Flask服务启动 | 0.0.0.0:{port} | 串行处理模式 | API间隔{API_CALL_INTERVAL}秒 | 429重试{TOO_MANY_REQUESTS_RETRIES}秒")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
