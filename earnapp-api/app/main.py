#!/usr/bin/python3
# coding=utf8
"""
EarnApp设备注册API服务
特性：
1. 串行处理UUID注册
2. 429限流错误切换代理重试
3. Token过期/服务启动发送QMSG告警
4. 支持注册/状态查询/健康检查接口，Header鉴权
5. 代理配置支持{RND:N}随机字符串占位符
6. 持久化存储UUID注册状态

环境变量（必填）：
- AUTH_TOKEN: 接口鉴权令牌
- XSRF_TOKEN: EarnApp认证Token
- BRD_SESS_ID: EarnApp会话ID

环境变量（代理）：
- PROXY_HOST/PROXY_PORT: 代理地址/端口
- PROXY_USER_TPL/PROXY_PASS_TPL: 代理账号模板（支持{RND:N}）
- RND_CHARSET: 随机字符集（默认字母+数字）

环境变量（通知）：
- QMSG_TOKEN/QMSG_QQ/QMSG_BOT: QMSG推送配置
"""

import json
import logging
import os
import queue
import random
import re
import threading
import time
from datetime import datetime

import requests
from flask import Flask, request, jsonify

# 基础配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
app = Flask(__name__)

# 环境变量读取
QMSG_TOKEN = os.getenv('QMSG_TOKEN')
QMSG_QQ = os.getenv('QMSG_QQ')
QMSG_BOT = os.getenv('QMSG_BOT')
QMSG_API = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else None

# 鉴权Token（必填）
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
if not AUTH_TOKEN:
    raise ValueError("环境变量 AUTH_TOKEN 未配置！")

# 代理配置（均为可选）
PROXY_HOST = os.getenv('PROXY_HOST')
PROXY_PORT = os.getenv('PROXY_PORT')
PROXY_USER_TPL = os.getenv('PROXY_USER_TPL', '')
PROXY_PASS_TPL = os.getenv('PROXY_PASS_TPL', '')
RND_CHARSET = os.getenv('RND_CHARSET', 'abcdefghijklmnopqrstuvwxyz0123456789')

# 核心配置
uuid_queue = queue.Queue()  # UUID处理队列
uuid_status = {}  # UUID状态缓存
queue_set = set()  # 队列UUID集合（查重用）
DATA_DIR = "/data"  # 数据目录
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")

API_CALL_INTERVAL = 5  # API调用间隔（秒）
MAX_PROXY_RETRY_COUNT = 2  # 429错误最大重试次数

# 线程锁
status_lock = threading.Lock()
notify_lock = threading.Lock()
queue_lock = threading.Lock()  # 队列集合操作锁
token_expired_notified = False  # Token过期通知标记

# 响应码定义
RESPONSE_CODES = {
    "SUCCESS": 0,  # 成功
    "INVALID_PARAM": 1001,  # 参数错误
    "UNAUTHORIZED": 1002,  # 未授权
    "UUID_NOT_FOUND": 1003,  # UUID不存在
    "SYSTEM_ERROR": 9999,  # 系统错误
    "DUPLICATE_UUID": 1004  # UUID已在队列中
}


# 工具函数
def generate_random_string(length):
    """生成指定长度的随机字符串"""
    if length <= 0:
        return ""
    return ''.join(random.choice(RND_CHARSET) for _ in range(length))


def render_template(template_str):
    """替换{RND:N}占位符为随机字符串"""
    if not template_str:
        return ""

    pattern = r'\{RND:(\d+)\}'

    def replace_match(match):
        return generate_random_string(int(match.group(1)))

    return re.sub(pattern, replace_match, template_str)


def get_proxy_dict():
    """生成代理配置字典，支持多种认证类型"""
    if not all([PROXY_HOST, PROXY_PORT]):
        logger.debug("代理未配置，返回空")
        return None

    try:
        proxy_user = render_template(PROXY_USER_TPL)
        proxy_pass = render_template(PROXY_PASS_TPL)

        # 构建代理URL
        if proxy_user and proxy_pass:
            proxy_url = f"http://{proxy_user}:{proxy_pass}@{PROXY_HOST}:{PROXY_PORT}"
        elif proxy_user:
            proxy_url = f"http://{proxy_user}@{PROXY_HOST}:{PROXY_PORT}"
        elif proxy_pass:
            proxy_url = f"http://:{proxy_pass}@{PROXY_HOST}:{PROXY_PORT}"
        else:
            proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"

        # 构建代理字典
        proxy_dict = {
            "http": proxy_url,
            "https": proxy_url
        }

        # 日志脱敏输出
        log_pass = proxy_pass[:3] + "***" if len(proxy_pass) > 3 else "***" if proxy_pass else ""
        logger.debug(f"生成代理: http://{proxy_user}:{log_pass}@{PROXY_HOST}:{PROXY_PORT}")
        return proxy_dict

    except Exception as e:
        logger.error(f"生成代理失败: {str(e)}")
        return None


# 队列辅助函数
def is_uuid_in_queue(uuid):
    """检查UUID是否在处理队列中"""
    with queue_lock:
        return uuid in queue_set


def add_uuid_to_queue(uuid):
    """添加UUID到队列并更新查重集合"""
    with queue_lock:
        uuid_queue.put(uuid)
        queue_set.add(uuid)
    return uuid_queue.qsize()


def remove_uuid_from_queue(uuid):
    """从查重集合移除UUID"""
    with queue_lock:
        if uuid in queue_set:
            queue_set.remove(uuid)
            logger.debug(f"UUID {uuid} 移出队列集合")


# 数据持久化
def ensure_data_dir_exists():
    """确保数据目录存在"""
    try:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, mode=0o755)
            logger.info(f"创建数据目录: {DATA_DIR}")
        else:
            logger.info(f"数据目录已存在: {DATA_DIR}")
    except Exception as e:
        logger.error(f"创建目录失败: {str(e)}")
        raise RuntimeError(f"无法创建目录: {str(e)}")


def load_uuid_status():
    """加载UUID状态文件"""
    global uuid_status
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f)
                uuid_status = data.get('uuid_status', {})
                logger.info(f"加载UUID状态: {len(uuid_status)}条")
        else:
            logger.info("UUID状态文件不存在，初始化空状态")
            uuid_status = {}
    except Exception as e:
        logger.error(f"加载UUID状态失败: {str(e)}")


def save_uuid_status():
    """保存UUID状态（原子写入）"""
    try:
        with status_lock:
            data = {'uuid_status': uuid_status}

        # 临时文件+原子替换
        temp_file = f"{STATUS_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        os.replace(temp_file, STATUS_FILE)
        logger.debug("UUID状态保存成功")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {str(e)}")


# 通知功能
def send_qmsg_notification(message):
    """发送QMSG通知"""
    if not all([QMSG_TOKEN, QMSG_QQ, QMSG_BOT]):
        logger.warning("QMSG配置不完整，跳过通知")
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
            logger.info(f"QMSG通知发送成功: {message[:50]}...")
            return True
        else:
            logger.error(f"QMSG发送失败 | 状态码: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"QMSG发送异常: {str(e)}")
        return False


def send_startup_notification():
    """发送服务启动通知"""
    proxy_status = "已配置" if all([PROXY_HOST, PROXY_PORT]) else "未配置"
    proxy_auth_type = "无认证"
    if PROXY_USER_TPL and PROXY_PASS_TPL:
        proxy_auth_type = "用户名+密码"
    elif PROXY_USER_TPL:
        proxy_auth_type = "仅用户名"
    elif PROXY_PASS_TPL:
        proxy_auth_type = "仅密码"

    startup_msg = f"""🚀 EarnApp注册服务已启动 🚀
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
队列长度: {uuid_queue.qsize()}
已记录UUID: {len(uuid_status)}
API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次
代理配置: {proxy_status} | 认证类型: {proxy_auth_type}"""
    send_qmsg_notification(startup_msg)


# API响应工具
def build_response(code, message, data=None):
    """构建统一API响应格式"""
    response = {"code": code, "message": message}
    if data is not None:
        response["data"] = data
    return jsonify(response)


def auth_required(f):
    """接口鉴权装饰器"""

    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr

        # 获取Token
        auth_header = request.headers.get('Authorization')
        custom_auth_header = request.headers.get('X-Auth-Token')
        token = None

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif custom_auth_header:
            token = custom_auth_header

        # 验证Token
        if not token:
            logger.warning(f"[{client_ip}] 未提供Token")
            return build_response(RESPONSE_CODES["UNAUTHORIZED"],
                                  "Invalid authentication token, please provide a valid token in request header"), 401
        elif token != AUTH_TOKEN:
            logger.warning(f"[{client_ip}] 无效Token: {token[:10]}...")
            return build_response(RESPONSE_CODES["UNAUTHORIZED"],
                                  "Invalid authentication token"), 401

        logger.info(f"[{client_ip}] 鉴权成功")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# 核心业务逻辑
def call_api_with_proxy_retry(uuid):
    """调用EarnApp注册API，429错误切换代理重试"""
    global token_expired_notified
    api_url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    # 检查认证信息
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

    # 重试逻辑
    for retry_idx in range(MAX_PROXY_RETRY_COUNT + 1):
        try:
            proxies = get_proxy_dict()

            # 发送请求
            response = requests.post(
                api_url,
                json={"uuid": uuid},
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=10
            )

            # Token过期处理
            if response.status_code == 403:
                with notify_lock:
                    if not token_expired_notified:
                        logger.error(f"Token过期 | UUID: {uuid}")
                        notify_msg = f"⚠️ Token过期 ⚠️\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nUUID: {uuid}"
                        send_qmsg_notification(notify_msg)
                        token_expired_notified = True
                return {"error": "EarnApp Token expired, notification sent, please update authentication info"}

            # 429限流处理
            if response.status_code == 429:
                if retry_idx >= MAX_PROXY_RETRY_COUNT:
                    logger.error(f"UUID {uuid} | 429重试{MAX_PROXY_RETRY_COUNT}次失败")
                    return {"error": f"Too many requests (429), failed after {MAX_PROXY_RETRY_COUNT} retries"}

                logger.warning(f"UUID {uuid} | 429第{retry_idx + 1}次重试")
                continue

            # 请求成功
            if response.status_code == 200:
                with notify_lock:
                    token_expired_notified = False
                return response.json()

            # 其他错误
            logger.error(f"UUID {uuid} | 请求失败 | 状态码: {response.status_code}")
            return {"error": f"Request failed | Status code: {response.status_code}"}

        except requests.exceptions.Timeout:
            logger.error(f"UUID {uuid} | 请求超时")
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            logger.error(f"UUID {uuid} | 连接失败")
            return {"error": "Connection error"}
        except Exception as e:
            logger.error(f"UUID {uuid} | 调用异常: {str(e)}")
            return {"error": str(e)}

    return {"error": "Unknown error"}


def process_uuids():
    """串行处理队列中的UUID"""
    logger.info("UUID处理线程启动")
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                logger.info(f"处理UUID: {uuid}")

                # 更新状态为处理中
                with status_lock:
                    if uuid in uuid_status and uuid_status[uuid]['status'] == 'success':
                        logger.info(f"UUID {uuid} 已成功，跳过")
                        remove_uuid_from_queue(uuid)
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

                # 调用API
                start_time = time.time()
                response = call_api_with_proxy_retry(uuid)
                process_time = round(time.time() - start_time, 2)

                # 处理响应
                if "error" in response:
                    if response['error'] == "This device was already linked":
                        logger.info(f"UUID {uuid} 已注册 | 耗时 {process_time}秒")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'success'
                            uuid_status[uuid]['message'] = "UUID already registered (duplicate)"
                        save_uuid_status()
                    else:
                        logger.error(f"UUID {uuid} 失败 | 耗时 {process_time}秒 | 错误: {response['error']}")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'failed'
                            uuid_status[uuid]['message'] = response['error']
                        save_uuid_status()
                else:
                    logger.info(f"UUID {uuid} 成功 | 耗时 {process_time}秒")
                    with status_lock:
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['message'] = "UUID registered successfully"
                    save_uuid_status()

                # 任务完成，移除队列记录
                remove_uuid_from_queue(uuid)
                uuid_queue.task_done()
                time.sleep(API_CALL_INTERVAL)
            else:
                time.sleep(1)
        except Exception as e:
            logger.error(f"处理线程异常: {str(e)}")
            time.sleep(API_CALL_INTERVAL)


# Flask接口
@app.route('/api/register', methods=['POST'])
@auth_required
def register_uuid():
    """UUID注册接口（防重复入队）"""
    client_ip = request.remote_addr

    # 验证JSON格式
    if not request.is_json:
        logger.warning(f"[{client_ip}] 请求非JSON格式")
        return build_response(RESPONSE_CODES["INVALID_PARAM"],
                              "Request format error, please submit data in JSON format"), 400

    # 获取UUID参数
    data = request.get_json()
    uuid = data.get('uuid')
    if not uuid:
        logger.warning(f"[{client_ip}] 缺少UUID参数")
        return build_response(RESPONSE_CODES["INVALID_PARAM"],
                              "Parameter error, missing required UUID field"), 400

    # 检查是否已在队列中
    if is_uuid_in_queue(uuid):
        logger.info(f"[{client_ip}] UUID {uuid} 已在队列中，拒绝重复入队")
        return build_response(RESPONSE_CODES["DUPLICATE_UUID"],
                              "UUID is already in processing queue, duplicate submission is not allowed",
                              {"uuid": uuid, "status": "in_queue"}), 200

    # 检查UUID状态
    now = time.time()
    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            if status == 'success':
                logger.info(f"[{client_ip}] UUID {uuid} 已成功")
                return build_response(RESPONSE_CODES["SUCCESS"],
                                      "UUID already registered successfully", {"uuid": uuid, "status": "success"}), 200
            elif status in ['processing', 'pending']:
                logger.info(f"[{client_ip}] UUID {uuid} 状态: {status}")
                return build_response(RESPONSE_CODES["SUCCESS"],
                                      f"UUID current status: {status}", {"uuid": uuid, "status": status}), 202

        # 新增UUID
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': now,
            'message': "UUID received, waiting for processing"
        }

    # 加入队列
    queue_size = add_uuid_to_queue(uuid)
    save_uuid_status()

    logger.info(f"[{client_ip}] UUID {uuid} 加入队列 | 长度: {queue_size}")
    return build_response(RESPONSE_CODES["SUCCESS"],
                          "UUID received, processing will start shortly", {
                              "uuid": uuid,
                              "queue_position": queue_size,
                              "status": "pending"
                          }), 202


@app.route('/api/uuid/status/<uuid>', methods=['GET'])
@auth_required
def get_uuid_status(uuid):
    """UUID状态查询接口"""
    client_ip = request.remote_addr

    # 检查UUID是否存在
    with status_lock:
        if uuid not in uuid_status:
            # 检查是否在队列中
            if is_uuid_in_queue(uuid):
                logger.info(f"[{client_ip}] UUID {uuid} 状态: 队列中等待")
                return build_response(RESPONSE_CODES["SUCCESS"],
                                      "UUID status query successful", {
                                          "status": "pending",
                                          "message": "UUID is in processing queue"
                                      }), 200

            logger.warning(f"[{client_ip}] 查询不存在的UUID: {uuid}")
            return build_response(RESPONSE_CODES["UUID_NOT_FOUND"],
                                  "UUID not found"), 404

        status_info = {
            "status": uuid_status[uuid]['status'],
            "message": uuid_status[uuid].get('message', 'No detailed information')
        }

    logger.info(f"[{client_ip}] 查询UUID {uuid} 状态: {status_info['status']}")
    return build_response(RESPONSE_CODES["SUCCESS"],
                          "UUID status query successful", status_info), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """服务健康检查接口"""
    with queue_lock:
        queue_unique_count = len(queue_set)

    return build_response(RESPONSE_CODES["SUCCESS"],
                          "Service is running normally", {
                              "service": "earnapp-uuid-register",
                              "status": "running",
                              "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                              "queue_size": uuid_queue.qsize(),
                              "queue_unique_count": queue_unique_count,
                              "recorded_uuids": len(uuid_status),
                              "proxy_configured": all([PROXY_HOST, PROXY_PORT])
                          }), 200


# 程序入口
if __name__ == "__main__":
    # 初始化
    ensure_data_dir_exists()
    load_uuid_status()
    send_startup_notification()

    # 检查必要环境变量
    required_envs = ['XSRF_TOKEN', 'BRD_SESS_ID']
    missing_envs = [env for env in required_envs if not os.getenv(env)]
    if missing_envs:
        logger.warning(f"未配置环境变量: {', '.join(missing_envs)}")

    # 打印代理配置
    if all([PROXY_HOST, PROXY_PORT]):
        auth_info = "无认证"
        if PROXY_USER_TPL and PROXY_PASS_TPL:
            auth_info = "用户名+密码认证"
        elif PROXY_USER_TPL:
            auth_info = "仅用户名认证"
        elif PROXY_PASS_TPL:
            auth_info = "仅密码认证"
        logger.info(f"代理配置 | 地址: {PROXY_HOST}:{PROXY_PORT} | 认证: {auth_info}")
    else:
        logger.info("未配置代理，禁用代理功能")

    # 启动处理线程
    threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()

    # 启动服务
    port = int(os.getenv("PORT", 5000))
    logger.info(f"服务启动 | 地址: 0.0.0.0:{port} | 间隔: {API_CALL_INTERVAL}秒 | 重试: {MAX_PROXY_RETRY_COUNT}次")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
