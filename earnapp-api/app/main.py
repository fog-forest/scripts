#!/usr/bin/python3
# coding=utf8
"""
EarnApp设备注册API服务
=======================
核心功能:
1. 串行处理UUID注册请求，避免并发冲突
2. 429限流错误自动切换代理重试机制
3. Token过期告警（连续3个403触发）、服务启动QMSG通知
4. 提供注册/状态查询/健康检查RESTful接口，支持Header鉴权
5. 代理配置支持{RND:N}随机字符串占位符，适配动态代理认证
6. UUID注册状态持久化存储，服务重启不丢失数据

环境变量配置说明:
【必填项】
- AUTH_TOKEN: 接口鉴权令牌（Header认证使用）
- XSRF_TOKEN: EarnApp认证Token（接口调用必备）
- BRD_SESS_ID: EarnApp会话ID（接口调用必备）

【代理配置（可选）】
- PROXY_HOST: 代理服务器地址
- PROXY_PORT: 代理服务器端口
- PROXY_USER_TPL: 代理账号模板（支持{RND:N}随机字符串）
- PROXY_PASS_TPL: 代理密码模板（支持{RND:N}随机字符串）
- RND_CHARSET: 随机字符集（默认: 字母+数字）

【通知配置（可选）】
- QMSG_TOKEN: QMSG推送Token
- QMSG_QQ: 接收通知的QQ号
- QMSG_BOT: QMSG机器人标识
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

# ======================== 基础配置 ========================
# 日志配置：设置日志级别、格式和时间格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)  # 获取日志实例
app = Flask(__name__)  # 初始化Flask应用

# ======================== 环境变量读取 ========================
# QMSG通知相关配置
QMSG_TOKEN = os.getenv('QMSG_TOKEN')
QMSG_QQ = os.getenv('QMSG_QQ')
QMSG_BOT = os.getenv('QMSG_BOT')
QMSG_API = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else None

# 接口鉴权Token（必填，缺失会抛出异常）
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
if not AUTH_TOKEN:
    raise ValueError("环境变量 AUTH_TOKEN 未配置！请设置接口鉴权令牌")

# 代理相关配置（均为可选）
PROXY_HOST = os.getenv('PROXY_HOST')
PROXY_PORT = os.getenv('PROXY_PORT')
PROXY_USER_TPL = os.getenv('PROXY_USER_TPL', '')  # 代理账号模板
PROXY_PASS_TPL = os.getenv('PROXY_PASS_TPL', '')  # 代理密码模板
RND_CHARSET = os.getenv('RND_CHARSET', 'abcdefghijklmnopqrstuvwxyz0123456789')  # 随机字符集

# ======================== 核心配置常量 ========================
# 队列与存储配置
uuid_queue = queue.Queue()  # UUID处理队列（串行处理）
uuid_status = {}  # UUID状态缓存（内存）
queue_set = set()  # 队列UUID集合（用于快速查重）
DATA_DIR = "/data"  # 数据持久化目录
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")  # UUID状态存储文件

# 接口调用配置
API_CALL_INTERVAL = 5  # API调用间隔（秒），防止频率限制
MAX_PROXY_RETRY_COUNT = 2  # 429限流错误最大重试次数
TOKEN_EXPIRE_ALERT_THRESHOLD = 3  # 连续403错误告警阈值（次）

# ======================== 线程安全配置 ========================
status_lock = threading.Lock()  # UUID状态操作锁
notify_lock = threading.Lock()  # 通知发送操作锁
queue_lock = threading.Lock()  # 队列集合操作锁
token_expired_notified = False  # Token过期通知发送标记（防止重复告警）
continuous_403_count = 0  # 连续403错误计数器

# ======================== 响应码定义 ========================
RESPONSE_CODES = {
    "SUCCESS": 0,  # 操作成功
    "INVALID_PARAM": 1001,  # 参数错误（格式/缺失）
    "UNAUTHORIZED": 1002,  # 未授权（Token错误/缺失）
    "UUID_NOT_FOUND": 1003,  # UUID不存在（未注册/无记录）
    "SYSTEM_ERROR": 9999,  # 系统内部错误
    "DUPLICATE_UUID": 1004  # UUID已在处理队列中
}


# ======================== 工具函数 ========================
def generate_random_string(length):
    """
    生成指定长度的随机字符串

    Args:
        length (int): 随机字符串长度（<=0返回空字符串）

    Returns:
        str: 指定长度的随机字符串
    """
    if length <= 0:
        return ""
    return ''.join(random.choice(RND_CHARSET) for _ in range(length))


def render_template(template_str):
    """
    替换模板字符串中的{RND:N}占位符为随机字符串

    Args:
        template_str (str): 包含{RND:N}占位符的模板字符串

    Returns:
        str: 替换后的字符串（空字符串返回空）
    """
    if not template_str:
        return ""

    # 正则匹配{RND:N}格式的占位符
    pattern = r'\{RND:(\d+)\}'

    def replace_match(match):
        """正则匹配替换函数"""
        return generate_random_string(int(match.group(1)))

    return re.sub(pattern, replace_match, template_str)


def get_proxy_dict():
    """
    生成requests可用的代理配置字典，支持多种认证类型

    支持的认证类型：
    1. 无认证: 仅主机+端口
    2. 仅用户名: 用户名@主机:端口
    3. 仅密码: :密码@主机:端口
    4. 用户名+密码: 用户名:密码@主机:端口

    Returns:
        dict/None: 代理配置字典（http/https），代理未配置返回None
    """
    if not all([PROXY_HOST, PROXY_PORT]):
        logger.debug("代理未配置（PROXY_HOST/PROXY_PORT缺失），返回空配置")
        return None

    try:
        # 渲染代理账号/密码模板（替换{RND:N}占位符）
        proxy_user = render_template(PROXY_USER_TPL)
        proxy_pass = render_template(PROXY_PASS_TPL)

        # 根据认证信息构建代理URL
        if proxy_user and proxy_pass:
            proxy_url = f"http://{proxy_user}:{proxy_pass}@{PROXY_HOST}:{PROXY_PORT}"
        elif proxy_user:
            proxy_url = f"http://{proxy_user}@{PROXY_HOST}:{PROXY_PORT}"
        elif proxy_pass:
            proxy_url = f"http://:{proxy_pass}@{PROXY_HOST}:{PROXY_PORT}"
        else:
            proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"

        # 构建requests兼容的代理字典
        proxy_dict = {
            "http": proxy_url,
            "https": proxy_url
        }

        # 日志脱敏输出（密码仅显示前3位）
        log_pass = proxy_pass[:3] + "***" if len(proxy_pass) > 3 else "***" if proxy_pass else ""
        logger.debug(f"生成代理配置: http://{proxy_user}:{log_pass}@{PROXY_HOST}:{PROXY_PORT}")
        return proxy_dict

    except Exception as e:
        logger.error(f"生成代理配置失败: {str(e)}")
        return None


# ======================== 队列辅助函数 ========================
def is_uuid_in_queue(uuid):
    """
    检查UUID是否已在处理队列中（防止重复入队）

    Args:
        uuid (str): 待检查的UUID

    Returns:
        bool: True-已在队列，False-不在队列
    """
    with queue_lock:
        return uuid in queue_set


def add_uuid_to_queue(uuid):
    """
    将UUID添加到处理队列，并更新查重集合

    Args:
        uuid (str): 待添加的UUID

    Returns:
        int: 添加后的队列长度
    """
    with queue_lock:
        uuid_queue.put(uuid)
        queue_set.add(uuid)
    return uuid_queue.qsize()


def remove_uuid_from_queue(uuid):
    """
    从查重集合中移除UUID（任务完成后清理）

    Args:
        uuid (str): 待移除的UUID
    """
    with queue_lock:
        if uuid in queue_set:
            queue_set.remove(uuid)
            logger.debug(f"UUID {uuid} 已移出队列查重集合")


# ======================== 数据持久化 ========================
def ensure_data_dir_exists():
    """
    确保数据目录存在，不存在则创建（权限0755）

    Raises:
        RuntimeError: 目录创建失败时抛出异常
    """
    try:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, mode=0o755)
            logger.info(f"数据目录不存在，已创建: {DATA_DIR}")
        else:
            logger.info(f"数据目录已存在: {DATA_DIR}")
    except Exception as e:
        logger.error(f"创建数据目录失败: {str(e)}")
        raise RuntimeError(f"无法创建数据目录 {DATA_DIR}: {str(e)}")


def load_uuid_status():
    """
    从持久化文件加载UUID注册状态到内存

    Notes:
        文件不存在时初始化空状态，加载失败记录错误日志
    """
    global uuid_status
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f)
                uuid_status = data.get('uuid_status', {})
                logger.info(f"成功加载UUID状态，共{len(uuid_status)}条记录")
        else:
            logger.info("UUID状态文件不存在，初始化空状态")
            uuid_status = {}
    except Exception as e:
        logger.error(f"加载UUID状态失败: {str(e)}")


def save_uuid_status():
    """
    将内存中的UUID状态持久化到文件（原子写入，防止文件损坏）

    Notes:
        1. 先写入临时文件，再替换目标文件
        2. 使用status_lock保证线程安全
    """
    try:
        with status_lock:
            data = {'uuid_status': uuid_status}

        # 原子写入：先写临时文件，再替换
        temp_file = f"{STATUS_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        os.replace(temp_file, STATUS_FILE)
        logger.debug("UUID状态已成功保存到文件")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {str(e)}")


# ======================== 通知功能 ========================
def send_qmsg_notification(message):
    """
    发送QMSG通知（需配置QMSG_TOKEN/QMSG_QQ/QMSG_BOT）

    Args:
        message (str): 通知内容

    Returns:
        bool: True-发送成功，False-发送失败/配置不完整
    """
    # 检查QMSG配置完整性
    if not all([QMSG_TOKEN, QMSG_QQ, QMSG_BOT]):
        logger.warning("QMSG配置不完整（TOKEN/QQ/BOT缺失），跳过通知发送")
        return False

    try:
        # 构建请求参数
        payload = {"msg": message, "qq": QMSG_QQ, "bot": QMSG_BOT}
        response = requests.post(
            QMSG_API,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        # 检查响应状态
        if response.status_code == 200:
            logger.info(f"QMSG通知发送成功: {message[:50]}...")
            return True
        else:
            logger.error(f"QMSG通知发送失败 | 状态码: {response.status_code} | 响应: {response.text}")
            return False
    except Exception as e:
        logger.error(f"QMSG通知发送异常: {str(e)}")
        return False


def send_startup_notification():
    """发送服务启动通知（包含基础配置信息）"""
    # 构建代理状态信息
    proxy_status = "已配置" if all([PROXY_HOST, PROXY_PORT]) else "未配置"
    proxy_auth_type = "无认证"
    if PROXY_USER_TPL and PROXY_PASS_TPL:
        proxy_auth_type = "用户名+密码"
    elif PROXY_USER_TPL:
        proxy_auth_type = "仅用户名"
    elif PROXY_PASS_TPL:
        proxy_auth_type = "仅密码"

    # 构建启动通知内容
    startup_msg = f"""🚀 EarnApp注册服务已启动 🚀
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
队列长度: {uuid_queue.qsize()}
已记录UUID: {len(uuid_status)}
API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次
代理配置: {proxy_status} | 认证类型: {proxy_auth_type}"""

    send_qmsg_notification(startup_msg)


# ======================== API响应工具 ========================
def build_response(code, message, data=None):
    """
    构建统一格式的API响应

    Args:
        code (int): 响应码（参考RESPONSE_CODES）
        message (str): 响应描述信息
        data (dict, optional): 响应数据（可选）

    Returns:
        flask.Response: JSON格式的响应对象
    """
    response = {"code": code, "message": message}
    if data is not None:
        response["data"] = data
    return jsonify(response)


def auth_required(f):
    """
    Flask接口鉴权装饰器（验证Header中的Token）

    支持的Token传递方式：
    1. Authorization: Bearer {TOKEN}
    2. X-Auth-Token: {TOKEN}

    Args:
        f (function): 被装饰的视图函数

    Returns:
        function: 装饰后的函数（未授权返回401）
    """

    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr

        # 从Header中提取Token
        auth_header = request.headers.get('Authorization')
        custom_auth_header = request.headers.get('X-Auth-Token')
        token = None

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif custom_auth_header:
            token = custom_auth_header

        # Token验证逻辑
        if not token:
            logger.warning(f"[{client_ip}] 接口请求未提供认证Token")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token, please provide a valid token in request header"
            ), 401
        elif token != AUTH_TOKEN:
            logger.warning(f"[{client_ip}] 接口请求使用无效Token: {token[:10]}...")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token"
            ), 401

        logger.info(f"[{client_ip}] 接口鉴权成功")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__  # 保留原函数名
    return wrapper


# ======================== 核心业务逻辑 ========================
def call_api_with_proxy_retry(uuid):
    """
    调用EarnApp设备注册API，支持429限流重试和403 Token过期检测

    Args:
        uuid (str): 待注册的设备UUID

    Returns:
        dict: API响应结果（成功返回接口数据，失败返回error字段）
    """
    global token_expired_notified, continuous_403_count
    api_url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    # 检查EarnApp认证信息
    xsrf_token = os.getenv('XSRF_TOKEN')
    brd_sess_id = os.getenv('BRD_SESS_ID')
    if not xsrf_token:
        logger.error("EarnApp认证信息缺失: XSRF_TOKEN未配置")
        return {"error": "XSRF_TOKEN not configured"}
    if not brd_sess_id:
        logger.error("EarnApp认证信息缺失: BRD_SESS_ID未配置")
        return {"error": "BRD_SESS_ID not configured"}

    # 构建请求头和Cookie
    headers = {"Xsrf-Token": xsrf_token}
    cookies = {"xsrf-token": xsrf_token, "brd_sess_id": brd_sess_id}

    # 重试逻辑（处理429限流错误）
    for retry_idx in range(MAX_PROXY_RETRY_COUNT + 1):
        try:
            # 获取代理配置（每次重试重新生成，支持随机占位符）
            proxies = get_proxy_dict()

            # 发送注册请求
            response = requests.post(
                api_url,
                json={"uuid": uuid},
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=10
            )

            # 403 Token过期处理
            if response.status_code == 403:
                with notify_lock:
                    # 增加连续403计数器
                    continuous_403_count += 1
                    logger.warning(
                        f"UUID {uuid} | 403 Token过期 | 连续计数: {continuous_403_count}/{TOKEN_EXPIRE_ALERT_THRESHOLD}")

                    # 达到阈值且未发送通知时触发告警
                    if continuous_403_count >= TOKEN_EXPIRE_ALERT_THRESHOLD and not token_expired_notified:
                        logger.error(f"连续{TOKEN_EXPIRE_ALERT_THRESHOLD}个UUID返回403，触发Token过期告警")
                        notify_msg = (
                            f"⚠️ EarnApp Token过期告警 ⚠️\n"
                            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                            f"连续403错误数: {continuous_403_count}\n"
                            f"最后出错UUID: {uuid}"
                        )
                        send_qmsg_notification(notify_msg)
                        token_expired_notified = True  # 标记已发送，防止重复告警

                return {"error": "EarnApp Token expired, please update authentication info"}

            # 非403响应：重置计数器和通知标记
            with notify_lock:
                if continuous_403_count > 0:
                    logger.info(f"UUID {uuid} | 非403响应，重置连续403计数器（当前值: {continuous_403_count}）")
                    continuous_403_count = 0
                token_expired_notified = False

            # 429限流处理
            if response.status_code == 429:
                if retry_idx >= MAX_PROXY_RETRY_COUNT:
                    logger.error(f"UUID {uuid} | 429限流重试{MAX_PROXY_RETRY_COUNT}次失败")
                    return {"error": f"Too many requests (429), failed after {MAX_PROXY_RETRY_COUNT} retries"}

                logger.warning(f"UUID {uuid} | 429限流 | 第{retry_idx + 1}次重试")
                continue

            # 200成功响应
            if response.status_code == 200:
                return response.json()

            # 其他状态码错误
            logger.error(f"UUID {uuid} | API请求失败 | 状态码: {response.status_code} | 响应: {response.text}")
            return {"error": f"Request failed | Status code: {response.status_code}"}

        # 异常处理
        except requests.exceptions.Timeout:
            with notify_lock:
                continuous_403_count = 0
                token_expired_notified = False
            logger.error(f"UUID {uuid} | API请求超时（10秒）")
            return {"error": "Request timeout"}

        except requests.exceptions.ConnectionError:
            with notify_lock:
                continuous_403_count = 0
                token_expired_notified = False
            logger.error(f"UUID {uuid} | API连接失败")
            return {"error": "Connection error"}

        except Exception as e:
            with notify_lock:
                continuous_403_count = 0
                token_expired_notified = False
            logger.error(f"UUID {uuid} | API调用异常: {str(e)}")
            return {"error": str(e)}

    return {"error": "Unknown error"}


def process_uuids():
    """
    UUID处理线程主函数（串行处理队列中的UUID）

    处理流程：
    1. 从队列取出UUID
    2. 更新状态为processing
    3. 调用注册API
    4. 根据结果更新状态
    5. 持久化状态，清理队列记录
    """
    logger.info("UUID处理线程已启动，开始监听处理队列")
    while True:
        try:
            if not uuid_queue.empty():
                # 取出队列中的UUID
                uuid = uuid_queue.get()
                logger.info(f"开始处理UUID: {uuid}")

                # 更新UUID状态为处理中
                with status_lock:
                    # 已成功注册的UUID直接跳过
                    if uuid in uuid_status and uuid_status[uuid]['status'] == 'success':
                        logger.info(f"UUID {uuid} 已成功注册，跳过处理")
                        remove_uuid_from_queue(uuid)
                        uuid_queue.task_done()
                        time.sleep(API_CALL_INTERVAL)
                        continue

                    # 更新状态为processing
                    if uuid in uuid_status:
                        uuid_status[uuid]['status'] = 'processing'
                        uuid_status[uuid]['message'] = "UUID is being processed"
                    else:
                        uuid_status[uuid] = {
                            'status': 'processing',
                            'create_time': time.time(),
                            'message': "UUID is being processed"
                        }
                save_uuid_status()  # 持久化状态

                # 调用注册API
                start_time = time.time()
                response = call_api_with_proxy_retry(uuid)
                process_time = round(time.time() - start_time, 2)

                # 处理API响应结果
                if "error" in response:
                    # 已注册错误（特殊处理，标记为成功）
                    if response['error'] == "This device was already linked":
                        logger.info(f"UUID {uuid} | 已注册 | 处理耗时: {process_time}秒")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'success'
                            uuid_status[uuid]['message'] = "UUID already registered (duplicate)"
                        save_uuid_status()
                    # 其他错误
                    else:
                        logger.error(f"UUID {uuid} | 处理失败 | 耗时: {process_time}秒 | 错误: {response['error']}")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'failed'
                            uuid_status[uuid]['message'] = response['error']
                        save_uuid_status()
                # API调用成功
                else:
                    logger.info(f"UUID {uuid} | 注册成功 | 处理耗时: {process_time}秒")
                    with status_lock:
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['message'] = "UUID registered successfully"
                    save_uuid_status()

                # 任务完成：清理队列记录，等待间隔后处理下一个
                remove_uuid_from_queue(uuid)
                uuid_queue.task_done()
                time.sleep(API_CALL_INTERVAL)
            else:
                # 队列为空时休眠1秒，减少CPU占用
                time.sleep(1)
        except Exception as e:
            logger.error(f"UUID处理线程异常: {str(e)}")
            time.sleep(API_CALL_INTERVAL)  # 异常时等待后重试


# ======================== Flask API接口 ========================
@app.route('/api/register', methods=['POST'])
@auth_required
def register_uuid():
    """
    UUID注册接口（POST）

    请求格式:
        Content-Type: application/json
        Body: {"uuid": "待注册的UUID"}

    响应格式:
        {
            "code": 响应码,
            "message": 描述信息,
            "data": {
                "uuid": "请求的UUID",
                "queue_position": 队列位置,
                "status": "pending/processing/success"
            }
        }

    鉴权方式:
        Header中携带Authorization或X-Auth-Token
    """
    client_ip = request.remote_addr

    # 验证请求格式（必须为JSON）
    if not request.is_json:
        logger.warning(f"[{client_ip}] /api/register | 请求格式错误（非JSON）")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Request format error, please submit data in JSON format"
        ), 400

    # 提取UUID参数
    data = request.get_json()
    uuid = data.get('uuid')
    if not uuid:
        logger.warning(f"[{client_ip}] /api/register | 缺少UUID参数")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Parameter error, missing required UUID field"
        ), 400

    # 检查UUID是否已在队列中（防止重复提交）
    if is_uuid_in_queue(uuid):
        logger.info(f"[{client_ip}] /api/register | UUID {uuid} 已在队列中，拒绝重复入队")
        return build_response(
            RESPONSE_CODES["DUPLICATE_UUID"],
            "UUID is already in processing queue, duplicate submission is not allowed",
            {"uuid": uuid, "status": "in_queue"}
        ), 200

    # 检查UUID历史状态
    now = time.time()
    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            # 已成功注册
            if status == 'success':
                logger.info(f"[{client_ip}] /api/register | UUID {uuid} 已成功注册")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    "UUID already registered successfully",
                    {"uuid": uuid, "status": "success"}
                ), 200
            # 处理中/待处理
            elif status in ['processing', 'pending']:
                logger.info(f"[{client_ip}] /api/register | UUID {uuid} 当前状态: {status}")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    f"UUID current status: {status}",
                    {"uuid": uuid, "status": status}
                ), 202

        # 新增UUID，初始化状态为pending
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': now,
            'message': "UUID received, waiting for processing"
        }

    # 添加到处理队列
    queue_size = add_uuid_to_queue(uuid)
    save_uuid_status()

    logger.info(f"[{client_ip}] /api/register | UUID {uuid} 加入队列 | 队列长度: {queue_size}")
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
    """
    UUID状态查询接口（GET）

    路径参数:
        uuid: 待查询的UUID

    响应格式:
        {
            "code": 响应码,
            "message": 描述信息,
            "data": {
                "status": "pending/processing/success/failed",
                "message": 详细信息
            }
        }

    鉴权方式:
        Header中携带Authorization或X-Auth-Token
    """
    client_ip = request.remote_addr

    # 检查UUID是否存在
    with status_lock:
        if uuid not in uuid_status:
            # 检查是否在处理队列中
            if is_uuid_in_queue(uuid):
                logger.info(f"[{client_ip}] /api/uuid/status | UUID {uuid} 状态: 队列中等待")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    "UUID status query successful",
                    {
                        "status": "pending",
                        "message": "UUID is in processing queue"
                    }
                ), 200

            # UUID不存在
            logger.warning(f"[{client_ip}] /api/uuid/status | 查询不存在的UUID: {uuid}")
            return build_response(
                RESPONSE_CODES["UUID_NOT_FOUND"],
                "UUID not found"
            ), 404

        # 组装状态信息
        status_info = {
            "status": uuid_status[uuid]['status'],
            "message": uuid_status[uuid].get('message', 'No detailed information')
        }

    logger.info(f"[{client_ip}] /api/uuid/status | UUID {uuid} 状态: {status_info['status']}")
    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "UUID status query successful",
        status_info
    ), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    服务健康检查接口（GET，无需鉴权）

    响应格式:
        {
            "code": 0,
            "message": "Service is running normally",
            "data": {
                "service": "服务名称",
                "status": "running",
                "timestamp": "当前时间",
                "queue_size": 队列长度,
                "queue_unique_count": 队列唯一UUID数,
                "recorded_uuids": 已记录UUID数,
                "proxy_configured": 是否配置代理
            }
        }
    """
    with queue_lock:
        queue_unique_count = len(queue_set)

    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "Service is running normally",
        {
            "service": "earnapp-uuid-register",
            "status": "running",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "queue_size": uuid_queue.qsize(),
            "queue_unique_count": queue_unique_count,
            "recorded_uuids": len(uuid_status),
            "proxy_configured": all([PROXY_HOST, PROXY_PORT])
        }
    ), 200


# ======================== 程序入口 ========================
if __name__ == "__main__":
    # 初始化流程
    try:
        # 1. 确保数据目录存在
        ensure_data_dir_exists()

        # 2. 加载UUID状态
        load_uuid_status()

        # 3. 发送服务启动通知
        send_startup_notification()

        # 4. 检查必要环境变量
        required_envs = ['XSRF_TOKEN', 'BRD_SESS_ID']
        missing_envs = [env for env in required_envs if not os.getenv(env)]
        if missing_envs:
            logger.warning(f"以下必要环境变量未配置: {', '.join(missing_envs)} | 接口调用可能失败")

        # 5. 打印代理配置信息
        if all([PROXY_HOST, PROXY_PORT]):
            auth_info = "无认证"
            if PROXY_USER_TPL and PROXY_PASS_TPL:
                auth_info = "用户名+密码认证"
            elif PROXY_USER_TPL:
                auth_info = "仅用户名认证"
            elif PROXY_PASS_TPL:
                auth_info = "仅密码认证"
            logger.info(f"代理配置信息 | 地址: {PROXY_HOST}:{PROXY_PORT} | 认证类型: {auth_info}")
        else:
            logger.info("未配置代理（PROXY_HOST/PROXY_PORT缺失），禁用代理功能")

        # 6. 启动UUID处理线程（守护线程）
        threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()

        # 7. 启动Flask服务
        port = int(os.getenv("PORT", 5000))
        logger.info(
            f"EarnApp注册服务启动成功 | 监听地址: 0.0.0.0:{port} | "
            f"API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次 | "
            f"403告警阈值: {TOKEN_EXPIRE_ALERT_THRESHOLD}次"
        )
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        exit(1)
