#!/usr/bin/python3
# coding=utf8
"""
EarnApp设备注册API服务
核心功能:
1. 串行处理UUID注册请求，避免并发冲突
2. 429限流自动切换代理重试，403 Token过期告警（按账号维度）
3. 失败UUID重试固定使用原绑定账号，新UUID轮询分配账号
4. 提供注册/状态查询/健康检查RESTful接口，支持Header鉴权
5. 代理配置支持{RND:N}随机字符串占位符，适配动态代理认证
6. UUID注册状态持久化存储，服务重启不丢失数据
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
from typing import Dict

import requests
import yaml
from flask import Flask, request, jsonify

# 基础配置 - 日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
app = Flask(__name__)

# 配置文件读取
CONFIG_FILE = "/data/config.yaml"


def load_config() -> Dict:
    """从YAML配置文件加载配置信息"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_FILE}")

    with open(CONFIG_FILE, 'r', encoding='utf8') as f:
        try:
            config = yaml.safe_load(f)
            logger.info(f"加载配置文件成功: {CONFIG_FILE}")
            return config
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"配置文件解析错误: {str(e)}")


# 加载并解析配置
config = load_config()

# 全局配置
AUTH_TOKEN = config.get('global', {}).get('auth_token')
if not AUTH_TOKEN:
    raise ValueError("配置文件中 global.auth_token 未配置！")

# 多账号配置
ACCOUNTS = config.get('accounts', [])
if not ACCOUNTS:
    raise ValueError("配置文件中 accounts 列表为空！请至少配置一个账号")
account_index = 0
account_lock = threading.Lock()

# 构建账号名称到账号配置的映射（方便快速查找）
ACCOUNT_MAP = {account['name']: account for account in ACCOUNTS}

# 告警配置
ALARM_ENABLED = config.get('alarm', {}).get('enabled', False)
QMSG_CONFIG = config.get('alarm', {}).get('qmsg', {})
QMSG_TOKEN = QMSG_CONFIG.get('token')
QMSG_QQ = QMSG_CONFIG.get('qq')
QMSG_BOT = QMSG_CONFIG.get('bot_id')
QMSG_API = f"https://qmsg.zendee.cn/jsend/{QMSG_TOKEN}" if QMSG_TOKEN else None

# 代理配置
PROXY_CONFIG = config.get('proxy', {})
PROXY_HOST = PROXY_CONFIG.get('host')
PROXY_PORT = PROXY_CONFIG.get('port')
PROXY_USER_TPL = PROXY_CONFIG.get('user_template', '')
PROXY_PASS_TPL = PROXY_CONFIG.get('password_template', '')
RND_CHARSET = PROXY_CONFIG.get('random_charset', 'abcdefghijklmnopqrstuvwxyz0123456789')

# 核心常量
uuid_queue = queue.Queue()
uuid_status = {}
queue_set = set()
DATA_DIR = "/data"
STATUS_FILE = os.path.join(DATA_DIR, "uuid_status.json")

# 接口调用配置
API_CALL_INTERVAL = 5
MAX_PROXY_RETRY_COUNT = 2
TOKEN_EXPIRE_ALERT_THRESHOLD = 5

# 线程安全配置
status_lock = threading.Lock()
notify_lock = threading.Lock()
queue_lock = threading.Lock()
account_403_status = {
    account['name']: {'count': 0, 'notified': False} for account in ACCOUNTS
}

# 响应码定义
RESPONSE_CODES = {
    "SUCCESS": 0,
    "INVALID_PARAM": 1001,
    "UNAUTHORIZED": 1002,
    "UUID_NOT_FOUND": 1003,
    "DUPLICATE_UUID": 1004,
    "SYSTEM_ERROR": 9999
}


# 工具函数
def generate_random_string(length):
    """生成指定长度的随机字符串"""
    if length <= 0:
        return ""
    return ''.join(random.choice(RND_CHARSET) for _ in range(length))


def render_template(template_str):
    """替换模板字符串中的{RND:N}占位符为随机字符串"""
    if not template_str:
        return ""

    pattern = r'\{RND:(\d+)\}'

    def replace_match(match):
        return generate_random_string(int(match.group(1)))

    return re.sub(pattern, replace_match, template_str)


def get_proxy_dict():
    """生成requests可用的代理配置字典"""
    if not all([PROXY_HOST, PROXY_PORT]):
        logger.debug("代理未配置，返回空配置")
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

        proxy_dict = {"http": proxy_url, "https": proxy_url}

        # 日志脱敏输出
        log_pass = proxy_pass[:3] + "***" if len(proxy_pass) > 3 else "***" if proxy_pass else ""
        logger.debug(f"生成代理配置: http://{proxy_user}:{log_pass}@{PROXY_HOST}:{PROXY_PORT}")
        return proxy_dict

    except Exception as e:
        logger.error(f"生成代理配置失败: {str(e)}")
        return None


def get_next_account() -> Dict:
    """轮询获取下一个账号配置"""
    global account_index
    with account_lock:
        account = ACCOUNTS[account_index]
        account_index = (account_index + 1) % len(ACCOUNTS)
        logger.debug(f"当前轮询账号: {account['name']}，下一个账号索引: {account_index}")
        return account


def get_account_for_uuid(uuid: str) -> Dict:
    """
    获取UUID对应的账号配置
    - 若UUID已有绑定账号，返回该账号
    - 若没有绑定账号，返回轮询的新账号
    """
    with status_lock:
        # 检查UUID是否有绑定的账号
        if uuid in uuid_status and uuid_status[uuid].get('account'):
            account_name = uuid_status[uuid]['account']
            # 检查账号是否存在（防止配置变更）
            if account_name in ACCOUNT_MAP:
                logger.info(f"UUID {uuid} 复用绑定账号: {account_name}")
                return ACCOUNT_MAP[account_name]

    # 无绑定账号，返回轮询的新账号
    return get_next_account()


# 队列辅助函数
def is_uuid_in_queue(uuid):
    """检查UUID是否已在处理队列中"""
    with queue_lock:
        return uuid in queue_set


def add_uuid_to_queue(uuid):
    """将UUID添加到处理队列"""
    with queue_lock:
        uuid_queue.put(uuid)
        queue_set.add(uuid)
    return uuid_queue.qsize()


def remove_uuid_from_queue(uuid):
    """从查重集合中移除UUID"""
    with queue_lock:
        if uuid in queue_set:
            queue_set.remove(uuid)
            logger.debug(f"UUID {uuid} 已移出队列查重集合")


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
        logger.error(f"创建数据目录失败: {str(e)}")
        raise RuntimeError(f"无法创建数据目录 {DATA_DIR}: {str(e)}")


def load_uuid_status():
    """从持久化文件加载UUID注册状态"""
    global uuid_status
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf8') as f:
                data = json.load(f)
                uuid_status = data.get('uuid_status', {})
                logger.info(f"加载UUID状态成功，共{len(uuid_status)}条记录")
        else:
            logger.info("UUID状态文件不存在，初始化空状态")
            uuid_status = {}
    except Exception as e:
        logger.error(f"加载UUID状态失败: {str(e)}")


def save_uuid_status():
    """将UUID状态持久化到文件（原子写入）"""
    try:
        with status_lock:
            data = {'uuid_status': uuid_status}

        temp_file = f"{STATUS_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        os.replace(temp_file, STATUS_FILE)
        logger.debug("UUID状态保存成功")
    except Exception as e:
        logger.error(f"保存UUID状态失败: {str(e)}")


# 通知功能
def send_qmsg_notification(message):
    """发送QMSG通知（需配置完整且告警开关开启）"""
    if not ALARM_ENABLED:
        logger.debug("告警功能已关闭，跳过QMSG通知")
        return False

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
            logger.info(f"QMSG通知发送成功: {message[:50]}...")
            return True
        else:
            logger.error(f"QMSG通知发送失败 | 状态码: {response.status_code} | 响应: {response.text}")
            return False
    except Exception as e:
        logger.error(f"QMSG通知发送异常: {str(e)}")
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
配置账号数: {len(ACCOUNTS)}
API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次
代理配置: {proxy_status} | 认证类型: {proxy_auth_type}
告警功能: {'开启' if ALARM_ENABLED else '关闭'}"""

    send_qmsg_notification(startup_msg)


def send_account_403_alert(account_name: str, count: int):
    """发送账号403过期告警"""
    alert_msg = (
        f"⚠️ EarnApp账号Token过期告警 ⚠️\n"
        f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"账号名称: {account_name}\n"
        f"连续403错误数: {count}\n"
        f"请及时更新该账号的认证信息！"
    )
    send_qmsg_notification(alert_msg)


# API响应工具
def build_response(code, message, data=None):
    """构建统一格式的API响应"""
    response = {"code": code, "message": message}
    if data is not None:
        response["data"] = data
    return jsonify(response)


def auth_required(f):
    """Flask接口鉴权装饰器"""

    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr

        # 提取Token
        auth_header = request.headers.get('Authorization')
        custom_auth_header = request.headers.get('X-Auth-Token')
        token = None

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif custom_auth_header:
            token = custom_auth_header

        # 验证Token
        if not token:
            logger.warning(f"[{client_ip}] 未提供认证Token")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token, please provide a valid token in request header"
            ), 401
        elif token != AUTH_TOKEN:
            logger.warning(f"[{client_ip}] 使用无效Token: {token[:10]}...")
            return build_response(
                RESPONSE_CODES["UNAUTHORIZED"],
                "Invalid authentication token"
            ), 401

        logger.info(f"[{client_ip}] 接口鉴权成功")
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# 核心业务逻辑
def call_api_with_proxy_retry(uuid: str) -> Dict:
    """调用EarnApp注册API，支持429重试和403检测"""
    api_url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    # 关键修改：获取UUID对应的账号（复用原有账号或轮询新账号）
    account = get_account_for_uuid(uuid)
    account_name = account['name']
    cookie_config = account.get('cookie', {})
    xsrf_token = cookie_config.get('xsrf_token')
    brd_sess_id = cookie_config.get('brd_sess_id')

    # 检查账号认证信息
    if not xsrf_token:
        logger.error(f"账号 {account_name} 缺失xsrf_token")
        return {"error": f"Account {account_name} missing xsrf_token", "account": account_name}
    if not brd_sess_id:
        logger.error(f"账号 {account_name} 缺失brd_sess_id")
        return {"error": f"Account {account_name} missing brd_sess_id", "account": account_name}

    # 构建请求参数
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

            # 403处理
            if response.status_code == 403:
                with notify_lock:
                    account_403_status[account_name]['count'] += 1
                    current_count = account_403_status[account_name]['count']
                    logger.warning(
                        f"UUID {uuid} | 账号 {account_name} | 403 Token过期 | 连续计数: {current_count}/{TOKEN_EXPIRE_ALERT_THRESHOLD}")

                    if current_count >= TOKEN_EXPIRE_ALERT_THRESHOLD and not account_403_status[account_name][
                        'notified']:
                        logger.error(f"账号 {account_name} 连续{TOKEN_EXPIRE_ALERT_THRESHOLD}次403，触发告警")
                        send_account_403_alert(account_name, current_count)
                        account_403_status[account_name]['notified'] = True

                return {
                    "error": f"Account {account_name} Token expired, please update authentication info",
                    "account": account_name
                }

            # 重置403计数器
            with notify_lock:
                if account_403_status[account_name]['count'] > 0:
                    logger.info(f"UUID {uuid} | 账号 {account_name} | 重置403计数器")
                    account_403_status[account_name]['count'] = 0
                account_403_status[account_name]['notified'] = False

            # 429处理
            if response.status_code == 429:
                if retry_idx >= MAX_PROXY_RETRY_COUNT:
                    logger.error(f"UUID {uuid} | 账号 {account_name} | 429重试{MAX_PROXY_RETRY_COUNT}次失败")
                    return {
                        "error": f"Account {account_name} Too many requests (429), failed after {MAX_PROXY_RETRY_COUNT} retries",
                        "account": account_name
                    }

                logger.warning(f"UUID {uuid} | 账号 {account_name} | 429限流 | 第{retry_idx + 1}次重试")
                continue

            # 200成功
            if response.status_code == 200:
                result = response.json()
                result['account'] = account_name
                return result

            # 其他错误
            logger.error(f"UUID {uuid} | 账号 {account_name} | 请求失败 | 状态码: {response.status_code}")
            return {
                "error": f"Account {account_name} Request failed | Status code: {response.status_code}",
                "account": account_name
            }

        # 异常处理
        except requests.exceptions.Timeout:
            with notify_lock:
                account_403_status[account_name]['count'] = 0
                account_403_status[account_name]['notified'] = False
            logger.error(f"UUID {uuid} | 账号 {account_name} | 请求超时")
            return {"error": f"Account {account_name} Request timeout", "account": account_name}

        except requests.exceptions.ConnectionError:
            with notify_lock:
                account_403_status[account_name]['count'] = 0
                account_403_status[account_name]['notified'] = False
            logger.error(f"UUID {uuid} | 账号 {account_name} | 连接失败")
            return {"error": f"Account {account_name} Connection error", "account": account_name}

        except Exception as e:
            with notify_lock:
                account_403_status[account_name]['count'] = 0
                account_403_status[account_name]['notified'] = False
            logger.error(f"UUID {uuid} | 账号 {account_name} | 调用异常: {str(e)}")
            return {"error": f"Account {account_name} {str(e)}", "account": account_name}

    return {"error": f"Account {account_name} Unknown error", "account": account_name}


def process_uuids():
    """UUID处理线程主函数"""
    logger.info("UUID处理线程已启动")
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                logger.info(f"开始处理UUID: {uuid}")

                # 更新状态为处理中
                with status_lock:
                    # 已成功注册的UUID跳过
                    if uuid in uuid_status and uuid_status[uuid]['status'] == 'success':
                        logger.info(f"UUID {uuid} 已成功注册，跳过处理")
                        remove_uuid_from_queue(uuid)
                        uuid_queue.task_done()
                        time.sleep(API_CALL_INTERVAL)
                        continue

                    # 初始化/更新状态
                    if uuid in uuid_status:
                        uuid_status[uuid]['status'] = 'processing'
                        uuid_status[uuid]['message'] = "UUID is being processed"
                    else:
                        uuid_status[uuid] = {
                            'status': 'processing',
                            'create_time': time.time(),
                            'message': "UUID is being processed",
                            'account': None  # 首次处理时account为None，调用API时会分配
                        }
                save_uuid_status()

                # 调用API
                start_time = time.time()
                response = call_api_with_proxy_retry(uuid)
                process_time = round(time.time() - start_time, 2)
                used_account = response.get('account')

                # 处理响应结果
                if "error" in response:
                    # 已注册错误特殊处理
                    if "This device was already linked" in response['error']:
                        logger.info(f"UUID {uuid} | 账号 {used_account} | 已注册 | 耗时: {process_time}秒")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'success'
                            uuid_status[uuid]['message'] = "UUID already registered (duplicate)"
                            uuid_status[uuid]['account'] = used_account  # 绑定账号
                        save_uuid_status()
                    # 其他错误（绑定账号，便于下次重试）
                    else:
                        logger.error(
                            f"UUID {uuid} | 账号 {used_account} | 处理失败 | 耗时: {process_time}秒 | 错误: {response['error']}")
                        with status_lock:
                            uuid_status[uuid]['status'] = 'failed'
                            uuid_status[uuid]['message'] = response['error']
                            uuid_status[uuid]['account'] = used_account  # 关键：绑定失败时的账号
                        save_uuid_status()
                # 成功响应
                else:
                    logger.info(f"UUID {uuid} | 账号 {used_account} | 注册成功 | 耗时: {process_time}秒")
                    with status_lock:
                        uuid_status[uuid]['status'] = 'success'
                        uuid_status[uuid]['message'] = "UUID registered successfully"
                        uuid_status[uuid]['account'] = used_account  # 绑定账号
                    save_uuid_status()

                # 清理队列
                remove_uuid_from_queue(uuid)
                uuid_queue.task_done()
                time.sleep(API_CALL_INTERVAL)
            else:
                time.sleep(1)
        except Exception as e:
            logger.error(f"UUID处理线程异常: {str(e)}")
            time.sleep(API_CALL_INTERVAL)


# Flask API接口
@app.route('/api/register', methods=['POST'])
@auth_required
def register_uuid():
    """UUID注册接口"""
    client_ip = request.remote_addr

    # 验证请求格式
    if not request.is_json:
        logger.warning(f"[{client_ip}] 请求格式错误（非JSON）")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Request format error, please submit data in JSON format"
        ), 400

    # 提取UUID
    data = request.get_json()
    uuid = data.get('uuid')
    if not uuid:
        logger.warning(f"[{client_ip}] 缺少UUID参数")
        return build_response(
            RESPONSE_CODES["INVALID_PARAM"],
            "Parameter error, missing required UUID field"
        ), 400

    # 检查重复入队
    if is_uuid_in_queue(uuid):
        logger.info(f"[{client_ip}] UUID {uuid} 已在队列中")
        return build_response(
            RESPONSE_CODES["DUPLICATE_UUID"],
            "UUID is already in processing queue, duplicate submission is not allowed",
            {"uuid": uuid, "status": "in_queue"}
        ), 200

    # 检查历史状态
    now = time.time()
    with status_lock:
        if uuid in uuid_status:
            status = uuid_status[uuid]['status']
            if status == 'success':
                logger.info(f"[{client_ip}] UUID {uuid} 已成功注册")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    "UUID already registered successfully",
                    {"uuid": uuid, "status": "success"}
                ), 200
            elif status in ['processing', 'pending']:
                logger.info(f"[{client_ip}] UUID {uuid} 当前状态: {status}")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    f"UUID current status: {status}",
                    {"uuid": uuid, "status": status}
                ), 202

        # 初始化状态（首次请求）
        uuid_status[uuid] = {
            'status': 'pending',
            'create_time': now,
            'message': "UUID received, waiting for processing",
            'account': None  # 首次请求时account为None，处理时会分配
        }

    # 加入队列
    queue_size = add_uuid_to_queue(uuid)
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
    """UUID状态查询接口"""
    client_ip = request.remote_addr

    # 检查UUID是否存在
    with status_lock:
        if uuid not in uuid_status:
            if is_uuid_in_queue(uuid):
                logger.info(f"[{client_ip}] UUID {uuid} 状态: 队列中等待")
                return build_response(
                    RESPONSE_CODES["SUCCESS"],
                    "UUID status query successful",
                    {"status": "pending", "message": "UUID is in processing queue"}
                ), 200

            logger.warning(f"[{client_ip}] 查询不存在的UUID: {uuid}")
            return build_response(RESPONSE_CODES["UUID_NOT_FOUND"], "UUID not found"), 404

        # 组装状态信息
        status_info = {
            "status": uuid_status[uuid]['status'],
            "message": uuid_status[uuid].get('message', 'No detailed information'),
            "account": uuid_status[uuid].get('account')  # 新增：返回绑定的账号
        }

    logger.info(
        f"[{client_ip}] UUID {uuid} 状态: {status_info['status']} | 绑定账号: {status_info.get('account', '无')}")
    return build_response(
        RESPONSE_CODES["SUCCESS"],
        "UUID status query successful",
        status_info
    ), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """服务健康检查接口"""
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
            "proxy_configured": all([PROXY_HOST, PROXY_PORT]),
            "account_count": len(ACCOUNTS),
            "alarm_enabled": ALARM_ENABLED
        }
    ), 200


# 程序入口
if __name__ == "__main__":
    try:
        # 初始化
        ensure_data_dir_exists()
        load_uuid_status()
        send_startup_notification()

        # 打印配置信息
        logger.info(f"配置信息 | 账号数: {len(ACCOUNTS)} | 告警功能: {'开启' if ALARM_ENABLED else '关闭'}")

        # 代理配置信息
        if all([PROXY_HOST, PROXY_PORT]):
            auth_info = "无认证"
            if PROXY_USER_TPL and PROXY_PASS_TPL:
                auth_info = "用户名+密码认证"
            elif PROXY_USER_TPL:
                auth_info = "仅用户名认证"
            elif PROXY_PASS_TPL:
                auth_info = "仅密码认证"
            logger.info(f"代理配置 | 地址: {PROXY_HOST}:{PROXY_PORT} | 认证类型: {auth_info}")
        else:
            logger.info("未配置代理，禁用代理功能")

        # 启动处理线程
        threading.Thread(target=process_uuids, name="UUID-Processor", daemon=True).start()

        # 启动Flask服务
        port = int(os.getenv("PORT", 5000))
        logger.info(
            f"EarnApp注册服务启动成功 | 监听地址: 0.0.0.0:{port} | "
            f"API间隔: {API_CALL_INTERVAL}秒 | 429重试: {MAX_PROXY_RETRY_COUNT}次 | "
            f"403告警阈值: {TOKEN_EXPIRE_ALERT_THRESHOLD}次 | 配置账号数: {len(ACCOUNTS)}"
        )
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        exit(1)
