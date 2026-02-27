#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2026/02/26
# @Desc  : EarnAPP 设备注册API（带Header Token鉴权）
import os
import queue
import threading
import time

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# UUID队列
uuid_queue = queue.Queue()

# 读取鉴权Token（必填）
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
if not AUTH_TOKEN:
    raise ValueError("环境变量 AUTH_TOKEN 未配置，请设置后启动服务！")


# 鉴权装饰器
def auth_required(f):
    def wrapper(*args, **kwargs):
        # 获取请求头中的Token（支持Bearer和自定义格式）
        auth_header = request.headers.get('Authorization')
        custom_auth_header = request.headers.get('X-Auth-Token')

        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif custom_auth_header:
            token = custom_auth_header

        # 校验Token有效性
        if not token or token != AUTH_TOKEN:
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid authentication token, please carry the correct Token in the request header"
            }), 401
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__  # 修复Flask路由装饰器名称问题
    return wrapper


# UUID处理线程
def process_uuids():
    while True:
        try:
            if not uuid_queue.empty():
                uuid = uuid_queue.get()
                response = call_api(uuid)
                print(f"Result for UUID {uuid}: {response}")
                time.sleep(3)  # 处理间隔
            else:
                time.sleep(1)  # 空队列时降低CPU占用
        except Exception as e:
            print(f"Error processing UUID: {str(e)}")


# 调用EarnAPP注册API
def call_api(uuid):
    url = f"https://earnapp.com/dashboard/api/link_device?appid=earnapp"

    # 从环境变量读取认证信息
    xsrf_token = os.getenv('XSRF_TOKEN')
    oauth_refresh_token = os.getenv('OAUTH_REFRESH_TOKEN')

    headers = {"Xsrf-Token": xsrf_token}
    cookies = {
        "xsrf-token": xsrf_token,
        "oauth-refresh-token": oauth_refresh_token
    }

    try:
        response = requests.post(url, json={"uuid": uuid}, headers=headers, cookies=cookies)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Request failed with status code {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# 注册接口（需鉴权）
@app.route('/api/register', methods=['POST'])
@auth_required
def get_request_result():
    data = request.json
    uuid = data.get('uuid')

    if not uuid:
        return jsonify({"error": "UUID is required"}), 400

    uuid_queue.put(uuid)
    return jsonify({"message": "UUID received, processing will start shortly."}), 202


if __name__ == "__main__":
    # 启动UUID处理线程
    threading.Thread(target=process_uuids, daemon=True).start()

    # 启动Flask服务（默认端口5000）
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
