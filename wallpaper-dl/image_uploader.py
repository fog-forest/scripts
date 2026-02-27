#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/08/09
# @Desc  : 图片批量上传（黑猫图床）
import os
import threading
import time
from datetime import datetime
from queue import Queue
from threading import Lock

import requests

# ================= 配置参数 - 所有配置项集中在此处 =================
TARGET_DIRECTORY = "D:/DL/动物萌宠"  # 硬编码的目标图片目录路径
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']  # 支持的图片格式
MAX_RETRIES = 2  # 最大重试次数
SUCCESS_URLS = 'success_urls.txt'  # 成功上传的URL列表
THREAD_COUNT = 4  # 线程数量，可根据需要调整
ALBUM_ID = 'zB7u'  # 相册ID album_id
API_URL = 'https://img.hmvod.cc/json'  # API地址
AUTH_TOKEN = '你的Token'  # 认证令牌

# API请求头
headers = {
    'Cookie': '你的Cookie'
}
# ==================================================================

# 线程安全的数据结构和锁
success_urls = []
processed_count = 0  # 已处理文件数量
total_count = 0  # 总文件数量
results_lock = Lock()  # 用于保护共享数据的锁


def get_current_timestamp():
    """获取当前时间戳（毫秒）"""
    return int(datetime.now().timestamp() * 1000)


def is_image_file(filename):
    """判断文件是否为图片"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in IMAGE_EXTENSIONS


def upload_image(file_path):
    """上传单个图片到API"""
    try:
        # 准备表单数据
        form_data = {
            'type': 'file',
            'action': 'upload',
            'timestamp': str(get_current_timestamp()),
            'auth_token': AUTH_TOKEN,
            'expiration': '',
            'nsfw': '',
            'album_id': ALBUM_ID,  # 使用提取出的配置项
            'mimetype': f'image/{os.path.splitext(file_path)[1][1:].lower()}'  # 提取文件扩展名作为mimetype
        }

        # 准备文件数据
        files = {
            'source': (os.path.basename(file_path), open(file_path, 'rb'), form_data['mimetype'])
        }

        # 发送请求
        response = requests.post(
            API_URL,  # 使用配置的API地址
            headers=headers,
            data=form_data,
            files=files,
            timeout=30
        )

        # 解析响应
        response_json = response.json()

        # 提取结果信息
        result = {
            'status_code': response.status_code,
            'response': response.text
        }

        # 处理成功响应
        if response.status_code == 200:
            # 从成功响应中提取image url
            result['url'] = response_json.get('image', {}).get('url')
        else:
            # 处理错误响应
            result['error'] = response_json.get('error', {}).get('message', '未知错误')

        return result

    except Exception as e:
        return {
            'status_code': None,
            'url': None,
            'error': str(e)
        }
    finally:
        # 确保文件被关闭
        if 'files' in locals() and 'source' in files:
            files['source'][1].close()


def worker(queue):
    """线程工作函数，处理队列中的文件上传任务"""
    global processed_count
    while not queue.empty():
        file_path = queue.get()
        try:
            # 上传文件，带重试机制
            result = None
            for attempt in range(MAX_RETRIES + 1):
                result = upload_image(file_path)

                if result['status_code'] == 200:
                    print(f"上传成功 (尝试 {attempt + 1}/{MAX_RETRIES + 1}) - {os.path.basename(file_path)}")

                    # 线程安全地更新共享数据
                    with results_lock:
                        success_urls.append(result['url'])
                    break
                else:
                    error_msg = result.get('error', f"状态码: {result['status_code']}")
                    print(
                        f"上传失败 (尝试 {attempt + 1}/{MAX_RETRIES + 1}) - {os.path.basename(file_path)}: {error_msg}")
                    if attempt < MAX_RETRIES:
                        time.sleep(2)  # 重试前等待2秒

            # 更新处理计数并显示进度
            with results_lock:
                processed_count += 1
                progress = (processed_count / total_count) * 100
                print(f"进度: {processed_count}/{total_count} ({progress:.1f}%)")

        except Exception as e:
            print(f"处理 {os.path.basename(file_path)} 时出错: {str(e)}")
        finally:
            queue.task_done()


def process_directory():
    """处理目录下的所有图片文件，使用多线程上传"""
    global total_count, processed_count

    # 检查目录是否存在
    if not os.path.isdir(TARGET_DIRECTORY):
        print(f"错误: 目录 '{TARGET_DIRECTORY}' 不存在")
        return

    # 收集所有图片文件路径
    image_files = []
    for root, dirs, files in os.walk(TARGET_DIRECTORY):
        for file in files:
            if is_image_file(file):
                file_path = os.path.join(root, file)
                image_files.append(file_path)

    total_count = len(image_files)
    processed_count = 0

    print(f"发现 {total_count} 个图片文件，准备上传...")
    if not image_files:
        print("没有找到图片文件，程序退出。")
        return

    # 创建任务队列
    queue = Queue()
    for file_path in image_files:
        queue.put(file_path)

    # 创建并启动线程
    threads = []
    for i in range(THREAD_COUNT):
        thread = threading.Thread(target=worker, args=(queue,), name=f"Thread-{i + 1}")
        threads.append(thread)
        thread.start()

    # 等待所有任务完成
    queue.join()

    # 等待所有线程结束
    for thread in threads:
        thread.join()

    # 保存成功的URL到TXT文件（只保存URL）
    with open(SUCCESS_URLS, 'w', encoding='utf-8') as f:
        for url in success_urls:
            f.write(f"{url}\n")

    print(f"\n处理完成")
    print(f"成功上传的URL已保存到 {SUCCESS_URLS}")
    print(f"成功上传: {len(success_urls)} 个文件")
    print(f"上传失败: {total_count - len(success_urls)} 个文件")


if __name__ == "__main__":
    process_directory()
