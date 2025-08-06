#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/08/06
# @Desc  : Wallhaven 壁纸批量下载脚本 - 支持多分类、自动分页、并发下载、自定义目录、重复文件直接丢弃

import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

# ===================== 配置项 =====================
# API基础地址
API_BASE_URL = "https://api.codelife.cc/wallpaper/wallhaven"

# 分类映射关系 (id: 分类名称)
CATEGORY_MAPPING = {
    "1": "动漫",
    "5": "动漫",
    "14": "科幻",
    "37": "自然",
    "711": "风景",
    "853": "幻想",
    "869": "图案",
    "1748": "吉卜力",
    "2321": "像素",
    "12757": "Cosplay"
}

# 自定义下载根目录
# 可以设置绝对路径，例如: "D:/Wallpapers"
# 或相对路径，例如: "./wallpapers"
DOWNLOAD_ROOT_DIR = "/Users/kinoko/Downloads/wallpapers"

# 并发下载线程数
MAX_WORKERS = 20

# 请求超时时间(秒)
TIMEOUT = 30

# 请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Connection": "keep-alive"
}

# 下载失败重试次数
MAX_RETRIES = 3

# 重试延迟时间(秒)
RETRY_DELAY = 2

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# =================================================


def clean_url(raw_url):
    """去除URL中?后面的参数"""
    if not raw_url:
        return ""
    return raw_url.split('?')[0]


def download_image(url, save_path):
    """下载单张图片并保存，带重试机制，重复文件直接丢弃"""
    # 检查文件是否已存在，如果存在则直接返回成功（不下载）
    if os.path.exists(save_path):
        logger.info(f"文件已存在，直接跳过: {os.path.basename(save_path)}")
        return True

    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"尝试下载 {url} (第 {attempt + 1} 次)")
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
                stream=True
            )
            response.raise_for_status()

            # 确保目录存在
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # 过滤掉保持连接的空块
                        f.write(chunk)

            logger.debug(f"成功下载: {save_path}")
            return True

        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                logger.warning(f"下载失败 {url} (第 {attempt + 1} 次)，错误: {str(e)}，将重试...")
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue

            logger.error(f"下载失败 {url} (已达最大重试次数)，错误: {str(e)}")
            return False


def fetch_page_images(category_id, page_num):
    """获取指定分类和页码的图片列表，参数直接嵌入URL"""
    try:
        # 尺寸(1920x1080)和每页数量(50)直接嵌入URL
        url = f"{API_BASE_URL}?lang=cn&sr=1920x1080&page={page_num}&size=50&q=id:{category_id}"

        logger.debug(f"请求URL: {url}")
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    except Exception as e:
        logger.error(f"获取第 {page_num} 页数据失败: {str(e)}")
        return None


def fetch_wallpapers(category_id, category_name):
    """获取指定分类的所有壁纸并下载"""
    logger.info(f"开始处理分类: {category_name} (ID: {category_id})")

    # 创建分类目录（基于自定义根目录）
    save_dir = os.path.join(DOWNLOAD_ROOT_DIR, category_name)
    os.makedirs(save_dir, exist_ok=True)
    logger.info(f"图片将保存到: {os.path.abspath(save_dir)}")

    # 存储所有图片URL和名称
    image_list = []
    current_page = 1

    try:
        # 获取第一页数据以确定总页数
        first_page_data = fetch_page_images(category_id, current_page)

        if not first_page_data or first_page_data.get("code") != 200:
            error_msg = first_page_data.get("msg", "未知错误") if first_page_data else "无法获取数据"
            logger.error(f"API请求失败: {error_msg}")
            return

        total_pages = first_page_data.get("pages", 0)
        total_count = first_page_data.get("count", 0)

        if total_pages == 0:
            logger.info(f"分类 {category_name} 没有找到壁纸")
            return

        logger.info(f"发现 {total_count} 张壁纸，共 {total_pages} 页，开始收集下载链接...")

        # 处理第一页的图片
        for item in first_page_data.get("data", []):
            clean_img_url = clean_url(item.get("raw", ""))
            image_name = f"{item.get('name', '')}.jpg"
            # 确保文件名有效
            image_name = re.sub(r'[\\/*?:"<>|]', "", image_name)
            image_list.append((clean_img_url, os.path.join(save_dir, image_name)))

        # 处理剩余页的图片
        for page in range(2, total_pages + 1):
            page_data = fetch_page_images(category_id, page)

            if not page_data or page_data.get("code") != 200:
                error_msg = page_data.get("msg", "未知错误") if page_data else "无法获取数据"
                logger.warning(f"获取第 {page} 页失败: {error_msg}，将跳过该页")
                continue

            for item in page_data.get("data", []):
                clean_img_url = clean_url(item.get("raw", ""))
                image_name = f"{item.get('name', '')}.jpg"
                image_name = re.sub(r'[\\/*?:"<>|]', "", image_name)
                image_list.append((clean_img_url, os.path.join(save_dir, image_name)))

            logger.info(f"已收集第 {page}/{total_pages} 页的图片链接")
            time.sleep(1)  # 避免请求过于频繁

        # 并发下载所有图片
        logger.info(f"开始下载 {len(image_list)} 张图片到 {save_dir}")
        success_count = 0
        skipped_count = 0  # 统计跳过的重复文件

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 创建下载任务
            futures = {
                executor.submit(download_image, url, path): (url, path)
                for url, path in image_list
                if url  # 过滤空URL
            }

            # 跟踪下载进度
            for future in tqdm(as_completed(futures), total=len(futures), desc=f"下载 {category_name}"):
                result = future.result()
                if result:
                    # 检查是否是因为文件已存在而返回的True
                    url, path = futures[future]
                    if os.path.exists(path):
                        skipped_count += 1
                    else:
                        success_count += 1

        logger.info(
            f"分类 {category_name} 处理完成，新下载 {success_count} 张，跳过重复 {skipped_count} 张，总计 {len(image_list)} 张\n")

    except Exception as e:
        logger.error(f"处理分类 {category_name} 时出错: {str(e)}", exc_info=True)


def main():
    """主函数：遍历所有分类并下载壁纸"""
    logger.info("====== Wallhaven 壁纸批量下载脚本启动 ======")
    logger.info(f"配置信息: 并发数={MAX_WORKERS}, 每页数量=50, 尺寸=1920x1080")
    logger.info(f"下载根目录: {os.path.abspath(DOWNLOAD_ROOT_DIR)}")
    logger.info(f"待处理分类: {', '.join([f'{k}:{v}' for k, v in CATEGORY_MAPPING.items()])}")

    # 确保根目录存在
    os.makedirs(DOWNLOAD_ROOT_DIR, exist_ok=True)

    # 遍历所有分类并下载
    for category_id, category_name in CATEGORY_MAPPING.items():
        fetch_wallpapers(category_id, category_name)

    logger.info("====== 所有分类处理完毕 ======")


if __name__ == "__main__":
    main()
