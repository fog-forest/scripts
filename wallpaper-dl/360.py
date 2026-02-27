#!/usr/bin/python3
# coding=utf8
# @Author: Modified based on Kinoko's script
# @Date  : 2025/08/10
# @Desc  : 360壁纸批量下载脚本 - 支持过滤黑白、纯色背景、偏暗和相似图片
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO

import numpy as np
import requests
from PIL import Image
from sklearn.cluster import KMeans
from tqdm import tqdm

# ===================== 配置项 =====================
# API基础地址
API_BASE_URL = "http://wallpaper.apc.360.cn/index.php"

# 分类映射关系 (cid: 分类名称)
CATEGORY_MAPPING = {
    "14": "动物萌宠"
}

# 每页图片数量
PAGE_SIZE = 100

# 自定义下载根目录
DOWNLOAD_ROOT_DIR = "D:/DL"

# 并发下载线程数
MAX_WORKERS = 5

# 请求超时时间(秒)
TIMEOUT = 10

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

# 图片过滤配置
BLACK_WHITE_THRESHOLD = 20  # 黑白判断阈值
SOLID_BACKGROUND_THRESHOLD = 0.6  # 纯色背景判断阈值
BRIGHTNESS_THRESHOLD = 50  # 亮度阈值（0-255）
SIMILARITY_THRESHOLD = 5  # 相似图片判断阈值（汉明距离），值越小要求越相似

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 存储已下载图片的哈希值，用于相似性检查
image_hashes = {}  # 结构: {category_name: [hash_values]}


# =================================================


def calculate_perceptual_hash(image, hash_size=16):
    """计算图片的感知哈希值"""
    try:
        # 缩小图片尺寸并转为灰度图
        img = image.resize((hash_size, hash_size), Image.LANCZOS).convert('L')
        img_array = np.array(img)

        # 计算平均亮度
        avg_brightness = img_array.mean()

        # 生成哈希值：像素亮度高于平均为1，否则为0
        hash_array = (img_array > avg_brightness).flatten()

        # 转换为整数哈希值
        hash_value = 0
        for bit in hash_array:
            hash_value = (hash_value << 1) | (1 if bit else 0)

        return hash_value
    except Exception as e:
        logger.error(f"计算哈希值失败: {str(e)}")
        return None


def hamming_distance(hash1, hash2):
    """计算两个哈希值的汉明距离"""
    if hash1 is None or hash2 is None:
        return float('inf')  # 无法计算时视为差异极大
    # 计算两个哈希值的异或结果中1的个数
    return bin(hash1 ^ hash2).count('1')


def is_similar_to_existing(image, category_name):
    """判断图片是否与同分类中已下载的图片相似"""
    if category_name not in image_hashes:
        return False, None

    current_hash = calculate_perceptual_hash(image)
    if current_hash is None:
        return False, None

    # 与同分类中所有已下载图片比较
    for existing_hash in image_hashes[category_name]:
        distance = hamming_distance(current_hash, existing_hash)
        if distance < SIMILARITY_THRESHOLD:
            return True, distance

    return False, None


def is_black_white(image):
    """判断图片是否为黑白"""
    try:
        img_rgb = image.convert('RGB')
        img_array = np.array(img_rgb)

        r, g, b = img_array[:, :, 0], img_array[:, :, 1], img_array[:, :, 2]
        diff1 = np.abs(r - g)
        diff2 = np.abs(r - b)
        diff3 = np.abs(g - b)

        total_pixels = img_array.shape[0] * img_array.shape[1]
        bw_pixels = np.sum((diff1 < BLACK_WHITE_THRESHOLD) &
                           (diff2 < BLACK_WHITE_THRESHOLD) &
                           (diff3 < BLACK_WHITE_THRESHOLD))

        return bw_pixels / total_pixels > 0.95
    except Exception as e:
        logger.error(f"黑白判断失败: {str(e)}")
        return False


def has_solid_background(image):
    """判断图片是否有纯色背景"""
    try:
        img_rgb = image.convert('RGB')
        img_array = np.array(img_rgb)
        pixels = img_array.reshape(-1, 3)

        kmeans = KMeans(n_clusters=min(10, len(pixels)), random_state=42)
        kmeans.fit(pixels)

        cluster_counts = np.bincount(kmeans.labels_)
        max_cluster_ratio = np.max(cluster_counts) / len(pixels)

        return max_cluster_ratio > SOLID_BACKGROUND_THRESHOLD
    except Exception as e:
        logger.error(f"纯色背景判断失败: {str(e)}")
        return False


def is_too_dark(image):
    """判断图片是否偏暗"""
    try:
        img_gray = image.convert('L')
        img_array = np.array(img_gray)
        average_brightness = np.mean(img_array)
        return average_brightness < BRIGHTNESS_THRESHOLD
    except Exception as e:
        logger.error(f"亮度判断失败: {str(e)}")
        return False


def download_and_filter_image(url, save_path, category_name):
    """下载图片并进行过滤"""
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

            image_data = BytesIO(response.content)

            try:
                with Image.open(image_data) as img:
                    # 检查是否为黑白图片
                    if is_black_white(img):
                        logger.debug(f"过滤黑白图片: {url}")
                        return False, "黑白图片"

                    # 检查是否为纯色背景图片
                    if has_solid_background(img):
                        logger.debug(f"过滤纯色背景图片: {url}")
                        return False, "纯色背景图片"

                    # 检查是否为偏暗图片
                    if is_too_dark(img):
                        logger.debug(f"过滤偏暗图片: {url}")
                        return False, "偏暗图片"

                    # 检查是否与已下载图片相似
                    is_similar, distance = is_similar_to_existing(img, category_name)
                    if is_similar:
                        logger.debug(f"过滤相似图片 (距离: {distance}): {url}")
                        return False, f"相似图片 (距离: {distance})"

            except Exception as e:
                logger.warning(f"图片分析失败 {url} (格式可能异常): {str(e)}")
                return False, "图片格式异常"

            # 保存图片
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'wb') as f:
                f.write(response.content)

            # 计算并保存哈希值
            with Image.open(save_path) as saved_img:
                img_hash = calculate_perceptual_hash(saved_img)
                if img_hash is not None:
                    if category_name not in image_hashes:
                        image_hashes[category_name] = []
                    image_hashes[category_name].append(img_hash)

            logger.debug(f"成功下载: {save_path}")
            return True, "成功"

        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                logger.warning(
                    f"下载失败 {url} (第 {attempt + 1} 次): {str(e)}，将重试..."
                )
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue

            logger.error(f"下载失败 {url} (已达最大重试次数): {str(e)}")
            return False, f"下载失败: {str(e)}"
    return None


def fetch_page_images(category_id, start_index):
    """获取指定分类和起始位置的图片列表"""
    try:
        params = {
            "c": "WallPaper",
            "a": "getAppsByCategory",
            "cid": category_id,
            "start": start_index,
            "count": PAGE_SIZE,
            "from": "360chrome"
        }

        logger.debug(f"请求URL: {API_BASE_URL}, 参数: {params}")
        response = requests.get(API_BASE_URL, params=params, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"获取起始位置 {start_index} 的数据失败: {str(e)}")
        return None


def collect_all_image_urls():
    """收集所有分类的图片URL，进行全局去重"""
    logger.info("====== 开始收集所有分类的图片URL ======")

    all_images = {}
    total_count = 0

    for category_id, category_name in CATEGORY_MAPPING.items():
        logger.info(f"开始收集分类: {category_name} (ID: {category_id}) 的图片URL")
        save_dir = os.path.join(DOWNLOAD_ROOT_DIR, category_name)

        try:
            # 获取第一页数据以确定总数
            first_page_data = fetch_page_images(category_id, 0)
            if not first_page_data or first_page_data.get("errno") != "0":
                error_msg = first_page_data.get("errmsg", "未知错误") if first_page_data else "无法获取数据"
                logger.error(f"API请求失败: {error_msg}")
                continue

            total_images = int(first_page_data.get("total", 0))
            total_count += total_images

            if total_images == 0:
                logger.info(f"分类 {category_name} 没有找到壁纸")
                continue

            logger.info(f"分类 {category_name} 发现 {total_images} 张壁纸")

            # 计算需要请求的页数
            pages = (total_images + PAGE_SIZE - 1) // PAGE_SIZE

            for page in range(pages):
                start_index = page * PAGE_SIZE
                # 避免请求超出总数
                if start_index >= total_images:
                    break

                page_data = fetch_page_images(category_id, start_index)
                if not page_data or page_data.get("errno") != "0":
                    error_msg = page_data.get("errmsg", "未知错误") if page_data else "无法获取数据"
                    logger.warning(f"获取起始位置 {start_index} 失败: {error_msg}，将跳过该页")
                    continue

                for item in page_data.get("data", []):
                    raw_url = item.get("url", "")
                    # 移除了URL清理逻辑，直接使用原始URL
                    if not raw_url:
                        continue

                    # 生成图片名称
                    image_id = item.get("id", str(int(time.time() * 1000)))
                    # 从URL提取扩展名
                    ext_match = re.search(r'\.(\w+)(?:\?|$)', raw_url)
                    ext = ext_match.group(1) if ext_match else 'jpg'
                    image_name = f"{image_id}.{ext}"
                    image_name = re.sub(r'[\\/*?:"<>|]', "", image_name)
                    save_path = os.path.join(save_dir, image_name)

                    if raw_url not in all_images:
                        all_images[raw_url] = (category_name, save_path)

                logger.info(f"已收集分类 {category_name} 第 {page + 1}/{pages} 页的图片链接")
                time.sleep(1)  # 避免请求过于频繁

        except Exception as e:
            logger.error(f"收集分类 {category_name} URL时出错: {str(e)}", exc_info=True)

    duplicate_count = total_count - len(all_images)
    logger.info(
        f"URL收集完成，原始总计 {total_count} 张，去重后剩余 {len(all_images)} 张，移除了 {duplicate_count} 个重复链接")

    categorized_images = {}
    for url, (category_name, save_path) in all_images.items():
        if category_name not in categorized_images:
            categorized_images[category_name] = []
        categorized_images[category_name].append((url, save_path))

    return categorized_images


def download_categorized_images(categorized_images):
    """按分类下载整理好的图片"""
    logger.info("====== 开始按分类下载图片 ======")
    os.makedirs(DOWNLOAD_ROOT_DIR, exist_ok=True)

    # 初始化哈希存储
    global image_hashes
    image_hashes = {category: [] for category in categorized_images.keys()}

    total_stats = {"total": 0, "success": 0, "failed": 0,
                   "filtered_black_white": 0, "filtered_solid_bg": 0,
                   "filtered_dark": 0, "filtered_similar": 0}

    for category_name, image_list in categorized_images.items():
        logger.info(f"开始处理分类: {category_name}，共 {len(image_list)} 张图片")
        cat_stats = {
            "total": len(image_list),
            "success": 0,
            "failed": 0,
            "filtered_black_white": 0,
            "filtered_solid_bg": 0,
            "filtered_dark": 0,
            "filtered_similar": 0
        }

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 提交任务时传递分类名称
            futures = {
                executor.submit(download_and_filter_image, url, path, category_name): (url, path)
                for url, path in image_list
            }

            for future in tqdm(as_completed(futures), total=len(futures), desc=f"下载 {category_name}"):
                url, path = futures[future]
                result, reason = future.result()
                if result:
                    cat_stats["success"] += 1
                else:
                    if reason == "黑白图片":
                        cat_stats["filtered_black_white"] += 1
                        logger.info(f"已过滤 {reason}: {url}")
                    elif reason == "纯色背景图片":
                        cat_stats["filtered_solid_bg"] += 1
                        logger.info(f"已过滤 {reason}: {url}")
                    elif reason == "偏暗图片":
                        cat_stats["filtered_dark"] += 1
                        logger.info(f"已过滤 {reason}: {url}")
                    elif reason.startswith("相似图片"):
                        cat_stats["filtered_similar"] += 1
                        logger.info(f"已过滤 {reason}: {url}")
                    else:
                        cat_stats["failed"] += 1
                        logger.info(f"下载失败 {reason}: {url}")

        for key in total_stats:
            total_stats[key] += cat_stats[key]

        logger.info(
            f"分类 {category_name} 处理完成: "
            f"成功 {cat_stats['success']} 张, "
            f"失败 {cat_stats['failed']} 张, "
            f"过滤黑白 {cat_stats['filtered_black_white']} 张, "
            f"过滤纯色背景 {cat_stats['filtered_solid_bg']} 张, "
            f"过滤偏暗图片 {cat_stats['filtered_dark']} 张, "
            f"过滤相似图片 {cat_stats['filtered_similar']} 张\n"
        )

    logger.info(
        f"====== 所有分类处理完毕 ======\n"
        f"总计: {total_stats['total']} 张\n"
        f"成功下载: {total_stats['success']} 张\n"
        f"下载失败: {total_stats['failed']} 张\n"
        f"过滤黑白图片: {total_stats['filtered_black_white']} 张\n"
        f"过滤纯色背景图片: {total_stats['filtered_solid_bg']} 张\n"
        f"过滤偏暗图片: {total_stats['filtered_dark']} 张\n"
        f"过滤相似图片: {total_stats['filtered_similar']} 张"
    )


def main():
    """主函数"""
    logger.info("====== 360壁纸批量下载脚本启动 ======")
    logger.info(f"配置信息: 并发数={MAX_WORKERS}, 每页数量={PAGE_SIZE}")
    logger.info(f"下载根目录: {os.path.abspath(DOWNLOAD_ROOT_DIR)}")
    logger.info(f"图片过滤: 黑白图片阈值={BLACK_WHITE_THRESHOLD}, "
                f"纯色背景阈值={SOLID_BACKGROUND_THRESHOLD}, "
                f"亮度阈值={BRIGHTNESS_THRESHOLD}, "
                f"相似图片阈值={SIMILARITY_THRESHOLD}")

    categorized_images = collect_all_image_urls()
    if categorized_images:
        download_categorized_images(categorized_images)
    else:
        logger.info("没有收集到任何图片URL，程序退出")


if __name__ == "__main__":
    main()
