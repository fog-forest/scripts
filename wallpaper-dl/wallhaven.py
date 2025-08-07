#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/08/07
# @Desc  : Wallhaven 壁纸批量下载脚本 - 提取特定路径部分版本

import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO

import numpy as np
import requests
from PIL import Image
from tqdm import tqdm

# ===================== 配置项 =====================
# API基础地址
API_BASE_URL = "https://api.codelife.cc/wallpaper/wallhaven"

# 分类映射关系 (id: 分类名称)
CATEGORY_MAPPING = {
    "1": "动漫",
    "5": "动漫",
    # "14": "科幻",
    # "37": "自然",
    # "711": "风景",
    # "853": "幻想",
    # "869": "图案",
    # "1748": "吉卜力",
    # "2321": "像素",
    # "12757": "Cosplay"
}

# 自定义下载根目录
DOWNLOAD_ROOT_DIR = "D:/DL"

# 并发下载线程数
MAX_WORKERS = 50

# 请求超时时间(秒)
TIMEOUT = 10

# 请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Connection": "keep-alive"
}

# 下载失败重试次数
MAX_RETRIES = 10

# 重试延迟时间(秒)
RETRY_DELAY = 2

# 图片过滤配置
BLACK_WHITE_THRESHOLD = 10  # 黑白判断阈值

# 域名配置 - 主域名和备用域名列表
PRIMARY_DOMAIN = "https://w.wallhaven.cc/"
BACKUP_DOMAINS = [
    "https://w.wallhaven.wpcoder.cn/",
    "https://w.wallhaven.clbug.com/",
    "https://w.wallhaven.1lou.top/"
    "https://files.codelife.cc/wallhaven/"
]

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# =================================================


def get_domain_url(raw_url, domain):
    """使用指定域名生成URL，只提取full/.../wallhaven-....[图片格式]部分"""
    if not raw_url:
        return ""

    # 提取full/开头直到常见图片格式后缀的路径部分
    # 匹配类似 full/5g/wallhaven-5ggol7.png 或 full/8k/wallhaven-8kabc1.jpg 的格式
    # 支持的图片格式：png, jpg, jpeg, gif, webp
    path_match = re.search(r'(full/.*?\.(?:png|jpg|jpeg|gif|webp))', raw_url)
    if path_match:
        path = path_match.group(1)  # 获取到类似"full/5g/wallhaven-5ggol7.png"的路径
        # 确保域名以/结尾
        if not domain.endswith('/'):
            domain += '/'
        return f"{domain}{path}"  # 拼接新域名和路径

    # 如果无法解析，返回清理后的原始URL
    logger.warning(f"无法提取有效路径: {raw_url}")
    return raw_url.split('?')[0]


def clean_url(raw_url):
    """默认URL清理：使用主域名"""
    return get_domain_url(raw_url, PRIMARY_DOMAIN)


def is_black_white(image):
    """判断图片是否为黑白"""
    try:
        # 转换为RGB格式，统一通道数
        img_rgb = image.convert('RGB')
        img_array = np.array(img_rgb)

        r, g, b = img_array[:, :, 0], img_array[:, :, 1], img_array[:, :, 2]
        # 计算RGB通道差异
        diff1 = np.abs(r - g)
        diff2 = np.abs(r - b)
        diff3 = np.abs(g - b)

        # 所有通道差异都小于阈值的像素比例
        total_pixels = img_array.shape[0] * img_array.shape[1]
        bw_pixels = np.sum((diff1 < BLACK_WHITE_THRESHOLD) &
                           (diff2 < BLACK_WHITE_THRESHOLD) &
                           (diff3 < BLACK_WHITE_THRESHOLD))

        return bw_pixels / total_pixels > 0.95
    except Exception as e:
        logger.error(f"黑白判断失败: {str(e)}")
        return False  # 出错时不判定为黑白


def download_and_filter_image(url, save_path):
    """下载图片并进行过滤（支持多域名切换重试）"""
    # 获取所有可能的域名列表（主域名+备用域名）
    all_domains = [PRIMARY_DOMAIN] + BACKUP_DOMAINS
    current_domain_index = 0

    for attempt in range(MAX_RETRIES):
        try:
            # 本次尝试使用的域名
            current_domain = all_domains[current_domain_index]
            # 生成当前域名的URL
            current_url = get_domain_url(url, current_domain)

            logger.debug(f"尝试下载 {current_url} (第 {attempt + 1} 次，使用域名: {current_domain})")
            response = requests.get(
                current_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                stream=True
            )
            response.raise_for_status()

            # 加载图片数据
            image_data = BytesIO(response.content)

            # 尝试打开图片
            try:
                with Image.open(image_data) as img:
                    # 仅过滤黑白图片，不限制尺寸
                    if is_black_white(img):
                        logger.debug(f"过滤黑白图片: {current_url}")
                        return False, "黑白图片"
            except Exception as e:
                logger.warning(f"图片分析失败 {current_url} (格式可能异常): {str(e)}")
                return False, "图片格式异常"

            # 保存图片
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'wb') as f:
                f.write(response.content)

            logger.debug(f"成功下载: {save_path} (来源: {current_url})")
            return True, "成功"

        except Exception as e:
            # 准备下次尝试
            # 切换到下一个域名（循环切换）
            current_domain_index = (current_domain_index + 1) % len(all_domains)

            if attempt < MAX_RETRIES - 1:
                next_domain = all_domains[current_domain_index]
                logger.warning(
                    f"下载失败 {current_url} (第 {attempt + 1} 次): {str(e)}，"
                    f"将尝试域名 {next_domain} 重试..."
                )
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue

            logger.error(f"下载失败 {current_url} (已达最大重试次数): {str(e)}")
            return False, f"下载失败: {str(e)}"
    return None


def fetch_page_images(category_id, page_num):
    """获取指定分类和页码的图片列表"""
    try:
        url = f"{API_BASE_URL}?lang=cn&sr=1920x1080&page={page_num}&size=50&q=id:{category_id}"
        logger.debug(f"请求URL: {url}")
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"获取第 {page_num} 页数据失败: {str(e)}")
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
            first_page_data = fetch_page_images(category_id, 1)
            if not first_page_data or first_page_data.get("code") != 200:
                error_msg = first_page_data.get("msg", "未知错误") if first_page_data else "无法获取数据"
                logger.error(f"API请求失败: {error_msg}")
                continue

            total_pages = first_page_data.get("pages", 0)
            cat_count = first_page_data.get("count", 0)
            total_count += cat_count

            if total_pages == 0:
                logger.info(f"分类 {category_name} 没有找到壁纸")
                continue

            logger.info(f"分类 {category_name} 发现 {cat_count} 张壁纸，共 {total_pages} 页")

            # 处理所有页面
            for page in range(1, total_pages + 1):
                page_data = fetch_page_images(category_id, page)
                if not page_data or page_data.get("code") != 200:
                    error_msg = page_data.get("msg", "未知错误") if page_data else "无法获取数据"
                    logger.warning(f"获取第 {page} 页失败: {error_msg}，将跳过该页")
                    continue

                for item in page_data.get("data", []):
                    raw_url = item.get("raw", "")
                    clean_img_url = clean_url(raw_url)
                    if not clean_img_url:
                        continue

                    image_name = f"{item.get('name', '')}.jpg"
                    image_name = re.sub(r'[\\/*?:"<>|]', "", image_name)
                    save_path = os.path.join(save_dir, image_name)

                    if clean_img_url not in all_images:
                        all_images[clean_img_url] = (category_name, save_path)

                logger.info(f"已收集分类 {category_name} 第 {page}/{total_pages} 页的图片链接")
                time.sleep(1)

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
    logger.info(f"使用的域名列表: 主域名={PRIMARY_DOMAIN}, 备用域名={BACKUP_DOMAINS}")
    os.makedirs(DOWNLOAD_ROOT_DIR, exist_ok=True)

    total_stats = {"total": 0, "success": 0, "failed": 0, "filtered": 0}

    for category_name, image_list in categorized_images.items():
        logger.info(f"开始处理分类: {category_name}，共 {len(image_list)} 张图片")
        cat_stats = {"total": len(image_list), "success": 0, "failed": 0, "filtered": 0}

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(download_and_filter_image, url, path): (url, path)
                for url, path in image_list
            }

            for future in tqdm(as_completed(futures), total=len(futures), desc=f"下载 {category_name}"):
                url, path = futures[future]
                cleaned_url = clean_url(url)
                result, reason = future.result()
                if result:
                    cat_stats["success"] += 1
                else:
                    if reason == "黑白图片":
                        cat_stats["filtered"] += 1
                        logger.info(f"已过滤 {reason}: {cleaned_url}")
                    else:
                        cat_stats["failed"] += 1
                        logger.info(f"下载失败 {reason}: {cleaned_url}")

        for key in total_stats:
            total_stats[key] += cat_stats[key]

        logger.info(
            f"分类 {category_name} 处理完成: "
            f"成功 {cat_stats['success']} 张, "
            f"失败 {cat_stats['failed']} 张, "
            f"过滤 {cat_stats['filtered']} 张\n"
        )

    logger.info(
        f"====== 所有分类处理完毕 ======\n"
        f"总计: {total_stats['total']} 张\n"
        f"成功下载: {total_stats['success']} 张\n"
        f"下载失败: {total_stats['failed']} 张\n"
        f"被过滤: {total_stats['filtered']} 张 (仅黑白图片)"
    )


def main():
    """主函数"""
    logger.info("====== Wallhaven 壁纸批量下载脚本启动 ======")
    logger.info(f"配置信息: 并发数={MAX_WORKERS}, 每页数量=50, 尺寸=1920x1080")
    logger.info(f"下载根目录: {os.path.abspath(DOWNLOAD_ROOT_DIR)}")
    logger.info(f"图片过滤: 仅过滤黑白图片，不限制尺寸")
    logger.info(f"域名配置: 主域名={PRIMARY_DOMAIN}, 备用域名={BACKUP_DOMAINS}")

    categorized_images = collect_all_image_urls()
    if categorized_images:
        download_categorized_images(categorized_images)
    else:
        logger.info("没有收集到任何图片URL，程序退出")


if __name__ == "__main__":
    main()
