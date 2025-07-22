#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/22
# @Desc  : mTab多分类网站书签导出工具
# @Func  : 批量获取多分类网站信息，处理URL去重、图标下载转换，最终生成SQL导入语句


# ============================== 配置参数区 ==============================
# 线程数量配置
MAX_WORKERS = 8  # 并发处理URL的线程数量

# 需要处理的分类列表
CATEGORIES = [
    "ai", "app", "news", "music", "tech", "photos", "life", "education",
    "entertainment", "shopping", "social", "read", "sports", "finance", "others"
]

# 分类ID映射表，用于SQL生成
CATEGORY_IDS = {
    "ai": 1, "app": 2, "news": 3, "music": 4,
    "tech": 5, "photos": 6, "life": 7, "education": 8,
    "entertainment": 9, "shopping": 10, "social": 11, "read": 12,
    "sports": 13, "finance": 14, "others": 15
}

# 域名黑名单，包含这些域名的URL将被直接丢弃（最高优先级）
DOMAIN_BLACKLIST = {
    "trae.ai", "trae.cn", "js.design", "zenvideo.qq.com"
}

# 域名白名单，白名单内的域名允许处理非www开头的URL（次高优先级）
DOMAIN_WHITELIST = {
    "qq.com", "google.com", "github.com", "yiyan.baidu.com",
    "outlook.live.com"
}

# 允许的常见子域名列表
ALLOWED_SUBDOMAINS = {
    # 核心访问类
    "www", "web", "site", "portal", "main",
    # 内容创作与展示类
    "blog", "note", "paper", "article", "story",
    "doc", "docs", "wiki", "book", "press",
    # 交互社区类
    "bbs", "forum", "chat", "talk", "group",
    "social", "club", "community",
    # 功能服务类
    "api", "app", "tool", "tools", "service",
    "admin", "auth", "login", "account", "user",
    # 通信与联系类
    "mail", "email", "contact", "msg", "notify",
    # 资源存储与分发类
    "cdn", "img", "pic", "image", "file",
    "pan", "drive", "store", "archive", "photo",
    # 设备与平台类
    "pc", "mobile", "m", "ios", "android",
    "applet", "client", "device",
    # 场景与环境类
    "dev", "test", "staging", "prod", "beta",
    "cloud", "local", "home", "office", "lab",
    # 业务场景类
    "shop", "store", "buy", "sell", "pay",
    "map", "location", "live", "video", "stream",
    "edu", "learn", "class", "course", "game"
}

# HTTP请求配置
HTTP_CONFIG = {
    'timeout': 20,  # 请求超时时间(秒)
    'max_redirects': 0,  # 禁用自动跳转
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'keep-alive'
    }
}

# 图标存储目录
ICON_DIRECTORY = 'icons'

# SQL输出文件路径
SQL_OUTPUT_FILE = "mtab_import.sql"

# ========================================================================


# 导入依赖库
import io
import logging
import os
import random
import re
import threading
import time
from base64 import b64encode
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import quote, urlparse

import requests
import validators
from PIL import Image
from tldextract import extract
from tqdm import tqdm


# 数据结构定义
@dataclass
class WebsiteData:
    name: str  # 网站名称
    url: str  # 网站URL
    description: str  # 网站描述
    img_src: str  # 图标原始URL
    local_filename: str  # 本地存储的图标文件名
    category: str  # 所属分类
    background_color: str  # 背景颜色


# ============================== 日志配置 ==============================
def setup_logger() -> logging.Logger:
    logger = logging.getLogger('mtab_exporter')
    logger.setLevel(logging.INFO)  # 降低日志级别，减少输出

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)  # 只输出INFO及以上级别

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')  # 简化日志格式，去掉线程ID
    ch.setFormatter(formatter)

    if logger.handlers:
        logger.handlers = []
    logger.addHandler(ch)

    return logger


# 初始化日志
logger = setup_logger()


# ============================== 主处理函数 ==============================
def main() -> None:
    # 图片下载重试配置 - 在主函数中定义，便于日志输出和后续传递
    MAX_IMAGE_RETRIES = 3  # 最大重试次数
    INITIAL_RETRY_DELAY = 1  # 初始重试延迟(秒)

    logger.info("\n" + "=" * 60)
    logger.info("开始执行mTab多分类网站书签导出工具")
    logger.info("=" * 60 + "\n")

    # 配置信息（只保留关键信息）
    logger.info(f"URL处理线程数量: {MAX_WORKERS}")
    logger.info(f"图片下载最大重试次数: {MAX_IMAGE_RETRIES}")
    logger.info(f"图片初始重试延迟: {INITIAL_RETRY_DELAY}秒")
    logger.info(f"处理分类数量: {len(CATEGORIES)}")
    logger.info(f"域名黑名单数量: {len(DOMAIN_BLACKLIST)}")
    logger.info(f"域名白名单数量: {len(DOMAIN_WHITELIST)}\n")

    # 初始化
    clear_directory(ICON_DIRECTORY)
    processed_data: List[WebsiteData] = []
    processed_normalized_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}
    url_queue = []  # 存储所有待处理的URL任务
    queue_lock = threading.Lock()  # 队列操作锁
    data_lock = threading.Lock()  # 数据操作锁

    # 第一步：多线程获取所有分类的URL并加入队列
    logger.info("===== 开始收集所有分类的URL =====")
    with ThreadPoolExecutor(max_workers=min(len(CATEGORIES), 2)) as category_executor:
        futures = [
            category_executor.submit(
                process_category,
                category,
                url_queue,
                queue_lock
            )
            for category in CATEGORIES
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"分类URL获取线程出错: {e}")

    logger.info(f"\n共收集到 {len(url_queue)} 个URL待处理\n")

    # 第二步：多线程处理所有URL
    logger.info("===== 开始多线程处理URL =====")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as url_executor:
        pbar = tqdm(total=len(url_queue), desc="处理URL进度")

        def process_with_progress(item, category):
            # 将重试参数传递给处理函数
            process_url(
                item,
                category,
                processed_normalized_urls,
                processed_domains,
                processed_data,
                data_lock,
                MAX_IMAGE_RETRIES,
                INITIAL_RETRY_DELAY
            )
            pbar.update(1)

        futures = [
            url_executor.submit(process_with_progress, item, category)
            for item, category in url_queue
        ]

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"URL处理线程出错: {e}")

        pbar.close()

    # 后续处理
    logger.info("\n" + "=" * 60)
    logger.info(f"所有URL处理完成，共获取 {len(processed_data)} 条不重复数据")
    logger.info("=" * 60 + "\n")

    if processed_data:
        print("\n按分类统计:")
        category_counts = Counter(item.category for item in processed_data)
        for cat, count in category_counts.items():
            print(f"- {cat}: {count} 条")

        print("\n前5条数据示例:")
        for i, item in enumerate(processed_data[:5], 1):
            print(f"{i}. [{item.category}] {item.name}")
            print(f"   URL: {item.url}")
            print(f"   描述: {item.description}")
            print(f"   本地文件: {item.local_filename}\n")

        # 生成SQL文件
        sql_content = generate_sql_statements(processed_data)
        save_file(sql_content, SQL_OUTPUT_FILE)

        print(f"\nSQL导入文件已生成: {SQL_OUTPUT_FILE}")
        print(f"包含 {len(sql_content.split('INSERT')) - 1} 条INSERT语句")
    else:
        logger.warning("未处理任何数据")

    logger.info("\n" + "=" * 60)
    logger.info("mTab多分类网站书签导出工具执行完成")
    logger.info("=" * 60 + "\n")


# ============================== URL解析工具函数 ==============================
def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


# 增强白名单检测逻辑，确保白名单域名能被正确识别
def is_domain_whitelisted(url: str) -> bool:
    # 解析URL获取域名组件
    ext = extract(url)
    domain_parts = [part for part in [ext.subdomain, ext.domain, ext.suffix] if part]
    full_domain = ".".join(domain_parts)

    # 1. 检查完整域名是否在白名单（如 yiyan.baidu.com）
    if full_domain in DOMAIN_WHITELIST:
        return True

    # 2. 检查主域名是否在白名单
    if ext.registered_domain in DOMAIN_WHITELIST:
        return True

    # 3. 检查所有可能的父域名
    for i in range(1, len(domain_parts)):
        parent_domain = ".".join(domain_parts[i:])
        if parent_domain in DOMAIN_WHITELIST:
            return True

    return False


# 优化黑名单检查函数
def is_domain_blocked(url: str) -> bool:
    domain = extract_domain(url)

    # 检查完整域名是否在黑名单
    if domain in DOMAIN_BLACKLIST:
        return True

    # 检查任何父域名是否在黑名单
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in DOMAIN_BLACKLIST:
            return True

    return False


# 优化URL可接受性检查函数
def is_url_acceptable(url: str) -> Tuple[bool, str]:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    ext = extract(domain)
    subdomain = ext.subdomain.lower()

    # 1. 黑名单检查（最高优先级）
    if is_domain_blocked(url):
        return False, f"URL在黑名单中: {domain}"

    # 2. 白名单检查（次高优先级）
    if is_domain_whitelisted(url):
        return True, f"白名单域名，跳过子域名检查: {domain}"

    # 3. 子域名检查（最低优先级）
    if subdomain in ALLOWED_SUBDOMAINS:
        return True, f"允许的子域名: {subdomain}.{ext.domain}.{ext.suffix}"

    if not subdomain:
        return True, f"标准主域名: {domain}"

    return False, f"不符合处理条件的URL (子域名不允许: {subdomain})"


# ============================== 文本验证与处理函数 ==============================
def is_valid_text(text: str) -> bool:
    if not text:
        return False

    text = text.strip()
    if not text:
        return False

    text_clean = re.sub(r'[\x00-\x1F\x7F]', '', text)

    valid_chars = re.findall(
        r'[\u4e00-\u9fa5a-zA-Z0-9，。,.;:!?()（）《》“”‘’\s]',
        text_clean
    )

    valid_ratio = len(valid_chars) / len(text_clean) if len(text_clean) > 0 else 0
    return valid_ratio > 0.7


def is_description_invalid(desc: str) -> bool:
    if not desc:
        return True

    desc = desc.strip().lower()

    if desc in ['none', '暂无描述', '无描述', 'null']:
        return True

    return not is_valid_text(desc)


def clean_api_description(desc: str) -> Optional[str]:
    desc = desc.strip().replace('\n', '').replace('\r', '')
    if not desc:
        return None

    has_chinese = re.search(r'[\u4e00-\u9fa5]', desc)
    if has_chinese:
        punctuation_map = {
            '.': '。', ',': '，', ';': '；', ':': '：',
            '!': '！', '?': '？', '(': '（', ')': '）',
            '<': '《', '>': '》', '"': '“', "'": '‘'
        }
        for en_punc, zh_punc in punctuation_map.items():
            desc = desc.replace(en_punc, zh_punc)

    for punct in ['。', '.']:
        if punct in desc:
            parts = desc.split(punct, 1)
            if parts[0].strip():
                return f"{parts[0].strip()}{punct}"
            else:
                return clean_api_description(parts[1]) if len(parts) > 1 else desc

    return desc


# ============================== URL处理函数 ==============================
def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    if not url.startswith(('http://', 'https://')):
        return None, "URL缺少协议前缀"

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')

    if not base_url.endswith('/'):
        base_url += '/'

    if not validators.url(base_url.rstrip('/')):
        return None, "URL格式无效"

    return base_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    try:
        if url.startswith('http://'):
            url = url.replace('http://', 'https://')

        is_acceptable, reason = is_url_acceptable(url)
        if not is_acceptable:
            return False, f"URL不符合处理条件: {reason}", url, None

        processed_url, error = validate_and_process_url(url)
        if not processed_url:
            return False, f"URL格式验证失败: {error}", url, None

        normalized = normalize_url(processed_url)
        return True, None, processed_url, normalized

    except Exception as e:
        normalized = normalize_url(url)
        return False, f"URL处理异常: {str(e)[:20]}", url, normalized


# ============================== API请求函数 ==============================
def fetch_api(api, url: str) -> Optional[str]:
    try:
        encoded_url = quote(url)
        api_url = api['url_template'].format(encoded_url)

        response = requests.get(
            api_url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=False
        )
        response.raise_for_status()
        data = response.json()

        return api['parse_func'](data)

    except Exception as e:
        return None


def fetch_website_description(url: str) -> Optional[str]:
    if not url:
        return None

    invalid_descriptions = {
        "未找到描述", "null"
    }

    api_list = [
        {
            "name": "geeker",
            "url_template": "https://geeker.moe/tdk.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 1
                    and desc.strip()
                    and desc not in invalid_descriptions
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "shanhe",
            "url_template": "https://shanhe.kim/api/wz/web_tdk.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 1
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "suol",
            "url_template": "https://api.suol.cc/v1/zs_wzxx.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 1
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "ahfi",
            "url_template": "https://api.ahfi.cn/api/websiteinfo?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', {}).get('description', ''))
                    and desc.strip()
                    and desc not in invalid_descriptions
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "yilianshuju",
            "url_template": "https://www.yilianshuju.com/api/?id=17&key=4ln9pr1ur5nlzgssaipcxdkacx7&url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', {}).get('description', ''))
                    and data.get('code') == 200
                    and desc.strip()
                    and desc not in invalid_descriptions
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "qlwc",
            "url_template": "https://api.qlwc.cn/api/tdk?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 200
                    and desc.strip()
                    and desc not in invalid_descriptions
                    and is_valid_text(desc)
            else None
        },
        {
            "name": "xxapi",
            "url_template": "https://v2.xxapi.cn/api/title?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', ''))
                    and is_valid_text(desc)
            else None
        }
    ]

    for api in api_list:
        try:
            website_desc = fetch_api(api, url)
            if website_desc:
                website_desc = website_desc.strip().replace('\n', ' ').replace('\r', ' ')
                if website_desc:
                    return website_desc
        except Exception as e:
            continue

    return None


def clean_description(url: str, original_desc: str = "") -> Optional[str]:
    # 优先使用API获取描述
    api_desc = fetch_website_description(url)
    if api_desc:
        cleaned_api_desc = clean_api_description(api_desc)
        if cleaned_api_desc:
            return cleaned_api_desc

    # API获取失败，检查URL是否在白名单或使用允许的子域名
    is_acceptable, _ = is_url_acceptable(url)
    if not is_acceptable:
        logger.warning(f"API获取描述失败且URL不在白名单/允许的子域名中，丢弃URL: {url}")
        return None

    # 在白名单或允许的子域名中，检查原始描述是否有效
    if not is_description_invalid(original_desc):
        return clean_api_description(original_desc)

    # 白名单或允许的子域名但无有效原始描述
    logger.warning(f"API获取描述失败且无有效原始描述，丢弃URL: {url}")
    return None


# ============================== 图像处理函数 ==============================
def compress_svg(svg_content: str) -> str:
    try:
        svg_content = re.sub(r'<!--.*?-->', '', svg_content, flags=re.DOTALL)
        lines = []
        for line in svg_content.split('\n'):
            line = line.strip()
            if line:
                lines.append(' '.join(line.split()))
        return ''.join(lines)
    except Exception as e:
        logger.error(f"SVG压缩失败: {e}")
        return svg_content


def image_to_svg(img_response: requests.Response) -> str:
    try:
        img = Image.open(io.BytesIO(img_response.content))
        img_base64 = b64encode(img_response.content).decode('utf-8')

        svg_template = """<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">
            <image href="data:image/{};base64,{}" width="{}" height="{}" preserveAspectRatio="xMidYMid meet"/>
        </svg>"""

        content_type = img_response.headers.get('Content-Type', 'png')
        img_format = content_type.split('/')[-1].lower()
        if img_format not in ['png', 'jpeg', 'jpg', 'gif']:
            img_format = 'png'

        svg_content = svg_template.format(
            img.width, img.height, img_format, img_base64, img.width, img.height
        )

        return compress_svg(svg_content)
    except Exception as e:
        logger.error(f"图片转换失败: {e}")
        raise ValueError(f"图片转换失败: {e}")


def validate_svg(svg_content: str) -> bool:
    return all(tag in svg_content for tag in ['<svg', '</svg>', '<image'])


def download_and_save_image(img_src: str, filename: str, max_retries: int, initial_delay: int) -> Tuple[bool, str]:
    """下载并保存图片，支持自动重试"""
    for attempt in range(1, max_retries + 1):
        try:
            if img_src.startswith('http://'):
                img_src = img_src.replace('http://', 'https://')

            # 记录图片下载尝试
            if attempt > 1:
                logger.info(f"重试下载图片 (尝试 {attempt}/{max_retries}): {img_src}")
            else:
                logger.info(f"开始下载图片: {img_src}")

            img_response = requests.get(
                img_src,
                headers=HTTP_CONFIG['headers'],
                timeout=HTTP_CONFIG['timeout'],
                allow_redirects=False
            )
            img_response.raise_for_status()

            file_path = os.path.join(ICON_DIRECTORY, filename)

            if img_src.lower().endswith('.svg'):
                svg_content = compress_svg(img_response.text)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
                logger.info(f"SVG图片保存成功: {filename}")
                return True, "SVG已压缩保存"
            else:
                svg_content = image_to_svg(img_response)
                if validate_svg(svg_content):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(svg_content)
                    logger.info(f"图片转换并保存为SVG: {filename}")
                    return True, "已转换为SVG"
                else:
                    logger.warning(f"生成的SVG文件无效: {filename}")
                    if attempt == max_retries:
                        return False, "生成的SVG文件无效"
                    else:
                        # 无效SVG也进行重试
                        time.sleep(initial_delay * attempt)
                        continue

        except Exception as e:
            error_msg = f"图片下载失败 (尝试 {attempt}/{max_retries}) {img_src}: {str(e)}"
            logger.warning(error_msg)

            # 如果不是最后一次尝试，等待后重试
            if attempt < max_retries:
                delay = initial_delay * attempt  # 指数退避策略
                time.sleep(delay)

    # 所有重试都失败
    return False, f"超过最大重试次数 ({max_retries}次)"


# ============================== 文件操作函数 ==============================
def clear_directory(directory: str) -> None:
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.error(f"无法删除 {file_path}: {e}")
    else:
        os.makedirs(directory)
        logger.info(f"创建图标存储目录: {directory}")


def save_file(content: str, file_path: str) -> None:
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        logger.error(f"保存文件失败: {file_path}, 错误: {e}")


# ============================== 数据处理辅助函数 ==============================
def generate_filename(
        url: str,
        processed_domains: Dict[str, Dict[str, str]],
        processed_data: List[WebsiteData],
        lock: threading.Lock
) -> Tuple[Optional[str], Optional[str]]:
    url_without_slash = url.rstrip('/')
    ext = extract(url_without_slash)

    subdomain = ext.subdomain.lower()
    main_domain = ext.domain.lower()
    suffix = ext.suffix.lower()

    is_www = subdomain == "www"
    is_allowed_subdomain = subdomain in ALLOWED_SUBDOMAINS
    is_main_domain = subdomain in ("", "www")

    base_key = main_domain if is_main_domain else f"{subdomain}-{main_domain}"

    with lock:
        if is_main_domain:
            if base_key in processed_domains:
                existing = processed_domains[base_key]

                if existing.get("is_www", False) and not is_www:
                    return None, f"主域名{main_domain}已存在www前缀版本，当前域名被丢弃"

                if existing["suffix"] == suffix:
                    return existing["filename"], None

                old_filename = existing["filename"]
                old_suffix = existing["suffix"]
                new_existing_filename = f"{main_domain}-{old_suffix}.svg"

                try:
                    old_path = os.path.join(ICON_DIRECTORY, old_filename)
                    new_path = os.path.join(ICON_DIRECTORY, new_existing_filename)
                    os.rename(old_path, new_path)
                except Exception as e:
                    logger.error(f"重命名文件失败: {old_filename} → {new_existing_filename}, 错误: {e}")
                    return None, "文件重命名失败"

                for item in processed_data:
                    if item.local_filename == old_filename:
                        item.local_filename = new_existing_filename
                        break

                existing["filename"] = new_existing_filename
                existing["suffix"] = old_suffix

                new_filename = f"{main_domain}-{suffix}.svg"
                processed_domains[base_key] = {
                    "filename": new_filename,
                    "suffix": suffix,
                    "is_www": is_www,
                    "base_key": base_key
                }
                return new_filename, f"主域名相同但后缀不同，新文件名为{new_filename}"

            filename = f"{main_domain}.svg"
            processed_domains[base_key] = {
                "filename": filename,
                "suffix": suffix,
                "is_www": is_www,
                "base_key": base_key
            }
            return filename, f"首次处理主域名，文件名为{filename}"

        elif is_allowed_subdomain:
            if base_key in processed_domains:
                existing = processed_domains[base_key]

                if existing["suffix"] == suffix:
                    return existing["filename"], None

                new_filename = f"{subdomain}-{main_domain}-{suffix}.svg"
                processed_domains[base_key] = {
                    "filename": new_filename,
                    "suffix": suffix,
                    "is_www": False,
                    "base_key": base_key
                }
                return new_filename, f"允许的子域名，前缀相同但后缀不同，文件名为{new_filename}"

            filename = f"{subdomain}-{main_domain}.svg"
            processed_domains[base_key] = {
                "filename": filename,
                "suffix": suffix,
                "is_www": False,
                "base_key": base_key
            }
            return filename, f"首次处理允许的子域名 {subdomain}，文件名为{filename}"

        else:
            # 白名单域名即使子域名不在允许列表也应通过
            if is_domain_whitelisted(url):
                filename = f"{subdomain}-{main_domain}.svg"
                processed_domains[base_key] = {
                    "filename": filename,
                    "suffix": suffix,
                    "is_www": False,
                    "base_key": base_key
                }
                return filename, f"白名单域名，特殊处理子域名 {subdomain}，文件名为{filename}"
            return None, f"不允许的子域名 {subdomain}，URL被丢弃"


def expand_color_format(color: str) -> str:
    if not color:
        return ''

    if not color.startswith('#'):
        return color

    color = color.lstrip('#')
    if len(color) == 3:
        return f"#{color[0]}{color[0]}{color[1]}{color[1]}{color[2]}{color[2]}"
    elif len(color) == 6:
        return f"#{color}"
    else:
        return color


# ============================== 分类与URL处理函数 ==============================
def process_url(
        item,
        category,
        processed_normalized_urls,
        processed_domains,
        processed_data,
        lock,
        max_image_retries: int,
        initial_retry_delay: int
):
    name = item.get('name', '').strip()
    if not name:
        logger.warning("丢弃name为空的条目")
        return

    url = item.get('url', '')
    img_src = item.get('imgSrc', '')
    background_color = item.get('backgroundColor', '')
    original_description = item.get('description', '')

    accessible, error, final_url, normalized_url = check_url_accessibility(url)
    if not accessible:
        logger.warning(f"不可处理URL: {url} - {error}")
        return

    if not normalized_url:
        logger.warning(f"无法标准化URL: {final_url}")
        return

    with lock:
        if normalized_url in processed_normalized_urls:
            return  # 简化重复URL的提示

    clean_desc = clean_description(final_url, original_description)
    if not clean_desc:
        return

    expanded_color = expand_color_format(background_color)

    filename, conflict_msg = generate_filename(final_url, processed_domains, processed_data, lock)

    if filename is None:
        logger.info(f"URL被丢弃: {final_url} - {conflict_msg}")
        return

    # 尝试下载图片，带重试机制
    success, status = download_and_save_image(
        img_src,
        filename,
        max_image_retries,
        initial_retry_delay
    )
    if not success:
        logger.warning(f"图片最终下载失败，丢弃条目: {url} - {status}")
        return

    with lock:
        processed_normalized_urls.add(normalized_url)
        domain = extract(final_url.rstrip('/'))
        processed_domains[domain.domain] = {
            'suffix': domain.suffix,
            'filename': filename
        }
        processed_data.append(WebsiteData(
            name=name,
            url=final_url,
            description=clean_desc,
            img_src=img_src,
            local_filename=filename,
            category=category,
            background_color=expanded_color
        ))


def process_category(category, url_queue, lock):
    logger.info(f"开始获取分类[{category}]的URL")
    base_url = 'https://api.codelife.cc/website/list'
    lang = 'zh'
    name = ''
    source = 'itab'
    page = 1

    while True:
        full_url = f"{base_url}?lang={lang}&type={category}&page={page}&name={name}&source={source}"
        try:
            response = requests.get(
                full_url,
                headers=HTTP_CONFIG['headers'],
                timeout=HTTP_CONFIG['timeout'],
                allow_redirects=False
            )
            response.raise_for_status()
            data = response.json()

            if not data.get('data', []):
                logger.info(f"分类[{category}]的URL获取完成")
                break

            with lock:
                for item in data['data']:
                    if item.get('url', '').startswith('http://'):
                        item['url'] = item['url'].replace('http://', 'https://')
                    url_queue.append((item, category))

            page += 1
            time.sleep(1 + random.uniform(0, 1))

        except Exception as e:
            logger.error(f"分类[{category}]第{page}页URL获取失败: {e}")
            page += 1
            time.sleep(2 + random.uniform(0, 1))


def generate_sql_statements(websites: List[WebsiteData]) -> str:
    sql_statements = []
    seen_normalized_urls = set()

    for site in websites:
        normalized = normalize_url(site.url)

        if normalized in seen_normalized_urls:
            logger.warning(f"生成SQL时发现重复URL，已跳过: {site.url}")
            continue

        seen_normalized_urls.add(normalized)

        escaped_name = site.name.replace("'", "''")
        escaped_description = site.description.replace("'", "''")

        domain_parts = extract(site.url.rstrip('/'))
        if domain_parts.subdomain:
            domain = f"{domain_parts.subdomain}.{domain_parts.registered_domain}"
        else:
            domain = domain_parts.registered_domain

        category_id = CATEGORY_IDS.get(site.category, 15)

        sql = (
            f"INSERT INTO `mtab`.`linkstore` "
            f"(`name`, `src`, `url`, `type`, `size`, `create_time`, `hot`, `area`, `tips`, `domain`, "
            f"`app`, `install_num`, `bgColor`, `vip`, `custom`, `user_id`, `status`, `group_ids`) "
            f"VALUES "
            f"('{escaped_name}', 'https://oss.amogu.cn/icon/website/{site.local_filename}', '{site.url}', "
            f"'icon', '1x1', '2025-01-01 00:00:00', 0, {category_id}, '{escaped_description}', '{domain}', "
            f"0, 0, '{site.background_color}', 0, NULL, NULL, 1, 0);"
        )

        sql_statements.append(sql)

    return "\n".join(sql_statements)


if __name__ == "__main__":
    main()
