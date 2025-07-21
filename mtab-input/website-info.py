#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/22
# @Desc  : mTab多分类网站书签导出工具（带全局API并发控制）


# ============================== 配置参数区 ==============================
# 请在此处修改配置参数

# 线程数量配置
MAX_WORKERS = 5  # 并发处理URL的线程数量
GLOBAL_API_CONCURRENT = 3  # 所有API的总并发数限制
API_REQUEST_INTERVAL = 1  # API请求之间的最小间隔时间(秒)

# 需要处理的分类列表
CATEGORIES = ["ai"]  # 可添加更多分类，如["ai", "tech", "news", "music"]

# 分类ID映射表，用于SQL生成
CATEGORY_IDS = {
    "ai": 1, "app": 2, "news": 3, "music": 4,
    "tech": 5, "photos": 6, "life": 7, "education": 8,
    "entertainment": 9, "shopping": 10, "social": 11, "read": 12,
    "sports": 13, "finance": 14, "others": 15
}

# 需要过滤的域名列表，包含这些域名的URL将被直接丢弃
BLOCKED_DOMAINS = {
    # 示例域名，可根据需要修改
    "trae.ai",
    "trae.cn"
}

# HTTP请求配置
HTTP_CONFIG = {
    'timeout': 20,  # 请求超时时间(秒)
    'max_redirects': 10,  # 最大跳转次数
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
import asyncio
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
from urllib.parse import urljoin, quote, urlparse

import aiohttp
import requests
import validators
from PIL import Image
from tldextract import extract
from tqdm import tqdm


# 数据结构定义
@dataclass
class WebsiteData:
    """网站数据结构，存储从API获取的各类网站信息"""
    name: str
    url: str
    description: str
    img_src: str
    local_filename: str
    category: str
    background_color: str


# 跳转模式正则表达式
JS_REDIRECT_PATTERNS = [
    r"location\s*=\s*[\"'](.*?)[\"']",
    r"window\.location\s*=\s*[\"'](.*?)[\"']",
    r"location\.href\s*=\s*[\"'](.*?)[\"']",
    r"window\.location\.href\s*=\s*[\"'](.*?)[\"']",
    r"location\.assign\s*\(\s*[\"'](.*?)[\"']\s*\)",
    r"window\.location\.assign\s*\(\s*[\"'](.*?)[\"']\s*\)",
    r"location\.replace\s*\(\s*[\"'](.*?)[\"']\s*\)",
    r"window\.location\.replace\s*\(\s*[\"'](.*?)[\"']\s*\)",
    r"setTimeout\s*\(\s*function\s*\(\)\s*\{\s*location(?:\.href)?\s*=\s*[\"'](.*?)[\"']\s*\}\s*,\s*\d+\s*\)",
]

META_REDIRECT_PATTERN = r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\d+;url=(.*?)["\']'


# 日志配置
def setup_logger() -> logging.Logger:
    """配置并并返回日志记录器，统一日志格式"""
    logger = logging.getLogger('mtab_exporter')
    logger.setLevel(logging.INFO)

    # 控制台处理器
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # 日志格式：时间 - 级别 - 线程ID - 消息
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - 线程%(thread)d - %(message)s')
    ch.setFormatter(formatter)

    # 清除现有处理器
    if logger.handlers:
        logger.handlers = []
    logger.addHandler(ch)

    return logger


# 初始化日志
logger = setup_logger()


# 全局API并发控制 - 创建跨线程共享的信号量和计时器
class GlobalAPIConfig:
    """全局API配置管理，确保所有API请求共享同一的并发控制和计时器"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    # 初始化全局信号量和最后请求时间
                    cls._instance.semaphore = asyncio.Semaphore(GLOBAL_API_CONCURRENT)
                    cls._instance.last_request_time = time.time() - API_REQUEST_INTERVAL
                    # 线程锁，确保对last_request_time的操作线程安全
                    cls._instance.time_lock = threading.Lock()
        return cls._instance

    def get_semaphore(self):
        """获取全局的信号量实例"""
        return self.semaphore

    def get_last_request_time(self):
        """获取上次请求时间（线程安全）"""
        with self.time_lock:
            return self.last_request_time

    def update_last_request_time(self, new_time):
        """更新上次请求时间（线程安全）"""
        with self.time_lock:
            self.last_request_time = new_time


# URL解析工具函数
def get_main_domain(url: str) -> str:
    """提取URL的主域名（协议+域名）"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_url(url: str) -> str:
    """标准化URL，用于比较和检测循环"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')


def extract_domain(url: str) -> str:
    """提取URL的域名（不含协议）用于过滤检查"""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def is_domain_blocked(url: str) -> bool:
    """检查URL的域名是否在过滤列表中"""
    domain = extract_domain(url)
    # 检查完整域名是否被阻止
    if domain in BLOCKED_DOMAINS:
        return True

    # 检查父域名是否被阻止（例如sub.example.com会检查example.com）
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in BLOCKED_DOMAINS:
            return True

    return False


def extract_js_redirects(html_content: str, current_url: str) -> list:
    """提取HTML中的JavaScript跳转链接"""
    redirect_urls = []
    cleaned_html = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)

    for pattern in JS_REDIRECT_PATTERNS:
        matches = re.finditer(pattern, cleaned_html, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if match.group(1):
                raw_url = match.group(1).strip()

                # 处理相对路径
                if raw_url.startswith('//'):
                    parsed_current = urlparse(current_url)
                    raw_url = f"{parsed_current.scheme}:{raw_url}"
                elif not raw_url.startswith(('http://', 'https://')):
                    parsed_raw = urlparse(raw_url)
                    if parsed_raw.path.startswith('/'):
                        parsed_current = urlparse(current_url)
                        raw_url = f"{parsed_current.scheme}://{parsed_current.netloc}{raw_url}"

                full_url = urljoin(current_url, raw_url)
                redirect_urls.append(full_url)

    # 去重
    return list(set(redirect_urls))


def extract_meta_redirect(html_content: str, current_url: str) -> str:
    """提取HTML中的Meta标签跳转链接"""
    match = re.search(META_REDIRECT_PATTERN, html_content, re.IGNORECASE | re.DOTALL)
    if match:
        redirect_url = match.group(1).strip()
        # 处理可能的引号
        redirect_url = re.sub(r'^["\'](.*?)["\']$', r'\1', redirect_url)
        return urljoin(current_url, redirect_url)
    return None


def follow_redirects(url: str, max_redirects: int = 10, history: list = None) -> tuple:
    """跟踪URL跳转，处理循环跳转和最大跳转次数限制"""
    if history is None:
        history = []

    # 检查最大跳转次数
    if len(history) >= max_redirects:
        last_url = history[-1] if history else url
        last_domain = get_main_domain(last_url)
        logger.info(f"达到最大跳转次数，返回最后URL的主域名: {last_domain}")
        return last_domain, "达到最大跳转次数", history

    # 检查循环跳转
    normalized_url = normalize_url(url)
    for idx, h in enumerate(history):
        if normalize_url(h) == normalized_url:
            # 提取循环中的URL并返回最后一个的主域名
            loop_urls = history[idx:] + [url]
            last_loop_url = loop_urls[-1]
            last_loop_domain = get_main_domain(last_loop_url)

            logger.info(f"检测到循环跳转，返回循环中最后的主域名: {last_loop_domain}")
            return last_loop_domain, "检测到循环跳转", history + [url]

    history.append(url)
    logger.debug(f"正在处理跳转: {url}")

    try:
        # 发送请求
        session = requests.Session()
        session.max_redirects = max_redirects - len(history)

        response = session.get(
            url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=True
        )

        final_http_url = response.url

        # 记录HTTP重定向历史
        if response.history:
            for resp in response.history:
                if resp.url not in history:
                    history.append(resp.url)
            logger.debug(f"HTTP重定向到: {final_http_url}")

        # 检查meta标签跳转
        meta_redirect = extract_meta_redirect(response.text, final_http_url)
        if meta_redirect:
            return follow_redirects(meta_redirect, max_redirects, history)

        # 检查JavaScript跳转
        js_redirects = extract_js_redirects(response.text, final_http_url)
        if js_redirects:
            return follow_redirects(js_redirects[0], max_redirects, history)

        # 没有更多跳转，返回当前URL的主域名
        current_domain = get_main_domain(final_http_url)
        return current_domain, "成功获取最终主域名", history

    except requests.RequestException as e:
        # 所有请求错误直接丢弃，返回None
        logger.warning(f"访问错误，丢弃该URL: {str(e)}")
        return None, f"访问错误: {str(e)}", history


# 文本验证与处理函数
def is_valid_text(text: str) -> bool:
    """检查文本是否有效，过滤乱码（包括无效Unicode和控制字符）"""
    if not text:
        return False

    text = text.strip()
    if not text:
        return False

    # 移除所有控制字符（ASCII 0-31和127）
    text_clean = re.sub(r'[\x00-\x1F\x7F]', '', text)

    # 匹配中文字符、英文字母、数字和常见标点
    valid_chars = re.findall(
        r'[\u4e00-\u9fa5'  # 中文
        r'a-zA-Z0-9'  # 英文和数字
        r'，。,.;:!?()（）《》“”‘’'  # 常见标点
        r'\s'  # 空白字符
        r']',
        text_clean
    )

    # 计算有效字符比例，低于70%视为乱码
    valid_ratio = len(valid_chars) / len(text_clean) if len(text_clean) > 0 else 0
    return valid_ratio > 0.7


def is_description_invalid(desc: str) -> bool:
    """检查描述是否无效（空值、默认值或无效文本）"""
    if not desc:
        return True

    desc = desc.strip().lower()

    # 检查默认无效值
    if desc in ['none', '暂无描述', '无描述', 'null']:
        return True

    # 结合is_valid_text函数检查文本有效性（过滤乱码）
    if not is_valid_text(desc):
        return True

    return False


def clean_api_description(desc: str) -> Optional[str]:
    """清理API返回的描述，移除多余空白并截断过长描述（仅保留第一个.或。前的内容）"""
    desc = desc.strip().replace('\n', '').replace('\r', '')
    if not desc:
        return None

    # 判断描述中是否有中文，若有则将英文标点替换为中文标点
    has_chinese = re.search(r'[\u4e00-\u9fa5]', desc)
    if has_chinese:
        # 替换常见英文标点为中文标点
        punctuation_map = {
            '.': '。',
            ',': '，',
            ';': '；',
            ':': '：',
            '!': '！',
            '?': '？',
            '(': '（',
            ')': '）',
            '<': '《',
            '>': '》',
            '"': '“',
            "'": '‘'
        }
        for en_punc, zh_punc in punctuation_map.items():
            desc = desc.replace(en_punc, zh_punc)

    # 截取第一个.或。前的内容（核心优化点）
    # 优先检查中文句号，再检查英文句号
    for punct in ['。', '.']:
        if punct in desc:
            # 分割后取第一个部分，加上标点，确保只保留到第一个标点
            parts = desc.split(punct, 1)  # 只分割一次
            if parts[0].strip():  # 确保分割后内容不为空
                return f"{parts[0].strip()}{punct}"
            else:
                # 若分割后前半部分为空，取后半部分的第一个标点前内容（避免空描述）
                return clean_api_description(parts[1]) if len(parts) > 1 else desc

    # 若没有标点，返回完整描述（或可添加长度限制，如return desc[:100]）
    return desc


# URL处理函数
def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """验证并处理URL，确保其格式正确"""
    if not url.startswith(('http://', 'https://')):
        return None, "URL缺少协议前缀"

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 优先使用HTTPS
    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')

    # 统一URL格式，确保以斜杠结尾
    if not base_url.endswith('/'):
        base_url += '/'

    # 验证URL有效性
    if not validators.url(base_url.rstrip('/')):
        return None, "URL格式无效"

    return base_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """检查URL的可访问性，返回检查结果、最终URL和标准化URL"""
    try:
        # 首先检查域名是否在过滤列表中
        if is_domain_blocked(url):
            return False, "URL域名在过滤列表中", url, None

        # 使用完善的跳转跟踪逻辑获取最终URL
        final_domain, message, history = follow_redirects(
            url,
            max_redirects=HTTP_CONFIG['max_redirects']
        )

        if not final_domain:
            return False, f"获取最终URL失败: {message}", url, None

        # 检查最终域名是否在过滤列表中
        if is_domain_blocked(final_domain):
            return False, "最终URL域名在过滤列表中", final_domain, None

        # 对最终域名再次验证处理
        final_base_url, error = validate_and_process_url(final_domain)
        if not final_base_url:
            return False, f"处理最终URL失败: {error}", url, None

        # 生成标准化URL用于去重
        normalized = normalize_url(final_base_url)

        # 检查最终URL的可访问性
        response = requests.head(
            final_base_url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=True
        )

        if response.status_code >= 400:
            return False, f"URL不可访问({response.status_code})", final_base_url, normalized

        logger.debug(
            f"URL处理成功: {url} → {final_domain} (跳转次数: {len(history)})"
        )
        return True, None, final_base_url, normalized

    except requests.RequestException as e:
        normalized = normalize_url(url)
        return False, f"URL检查失败({str(e)[:20]})", url, normalized
    except Exception as e:
        normalized = normalize_url(url)
        return False, f"URL处理异常: {str(e)[:20]}", url, normalized


# API请求函数
async def fetch_api(session, api_url: str, api: dict) -> tuple:
    """异步请求单个API获取网站描述，使用全局共享的并发控制"""
    # 获取全局API配置
    global_api = GlobalAPIConfig()
    semaphore = global_api.get_semaphore()

    # 使用全局信号量控制所有API的总并发数
    async with semaphore:
        # 控制请求间隔，确保不超过频率限制
        current_time = time.time()
        last_time = global_api.get_last_request_time()
        elapsed = current_time - last_time

        if elapsed < API_REQUEST_INTERVAL:
            wait_time = API_REQUEST_INTERVAL - elapsed
            await asyncio.sleep(wait_time)
            current_time += wait_time

        # 更新全局最后请求时间
        global_api.update_last_request_time(current_time)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # 随重试次数增加超时时间
                timeout = aiohttp.ClientTimeout(total=HTTP_CONFIG['timeout'] * (attempt + 1))

                async with session.get(api_url, timeout=timeout) as response:
                    response.raise_for_status()
                    data = await response.json()
                    website_desc = api['parse_func'](data)
                    return api['name'], website_desc

            except asyncio.TimeoutError:
                if attempt == max_retries - 1:
                    return api['name'], None
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.debug(f"API请求失败: {str(e)}")
                    return api['name'], None

        return api['name'], None


async def fetch_website_description(url: str) -> Optional[str]:
    """异步获取网站描述，尝试多个API，使用全局并发控制"""
    if not url:
        return None

    # 无效描述列表，用于在API解析时直接过滤
    invalid_descriptions = {
        "本站是一个互联网官网",
        "未找到描述",
        "/index.html",
        "/index.",
        "null"
    }

    # API列表，包含API名称、URL模板和解析函数
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
            else ''
        },
        {
            "name": "shanhe",
            "url_template": "https://shanhe.kim/api/wz/web_tdk.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 1
                    and is_valid_text(desc)
            else ''
        },
        {
            "name": "suol",
            "url_template": "https://api.suol.cc/v1/zs_wzxx.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('description', ''))
                    and data.get('code') == 1
                    and is_valid_text(desc)
            else ''
        },
        {
            "name": "ahfi",
            "url_template": "https://api.ahfi.cn/api/websiteinfo?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', {}).get('description', ''))
                    and desc.strip()
                    and desc not in invalid_descriptions
                    and is_valid_text(desc)
            else ''
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
            else ''
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
            else ''
        },
        {
            "name": "xxapi",
            "url_template": "https://v2.xxapi.cn/api/title?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', ''))
                    and is_valid_text(desc)
            else ''
        }
    ]

    async with aiohttp.ClientSession(headers=HTTP_CONFIG['headers']) as session:
        tasks = []
        for api in api_list:
            encoded_url = quote(url)
            api_url = api['url_template'].format(encoded_url)
            tasks.append(fetch_api(session, api_url, api))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 检查结果，返回第一个有效的描述
        for result in results:
            if isinstance(result, Exception):
                continue

            api_name, website_desc = result
            if website_desc:
                website_desc = website_desc.strip().replace('\n', ' ').replace('\r', ' ')
                if website_desc:
                    return website_desc

        return None


def fetch_website_description_sync(url: str) -> Optional[str]:
    """同步调用异步函数获取网站描述，修复多线程问题"""
    try:
        # 为每个线程创建独立的事件循环，解决多线程问题
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(fetch_website_description(url))
        loop.close()  # 确保循环关闭，释放资源
        return result
    except Exception as e:
        # 提高日志级别，便于调试多线程问题
        logger.error(f"获取网站描述失败: {str(e)}，URL: {url}")
        return None


def clean_description(url: str, original_desc: str = "") -> Optional[str]:
    """获取并清理网站描述，优先使用API获取，其次使用原始描述"""
    # 尝试从API获取描述
    api_desc = fetch_website_description_sync(url)
    if api_desc:
        cleaned_api_desc = clean_api_description(api_desc)
        if cleaned_api_desc:
            return cleaned_api_desc

    # 检查原始描述是否有效
    if not is_description_invalid(original_desc):
        return clean_api_description(original_desc)  # 确保原始描述也经过截取处理

    logger.warning(f"无法为URL获取有效描述: {url}")
    return None


# 图像处理函数
def compress_svg(svg_content: str) -> str:
    """压缩SVG内容，移除注释和多余空白"""
    try:
        # 移除注释
        svg_content = re.sub(r'<!--.*?-->', '', svg_content, flags=re.DOTALL)
        lines = []
        for line in svg_content.split('\n'):
            line = line.strip()
            if line:
                # 合并多余空格
                lines.append(' '.join(line.split()))
        return ''.join(lines)
    except Exception as e:
        logger.error(f"SVG压缩失败: {e}")
        return svg_content


def image_to_svg(img_response: requests.Response) -> str:
    """将图片转换为SVG格式，嵌入base64编码的图片数据"""
    try:
        img = Image.open(io.BytesIO(img_response.content))
        img_base64 = b64encode(img_response.content).decode('utf-8')

        # SVG模板
        svg_template = """<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">
            <image href="data:image/{};base64,{}" width="{}" height="{}" preserveAspectRatio="xMidYMid meet"/>
        </svg>"""

        # 确定图片格式
        content_type = img_response.headers.get('Content-Type', 'png')
        img_format = content_type.split('/')[-1].lower()
        if img_format not in ['png', 'jpeg', 'jpg', 'gif']:
            img_format = 'png'

        # 填充模板
        svg_content = svg_template.format(
            img.width, img.height, img_format, img_base64, img.width, img.height
        )

        return compress_svg(svg_content)
    except Exception as e:
        logger.error(f"图片转换失败: {e}")
        raise ValueError(f"图片转换失败: {e}")


def validate_svg(svg_content: str) -> bool:
    """验证SVG内容是否有效"""
    return all(tag in svg_content for tag in ['<svg', '</svg>', '<image'])


def download_and_save_image(img_src: str, filename: str) -> Tuple[bool, str]:
    """下载图片并保存为SVG格式（直接保存或转换）"""
    try:
        img_response = requests.get(
            img_src,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout']
        )
        img_response.raise_for_status()

        file_path = os.path.join(ICON_DIRECTORY, filename)

        # 处理SVG文件
        if img_src.lower().endswith('.svg'):
            svg_content = compress_svg(img_response.text)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(svg_content)
            return True, "SVG已压缩保存"
        # 处理其他图片格式
        else:
            svg_content = image_to_svg(img_response)
            if validate_svg(svg_content):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
                return True, "已转换为SVG"
            else:
                return False, "生成的SVG文件无效"

    except Exception as e:
        return False, f"图片处理失败({str(e)})"


# 文件操作函数
def clear_directory(directory: str) -> None:
    """清空指定目录，如果目录不存在则创建"""
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
        logger.info(f"创建目录: {directory}")


def save_file(content: str, file_path: str) -> None:
    """将内容保存到指定文件"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        logger.error(f"保存文件失败: {file_path}, 错误: {e}")


# 数据处理辅助函数
def generate_filename(
        url: str,
        processed_domains: Dict[str, Dict[str, str]],
        processed_data: List[WebsiteData],
        lock: threading.Lock  # 添加锁参数确保线程安全
) -> Tuple[str, Optional[str]]:
    """生成唯一的文件名，处理可能的域名冲突"""
    url_without_slash = url.rstrip('/')
    ext = extract(url_without_slash)
    main_domain = ext.domain
    suffix = ext.suffix

    base_filename = f"{main_domain}.svg"
    suffix_filename = f"{main_domain}-{suffix}.svg"

    # 使用锁确保对共享数据的操作安全
    with lock:
        # 如果域名未处理过，直接使用基础文件名
        if main_domain not in processed_domains:
            return base_filename, None

        # 处理域名冲突
        existing_info = processed_domains[main_domain]
        existing_suffix = existing_info['suffix']
        existing_filename = existing_info['filename']
        existing_file_path = os.path.join(ICON_DIRECTORY, existing_filename)

        # 后缀相同，无需处理
        if existing_suffix == suffix:
            return base_filename, None

        # 重命名已存在的文件
        new_existing_filename = f"{main_domain}-{existing_suffix}.svg"

        try:
            os.rename(existing_file_path, os.path.join(ICON_DIRECTORY, new_existing_filename))
        except Exception as e:
            logger.error(
                f"文件重命名失败: {existing_filename} → {new_existing_filename}, 错误: {e}"
            )
            return suffix_filename, "文件重命名失败"

        # 更新已处理数据中的文件名
        for item in processed_data:
            if item.local_filename == existing_filename:
                item.local_filename = new_existing_filename
                break

        # 更新已处理域名信息
        processed_domains[main_domain]['filename'] = new_existing_filename

    return suffix_filename, "添加后缀区分"


def expand_color_format(color: str) -> str:
    """扩展颜色格式，将3位十六进制颜色转换为6位"""
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


# 主处理函数
def process_url(item, category, processed_normalized_urls, processed_domains, processed_data, lock):
    """处理单个URL的函数，可被多线程调用"""
    # 新增：丢弃name为空的条目（核心优化点）
    name = item.get('name', '').strip()
    if not name:
        logger.warning("丢弃name为空的条目")
        return

    url = item.get('url', '')
    img_src = item.get('imgSrc', '')
    background_color = item.get('backgroundColor', '')
    original_description = item.get('description', '')

    # 检查URL可访问性
    accessible, error, final_url, normalized_url = check_url_accessibility(url)
    if not accessible:
        logger.warning(f"不可访问URL: {url} - {error}")
        return

    if not normalized_url:
        logger.warning(f"无法标准化URL: {final_url}")
        return

    # 检查重复URL
    with lock:
        if normalized_url in processed_normalized_urls:
            logger.debug(f"发现重复URL（标准化后）: {final_url}")
            return

    # 获取清理后的描述
    clean_desc = clean_description(final_url, original_description)
    if not clean_desc:
        return

    # 处理颜色格式
    expanded_color = expand_color_format(background_color)

    # 生成文件名
    filename, conflict_msg = generate_filename(final_url, processed_domains, processed_data, lock)

    # 下载并保存图片
    success, status = download_and_save_image(img_src, filename)
    if not success:
        logger.warning(f"图片处理失败: {img_src}, 状态: {status}")
        return

    # 更新共享数据结构
    with lock:
        processed_normalized_urls.add(normalized_url)
        domain = extract(final_url.rstrip('/'))
        processed_domains[domain.domain] = {
            'suffix': domain.suffix,
            'filename': filename
        }
        processed_data.append(WebsiteData(
            name=name,  # 使用已验证非空的name
            url=final_url,
            description=clean_desc,
            img_src=img_src,
            local_filename=filename,
            category=category,
            background_color=expanded_color
        ))


def process_category(category, url_queue, lock):
    """仅负责获取分类下的URL并加入任务队列，不处理具体URL"""
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
                timeout=HTTP_CONFIG['timeout']
            )
            response.raise_for_status()
            data = response.json()

            if not data.get('data', []):
                logger.info(f"分类[{category}]的URL获取完成")
                break

            # 将获取到的URL加入队列
            with lock:
                for item in data['data']:
                    url_queue.append((item, category))

            page += 1
            # 控制分类API请求频率
            time.sleep(1 + random.uniform(0, 1))

        except Exception as e:
            logger.error(f"分类[{category}]第{page}页URL获取失败: {e}")
            page += 1
            # 出错后延长等待时间
            time.sleep(2 + random.uniform(0, 1))


def generate_sql_statements(websites: List[WebsiteData]) -> str:
    """根据处理后的网站数据生成SQL插入语句，确保URL不重复"""
    sql_statements = []
    seen_normalized_urls = set()  # 用于在生成SQL时再次检查重复URL

    for site in websites:
        # 标准化URL用于最终检查
        normalized = normalize_url(site.url)

        # 检查URL是否已处理过
        if normalized in seen_normalized_urls:
            logger.warning(f"生成SQL时发现重复URL，已跳过: {site.url}")
            continue

        seen_normalized_urls.add(normalized)

        # 转义SQL中的单引号
        escaped_name = site.name.replace("'", "''")
        escaped_description = site.description.replace("'", "''")

        # 提取域名信息
        domain_parts = extract(site.url.rstrip('/'))
        if domain_parts.subdomain:
            domain = f"{domain_parts.subdomain}.{domain_parts.registered_domain}"
        else:
            domain = domain_parts.registered_domain

        # 获取分类ID
        category_id = CATEGORY_IDS.get(site.category, 15)

        # 构建SQL语句
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


def main() -> None:
    """主函数：先收集所有URL，再用多线程处理"""
    logger.info("=" * 50)
    logger.info("开始执行mTab多分类网站书签导出工具（带全局API并发控制）")
    logger.info("=" * 50)

    # 配置信息
    logger.info(f"URL处理线程数量: {MAX_WORKERS}")
    logger.info(f"所有API的总并发限制: {GLOBAL_API_CONCURRENT}")
    logger.info(f"API请求最小间隔: {API_REQUEST_INTERVAL}秒")
    logger.info(f"处理分类: {', '.join(CATEGORIES)}")
    logger.info(f"过滤的域名列表: {', '.join(BLOCKED_DOMAINS)}")

    # 初始化
    clear_directory(ICON_DIRECTORY)
    processed_data: List[WebsiteData] = []
    processed_normalized_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}
    url_queue = []  # 存储所有待处理的URL任务
    queue_lock = threading.Lock()  # 队列操作锁
    data_lock = threading.Lock()  # 数据操作锁

    # 第一步：多线程获取所有分类的URL并加入队列
    logger.info("开始收集所有分类的URL...")
    with ThreadPoolExecutor(max_workers=min(len(CATEGORIES), 2)) as category_executor:
        # 限制分类获取线程数，避免API请求过于密集
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

    logger.info(f"共收集到 {len(url_queue)} 个URL待处理")

    # 第二步：多线程处理所有URL
    logger.info("开始多线程处理URL...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as url_executor:
        # 创建进度条
        pbar = tqdm(total=len(url_queue), desc="处理URL进度")

        # 包装处理函数，用于更新进度条
        def process_with_progress(item, category):
            process_url(item, category, processed_normalized_urls, processed_domains, processed_data, data_lock)
            pbar.update(1)

        # 提交所有URL处理任务
        futures = [
            url_executor.submit(process_with_progress, item, category)
            for item, category in url_queue
        ]

        # 等待所有任务完成
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"URL处理线程出错: {e}")

        pbar.close()

    # 后续处理
    logger.info("\n" + "=" * 50)
    logger.info(f"所有URL处理完成，共获取 {len(processed_data)} 条不重复数据")

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

    logger.info("\n" + "=" * 50)
    logger.info("mTab多分类网站书签导出工具执行完成")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()