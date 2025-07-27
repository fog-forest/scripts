#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/24
# @Desc  : mTab多分类网站书签书签导入工具（AI）
# @Func  : 批量获取多分类网站信息，处理URL去重、AI生成标题和描述、图标下载转换压缩SVG，最终生成SQL导入语句


# ============================== 公共配置参数区 ==============================
# 线程数量配置
MAX_WORKERS = 40  # 并发处理URL的线程数量

# AI模型配置
AI_CONFIG = {
    "api_key_env_var": "AI_API_KEY",
    "base_url": "https://www.gptapi.us/v1",
    "model": "gpt-4o-mini",
    "temperature": 0.7,
    "max_tokens": 1024,
    "max_retries": 2,  # AI调用失败最大重试次数
    "retry_delay": 1  # 重试延迟时间(秒)
}

# 分类配置
CATEGORIES = [
    "ai", "app", "news", "music", "tech", "photos", "life", "education",
    "entertainment", "shopping", "social", "read", "sports", "finance", "others"
]
CATEGORY_IDS = {
    "ai": 1, "app": 1, "news": 2, "music": 3,
    "tech": 4, "photos": 5, "life": 6, "education": 9,
    "entertainment": 8, "shopping": 9, "social": 10, "read": 11,
    "sports": 12, "finance": 13, "others": 14
}

# 域名过滤配置
DOMAIN_BLACKLIST = {
    "trae.cn", "trae.ai", "js.design", "itab.link", "zenvideo.qq.com"
}
DOMAIN_WHITELIST = {
    "x.com", "qq.com", "google.com", "github.com", "youtube.com", "facebook.com",
    "www.iqiyi.com", "yiyan.baidu.com", "outlook.live.com"
}

# 网络请求配置
HTTP_CONFIG = {
    'timeout': 20,  # 请求超时时间(秒)
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'keep-alive'
    }
}

# URL跳转配置
REDIRECT_CONFIG = {
    'max_redirects': 10,  # 最大跳转次数，防止无限循环
    'js_redirect_patterns': [
        r'window\.location\.href\s*=\s*["\'](.*?)["\']',
        r'window\.location\s*=\s*["\'](.*?)["\']',
        r'location\.href\s*=\s*["\'](.*?)["\']',
        r'location\s*=\s*["\'](.*?)["\']',
        r'redirect\s*\(\s*["\'](.*?)["\']\s*\)',
        r'window\.open\s*\(\s*["\'](.*?)["\']\s*\)'
    ]
}

# 文件路径配置
ICON_DIRECTORY = 'icons'
SQL_OUTPUT_FILE = "mtab_import.sql"

# 图片下载配置
MAX_IMAGE_RETRIES = 3  # 最大重试次数
INITIAL_RETRY_DELAY = 1  # 初始重试延迟(秒)
# ========================================================================


# 导入依赖库
import io
import json
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
from urllib.parse import quote, urlparse, urljoin

import requests
import validators
from PIL import Image
from openai import OpenAI
from openai.types.chat import (
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam,
    ChatCompletionMessageParam
)
from tldextract import extract
from tqdm import tqdm


# 数据结构定义
@dataclass
class WebsiteData:
    name: str  # 网站名称（AI生成）
    url: str  # 网站URL（小写处理后）
    description: str  # 网站描述（AI生成）
    img_src: str  # 图标原始URL
    local_filename: str  # 本地存储的图标文件名
    category: str  # 所属分类
    background_color: str  # 背景颜色


# 初始化AI客户端 - 从环境变量获取API密钥
def get_ai_client():
    """从环境变量获取API密钥并初始化AI客户端"""
    api_key = os.getenv(AI_CONFIG["api_key_env_var"])
    if not api_key:
        raise EnvironmentError(f"未设置环境变量 {AI_CONFIG['api_key_env_var']}，请配置API密钥")

    return OpenAI(
        api_key=api_key,
        base_url=AI_CONFIG["base_url"]
    )


# 初始化AI客户端
ai_client = get_ai_client()


# ============================== 日志配置 ==============================
def setup_logger() -> logging.Logger:
    """配置并返回日志记录器"""
    logger = logging.getLogger('mtab_exporter')
    logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    if logger.handlers:
        logger.handlers = []
    logger.addHandler(ch)

    return logger


# 初始化日志
logger = setup_logger()


# ============================== URL处理工具函数 ==============================
def normalize_url(url: str) -> str:
    """标准化URL格式并转换为小写"""
    parsed = urlparse(url)
    # 对URL各部分进行小写处理
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}".rstrip('/')
    return normalized


def extract_domain(url: str) -> str:
    """提取URL中的域名（小写）"""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def is_domain_whitelisted(url: str) -> bool:
    """检查域名是否在白名单中（使用小写域名检查）"""
    ext = extract(url)
    domain_parts = [part for part in [ext.subdomain, ext.domain, ext.suffix] if part]
    full_domain = ".".join(domain_parts).lower()

    # 检查完整域名、主域名及所有父域名（均转为小写）
    if full_domain in DOMAIN_WHITELIST:
        return True
    if ext.registered_domain.lower() in DOMAIN_WHITELIST:
        return True
    for i in range(1, len(domain_parts)):
        if ".".join(domain_parts[i:]).lower() in DOMAIN_WHITELIST:
            return True
    return False


def is_domain_blocked(url: str) -> bool:
    """检查域名是否在黑名单中（使用小写域名检查）"""
    domain = extract_domain(url).lower()
    parts = domain.split('.')

    # 检查完整域名及所有父域名（均转为小写）
    if domain in DOMAIN_BLACKLIST:
        return True
    for i in range(len(parts) - 1):
        if '.'.join(parts[i:]).lower() in DOMAIN_BLACKLIST:
            return True
    return False


def is_url_acceptable(url: str) -> Tuple[bool, str]:
    """检查URL是否符合处理条件（使用小写URL检查）"""
    # 先将URL转为小写再检查
    lower_url = url.lower()
    if is_domain_blocked(lower_url):
        return False, f"URL在黑名单中: {extract_domain(lower_url)}"
    return True, "URL符合处理条件"


def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """验证并处理URL格式（确保返回小写URL）"""
    # 先将URL转为小写
    url = url.lower()

    if not url.startswith(('http://', 'https://')):
        return None, "URL缺少协议前缀"

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 强制使用HTTPS（小写）
    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')

    if not base_url.endswith('/'):
        base_url += '/'

    if not validators.url(base_url.rstrip('/')):
        return None, "URL格式无效"

    return base_url, None


def get_preferred_url(original_url: str, redirect_history: List[str]) -> str:
    """
    根据跳转历史选择最优URL（返回小写URL）
    1. 仅对主域名相同（包括不同后缀）的URL应用后续规则
    2. 同一主域名下，优先保留带www的URL；
    3. 若后缀长度不同（如.com vs .com.hk），保留后缀最短的URL；
    4. 若无www且后缀长度相同，保留最早出现的URL
    """
    if not redirect_history:
        return original_url.lower()

    # 解析所有URL的域名信息（转为小写）
    url_info = []
    for url in redirect_history:
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        domain = parsed.netloc
        ext = extract(domain)

        url_info.append({
            "url": url_lower,
            "main_domain": ext.domain.lower(),  # 核心主域名（如google、baidu）
            "registered_domain": ext.registered_domain.lower(),  # 带后缀的域名
            "subdomain": ext.subdomain.lower(),
            "is_www": ext.subdomain.lower() == "www",
            "suffix": ext.suffix.lower(),
            "suffix_length": len(ext.suffix.split('.'))
        })

    # 获取第一个URL的主域名作为基准
    base_main_domain = url_info[0]["main_domain"]
    # 筛选出主域名相同的URL（核心主域一致，允许不同后缀）
    same_main_domain_urls = [
        info for info in url_info
        if info["main_domain"] == base_main_domain
    ]

    # 如果存在主域名不同的URL，直接返回最终跳转URL（小写）
    if len(same_main_domain_urls) != len(url_info):
        return redirect_history[-1].lower()

    # 1. 优先保留带www的URL
    www_urls = [info for info in same_main_domain_urls if info["is_www"]]
    if www_urls:
        # 带www时选择后缀最短的
        www_urls_sorted = sorted(www_urls, key=lambda x: x["suffix_length"])
        return www_urls_sorted[0]["url"]

    # 2. 无www时保留后缀最短的URL
    non_www_urls_sorted = sorted(same_main_domain_urls, key=lambda x: x["suffix_length"])
    shortest_suffix_urls = [
        info for info in non_www_urls_sorted
        if info["suffix_length"] == non_www_urls_sorted[0]["suffix_length"]
    ]

    # 3. 后缀长度相同时保留最早出现的URL
    return shortest_suffix_urls[0]["url"]


def follow_redirects(url: str) -> Tuple[str, int, str, List[str]]:
    """
    跟踪URL跳转，包括HTTP重定向和JS跳转（返回小写URL）
    返回最终URL、状态码、状态描述和跳转历史
    """
    visited_urls = set()
    current_url = url.lower()  # 初始URL转为小写
    redirect_history = [current_url]
    redirect_count = 0

    while redirect_count < REDIRECT_CONFIG['max_redirects']:
        if current_url in visited_urls:
            # 检测到循环跳转，返回当前URL（小写）
            return current_url, 302, f"循环跳转 detected after {redirect_count} steps", redirect_history
        visited_urls.add(current_url)

        try:
            # 发送请求检查状态和可能的跳转
            response = requests.get(
                current_url,
                headers=HTTP_CONFIG['headers'],
                timeout=HTTP_CONFIG['timeout'],
                allow_redirects=False,
                stream=True  # 不下载完整内容，提高效率
            )

            # 处理HTTP重定向
            if 300 <= response.status_code < 400 and 'Location' in response.headers:
                next_url = response.headers['Location'].lower()  # 跳转URL转为小写
                # 处理相对路径
                next_url = urljoin(current_url, next_url)
                logger.info(f"HTTP重定向: {current_url} -> {next_url}")
                current_url = next_url
                redirect_history.append(current_url)
                redirect_count += 1
                continue

            # 处理JS跳转 (检测常见的JS跳转模式)
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                # 只读取部分内容来检测JS跳转，提高效率
                content = response.raw.read(8192).decode('utf-8', errors='ignore')

                for pattern in REDIRECT_CONFIG['js_redirect_patterns']:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        js_redirect_url = match.group(1).lower()  # JS跳转URL转为小写
                        # 处理相对路径
                        js_redirect_url = urljoin(current_url, js_redirect_url)
                        logger.info(f"JS跳转检测: {current_url} -> {js_redirect_url}")
                        current_url = js_redirect_url
                        redirect_history.append(current_url)
                        redirect_count += 1
                        response.close()  # 关闭当前连接
                        break
                else:
                    # 没有找到JS跳转模式，结束跳转跟踪
                    return current_url, response.status_code, f"最终URL，经过{redirect_count}次跳转", redirect_history
                continue

            # 如果没有更多跳转，返回当前URL和状态（小写）
            return current_url, response.status_code, f"最终URL，经过{redirect_count}次跳转", redirect_history

        except requests.exceptions.SSLError:
            return current_url, 495, "HTTPS证书错误", redirect_history
        except Exception as e:
            return current_url, 500, f"请求错误: {str(e)}", redirect_history

    # 达到最大跳转次数（返回小写URL）
    return current_url, 302, f"达到最大最大跳转次数 ({REDIRECT_CONFIG['max_redirects']})", redirect_history


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """检查URL可访问性并处理跳转，返回最终小写URL"""
    try:
        # 强制使用HTTPS并转为小写
        url = url.lower()
        if url.startswith('http://'):
            url = url.replace('http://', 'https://')

        # 跟踪所有跳转，获取最终URL和跳转历史（均为小写）
        final_url, status_code, status_msg, redirect_history = follow_redirects(url)
        # 应用URL优选逻辑（返回小写URL）
        preferred_url = get_preferred_url(url, redirect_history)
        logger.info(f"URL跳转跟踪结果: {preferred_url} (状态码: {status_code}, {status_msg})")

        # 检查是否是HTTPS错误或500以上状态码
        if status_code == 495 or status_code >= 500:
            return False, f"URL访问失败: {status_msg} (状态码: {status_code})", url, None

        # 检查URL是否符合处理条件（使用小写URL）
        is_acceptable, reason = is_url_acceptable(preferred_url)
        if not is_acceptable:
            return False, f"URL不符合处理条件: {reason}", url, None

        # 验证最终URL格式（确保返回小写URL）
        processed_url, error = validate_and_process_url(preferred_url)
        if not processed_url:
            return False, f"URL格式验证失败: {error}", url, None

        normalized = normalize_url(processed_url)
        return True, None, processed_url, normalized

    except Exception as e:
        normalized = normalize_url(url.lower())
        return False, f"URL处理异常: {str(e)[:20]}", url, normalized


# ============================== 网站信息处理函数 ==============================
def is_valid_text(text: str) -> bool:
    """检查文本是否有效（不是乱码），兼容中文、英文和俄文"""
    if not text or not text.strip():
        return False

    # 移除控制字符
    text_clean = re.sub(r'[\x00-\x1F\x7F]', '', text)
    if not text_clean:
        return False

    # 定义有效字符集（中文、俄文、英文、数字、多语言常见标点）
    valid_chars = re.findall(
        r'[\u4e00-\u9fa5\u0400-\u04FFa-zA-Z0-9，。,.;:!?()（）《》“”‘’«»\s]',
        text_clean
    )

    # 有效字符占比需超过50%
    return len(valid_chars) / len(text_clean) > 0.5


def clean_html_entities(text: str) -> str:
    """清理HTML实体编码，保留单引号转换"""
    text = text.replace('&#x27;', "'")  # 保留单引号
    return re.sub(r'&#x[0-9a-fA-F]+;', '', text)  # 移除其他实体


def fetch_api(api, url: str) -> Optional[Dict[str, str]]:
    """调用API获取取网站标题和描述（使用小写URL）"""
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
        return api['parse_func'](response.json())

    except Exception:
        return None


def fetch_website_info(url: str) -> Optional[Dict[str, str]]:
    """通过多个API获取网站标题和描述（使用小写URL）"""
    if not url:
        return None

    # 合并无效值集合
    invalid_values = {"null", "暂无标题", "暂无描述"}

    api_list = [
        {
            "name": "geeker",
            "url_template": "https://geeker.moe/tdk.php?url={}",
            "parse_func": lambda data: {
                "title": title,
                "description": desc
            } if (desc := data.get('description', ''))
                 and (title := data.get('title', ''))
                 and data.get('code') == 1
                 # 只要标题或描述中有一个不为空且有效，就接受
                 and (title.strip() and title not in invalid_values or
                      desc.strip() and desc not in invalid_values)
                 and (not desc.strip() or is_valid_text(desc))
            else None
        },
        {
            "name": "shanhe",
            "url_template": "https://shanhe.kim/api/wz/web_tdk.php?url={}",
            "parse_func": lambda data: {
                "title": title,
                "description": desc
            } if (desc := data.get('description', ''))
                 and (title := data.get('title', ''))
                 and data.get('code') == 1
                 # 只要标题或描述中有一个不为空且有效，就接受
                 and (title.strip() and title not in invalid_values or
                      desc.strip() and desc not in invalid_values)
                 and (not desc.strip() or is_valid_text(desc))
            else None
        },
        {
            "name": "suol",
            "url_template": "https://api.suol.cc/v1/zs_wzxx.php?url={}",
            "parse_func": lambda data: {
                "title": title,
                "description": desc
            } if (desc := data.get('description', ''))
                 and (title := data.get('title', ''))
                 and data.get('code') == 1
                 # 只要标题或描述中有一个不为空且有效，就接受
                 and (title.strip() and title not in invalid_values or
                      desc.strip() and desc not in invalid_values)
                 and (not desc.strip() or is_valid_text(desc))
            else None
        },
        {
            "name": "ahfi",
            "url_template": "https://api.ahfi.cn/api/websiteinfo?url={}",
            "parse_func": lambda data: {
                "title": title,
                "description": desc
            } if (desc := data.get('data', {}).get('description', ''))
                 and (title := data.get('data', {}).get('title', ''))
                 # 只要标题或描述中有一个不为空且有效，就接受
                 and (title.strip() and title not in invalid_values or
                      desc.strip() and desc not in invalid_values)
                 and (not desc.strip() or is_valid_text(desc))
            else None
        }
    ]

    # 尝试所有API获取信息（使用小写URL）
    for api in api_list:
        try:
            if website_info := fetch_api(api, url):
                # 清理理标题和描述
                cleaned_title = website_info["title"].strip().replace('\n', ' ').replace('\r', ' ')
                cleaned_desc = website_info["description"].strip().replace('\n', ' ').replace('\r', ' ')
                return {
                    "title": cleaned_title,
                    "description": cleaned_desc
                }
        except Exception as e:
            logger.warning(f"{api['name']} API失败: {str(e)}")
            continue

    return None


def ask_openai(question: str) -> Optional[Dict[str, str]]:
    """调用AI接口生成标题和描述（带重试机制）"""
    # 定义消息类型
    system_msg: ChatCompletionSystemMessageParam = {
        "role": "system",
        "content": "我会给你一个网址、网站标题和网站描述，帮我生成网站收藏的标题和中文描述。"
                   "1. 标题要求简短最好一个词，优先从我给你的标题中取，不要翻译；"
                   "2. 描述长度控制在120字符（varchar）内，尽量精简，末尾不需要标点符号；"
                   "返回给我内容要求两个字段 title、description 的JSON格式。"
    }

    user_msg: ChatCompletionUserMessageParam = {
        "role": "user",
        "content": question
    }

    messages: List[ChatCompletionMessageParam] = [system_msg, user_msg]

    # 带指数退避的重试机制
    for attempt in range(1, AI_CONFIG["max_retries"] + 1):
        try:
            response = ai_client.chat.completions.create(
                model=AI_CONFIG["model"],
                messages=messages,
                temperature=AI_CONFIG["temperature"],
                max_tokens=AI_CONFIG["max_tokens"]
            )

            result = response.choices[0].message.content.strip()
            if result == "不知道":
                return None

            # 移除可能的JSON代码块标记
            result = re.sub(r'^```json\s*', '', result)  # 移除开头的```json
            result = re.sub(r'\s*```$', '', result)  # 移除结尾的```

            # 解析JSON响应
            json_result = json.loads(result)
            # 验证必要字段
            if "title" in json_result and "description" in json_result:
                return {
                    "title": json_result["title"].strip(),
                    "description": json_result["description"].strip()
                }
            return None

        except json.JSONDecodeError:
            logger.warning(f"AI返回的不是有效的JSON: {result}")
            if attempt < AI_CONFIG["max_retries"]:
                time.sleep(AI_CONFIG["retry_delay"] * attempt)
                continue
            return None
        except Exception as e:
            logger.warning(f"AI调用失败 (尝试 {attempt}/{AI_CONFIG['max_retries']}): {str(e)}")
            if attempt < AI_CONFIG["max_retries"]:
                time.sleep(AI_CONFIG["retry_delay"] * attempt)

    logger.error(f"AI调用超过最大重试次数 ({AI_CONFIG['max_retries']}次)，放弃请求")
    return None


def clean_website_info(url: str, original_title: str = "", original_desc: str = "") -> Optional[Dict[str, str]]:
    """清理并优化网站标题和描述（结合API和AI，使用小写URL）"""
    # 合并无效值集合
    invalid_values = {"null", "暂无标题", "暂无描述"}

    # 清理原始信息
    cleaned_original_title = clean_html_entities(original_title).strip() if original_title else ""
    cleaned_original_desc = clean_html_entities(original_desc).strip() if original_desc else ""

    # 过滤无效值
    if cleaned_original_title in invalid_values:
        cleaned_original_title = ""
    if cleaned_original_desc in invalid_values:
        cleaned_original_desc = ""

    # 尝试通过API获取信息（使用小写URL）
    api_info = fetch_website_info(url)
    domain = extract_domain(url)

    # 处理API获取到的信息
    if api_info:
        # 过滤API返回的无效值
        api_title = api_info["title"] if api_info["title"] not in invalid_values else ""
        api_desc = api_info["description"] if api_info["description"] not in invalid_values else ""

        # 只要标题或描述有一个有效就调用AI
        if api_title or api_desc:
            if ai_info := ask_openai(f"网址：{domain}\n网站标题：{api_title}\n网站描述：{api_desc}"):
                return ai_info
        logger.warning(f"API获取到信息但都无效，丢弃URL: {url}")
        return None

    # 白名单域名直接调用AI（使用小写URL检查）
    if is_domain_whitelisted(url):
        prompt = f"网址：{domain}"
        if cleaned_original_title:
            prompt += f"\n网站标题：{cleaned_original_title}"
        if cleaned_original_desc:
            prompt += f"\n网站描述：{cleaned_original_desc}"

        if ai_info := ask_openai(prompt):
            return ai_info
        logger.warning(f"白名单域名但AI调用失败，丢弃URL: {url}")
        return None

    # 只要有原始标题或描述，就尝试使用AI处理
    if cleaned_original_title or cleaned_original_desc:
        prompt = f"网址：{domain}"
        if cleaned_original_title:
            prompt += f"\n网站标题：{cleaned_original_title}"
        if cleaned_original_desc:
            prompt += f"\n网站描述：{cleaned_original_desc}"

        if ai_info := ask_openai(prompt):
            return ai_info
        logger.warning(f"有原始信息但AI调用失败，丢弃URL: {url}")
        return None

    # 没有API信息且非白名单，也没有原始信息则丢弃
    return None


# ============================== 图像处理函数 ==============================
def compress_svg(svg_content: str) -> str:
    """压缩SVG内容，移除注释和多余空格"""
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
    """将图片转换为SVG格式"""
    try:
        img = Image.open(io.BytesIO(img_response.content))
        img_base64 = b64encode(img_response.content).decode('utf-8')

        content_type = img_response.headers.get('Content-Type', 'png')
        img_format = content_type.split('/')[-1].lower()
        if img_format not in ['png', 'jpeg', 'jpg', 'gif']:
            img_format = 'png'

        svg_template = """<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">
            <image href="data:image/{};base64,{}" width="{}" height="{}" preserveAspectRatio="xMidYMid meet"/>
        </svg>"""

        return compress_svg(svg_template.format(
            img.width, img.height, img_format, img_base64, img.width, img.height
        ))
    except Exception as e:
        logger.error(f"图片转换失败: {e}")
        raise ValueError(f"图片转换失败: {e}")


def validate_svg(svg_content: str) -> bool:
    """验证SVG内容有效性"""
    return all(tag in svg_content for tag in ['<svg', '</svg>', '<image'])


def download_and_save_image(img_src: str, filename: str) -> Tuple[bool, str]:
    """下载并保存图片（带重试机制，使用小写URL）"""
    for attempt in range(1, MAX_IMAGE_RETRIES + 1):
        try:
            # 强制使用HTTPS并转为小写
            img_src = img_src.lower()
            if img_src.startswith('http://'):
                img_src = img_src.replace('http://', 'https://')

            # 记录下载尝试
            log_msg = f"重试下载图片 (尝试 {attempt}/{MAX_IMAGE_RETRIES}): {img_src}" if attempt > 1 else f"开始下载图片: {img_src}"
            logger.info(log_msg)

            img_response = requests.get(
                img_src,
                headers=HTTP_CONFIG['headers'],
                timeout=HTTP_CONFIG['timeout'],
                allow_redirects=False
            )
            img_response.raise_for_status()

            file_path = os.path.join(ICON_DIRECTORY, filename)

            # 处理SVG文件
            if img_src.endswith('.svg'):
                svg_content = compress_svg(img_response.text)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
                return True, "SVG已压缩保存"

            # 处理其他图片格式
            svg_content = image_to_svg(img_response)
            if validate_svg(svg_content):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
                return True, "已转换为SVG"

            # 无效SVG处理
            logger.warning(f"生成的SVG文件无效: {filename}")
            if attempt == MAX_IMAGE_RETRIES:
                return False, "生成的SVG文件无效"
            time.sleep(INITIAL_RETRY_DELAY * attempt)

        except Exception as e:
            error_msg = f"图片下载失败 (尝试 {attempt}/{MAX_IMAGE_RETRIES}) {img_src}: {str(e)}"
            logger.warning(error_msg)

            if attempt < MAX_IMAGE_RETRIES:
                time.sleep(INITIAL_RETRY_DELAY * attempt)  # 指数退避

    return False, f"超过最大重试次数 ({MAX_IMAGE_RETRIES}次)"


# ============================== 文件操作函数 ==============================
def clear_directory(directory: str) -> None:
    """清理目录（删除所有文件），如果目录不存在则创建"""
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
    """保存内容到文件"""
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
    """生成唯一的图标文件名，处理域名冲突（使用小写URL）"""
    url_without_slash = url.rstrip('/').lower()  # URL转为小写
    ext = extract(url_without_slash)

    subdomain = ext.subdomain.lower()
    main_domain = ext.domain.lower()
    suffix = ext.suffix.lower()

    is_www = subdomain == "www"
    is_main_domain = subdomain in ("", "www")
    base_key = main_domain if is_main_domain else f"{subdomain}-{main_domain}"

    with lock:
        if is_main_domain:
            if base_key in processed_domains:
                existing = processed_domains[base_key]

                # 已存在www版本，丢弃非www版本
                if existing.get("is_www", False) and not is_www:
                    return None, f"主域名{main_domain}已存在www前缀版本，当前域名被丢弃"

                # 后缀相同，使用现有文件名
                if existing["suffix"] == suffix:
                    return existing["filename"], None

                # 处理不同后缀的情况
                old_filename = existing["filename"]
                old_suffix = existing["suffix"]
                new_existing_filename = f"{main_domain}-{old_suffix}.svg"

                # 重命名现有文件
                try:
                    old_path = os.path.join(ICON_DIRECTORY, old_filename)
                    new_path = os.path.join(ICON_DIRECTORY, new_existing_filename)
                    os.rename(old_path, new_path)
                except Exception as e:
                    logger.error(f"重命名文件失败: {old_filename} → {new_existing_filename}, 错误: {e}")
                    return None, "文件重命名失败"

                # 更新已有数据的文件名
                for item in processed_data:
                    if item.local_filename == old_filename:
                        item.local_filename = new_existing_filename
                        break

                # 记录新文件名
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

            # 首次处理主域名
            filename = f"{main_domain}.svg"
            processed_domains[base_key] = {
                "filename": filename,
                "suffix": suffix,
                "is_www": is_www,
                "base_key": base_key
            }
            return filename, f"首次处理主域名，文件名为{filename}"

        else:
            # 非主域名情况，处理子域名
            if base_key in processed_domains:
                existing = processed_domains[base_key]
                if existing["suffix"] == suffix:
                    return existing["filename"], None

                # 不同后缀的子域名
                new_filename = f"{subdomain}-{main_domain}-{suffix}.svg"
                processed_domains[base_key] = {
                    "filename": new_filename,
                    "suffix": suffix,
                    "is_www": False,
                    "base_key": base_key
                }
                return new_filename, f"子域名，前缀相同但后缀不同，文件名为{new_filename}"

            # 首次处理子域名
            filename = f"{subdomain}-{main_domain}.svg"
            processed_domains[base_key] = {
                "filename": filename,
                "suffix": suffix,
                "is_www": False,
                "base_key": base_key
            }
            return filename, f"首次处理子域名 {subdomain}，文件名为{filename}"


def expand_color_format(color: str) -> str:
    """标准化颜色格式（3位HEX转6位）"""
    if not color:
        return ''

    if not color.startswith('#'):
        return color

    color = color.lstrip('#')
    if len(color) == 3:
        return f"#{color[0]}{color[0]}{color[1]}{color[1]}{color[2]}{color[2]}"
    elif len(color) == 6:
        return f"#{color}"
    return color


# ============================== 核心处理函数 ==============================
def process_url(
        item,
        category: str,
        processed_normalized_urls: Set[str],
        processed_domains: Dict[str, Dict[str, str]],
        processed_data: List[WebsiteData],
        lock: threading.Lock
):
    """处理单个URL，包括验证、去重、标题描述生成和图标下载（确保URL小写）"""
    # 提取基础信息，URL转为小写
    original_title = item.get('name', '').strip()
    url = item.get('url', '').lower()  # 原始URL转为小写
    img_src = item.get('imgSrc', '').lower()  # 图标URL转为小写
    background_color = item.get('backgroundColor', '')
    original_desc = item.get('description', '')

    # 验证基础信息
    if not url:
        logger.warning("丢弃url为空的条目")
        return

    # 检查颜色是否为空，为空则丢弃
    if not background_color:
        logger.warning(f"丢弃颜色为空的条目: {url}")
        return

    # 检查URL可访问性和跳转处理（返回小写URL）
    accessible, error, final_url, normalized_url = check_url_accessibility(url)
    if not accessible:
        logger.warning(f"不可处理URL: {url} - {error}")
        return

    if not normalized_url:
        logger.warning(f"无法标准化URL: {final_url}")
        return

    # 检查重复URL（使用小写URL）
    with lock:
        if normalized_url in processed_normalized_urls:
            return

    # 处理标题和描述（使用小写URL）
    website_info = clean_website_info(final_url, original_title, original_desc)
    if not website_info:
        logger.warning(f"无法生成有效的标题和描述，丢弃URL: {final_url}")
        return

    # 处理颜色
    expanded_color = expand_color_format(background_color)
    # 再次检查扩展后的颜色是否为空
    if not expanded_color:
        logger.warning(f"丢弃扩展后颜色为空的条目: {url}")
        return

    # 生成文件名（使用小写URL）
    filename, conflict_msg = generate_filename(final_url, processed_domains, processed_data, lock)
    if filename is None:
        logger.info(f"URL被丢弃: {final_url} - {conflict_msg}")
        return

    # 下载并保存图片（使用小写URL）
    success, status = download_and_save_image(img_src, filename)
    if not success:
        logger.warning(f"图片最终下载失败，丢弃条目: {url} - {status}")
        return

    # 保存处理结果（URL确保为小写）
    with lock:
        processed_normalized_urls.add(normalized_url)
        domain = extract(final_url.rstrip('/').lower())
        processed_domains[domain.domain] = {
            'suffix': domain.suffix,
            'filename': filename
        }
        processed_data.append(WebsiteData(
            name=website_info["title"],  # 使用AI生成的标题
            url=final_url,  # 使用跳转后的最终URL（已确保小写）
            description=website_info["description"],  # 使用AI生成的描述
            img_src=img_src,
            local_filename=filename,
            category=category,
            background_color=expanded_color
        ))


def process_category(category: str, url_queue: list, lock: threading.Lock):
    """获取指定分类的所有URL并加入处理队列（URL转为小写）"""
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

            # 没有更多数据时退出
            if not data.get('data', []):
                logger.info(f"分类[{category}]的URL获取完成")
                break

            # 添加到队列，将URL转为小写
            with lock:
                for item in data['data']:
                    url = item.get('url', '').lower()  # URL转为小写
                    if url.startswith('http://'):
                        url = url.replace('http://', 'https://')
                    item['url'] = url
                    item['imgSrc'] = item.get('imgSrc', '').lower()  # 图标URL转为小写
                    url_queue.append((item, category))

            page += 1
            time.sleep(1 + random.uniform(0, 1))  # 随机延迟避免请求过于频繁

        except Exception as e:
            logger.error(f"分类[{category}]第{page}页URL获取失败: {e}")
            page += 1
            time.sleep(2 + random.uniform(0, 1))


def generate_sql_statements(websites: List[WebsiteData]) -> str:
    """生成SQL导入语句（确保URL为小写）"""
    # 按area值(分类ID)排序，再按name排序
    sorted_websites = sorted(
        websites,
        key=lambda x: (CATEGORY_IDS.get(x.category, 15), x.name)
    )

    sql_statements = []
    seen_normalized_urls = set()

    for site in sorted_websites:
        # 确保URL末尾带有斜杠且为小写
        url_with_slash = site.url.rstrip('/').lower() + '/'
        normalized = normalize_url(url_with_slash)

        if normalized in seen_normalized_urls:
            logger.warning(f"生成SQL时发现重复URL，已跳过: {site.url}")
            continue

        seen_normalized_urls.add(normalized)

        # 转义SQL特殊字符
        escaped_name = site.name.replace("'", "''")
        escaped_description = site.description.replace("'", "''")

        # 提取域名（小写）
        domain_parts = extract(url_with_slash)
        domain = f"{domain_parts.subdomain}.{domain_parts.registered_domain}" if domain_parts.subdomain else domain_parts.registered_domain
        domain = domain.lower()  # 确保域名为小写

        # 获取分类ID(area值)
        category_id = CATEGORY_IDS.get(site.category, 15)

        # 生成SQL语句，使用带斜杠的小写URL
        sql = (
            f"INSERT INTO `mtab`.`linkstore` "
            f"(`name`, `src`, `url`, `type`, `size`, `create_time`, `hot`, `area`, `tips`, `domain`, "
            f"`app`, `install_num`, `bgColor`, `vip`, `custom`, `user_id`, `status`, `group_ids`) "
            f"VALUES "
            f"('{escaped_name}', 'https://oss.amogu.cn/icon/website/{site.local_filename}', '{url_with_slash}', "
            f"'icon', '1x1', '2025-01-01 00:00:00', 0, {category_id}, '{escaped_description}', '{domain}', "
            f"0, 0, '{site.background_color}', 0, NULL, NULL, 1, 0);"
        )
        sql_statements.append(sql)

    return "\n".join(sql_statements)


# ============================== 主函数 ==============================
def main() -> None:
    """程序主入口"""
    logger.info("\n" + "=" * 60)
    logger.info("开始执行mTab多分类网站书签导出工具")
    logger.info("=" * 60 + "\n")

    # 显示配置信息
    logger.info(f"URL处理线程数量: {MAX_WORKERS}")
    logger.info(f"AI模型: {AI_CONFIG['model']}")
    logger.info(f"AI API密钥环境变量: {AI_CONFIG['api_key_env_var']}")
    logger.info(f"AI最大重试次数: {AI_CONFIG['max_retries']}")
    logger.info(f"最大URL跳转次数: {REDIRECT_CONFIG['max_redirects']}")
    logger.info(f"图片下载最大重试次数: {MAX_IMAGE_RETRIES}")
    logger.info(f"处理分类数量: {len(CATEGORIES)}")
    logger.info(f"域名黑名单数量: {len(DOMAIN_BLACKLIST)}")
    logger.info("\n")

    # 初始化数据结构
    clear_directory(ICON_DIRECTORY)
    processed_data: List[WebsiteData] = []
    processed_normalized_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}
    url_queue = []  # 存储所有待处理的URL任务
    queue_lock = threading.Lock()  # 队列操作锁
    data_lock = threading.Lock()  # 数据操作锁

    # 第一步：多线程获取所有分类的URL（转为小写）
    logger.info("===== 开始收集所有分类的URL =====")
    with ThreadPoolExecutor(max_workers=min(len(CATEGORIES), 2)) as category_executor:
        futures = [
            category_executor.submit(process_category, category, url_queue, queue_lock)
            for category in CATEGORIES
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"分类URL获取线程出错: {e}")

    logger.info(f"\n共收集到 {len(url_queue)} 个URL待处理\n")

    # 第二步：多线程处理所有URL（确保处理过程中URL为小写）
    logger.info("===== 开始多线程处理URL =====")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as url_executor:
        pbar = tqdm(total=len(url_queue), desc="处理URL进度")

        def process_with_progress(item, category):
            process_url(item, category, processed_normalized_urls, processed_domains, processed_data, data_lock)
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

    # 后续处理与结果展示
    logger.info("\n" + "=" * 60)
    logger.info(f"所有URL处理完成，共获取 {len(processed_data)} 条不重复数据")
    logger.info("=" * 60 + "\n")

    if processed_data:
        # 分类统计
        print("\n按分类统计:")
        category_counts = Counter(item.category for item in processed_data)
        for cat, count in category_counts.items():
            print(f"- {cat}: {count} 条")

        # 数据示例
        print("\n前5条数据示例:")
        for i, item in enumerate(processed_data[:5], 1):
            print(f"{i}. [{item.category}] {item.name}")
            print(f"   URL: {item.url}")
            print(f"   描述: {item.description}")
            print(f"   本地文件: {item.local_filename}")
            print(f"   背景颜色: {item.background_color}\n")

        # 生成SQL文件（确保URL为小写）
        sql_content = generate_sql_statements(processed_data)
        save_file(sql_content, SQL_OUTPUT_FILE)

        print(f"\nSQL导入文件已生成: {SQL_OUTPUT_FILE}")
        print(f"包含 {len(sql_content.split('INSERT')) - 1} 条INSERT语句")
    else:
        logger.warning("未处理任何数据")

    logger.info("\n" + "=" * 60)
    logger.info("mTab多分类网站书签导出工具执行完成")
    logger.info("=" * 60 + "\n")


if __name__ == "__main__":
    main()
