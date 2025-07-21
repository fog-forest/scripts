#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/18
# @Desc  : mTab多分类网站书签导出工具
import asyncio
import io
import logging
import os
import random
import re
import time
from base64 import b64encode
from collections import Counter
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional

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
    name: str  # 网站名称
    url: str  # 网站URL
    description: str  # 网站描述
    img_src: str  # 图片源地址
    local_filename: str  # 本地保存的文件名
    category: str  # 所属分类
    background_color: str  # 背景颜色


# 配置常量
# 分类ID映射表，用于SQL生成
CATEGORY_IDS = {
    "ai": 1, "app": 2, "news": 3, "music": 4,
    "tech": 5, "photos": 6, "life": 7, "education": 8,
    "entertainment": 9, "shopping": 10, "social": 11, "read": 12,
    "sports": 13, "finance": 14, "others": 15
}

# HTTP请求配置
HTTP_CONFIG = {
    'timeout': 10,
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    }
}


# 日志配置
def setup_logger():
    """配置并返回日志记录器"""
    logger = logging.getLogger('mtab_exporter')
    logger.setLevel(logging.INFO)

    # 控制台处理器
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # 日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    # 清除现有处理器并添加新处理器
    if logger.handlers:
        logger.handlers = []
    logger.addHandler(ch)

    return logger


# 初始化日志
logger = setup_logger()


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


# URL处理函数
def normalize_url(url: str) -> str:
    """标准化URL，用于更精确的去重"""
    from urllib.parse import urlparse

    # 解析URL
    parsed = urlparse(url)

    # 提取核心部分：协议 + 域名 + 端口
    normalized = f"{parsed.scheme}://{parsed.netloc}"

    # 确保格式统一（不带尾部斜杠）
    return normalized.rstrip('/')


def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """验证并处理URL，确保其格式正确"""
    if not url.startswith(('http://', 'https://')):
        return None, f"URL缺少协议前缀"

    from urllib.parse import urlparse
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
        return None, f"URL格式无效"

    return base_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """检查URL的可访问性，返回检查结果、最终URL和标准化URL"""
    try:
        session = requests.Session()
        session.max_redirects = 10  # 限制重定向次数

        response = session.get(
            url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=True
        )

        final_url = response.url
        final_base_url, error = validate_and_process_url(final_url)
        if not final_base_url:
            return False, f"处理最终URL失败: {error}", url, None

        # 生成标准化URL用于去重
        normalized = normalize_url(final_base_url)

        # 检查状态码
        if response.status_code >= 400:
            return False, f"URL不可访问({response.status_code})", final_base_url, normalized
        return True, None, final_base_url, normalized
    except requests.TooManyRedirects:
        normalized = normalize_url(url)
        return False, "URL重定向次数过多", url, normalized
    except requests.RequestException as e:
        normalized = normalize_url(url)
        return False, f"URL检查失败({str(e)[:20]})", url, normalized


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

        file_path = os.path.join('icons', filename)

        # 处理SVG文件
        if img_src.lower().endswith('.svg'):
            svg_content = compress_svg(img_response.text)
            save_file(svg_content, file_path)
            return True, "SVG已压缩保存"
        # 处理其他图片格式
        else:
            svg_content = image_to_svg(img_response)
            if validate_svg(svg_content):
                save_file(svg_content, file_path)
                return True, "已转换为SVG"
            else:
                return False, "生成的SVG文件无效"

    except Exception as e:
        return False, f"图片处理失败({str(e)})"


# 文件名和数据处理函数
def generate_filename(url: str, processed_domains: Dict[str, Dict[str, str]],
                      processed_data: List[WebsiteData]) -> Tuple[str, Optional[str]]:
    """生成唯一的文件名，处理可能的域名冲突"""
    url_without_slash = url.rstrip('/')
    ext = extract(url_without_slash)
    main_domain = ext.domain
    suffix = ext.suffix

    base_filename = f"{main_domain}.svg"
    suffix_filename = f"{main_domain}-{suffix}.svg"

    # 如果域名未处理过，直接使用基础文件名
    if main_domain not in processed_domains:
        return base_filename, None

    # 处理域名冲突
    existing_info = processed_domains[main_domain]
    existing_suffix = existing_info['suffix']
    existing_filename = existing_info['filename']
    existing_file_path = os.path.join('icons', existing_filename)

    # 后缀相同，无需处理
    if existing_suffix == suffix:
        return base_filename, None

    # 重命名已存在的文件
    new_existing_filename = f"{main_domain}-{existing_suffix}.svg"

    try:
        os.rename(existing_file_path, os.path.join('icons', new_existing_filename))
    except Exception as e:
        logger.error(f"文件重命名失败: {existing_filename} → {new_existing_filename}, 错误: {e}")
        return suffix_filename, f"文件重命名失败"

    # 更新已处理数据中的文件名
    for item in processed_data:
        if item.local_filename == existing_filename:
            item.local_filename = new_existing_filename
            break

    # 更新已处理域名信息
    processed_domains[main_domain]['filename'] = new_existing_filename

    return suffix_filename, f"添加后缀区分"


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


# 网站描述处理函数
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
        return original_desc.strip().replace('\n', '').replace('\r', '')

    logger.warning(f"无法为URL获取有效描述: {url}")
    return None


def is_description_invalid(desc: str) -> bool:
    """检查描述是否无效（空值、默认值或包含非ASCII字符）"""
    if not desc:
        return True
    desc = desc.strip().lower()
    if desc in ['none', '暂无描述']:
        return True
    # 检查是否包含非ASCII字符
    if re.search(r'[^\x00-\x7F]{1,}', desc):
        return True
    return False


def clean_api_description(desc: str) -> Optional[str]:
    """清理API返回的描述，移除多余空白并截断过长描述"""
    desc = desc.strip().replace('\n', '').replace('\r', '')
    if not desc:
        return None

    # 按标点符号截断描述
    for punct in ['。', '.']:
        if punct in desc:
            desc = desc.split(punct, 1)[0].strip() + punct
            break

    return desc if desc else None


# API请求函数
async def fetch_api(session, api_url, api):
    """异步请求单个API获取网站描述"""
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
        except Exception:
            if attempt == max_retries - 1:
                return api['name'], None

    return api['name'], None


async def fetch_website_description(url: str) -> Optional[str]:
    """异步获取网站描述，尝试多个API"""
    if not url:
        return None

    # 无效描述列表，用于在API解析时直接过滤
    invalid_descriptions = {
        "本站是一个互联网官网"
    }

    # API列表，包含API名称、URL模板和解析函数
    api_list = [
        {
            "name": "shanhe",
            "url_template": "https://shanhe.kim/api/wz/web_tdk.php?url={}",
            "parse_func": lambda data: data.get('description', '') if data.get('code') == 1 else ''
        },
        {
            "name": "suol",
            "url_template": "https://api.suol.cc/v1/zs_wzxx.php?url={}",
            "parse_func": lambda data: data.get('description', '') if data.get('code') == 1 else ''
        },
        {
            "name": "ahfi",
            "url_template": "https://api.ahfi.cn/api/websiteinfo?url={}",
            "parse_func": lambda data:
            # 提取描述并验证是否有效
            desc if (desc := data.get('data', {}).get('description', ''))
                    and desc.strip()
                    and desc not in invalid_descriptions
            else ''
        },
        {
            "name": "cenguigui",
            "url_template": "https://api.cenguigui.cn/api/ico/ico.php?url={}",
            "parse_func": lambda data:
            desc if (desc := data.get('data', {}).get('description', ''))
                    and desc.strip()
                    and desc not in invalid_descriptions
            else ''
        },
        {
            "name": "xxapi",
            "url_template": "https://v2.xxapi.cn/api/title?url={}",
            "parse_func": lambda data: data.get('data', '')
        }
    ]

    async with aiohttp.ClientSession(headers=HTTP_CONFIG['headers']) as session:
        tasks = []
        for api in api_list:
            from urllib.parse import quote
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
    """同步调用异步函数获取网站描述"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            result = new_loop.run_until_complete(fetch_website_description(url))
            new_loop.close()
            return result
        else:
            return loop.run_until_complete(fetch_website_description(url))
    except Exception:
        return None


# 主处理函数
def process_category(category: str, processed_normalized_urls: Set[str],
                     processed_domains: Dict[str, Dict[str, str]],
                     processed_data: List[WebsiteData]) -> None:
    """处理单个分类，获取并处理该分类下的所有网站数据"""
    logger.info(f"开始处理分类: {category}")
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

            # 如果没有数据，说明处理完成
            if not data.get('data', []):
                logger.info(f"分类[{category}]处理完成")
                break

            # 处理当前页的每个项目
            for item in tqdm(data['data'], desc=f"分类[{category}]第{page}页", unit="项"):
                url = item.get('url', '')
                img_src = item.get('imgSrc', '')
                background_color = item.get('backgroundColor', '')
                original_description = item.get('description', '')

                # 验证URL
                clean_url, error = validate_and_process_url(url)
                if not clean_url:
                    logger.warning(f"无效URL: {url} - {error}")
                    continue

                # 检查URL可访问性，获取最终URL和标准化URL
                accessible, error, final_url, normalized_url = check_url_accessibility(clean_url)
                if not accessible:
                    logger.warning(f"不可访问URL: {url} - {error}")
                    continue

                if not normalized_url:
                    logger.warning(f"无法标准化URL: {final_url}")
                    continue

                # 检查是否已处理（基于标准化URL去重）
                if normalized_url in processed_normalized_urls:
                    logger.debug(f"发现重复URL（标准化后）: {final_url}")
                    continue

                # 获取清理后的描述
                clean_desc = clean_description(final_url, original_description)
                if not clean_desc:
                    continue

                # 处理颜色格式
                expanded_color = expand_color_format(background_color)

                # 生成文件名
                filename, conflict_msg = generate_filename(final_url, processed_domains, processed_data)

                # 下载并保存图片
                success, status = download_and_save_image(img_src, filename)
                if not success:
                    logger.warning(f"图片处理失败: {img_src}, 状态: {status}")
                    continue

                # 更新处理记录（使用标准化URL）
                processed_normalized_urls.add(normalized_url)
                domain = extract(final_url.rstrip('/'))
                processed_domains[domain.domain] = {
                    'suffix': domain.suffix,
                    'filename': filename
                }
                processed_data.append(WebsiteData(
                    name=item.get('name', ''),
                    url=final_url,
                    description=clean_desc,
                    img_src=img_src,
                    local_filename=filename,
                    category=category,
                    background_color=expanded_color
                ))

            # 处理下一页
            page += 1
            # 添加随机延迟，避免请求过于频繁
            time.sleep(0.5 + random.uniform(0, 0.5))

        except Exception as e:
            logger.error(f"分类[{category}]第{page}页处理失败: {e}")
            page += 1
            # 出错时延迟更长
            time.sleep(1 + random.uniform(0, 1))


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
        sql = f"""INSERT INTO `mtab`.`linkstore` 
(`name`, `src`, `url`, `type`, `size`, `create_time`, `hot`, `area`, `tips`, `domain`, `app`, `install_num`, `bgColor`, `vip`, `custom`, `user_id`, `status`, `group_ids`) 
VALUES 
('{escaped_name}', 'https://oss.amogu.cn/icon/website/{site.local_filename}', '{site.url}', 'icon', '1x1', '2025-01-01 00:00:00', 0, {category_id}, '{escaped_description}', '{domain}', 0, 0, '{site.background_color}', 0, NULL, NULL, 1, 0);"""

        sql_statements.append(sql)

    return "\n".join(sql_statements)


def main():
    """主函数，协调整个程序的执行流程"""
    logger.info("开始执行mTab多分类网站书签导出工具")

    # 准备工作：清空图标目录
    clear_directory('icons')
    logger.info("已清空icons目录")

    # 配置要处理的分类
    categories = ["ai"]  # 可以添加更多分类，如["ai", "tech", "news"]
    logger.info(f"准备处理分类: {', '.join(categories)}")

    # 初始化数据存储结构
    processed_data: List[WebsiteData] = []
    # 使用标准化URL集合进行去重，而不是原始URL
    processed_normalized_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}  # 用于处理域名冲突

    # 处理所有分类
    for category in tqdm(categories, desc="处理分类", unit="分类"):
        process_category(category, processed_normalized_urls, processed_domains, processed_data)

    # 处理结果统计和输出
    logger.info(f"所有分类处理完成，共获取 {len(processed_data)} 条不重复数据")
    if processed_data:
        print("\n按分类统计:")
        category_counts = Counter(item.category for item in processed_data)
        for cat, count in category_counts.items():
            print(f"- {cat}: {count} 条")

        print("\n前5条数据示例:")
        for i, item in enumerate(processed_data[:5], 1):
            print(f"{i}. [{item.category}] {item.name} - {item.url} ({item.local_filename}) - {item.description}")

        # 生成SQL文件
        sql_content = generate_sql_statements(processed_data)
        sql_file_path = "mtab_import.sql"
        save_file(sql_content, sql_file_path)

        print(f"\nSQL导入文件已生成: {sql_file_path}")
        print(f"包含 {len(sql_content.split('INSERT')) - 1} 条INSERT语句")
    else:
        logger.warning("未处理任何数据")

    logger.info("mTab多分类网站书签导出工具执行完成")


if __name__ == "__main__":
    main()
