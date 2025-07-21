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


# 配置日志
def setup_logger():
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


logger = setup_logger()

# HTTP请求配置
HTTP_CONFIG = {
    'timeout': 10,
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    }
}

CATEGORY_IDS = {
    "ai": 1, "app": 2, "news": 3, "music": 4,
    "tech": 5, "photos": 6, "life": 7, "education": 8,
    "entertainment": 9, "shopping": 10, "social": 11, "read": 12,
    "sports": 13, "finance": 14, "others": 15
}


@dataclass
class WebsiteData:
    name: str
    url: str
    description: str
    img_src: str
    local_filename: str
    category: str
    background_color: str


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
        logger.info(f"创建目录: {directory}")


def save_file(content: str, file_path: str) -> None:
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        logger.error(f"保存文件失败: {file_path}, 错误: {e}")


def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    if not url.startswith(('http://', 'https://')):
        return None, f"URL缺少协议前缀: {url}"

    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')

    if not base_url.endswith('/'):
        base_url += '/'

    if not validators.url(base_url.rstrip('/')):
        return None, f"URL格式无效: {base_url}"

    return base_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        session = requests.Session()
        session.max_redirects = 10

        response = session.get(
            url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=True
        )

        final_url = response.url
        final_base_url, error = validate_and_process_url(final_url)
        if not final_base_url:
            return False, f"处理最终URL失败: {error}", url

        if response.status_code >= 400:
            return False, f"URL不可访问({response.status_code})", final_base_url
        return True, None, final_base_url
    except requests.TooManyRedirects:
        return False, "URL重定向次数过多", url
    except requests.RequestException as e:
        return False, f"URL检查失败({str(e)[:20]})", url


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


def generate_filename(url: str, processed_domains: Dict[str, Dict[str, str]],
                      processed_data: List[WebsiteData]) -> Tuple[str, Optional[str]]:
    url_without_slash = url.rstrip('/')
    ext = extract(url_without_slash)
    main_domain = ext.domain
    suffix = ext.suffix

    base_filename = f"{main_domain}.svg"
    suffix_filename = f"{main_domain}-{suffix}.svg"

    if main_domain not in processed_domains:
        return base_filename, None

    existing_info = processed_domains[main_domain]
    existing_suffix = existing_info['suffix']
    existing_filename = existing_info['filename']
    existing_file_path = os.path.join('icons', existing_filename)

    if existing_suffix == suffix:
        return base_filename, None

    new_existing_filename = f"{main_domain}-{existing_suffix}.svg"

    try:
        os.rename(existing_file_path, os.path.join('icons', new_existing_filename))
    except Exception as e:
        logger.error(f"文件重命名失败: {existing_filename} → {new_existing_filename}, 错误: {e}")
        return suffix_filename, f"文件重命名失败: {existing_filename} → {new_existing_filename}"

    for item in processed_data:
        if item.local_filename == existing_filename:
            item.local_filename = new_existing_filename
            break

    processed_domains[main_domain]['filename'] = new_existing_filename

    return suffix_filename, f"添加后缀区分: {existing_filename} → {new_existing_filename}"


def download_and_save_image(img_src: str, filename: str) -> Tuple[bool, str]:
    try:
        img_response = requests.get(
            img_src,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout']
        )
        img_response.raise_for_status()

        file_path = os.path.join('icons', filename)

        if img_src.lower().endswith('.svg'):
            svg_content = compress_svg(img_response.text)
            save_file(svg_content, file_path)
            return True, "SVG已压缩保存"
        else:
            svg_content = image_to_svg(img_response)
            if validate_svg(svg_content):
                save_file(svg_content, file_path)
                return True, "已转换为SVG"
            else:
                return False, "生成的SVG文件无效"

    except Exception as e:
        return False, f"图片处理失败({str(e)})"


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


def clean_description(url: str, original_desc: str = "") -> Optional[str]:
    """
    先通过API获取网站描述，若获取失败则检查原始描述是否有效，
    若均无效则返回None
    """
    api_desc = fetch_website_description_sync(url)
    if api_desc:
        cleaned_api_desc = clean_api_description(api_desc)
        if cleaned_api_desc:
            logger.debug(f"从API获取有效描述: {url}")
            return cleaned_api_desc

    if not is_description_invalid(original_desc):
        logger.debug(f"使用原始有效描述: {url}")
        return original_desc.strip().replace('\n', '').replace('\r', '')

    logger.warning(f"无法为URL获取有效描述: {url}")
    return None


def is_description_invalid(desc: str) -> bool:
    if not desc:
        return True
    desc = desc.strip().lower()
    if desc in ['none', '暂无描述']:
        return True
    if re.search(r'[^\x00-\x7F]{10,}', desc):
        return True
    return False


def clean_api_description(desc: str) -> Optional[str]:
    desc = desc.strip().replace('\n', '').replace('\r', '')
    if not desc:
        return None

    for punct in ['。', '.']:
        if punct in desc:
            desc = desc.split(punct, 1)[0].strip() + punct
            break

    return desc if desc else None


def fetch_website_description_sync(url: str) -> Optional[str]:
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
    except Exception as e:
        return None


async def fetch_website_description(url: str) -> Optional[str]:
    if not url:
        return None

    api_list = [
        {
            "name": "cenguigui",
            "url_template": "https://api.cenguigui.cn/api/ico/ico.php?url={}",
            "parse_func": lambda data: data.get('data', {}).get('description', '')
        },
        {
            "name": "shanhe",
            "url_template": "https://shanhe.kim/api/wz/web_tdk.php?url={}",
            "parse_func": lambda data: data.get('description', '') if data.get('code') == 1 else ''
        },
        {
            "name": "ahfi",
            "url_template": "https://api.ahfi.cn/api/websiteinfo?url={}",
            "parse_func": lambda data: data.get('data', {}).get('description', '')
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

        for result in results:
            if isinstance(result, Exception):
                continue

            api_name, website_desc = result
            if website_desc:
                website_desc = website_desc.strip().replace('\n', ' ').replace('\r', ' ')
                if website_desc:
                    return website_desc

        return None


async def fetch_api(session, api_url, api):
    api_name = api['name']
    max_retries = 3
    for attempt in range(max_retries):
        try:
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
                return api['name'], None

    return api['name'], None


def process_category(category: str, processed_urls: Set[str],
                     processed_domains: Dict[str, Dict[str, str]],
                     processed_data: List[WebsiteData]) -> None:
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

            if not data.get('data', []):
                logger.info(f"分类[{category}]第{page}页无数据，处理完成")
                break

            for item in tqdm(data['data'], desc=f"分类[{category}]第{page}页", unit="项"):
                url = item.get('url', '')
                img_src = item.get('imgSrc', '')
                background_color = item.get('backgroundColor', '')
                original_description = item.get('description', '')

                clean_url, error = validate_and_process_url(url)
                if not clean_url:
                    logger.warning(f"无效URL: {url} - {error}")
                    continue

                if clean_url in processed_urls:
                    continue

                accessible, error, final_url = check_url_accessibility(clean_url)
                if not accessible:
                    logger.warning(f"不可访问URL: {url} - {error}")
                    continue

                clean_desc = clean_description(final_url, original_description)
                if not clean_desc:
                    continue

                expanded_color = expand_color_format(background_color)

                filename, conflict_msg = generate_filename(final_url, processed_domains, processed_data)

                success, status = download_and_save_image(img_src, filename)
                if not success:
                    logger.warning(f"图片处理失败: {img_src}, 状态: {status}")
                    continue

                processed_urls.add(final_url)
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

            page += 1
            time.sleep(0.5 + random.uniform(0, 0.5))

        except Exception as e:
            logger.error(f"分类[{category}]第{page}页处理失败: {e}")
            page += 1
            time.sleep(1 + random.uniform(0, 1))


def generate_sql_statements(websites: List[WebsiteData]) -> str:
    sql_statements = []
    for site in websites:
        escaped_name = site.name.replace("'", "''")
        escaped_description = site.description.replace("'", "''")

        domain_parts = extract(site.url.rstrip('/'))
        if domain_parts.subdomain:
            domain = f"{domain_parts.subdomain}.{domain_parts.registered_domain}"
        else:
            domain = domain_parts.registered_domain

        category_id = CATEGORY_IDS.get(site.category, 15)

        sql = f"""INSERT INTO `mtab`.`linkstore` 
(`name`, `src`, `url`, `type`, `size`, `create_time`, `hot`, `area`, `tips`, `domain`, `app`, `install_num`, `bgColor`, `vip`, `custom`, `user_id`, `status`, `group_ids`) 
VALUES 
('{escaped_name}', 'https://oss.amogu.cn/icon/website/{site.local_filename}', '{site.url}', 'icon', '1x1', '2025-01-01 00:00:00', 0, {category_id}, '{escaped_description}', '{domain}', 0, 0, '{site.background_color}', 0, NULL, NULL, 1, 0);"""

        sql_statements.append(sql)

    return "\n".join(sql_statements)


def main():
    logger.info("开始执行mTab多分类网站书签导出工具")

    clear_directory('icons')
    logger.info("已清空icons目录")

    categories = ["ai", "app"]
    logger.info(f"准备处理分类: {', '.join(categories)}")

    processed_data: List[WebsiteData] = []
    processed_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}

    for category in tqdm(categories, desc="处理分类", unit="分类"):
        process_category(category, processed_urls, processed_domains, processed_data)

    logger.info(f"所有分类处理完成，共获取 {len(processed_data)} 条不重复数据")
    if processed_data:
        print("\n按分类统计:")
        category_counts = Counter(item.category for item in processed_data)
        for cat, count in category_counts.items():
            print(f"- {cat}: {count} 条")

        print("\n前5条数据示例:")
        for i, item in enumerate(processed_data[:5], 1):
            print(f"{i}. [{item.category}] {item.name} - {item.url} ({item.local_filename}) - {item.description}")

        sql_content = generate_sql_statements(processed_data)
        sql_file_path = "mtab_import.sql"
        save_file(sql_content, sql_file_path)

        print(f"\nSQL导入文件已生成: {sql_file_path}")
        print(f"包含 {len(processed_data)} 条INSERT语句")
    else:
        logger.warning("未处理任何数据")

    logger.info("mTab多分类网站书签导出工具执行完成")


if __name__ == "__main__":
    main()
