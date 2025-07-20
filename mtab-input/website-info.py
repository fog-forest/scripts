#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/18
# @Desc  : mTab多分类网站书签导出工具

import asyncio
import io
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

# HTTP请求配置
HTTP_CONFIG = {
    'timeout': 10,
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,en;q=0.6',
    }
}

CATEGORY_IDS = {
    "ai": 1,
    "app": 2,
    "news": 3,
    "music": 4,
    "tech": 5,
    "photos": 6,
    "life": 7,
    "education": 8,
    "entertainment": 9,
    "shopping": 10,
    "social": 11,
    "read": 12,
    "sports": 13,
    "finance": 14,
    "others": 15
}


@dataclass
class WebsiteData:
    """网站数据结构"""
    name: str
    url: str
    description: str
    img_src: str
    local_filename: str
    category: str
    background_color: str  # 新增字段


def clear_directory(directory: str) -> None:
    """清空目录中的所有文件，若目录不存在则创建"""
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    import shutil
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"无法删除 {file_path}: {e}")
    else:
        os.makedirs(directory)


def save_file(content: str, file_path: str) -> None:
    """保存内容到文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def validate_and_process_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """验证URL有效性并处理协议，只保留根路径并确保以/结尾"""
    if not url.startswith(('http://', 'https://')):
        return None, f"URL缺少协议前缀: {url}"

    # 解析URL
    from urllib.parse import urlparse
    parsed = urlparse(url)

    # 构建只包含协议、域名和端口的基础URL
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # HTTP转HTTPS
    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')

    # 确保URL以/结尾
    if not base_url.endswith('/'):
        base_url += '/'

    # 验证URL格式
    if not validators.url(base_url.rstrip('/')):  # validators不接受末尾的/
        return None, f"URL格式无效: {base_url}"

    return base_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """检查URL可访问性，使用GET请求获取真实状态码和最终URL"""
    try:
        response = requests.get(
            url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout'],
            allow_redirects=True
        )
        final_url = response.url  # 获取最终访问的URL（处理重定向后）

        # 再次处理最终URL，确保只保留根路径并以/结尾
        final_base_url, error = validate_and_process_url(final_url)
        if not final_base_url:
            return False, f"处理最终URL失败: {error} URL: {url}", url

        if response.status_code >= 400:
            return False, f"URL不可访问({response.status_code}), URL: {url}", final_base_url
        return True, None, final_base_url
    except requests.RequestException as e:
        return False, f"URL检查失败({str(e)[:20]}) URL: {url}", url


def compress_svg(svg_content: str) -> str:
    """安全压缩SVG内容，避免破坏XML结构"""
    # 移除注释
    svg_content = re.sub(r'<!--.*?-->', '', svg_content, flags=re.DOTALL)

    # 合并空格，但保留标签内的空格
    lines = []
    for line in svg_content.split('\n'):
        line = line.strip()
        if line:
            lines.append(' '.join(line.split()))

    return ''.join(lines)


def image_to_svg(img_response: requests.Response) -> str:
    """将图片转换为压缩的SVG格式，确保格式正确"""
    try:
        img = Image.open(io.BytesIO(img_response.content))
        img_base64 = b64encode(img_response.content).decode('utf-8')

        # 创建结构完整的SVG，确保所有属性都有引号
        svg_template = """<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">
            <image href="data:image/{};base64,{}" width="{}" height="{}" preserveAspectRatio="xMidYMid meet"/>
        </svg>"""

        # 尝试确定图片类型
        content_type = img_response.headers.get('Content-Type', 'png')
        img_format = content_type.split('/')[-1].lower()
        if img_format not in ['png', 'jpeg', 'jpg', 'gif']:
            img_format = 'png'  # 默认为PNG

        # 生成SVG
        svg_content = svg_template.format(
            img.width, img.height, img_format, img_base64, img.width, img.height
        )

        return compress_svg(svg_content)
    except Exception as e:
        raise ValueError(f"图片转换失败: {e}")


def validate_svg(svg_content: str) -> bool:
    """简单验证SVG内容是否有效"""
    return all(tag in svg_content for tag in ['<svg', '</svg>', '<image'])


def generate_filename(url: str, processed_domains: Dict[str, Dict[str, str]],
                      processed_data: List[WebsiteData]) -> Tuple[str, Optional[str]]:
    """生成图标文件名：仅主域名相同但后缀不同时添加后缀"""
    # 处理URL时已经确保以/结尾，这里先去掉/再提取域名
    url_without_slash = url.rstrip('/')
    ext = extract(url_without_slash)
    main_domain = ext.domain  # 主域名（如qq、baidu）
    suffix = ext.suffix  # 后缀（如com、cn）

    # 基础文件名（无后缀，如qq.svg）
    base_filename = f"{main_domain}.svg"
    # 带后缀的文件名（仅主域名相同但后缀不同时使用，如qq-com.svg）
    suffix_filename = f"{main_domain}-{suffix}.svg"

    # 情况1：主域名未被处理过 → 使用基础文件名
    if main_domain not in processed_domains:
        return base_filename, None

    # 情况2：主域名已处理过 → 检查后缀是否相同
    existing_info = processed_domains[main_domain]
    existing_suffix = existing_info['suffix']
    existing_filename = existing_info['filename']
    existing_file_path = os.path.join('icons', existing_filename)

    # 子情况2.1：主域名相同且后缀相同 → 保持基础文件名
    if existing_suffix == suffix:
        return base_filename, None

    # 子情况2.2：主域名相同但后缀不同 → 两者都添加后缀
    new_existing_filename = f"{main_domain}-{existing_suffix}.svg"
    os.rename(existing_file_path, os.path.join('icons', new_existing_filename))

    # 更新已处理数据中的文件名
    for item in processed_data:
        if item.local_filename == existing_filename:
            item.local_filename = new_existing_filename
            break

    # 更新processed_domains记录
    processed_domains[main_domain]['filename'] = new_existing_filename

    return suffix_filename, f"主域名相同后缀不同，添加后缀区分: {existing_filename} → {new_existing_filename}"


def download_and_save_image(img_src: str, filename: str) -> Tuple[bool, str]:
    """下载图片并保存为SVG格式"""
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
                return True, "已转换为高度压缩SVG"
            else:
                return False, "生成的SVG文件无效"

    except Exception as e:
        return False, f"图片处理失败({str(e)})"


def expand_color_format(color: str) -> str:
    """将简写的颜色格式（如#fff）扩展为标准格式（如#ffffff），如果颜色为空则返回空字符串"""
    if not color:  # 新增：如果颜色为空字符串，直接返回空字符串
        return ''

    if not color.startswith('#'):
        return color  # 不是颜色格式，直接返回

    color = color.lstrip('#')
    if len(color) == 3:  # 简写格式 #fff
        return f"#{color[0]}{color[0]}{color[1]}{color[1]}{color[2]}{color[2]}"
    elif len(color) == 6:  # 标准格式 #ffffff
        return f"#{color}"
    else:
        return color  # 无法识别的格式，直接返回原字符串


def clean_description(desc: str, url: str) -> str:
    """清理description字段，处理空值时调用API获取，提取首个句号前的内容"""
    # 如果是None或字符串"none"（忽略大小写），尝试调用API
    if desc is None or (isinstance(desc, str) and desc.strip().lower() == 'none'):
        api_desc = fetch_website_description(url)
        return api_desc if api_desc else "暂无描述"

    # 确保desc是字符串类型
    if not isinstance(desc, str):
        desc = str(desc)

    # 移除换行符和多余空格
    desc = desc.strip().replace('\n', ' ').replace('\r', ' ')

    # 如果处理后为空字符串，尝试调用API
    if not desc:
        api_desc = fetch_website_description(url)
        return api_desc if api_desc else "暂无描述"

    # 检查是否包含大量乱码字符
    if re.search(r'[^\x00-\x7F]{5,}', desc):  # 连续5个以上非ASCII字符
        return "暂无描述"

    # 提取第一个句号或英文句号之前的内容
    for punct in ['。', '.']:
        if punct in desc:
            desc = desc.split(punct, 1)[0].strip() + punct
            break

    return desc


async def fetch_website_description(url: str) -> Optional[str]:
    """异步尝试从多个API获取网站描述，使用处理后的URL"""
    if not url:
        return None

    # 定义API列表及其解析逻辑
    api_list = [
        {
            "name": "cenguigui",
            "url_template": "https://api.cenguigui.cn/api/ico/ico.php?url={}",
            "parse_func": lambda data: data.get('data', {}).get('description', '')
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

    # 创建会话
    async with aiohttp.ClientSession(headers=HTTP_CONFIG['headers']) as session:
        tasks = []
        for api in api_list:
            # 构建API请求URL
            from urllib.parse import quote
            encoded_url = quote(url)
            api_url = api['url_template'].format(encoded_url)

            # 创建异步任务
            tasks.append(fetch_api(session, api_url, api))

        # 并发执行所有API请求
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理结果
        for result in results:
            if isinstance(result, Exception):
                print(f"API请求异常: {result}")
                continue

            api_name, website_desc = result
            if website_desc:
                # 简单清理API返回的描述
                website_desc = website_desc.strip().replace('\n', ' ').replace('\r', ' ')
                if website_desc:
                    print(f"从 {api_name} API 获取描述成功: {url}")
                    return website_desc

        # 所有API都失败
        print(f"所有API均无法获取描述: {url}")
        return None


async def fetch_api(session, api_url, api):
    """执行单个API请求的协程"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # 发送请求，每次重试增加超时时间
            timeout = aiohttp.ClientTimeout(total=HTTP_CONFIG['timeout'] * (attempt + 1))
            async with session.get(api_url, timeout=timeout) as response:
                response.raise_for_status()
                data = await response.json()

                # 提取description
                website_desc = api['parse_func'](data)
                return api['name'], website_desc

        except asyncio.TimeoutError:
            print(f"{api['name']} API 请求超时，尝试第{attempt + 1}/{max_retries}次重试")
            if attempt == max_retries - 1:
                print(f"{api['name']} API 所有重试均超时")
        except Exception as e:
            print(f"{api['name']} API 请求失败，尝试第{attempt + 1}/{max_retries}次重试: {e}")
            if attempt == max_retries - 1:
                print(f"{api['name']} API 所有重试均失败")

    return api['name'], None


def process_category(category: str, processed_urls: Set[str],
                     processed_domains: Dict[str, Dict[str, str]],
                     processed_data: List[WebsiteData]) -> None:
    """处理单个分类的数据"""
    base_url = 'https://api.codelife.cc/website/list'
    lang = 'zh'
    name = ''
    source = 'itab'
    page = 1

    while True:
        full_url = f"{base_url}?lang={lang}&type={category}&page={page}&name={name}&source={source}"

        try:
            # 请求数据
            response = requests.get(
                full_url,
                headers=HTTP_CONFIG['headers'],
                timeout=HTTP_CONFIG['timeout']
            )
            response.raise_for_status()
            data = response.json()

            # 若当前页无数据，返回
            if not data.get('data', []):
                break

            # 处理当前页数据
            items_iter = tqdm(data['data'], desc=f"分类[{category}]第{page}页", unit="项", leave=False)
            for item in items_iter:
                url = item.get('url', '')
                img_src = item.get('imgSrc', '')
                background_color = item.get('backgroundColor', '')
                description = item.get('description', '')

                # 验证并处理URL（只保留根路径并确保以/结尾）
                clean_url, error = validate_and_process_url(url)
                if not clean_url:
                    items_iter.set_postfix(status=error)
                    continue

                # 检查URL是否已处理过
                if clean_url in processed_urls:
                    items_iter.set_postfix(status="URL已存在（去重）")
                    continue

                # 检查URL可访问性，获取最终URL
                accessible, error, final_url = check_url_accessibility(clean_url)
                if not accessible:
                    items_iter.set_postfix(status=error)
                    continue

                # 使用最终URL（处理重定向后）
                clean_url = final_url

                # 使用异步方式获取网站描述
                loop = asyncio.get_event_loop()
                clean_desc = loop.run_until_complete(fetch_website_description(clean_url))
                if not clean_desc:
                    clean_desc = "暂无描述"

                # 扩展颜色格式
                expanded_color = expand_color_format(background_color)

                # 生成文件名
                filename, conflict_msg = generate_filename(clean_url, processed_domains, processed_data)

                # 下载并保存图片
                success, status = download_and_save_image(img_src, filename)
                if not success:
                    items_iter.set_postfix(status=status)
                    continue

                # 更新处理状态
                postfix = status
                if conflict_msg:
                    postfix += f", {conflict_msg}"
                items_iter.set_postfix(status=postfix)

                # 记录已处理的URL和域名信息
                processed_urls.add(clean_url)
                # 处理URL时已经确保以/结尾，这里先去掉/再提取域名
                url_without_slash = clean_url.rstrip('/')
                domain = extract(url_without_slash)
                processed_domains[domain.domain] = {
                    'suffix': domain.suffix,
                    'filename': filename
                }
                processed_data.append(WebsiteData(
                    name=item.get('name', ''),
                    url=clean_url,
                    description=clean_desc,  # 使用清理后的描述
                    img_src=img_src,
                    local_filename=filename,
                    category=category,
                    background_color=expanded_color  # 保存扩展后的颜色
                ))

            items_iter.close()
            page += 1
            time.sleep(0.5 + random.uniform(0, 0.5))  # 随机延迟

        except Exception as e:
            tqdm.write(f"分类[{category}]第{page}页处理失败: {e}")
            page += 1
            time.sleep(1 + random.uniform(0, 1))


def generate_sql_statements(websites: List[WebsiteData]) -> str:
    """生成SQL插入语句"""
    sql_statements = []
    for site in websites:
        # 转义单引号
        escaped_name = site.name.replace("'", "''")
        escaped_description = site.description.replace("'", "''")

        # 提取完整域名（包括子域名）
        domain_parts = extract(site.url.rstrip('/'))
        if domain_parts.subdomain:
            domain = f"{domain_parts.subdomain}.{domain_parts.registered_domain}"
        else:
            domain = domain_parts.registered_domain

        # 获取分类ID
        category_id = CATEGORY_IDS.get(site.category, 15)  # 默认15为others

        # 构建SQL语句，包含background_color
        sql = f"""INSERT INTO `mtab`.`linkstore` 
(`name`, `src`, `url`, `type`, `size`, `create_time`, `hot`, `area`, `tips`, `domain`, `app`, `install_num`, `bgColor`, `vip`, `custom`, `user_id`, `status`, `group_ids`) 
VALUES 
('{escaped_name}', 'https://oss.amogu.cn/icon/website/{site.local_filename}', '{site.url}', 'icon', '1x1', '2025-01-01 00:00:00', 0, {category_id}, '{escaped_description}', '{domain}', 0, 0, '{site.background_color}', 0, NULL, NULL, 1, 0);"""

        sql_statements.append(sql)

    return "\n".join(sql_statements)


def main():
    """主函数"""
    # 清空并创建icons目录
    clear_directory('icons')
    print("已清空icons目录，准备开始处理数据...")

    # 配置待遍历的分类列表
    categories = ["ai", "app"]

    # 存储处理后的数据和已处理的URL/域名
    processed_data: List[WebsiteData] = []
    processed_urls: Set[str] = set()
    processed_domains: Dict[str, Dict[str, str]] = {}

    # 遍历所有分类
    for category in tqdm(categories, desc="处理分类", unit="分类"):
        process_category(category, processed_urls, processed_domains, processed_data)

    # 结果统计与展示
    print(f"\n所有分类处理完成，共获取 {len(processed_data)} 条不重复数据")
    if processed_data:
        print("\n按分类统计:")
        category_counts = Counter(item.category for item in processed_data)
        for cat, count in category_counts.items():
            print(f"- {cat}: {count} 条")

        print("\n文件名规则示例:")
        examples = {}
        for item in processed_data:
            if '-' in item.local_filename and item.local_filename not in examples:
                examples[item.local_filename] = "主域名相同但后缀不同（加后缀）"
            elif '-' not in item.local_filename and item.local_filename not in examples:
                examples[item.local_filename] = "主域名+后缀相同（无后缀）"
        for filename, rule in list(examples.items())[:5]:
            print(f"- {filename}: {rule}")

        print("\n前5条数据示例:")
        for i, item in enumerate(processed_data[:5], 1):
            print(f"{i}. [{item.category}] {item.name} - {item.url} ({item.local_filename}) - {item.description}")

        # 生成SQL语句
        sql_content = generate_sql_statements(processed_data)

        # 保存SQL文件
        sql_file_path = "mtab_import.sql"
        save_file(sql_content, sql_file_path)

        print(f"\nSQL导入文件已生成: {sql_file_path}")
        print(f"包含 {len(processed_data)} 条INSERT语句")


if __name__ == "__main__":
    main()