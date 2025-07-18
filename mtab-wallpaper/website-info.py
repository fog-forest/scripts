#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/18
# @Desc  : mTab多分类网站书签导出工具

import io
import os
import random
import re
import time
from base64 import b64encode
from collections import Counter
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional

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


@dataclass
class WebsiteData:
    """网站数据结构"""
    name: str
    url: str
    description: str
    img_src: str
    local_filename: str
    category: str


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
    """验证URL有效性并处理协议"""
    if not url.startswith(('http://', 'https://')):
        return None, f"URL缺少协议前缀: {url}"

    # HTTP转HTTPS
    if url.startswith('http://'):
        url = url.replace('http://', 'https://')

    # 清理URL（移除查询参数）
    clean_url = url.split('?')[0]

    # 验证URL格式
    if not validators.url(clean_url):
        return None, f"URL格式无效: {clean_url}"

    return clean_url, None


def check_url_accessibility(url: str) -> Tuple[bool, Optional[str]]:
    """检查URL可访问性"""
    try:
        head_response = requests.head(
            url,
            headers=HTTP_CONFIG['headers'],
            timeout=HTTP_CONFIG['timeout']
        )
        if head_response.status_code >= 400:
            return False, f"URL不可访问({head_response.status_code})"
        return True, None
    except requests.RequestException as e:
        return False, f"URL检查失败({str(e)[:20]})"


def compress_svg(svg_content: str) -> str:
    """压缩SVG内容"""
    svg_content = re.sub(r'<!--.*?-->', '', svg_content, flags=re.DOTALL)  # 移除注释
    svg_content = re.sub(r'\s+', ' ', svg_content)  # 合并空格
    svg_content = re.sub(r'([a-zA-Z0-9])="([a-zA-Z0-9]+)"', r'\1=\2', svg_content)  # 移除简单属性的引号
    return svg_content.strip()


def image_to_svg(img_response: requests.Response) -> str:
    """将图片转换为压缩的SVG格式"""
    try:
        img = Image.open(io.BytesIO(img_response.content))
        img_base64 = b64encode(img_response.content).decode('utf-8')

        # 创建最小化的SVG结构
        svg_content = f'<svg xmlns="http://www.w3.org/2000/svg" width="{img.width}" height="{img.height}"><image href="data:image/png;base64,{img_base64}" width="{img.width}" height="{img.height}"/></svg>'
        return compress_svg(svg_content)
    except Exception as e:
        raise ValueError(f"图片转换失败: {e}")


def validate_svg(svg_content: str) -> bool:
    """简单验证SVG内容是否有效"""
    return all(tag in svg_content for tag in ['<svg', '</svg>', '<image'])


def generate_filename(url: str, processed_domains: Dict[str, Dict[str, str]],
                      processed_data: List[WebsiteData]) -> Tuple[str, Optional[str]]:
    """生成图标文件名：仅主域名相同但后缀不同时添加后缀"""
    ext = extract(url)
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

                # 验证并处理URL
                clean_url, error = validate_and_process_url(url)
                if not clean_url:
                    items_iter.set_postfix(status=error)
                    continue

                # 检查URL是否已处理过
                if clean_url in processed_urls:
                    items_iter.set_postfix(status="URL已存在（去重）")
                    continue

                # 检查URL可访问性
                accessible, error = check_url_accessibility(clean_url)
                if not accessible:
                    items_iter.set_postfix(status=error)
                    continue

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
                processed_domains[clean_url] = {
                    'suffix': extract(clean_url).suffix,
                    'filename': filename
                }
                processed_data.append(WebsiteData(
                    name=item.get('name', ''),
                    url=clean_url,
                    description=item.get('description', ''),
                    img_src=img_src,
                    local_filename=filename,
                    category=category
                ))

            items_iter.close()
            page += 1
            time.sleep(0.5 + random.uniform(0, 0.5))  # 随机延迟

        except Exception as e:
            tqdm.write(f"分类[{category}]第{page}页处理失败: {e}")
            page += 1
            time.sleep(1 + random.uniform(0, 1))


def main():
    """主函数"""
    # 清空并创建icons目录
    clear_directory('icons')
    print("已清空icons目录，准备开始处理数据...")

    # 配置待遍历的分类列表
    categories = ["ai", "app", "news", "music", "tech", "photos", "life",
                  "education", "entertainment", "shopping", "social",
                  "read", "sports", "finance", "others"]

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
            print(f"{i}. [{item.category}] {item.name} - {item.url} ({item.local_filename})")


if __name__ == "__main__":
    main()
