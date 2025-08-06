#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/17
# @Desc  : mTab必应壁纸导入脚本，设置必应壁纸分类为2
import re
import time
from datetime import datetime

import requests

# API请求基础URL
BASE_URL = "https://api.codelife.cc/bing/list?lang=cn"

# 设置请求头
headers = {
    'Origin': 'https://go.itab.link',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}


def process_url(url):
    """处理壁纸URL，移除冗余参数并统一分辨率"""
    if not url:
        return url

    # 按顺序处理URL
    url = re.sub(r'&rf=[^&]*&pid=hp', '', url)  # 移除广告参数
    url = url.replace('www4.bing.com', 'www.bing.com')  # 统一域名
    url = re.sub(r'(?<!:)//', '/', url)  # 修正双斜杠
    url = re.sub(r'(1920x1080|1366x768|1080x1920)', 'UHD', url)  # 替换各种分辨率

    return url


def fetch_wallpapers(page_num, page_size=16):
    """获取指定页的壁纸数据"""
    url = f"{BASE_URL}&page={page_num}&size={page_size}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # 检查HTTP状态码

        data = response.json()
        if data.get("code") != 200:
            print(f"API返回错误: {data.get('msg')}")
            return None

        return data.get("data", [])

    except requests.exceptions.RequestException as e:
        print(f"网络请求异常: {e}")
        raise  # 直接抛出异常
    except ValueError as e:
        print(f"JSON解析失败: {e}")
        raise  # 直接抛出异常
    except Exception as e:
        print(f"未知异常: {e}")
        raise  # 直接抛出异常


def main():
    """主函数，控制整个爬取流程"""
    wallpapers = []  # 存储处理后的壁纸数据
    page = 1  # 当前页码
    page_size = 16  # 每页大小
    max_wallpapers = 960  # 最大壁纸数量
    processed_urls = set()  # 用于记录已处理的URL

    print(f"开始爬取必应壁纸，目标数量: {max_wallpapers}  ")

    try:
        while True:
            # 获取当前页数据
            print(f"\n=== 正在请求第{page}页 ===")
            wallpaper_list = fetch_wallpapers(page, page_size)

            # 处理壁纸数据
            processed_count = 0
            for wallpaper in wallpaper_list:
                thumb = wallpaper.get("thumb", "")
                raw = wallpaper.get("raw", "")

                thumb = process_url(thumb)
                raw = process_url(raw)

                # 去重逻辑：检查raw和thumb是否都未被处理过
                if thumb and raw and (raw not in processed_urls) and (thumb not in processed_urls):
                    wallpapers.append({"raw": raw, "thumb": thumb})
                    processed_urls.add(raw)
                    processed_urls.add(thumb)
                    processed_count += 1

                    # 检查是否达到最大数量
                    if len(wallpapers) >= max_wallpapers:
                        print(f"已获取{len(wallpapers)}张壁纸，达到最大限制")
                        break

            print(f"第{page}页: 成功处理 {processed_count}/{len(wallpaper_list)} 条数据")
            print(f"累计已获取: {len(wallpapers)} 张壁纸")

            # 检查是否需要继续
            if len(wallpapers) >= max_wallpapers:
                break

            page += 1
            time.sleep(1)  # 控制爬取频率

    except Exception as e:
        print(f"发生致命错误，终止爬取: {e}")

    # 自动增补逻辑：如果去重后数量不足，继续爬取更多页面
    if len(wallpapers) < max_wallpapers:
        print(f"去重后壁纸数量不足，需要增补 {max_wallpapers - len(wallpapers)} 张")

        try:
            while len(wallpapers) < max_wallpapers:
                print(f"\n=== 正在增补数据，请求第{page}页 ===")
                wallpaper_list = fetch_wallpapers(page, page_size)

                processed_count = 0
                for wallpaper in wallpaper_list:
                    thumb = wallpaper.get("thumb", "")
                    raw = wallpaper.get("raw", "")

                    thumb = process_url(thumb)
                    raw = process_url(raw)

                    if thumb and raw and (raw not in processed_urls) and (thumb not in processed_urls):
                        wallpapers.append({"raw": raw, "thumb": thumb})
                        processed_urls.add(raw)
                        processed_urls.add(thumb)
                        processed_count += 1

                        if len(wallpapers) >= max_wallpapers:
                            print(f"已获取{len(wallpapers)}张壁纸，达到最大限制")
                            break

                print(f"第{page}页: 成功增补 {processed_count}/{len(wallpaper_list)} 条数据")
                print(f"累计已获取: {len(wallpapers)} 张壁纸")

                if len(wallpapers) >= max_wallpapers:
                    break

                page += 1
                time.sleep(1)

        except Exception as e:
            print(f"增补过程中发生错误: {e}")

    # 生成SQL文件
    if wallpapers:
        create_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = f"bing_wallpapers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"-- 必应壁纸SQL插入语句\n-- 生成时间: {create_time}\n\n")

            for wallpaper in wallpapers:
                raw = wallpaper["raw"].replace("'", "''")
                thumb = wallpaper["thumb"].replace("'", "''")
                sql = (f"INSERT INTO `mtab`.`wallpaper` "
                       f"(`type`, `folder`, `mime`, `url`, `cover`, `create_time`, `name`, `sort`) "
                       f"VALUES (0, 2, 0, '{raw}', '{thumb}', '2025-01-01 00:00:00', NULL, 999);\n")
                f.write(sql)

        print(f"\n成功生成SQL文件: {filename}，共{len(wallpapers)}条记录")
    else:
        print("\n未获取到任何壁纸数据")


if __name__ == "__main__":
    main()
