#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/25
# @Desc  : SQL URL浏览器与截图工具（URL自动修正版）
# @Func  : 从SQL文件中提取URL，批量获取网站信息并管理，自动修正URL域名不匹配问题

# 公共配置项
# 截图重试配置
SCREENSHOT_MAX_RETRIES = 3  # 最大重试次数
SCREENSHOT_RETRY_DELAY = 2  # 重试延迟（秒）
MAX_THREADS = 4  # 最大同时运行的线程数量

# 分类映射关系
CATEGORY_IDS = {
    "ai": 1, "app": 1, "news": 2, "music": 3,
    "tech": 4, "photos": 5, "life": 6, "education": 9,
    "entertainment": 8, "shopping": 9, "social": 10, "read": 11,
    "sports": 12, "finance": 13, "others": 14
}
ID_TO_CATEGORY = {v: k for k, v in CATEGORY_IDS.items()}  # 反向映射：ID到分类名称

# 域名白名单配置
DOMAIN_WHITELIST = [
    "google.com", "yandex.com"
]

import json
# 导入模块
import logging
import os
import queue
import re
import tempfile
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from PIL import Image, ImageTk, ImageDraw, ImageFont
from reportlab.graphics import renderPM
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from svglib.svglib import svg2rlg
from webdriver_manager.chrome import ChromeDriverManager


# 配置日志
def setup_logger() -> logging.Logger:
    """配置并返回日志记录器"""
    logger = logging.getLogger('sql_url_browser')
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


class SQLURLBrowser:
    def __init__(self, root):
        """初始化应用程序"""
        self.root = root
        self.root.title("SQL URL浏览器与截图工具")
        self.root.geometry("1200x800")

        # 数据存储
        self.url_data = {}  # {id: data_dict}
        self.id_list = []  # 保持ID的顺序
        self.current_id = None  # 当前选中的ID

        # 临时时存储 - 这些将被自动保存
        self.temp_title_changes = {}  # {id: new_title}
        self.temp_desc_changes = {}  # {id: new_desc}
        self.items_to_discard = set()  # 待丢弃的项ID

        # 历史记录文件路径
        self.history_file = os.path.join(os.getcwd(), ".url_modifications.json")

        # 目录与文件路径
        self.sql_dir = None
        self.icons_dir = None
        self.trash_dir = None
        self.screenshot_dir = None
        self.save_file = os.path.join(os.getcwd(), "mtab_import_save.sql")

        # 浏览器相关
        self.browser = None
        self.thread_pool = None
        self.update_queue = queue.Queue()

        # 初始化UI
        self.init_ui()

        # 绑定事件
        self.bind_events()

        # 加载历史记录
        self.load_history()

        logger.info("应用程序初始化完成")

    def init_ui(self):
        """初始化用户界面"""
        # 设置中文字体支持
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TCombobox", font=("SimHei", 10))

        # 主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件选择区域
        self.create_file_frame()

        # 数据展示区域
        self.create_data_frame()

        # 操作按钮区域
        self.create_action_frame()

        # 结果展示区域
        self.create_result_frame()

        # 状态和进度条
        self.create_status_bar()

        # 白名单配置区域
        self.create_whitelist_frame()

    def create_whitelist_frame(self):
        """创建白名单配置区域"""
        self.whitelist_frame = ttk.LabelFrame(self.main_frame, text="域名白名单", padding="10")
        self.whitelist_frame.pack(fill=tk.X, pady=5)

        self.whitelist_text = ScrolledText(self.whitelist_frame, wrap=tk.WORD, height=3)
        self.whitelist_text.pack(fill=tk.X, padx=5, pady=5)

        # 从配置加载白名单
        self.load_whitelist()

        self.whitelist_button = ttk.Button(self.whitelist_frame, text="保存白名单", command=self.save_whitelist)
        self.whitelist_button.pack(side=tk.RIGHT, padx=5)

    def load_whitelist(self):
        """从配置文件加载白名单"""
        whitelist_path = os.path.join(os.getcwd(), "domain_whitelist.txt")
        if os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    domains = [line.strip() for line in f if line.strip()]
                    self.whitelist_text.delete(1.0, tk.END)
                    self.whitelist_text.insert(tk.END, '\n'.join(domains))
            except Exception as e:
                logger.error(f"加载白名单失败: {str(e)}")
                self.whitelist_text.delete(1.0, tk.END)
                self.whitelist_text.insert(tk.END, '\n'.join(DOMAIN_WHITELIST))
        else:
            # 使用默认白名单
            self.whitelist_text.delete(1.0, tk.END)
            self.whitelist_text.insert(tk.END, '\n'.join(DOMAIN_WHITELIST))

    def save_whitelist(self):
        """保存白名单到配置文件"""
        whitelist_text = self.whitelist_text.get(1.0, tk.END).strip()
        domains = [line.strip() for line in whitelist_text.split('\n') if line.strip()]

        whitelist_path = os.path.join(os.getcwd(), "domain_whitelist.txt")
        try:
            with open(whitelist_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(domains))
            messagebox.showinfo("成功", f"已保存 {len(domains)} 个域名到白名单")
            logger.info(f"已保存白名单: {domains}")
        except Exception as e:
            messagebox.showerror("错误", f"保存白名单失败: {str(e)}")
            logger.error(f"保存白名单失败: {str(e)}")

    def create_file_frame(self):
        """创建文件选择区域"""
        self.file_frame = ttk.LabelFrame(self.main_frame, text="文件选择", padding="10")
        self.file_frame.pack(fill=tk.X, pady=5)

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, width=70)
        self.file_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = ttk.Button(self.file_frame, text="浏览...", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        self.process_button = ttk.Button(self.file_frame, text="处理SQL文件", command=self.process_file)
        self.process_button.pack(side=tk.LEFT, padx=5)

        self.fetch_info_button = ttk.Button(self.file_frame, text="批量获取网站信息",
                                            command=self.fetch_all_site_info, state=tk.DISABLED)
        self.fetch_info_button.pack(side=tk.LEFT, padx=5)

    def create_data_frame(self):
        """创建数据展示区域"""
        self.data_frame = ttk.LabelFrame(self.main_frame, text="URL列表", padding="10")
        self.data_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 创建Treeview和滚动条
        columns = ("id", "name", "url", "category", "status")
        self.url_tree = ttk.Treeview(self.data_frame, columns=columns, show="headings", height=10)

        # 设置列宽和标题
        self.url_tree.column("id", width=50)
        self.url_tree.column("name", width=150)
        self.url_tree.column("url", width=300)
        self.url_tree.column("category", width=100)
        self.url_tree.column("status", width=100)

        self.url_tree.heading("id", text="ID")
        self.url_tree.heading("name", text="网站名称")
        self.url_tree.heading("url", text="URL")
        self.url_tree.heading("category", text="分类")
        self.url_tree.heading("status", text="状态")

        self.url_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree_scroll = ttk.Scrollbar(self.data_frame, orient=tk.VERTICAL, command=self.url_tree.yview)
        self.url_tree.configure(yscroll=self.tree_scroll.set)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def create_action_frame(self):
        """创建操作按钮区域"""
        self.action_frame = ttk.LabelFrame(self.main_frame, text="操作", padding="10")
        self.action_frame.pack(fill=tk.X, pady=5)

        self.open_button = ttk.Button(self.action_frame, text="打开网站", command=self.open_website)
        self.open_button.pack(side=tk.LEFT, padx=5)

        self.prev_button = ttk.Button(self.action_frame, text="上一个", command=self.prev_url)
        self.prev_button.pack(side=tk.LEFT, padx=5)

        self.next_button = ttk.Button(self.action_frame, text="下一个", command=self.next_url)
        self.next_button.pack(side=tk.LEFT, padx=5)

        self.discard_button = ttk.Button(self.action_frame, text="丢弃", command=self.discard_item, state=tk.DISABLED)
        self.discard_button.pack(side=tk.LEFT, padx=5)

        self.save_button = ttk.Button(self.action_frame, text="保存全部", command=self.save_all_items,
                                      state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # 添加清空记录按钮
        self.clear_history_button = ttk.Button(self.action_frame, text="清空记录", command=self.clear_history)
        self.clear_history_button.pack(side=tk.LEFT, padx=5)

    def create_result_frame(self):
        """创建结果展示区域"""
        self.result_frame = ttk.LabelFrame(self.main_frame, text="结果展示", padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 左侧展示图标和截图
        self.left_frame = ttk.Frame(self.result_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 图标区域
        self.icon_frame = ttk.LabelFrame(self.left_frame, text="网站图标", padding="5")
        self.icon_frame.pack(fill=tk.X, pady=5)

        self.icon_label = ttk.Label(self.icon_frame, text="图标将显示在这里", width=10)
        self.icon_label.pack(padx=5, pady=5)

        # 截图区域
        self.screenshot_frame = ttk.LabelFrame(self.left_frame, text="网站截图", padding="5")
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.screenshot_canvas = tk.Canvas(self.screenshot_frame)
        self.screenshot_canvas.pack(fill=tk.BOTH, expand=True)
        self.screenshot_label = ttk.Label(self.screenshot_canvas, text="截图将显示在这里")
        self.screenshot_canvas.create_window((0, 0), window=self.screenshot_label, anchor="nw", tags="window")

        # 右侧展示信息和SQL
        self.right_frame = ttk.Frame(self.result_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 浏览器标签标题区域
        self.browser_title_frame = ttk.LabelFrame(self.right_frame, text="浏览器标签标题（参考）", padding="5")
        self.browser_title_frame.pack(fill=tk.X, pady=5)

        self.browser_title_var = tk.StringVar()
        self.browser_title_label = ttk.Label(self.browser_title_frame, textvariable=self.browser_title_var,
                                             anchor=tk.W, wraplength=400)
        self.browser_title_label.pack(fill=tk.X, padx=5, pady=5)

        # SQL标题编辑区域
        self.title_frame = ttk.LabelFrame(self.right_frame, text="SQL标题（可修改）", padding="5")
        self.title_frame.pack(fill=tk.X, pady=5)

        self.title_var = tk.StringVar()
        self.title_entry = ttk.Entry(self.title_frame, textvariable=self.title_var, width=50)
        self.title_entry.pack(fill=tk.X, padx=5, pady=5)

        # 描述编辑区域
        self.desc_frame = ttk.LabelFrame(self.right_frame, text="网站描述（可修改）", padding="5")
        self.desc_frame.pack(fill=tk.X, pady=5)

        self.desc_text = ScrolledText(self.desc_frame, wrap=tk.WORD, width=40, height=3)
        self.desc_text.pack(fill=tk.X, padx=5, pady=5)

        # URL信息区域
        self.url_frame = ttk.LabelFrame(self.right_frame, text="URL信息", padding="5")
        self.url_frame.pack(fill=tk.X, pady=5)

        self.url_var = tk.StringVar()
        self.url_label = ttk.Label(self.url_frame, textvariable=self.url_var, anchor=tk.W)
        self.url_label.pack(fill=tk.X, padx=5, pady=5)

        # SQL展示区域
        self.sql_frame = ttk.LabelFrame(self.right_frame, text="SQL语句", padding="5")
        self.sql_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.sql_text = ScrolledText(self.sql_frame, wrap=tk.WORD, width=40, height=5)
        self.sql_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_status_bar(self):
        """创建状态条和进度条"""
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_frame, variable=self.progress_var, length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

    def bind_events(self):
        """绑定各类事件"""
        # Treeview选择事件
        self.url_tree.bind("<<TreeviewSelect>>", self.on_url_select)

        # 截图区域大小变化事件
        self.screenshot_canvas.bind("<Configure>", self.on_canvas_configure)

        # 标题和描述编辑事件
        self.title_entry.bind("<Return>", self.update_title)
        self.desc_text.bind("<FocusOut>", self.update_desc)
        self.desc_text.bind("<KeyRelease>", self.update_desc)

        # 键盘事件
        self.root.bind("<Up>", self.on_up_key)
        self.root.bind("<Down>", self.on_down_key)
        self.root.bind("<Delete>", self.on_delete_key)

        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_canvas_configure(self, event):
        """调整截图标签位置以适应窗口大小"""
        self.screenshot_canvas.itemconfig(self.screenshot_canvas.find_withtag("window"), width=event.width)
        # 当画布大小改变时，重新调整当前显示的截图
        if self.current_id and self.current_id in self.url_data:
            self.load_screenshot(self.url_data[self.current_id].copy())

    # 文件处理方法
    def browse_file(self):
        """浏览览并选择SQL文件"""
        file_path = filedialog.askopenfilename(
            title="选择SQL文件",
            filetypes=[("SQL files", "*.sql"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            logger.info(f"已选择文件: {file_path}")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    line_count = sum(1 for line in f)
                self.status_var.set(f"已选择文件，共 {line_count} 行")
            except Exception as e:
                logger.warning(f"无法计算文件行数: {str(e)}")

    def process_file(self):
        """处理SQL文件，提取URL信息"""
        sql_file = self.file_path_var.get()
        if not sql_file or not os.path.exists(sql_file):
            messagebox.showerror("错误", "请选择有效的SQL文件")
            return

        try:
            logger.info(f"开始处理文件: {sql_file}")
            self.sql_dir = os.path.dirname(sql_file)

            # 设置目录
            self.icons_dir = os.path.join(self.sql_dir, "icons")
            self.trash_dir = os.path.join(self.icons_dir, "trash")
            self.screenshot_dir = os.path.join(self.sql_dir, "screenshots")
            for dir_path in [self.icons_dir, self.trash_dir, self.screenshot_dir]:
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)

            self.status_var.set("正在处理SQL文件...")
            self.progress_var.set(0)

            # 清空现有数据
            for item in self.url_tree.get_children():
                self.url_tree.delete(item)
            self.url_data.clear()
            self.id_list.clear()
            self.current_id = None

            # 读取并解析SQL文件
            with open(sql_file, 'r', encoding='utf-8') as f:
                sql_content = f.read()

            # 提取INSERT语句
            insert_pattern = re.compile(
                r"INSERT\s+INTO\s+`mtab`\.`linkstore`\s*\([^)]*\)\s*VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*([^,]*)\s*,\s*([^,]*)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*([^,]*)\s*,\s*([^,]*)\s*,\s*'([^']*)'\s*,\s*([^,]*)\s*,\s*([^,]*)\s*,\s*([^,]*)\s*,\s*([^,]*)\s*,\s*([^)]*)\s*\);",
                re.DOTALL | re.IGNORECASE
            )

            matches = list(insert_pattern.finditer(sql_content))
            total_matches = len(matches)
            logger.info(f"SQL文件中匹配到 {total_matches} 条INSERT语句")

            if total_matches == 0:
                messagebox.showinfo("提示", "未在SQL文件中找到URL记录")
                self.status_var.set("就绪")
                return

            # 处理提取的数据
            for i, match in enumerate(matches):
                try:
                    item_id = i + 1
                    name = match.group(1)
                    src = match.group(2)
                    url = match.group(3)
                    tips = match.group(9)
                    category_id = int(match.group(8))

                    # 标准化初始URL格式
                    url = self.normalize_url(url)

                    category = ID_TO_CATEGORY.get(category_id, "未知")
                    icon_file = os.path.basename(src)
                    screenshot_file = f"screenshot_{item_id}.png"

                    self.url_data[item_id] = {
                        "id": item_id, "name": name, "src": src, "url": url,
                        "tips": tips, "icon_file": icon_file, "screenshot_file": screenshot_file,
                        "sql": match.group(0), "processed": False, "status": "未处理",
                        "title": "", "screenshot_path": os.path.join(self.screenshot_dir, screenshot_file),
                        "category": category
                    }
                    self.id_list.append(item_id)
                except Exception as e:
                    logger.error(f"处理第 {i + 1} 条记录失败: {str(e)}")
                    continue

                # 更新进度
                self.progress_var.set((i + 1) / total_matches * 100)
                self.root.update_idletasks()

            # 在Treeview中显示数据
            for item_id in self.id_list:
                item = self.url_data[item_id]
                # 初始状态值
                status = item["status"]
                name = item["name"]

                self.url_tree.insert("", tk.END, iid=item_id, values=(
                    item["id"], name, item["url"], item["category"], status
                ))

            # 数据加载完成后应用历史记录
            self.apply_history_to_ui()

            # 显示结果统计
            extracted_count = len(self.url_data)
            skipped_count = total_matches - extracted_count
            self.status_var.set(f"处理完成，共找到 {extracted_count} 条URL记录（跳过 {skipped_count} 条）")
            logger.info(f"处理完成，提取 {extracted_count} 条记录，跳过 {skipped_count} 条")

            message = f"已提取 {extracted_count} 条URL记录\n"
            if skipped_count > 0:
                message += f"注意：有 {skipped_count} 条记录因格式问题被跳过"
            messagebox.showinfo("处理结果", message)

            # 启用相关按钮
            self.fetch_info_button.config(state=tk.NORMAL)

            # 选中第一条记录
            if self.id_list:
                first_id = self.id_list[0]
                self.url_tree.selection_set(first_id)
                self.current_id = first_id
                self.update_display()

        except Exception as e:
            self.status_var.set("处理失败")
            messagebox.showerror("错误", f"处理文件时出错: {str(e)}")
            logger.error(f"处理文件时出错: {str(e)}")

    def normalize_url(self, url):
        """标准化URL格式：确保以http/https开头，以/结尾，无路径参数"""
        # 确保URL以http/https开头
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        # 解析URL，提取域名
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc

        # 构建标准化URL：协议+域名+斜杠
        normalized = f"{parsed.scheme}://{domain}/"
        return normalized

    # 数据展示与更新方法
    def on_url_select(self, event):
        """处理Treeview选择事件"""
        selected_items = self.url_tree.selection()
        if not selected_items:
            return

        try:
            new_id = int(selected_items[0])
            if new_id in self.url_data:
                self.current_id = new_id
                self.update_display()
            else:
                logger.warning(f"选中的ID {new_id} 不存在于数据中")
                if self.id_list:
                    self.current_id = self.id_list[0]
                    self.url_tree.selection_set(self.current_id)
                    self.update_display()
        except (ValueError, TypeError) as e:
            logger.error(f"无效的ID格式: {selected_items[0]}, 错误: {str(e)}")
            if self.id_list:
                self.current_id = self.id_list[0]
                self.url_tree.selection_set(self.current_id)
                self.update_display()

    def update_display(self):
        """更新显示内容"""
        if self.current_id is None or self.current_id not in self.url_data:
            # 重置显示
            self.browser_title_var.set("")
            self.title_var.set("")
            self.desc_text.delete(1.0, tk.END)
            self.url_var.set("")
            self.sql_text.delete(1.0, tk.END)
            self.icon_label.config(image="", text="无数据")
            self.icon_label.image = None
            self.screenshot_label.config(image="", text="无数据")
            self.screenshot_label.image = None
            return

        data = self.url_data[self.current_id]

        # 更新显示内容
        self.browser_title_var.set(data["title"] if data["title"] else "未获取标题")
        # 应用历史修改
        self.title_var.set(self.temp_title_changes.get(self.current_id, data["name"]))

        self.desc_text.delete(1.0, tk.END)
        # 应用历史修改
        self.desc_text.insert(tk.END, self.temp_desc_changes.get(self.current_id, data["tips"]))

        self.url_var.set(data["url"])
        self.sql_text.delete(1.0, tk.END)
        self.sql_text.insert(tk.END, data["sql"])

        # 加载图标和截图
        self.load_icon(data.copy())
        self.load_screenshot(data.copy())

        # 更新按钮状态
        self.update_button_states()

    def update_button_states(self):
        """更新按钮状态"""
        if self.current_id is None or self.current_id not in self.url_data:
            self.discard_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.DISABLED)
            return

        data = self.url_data[self.current_id]

        # 更新丢弃按钮状态
        if data["processed"] and self.current_id not in self.items_to_discard:
            self.discard_button.config(state=tk.NORMAL)
        else:
            self.discard_button.config(state=tk.DISABLED)

        # 更新保存按钮状态
        has_savable = any(
            item["processed"] and item_id not in self.items_to_discard
            for item_id, item in self.url_data.items()
        )
        self.save_button.config(state=tk.NORMAL if has_savable else tk.DISABLED)

    def load_icon(self, data):
        """加载并显示图标"""
        self.icon_label.config(image="")
        self.icon_label.image = None

        if data.get("id") != self.current_id:
            self.icon_label.config(text="数据不匹配")
            return

        if data["icon_file"]:
            icon_path = os.path.join(self.icons_dir, data["icon_file"])
            if os.path.exists(icon_path):
                try:
                    # 处理SVG文件
                    if icon_path.lower().endswith('.svg'):
                        try:
                            drawing = svg2rlg(icon_path)
                            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_png:
                                temp_path = temp_png.name

                            renderPM.drawToFile(drawing, temp_path, fmt='PNG')
                            img = Image.open(temp_path)
                            img.thumbnail((64, 64))
                            photo = ImageTk.PhotoImage(img)

                            self.icon_label.config(image=photo)
                            self.icon_label.image = photo
                            img.close()

                            # 延迟删除临时文件
                            self.root.after(500, lambda p=temp_path: self.delete_temp_file(p))
                        except Exception as e:
                            logger.error(f"处理SVG图标失败: {str(e)}")
                            self.icon_label.config(text="无法解析SVG图标")
                    else:
                        # 处理普通图片
                        img = Image.open(icon_path)
                        img.thumbnail((64, 64))
                        photo = ImageTk.PhotoImage(img)
                        self.icon_label.config(image=photo)
                        self.icon_label.image = photo
                except Exception as e:
                    logger.error(f"无法加载图标: {str(e)}")
                    self.icon_label.config(text="无法加载图标")
            else:
                self.icon_label.config(text="图标文件不存在")
        else:
            self.icon_label.config(text="无图标")

    def load_screenshot(self, data):
        """加载并显示网站截图 - 优化版：先保证完全展示再尽可能大"""
        self.screenshot_label.config(image="")
        self.screenshot_label.image = None

        if data.get("id") != self.current_id:
            self.screenshot_label.config(text="数据不匹配")
            return

        screenshot_path = data.get("screenshot_path")
        if not screenshot_path:
            self.screenshot_label.config(text="无截图路径")
            return

        if os.path.exists(screenshot_path):
            try:
                # 检查文件是否为空
                if os.path.getsize(screenshot_path) == 0:
                    logger.warning(f"截图文件为空: {screenshot_path}")
                    self.screenshot_label.config(text="截图文件损坏")
                    return

                # 加载截图
                img = Image.open(screenshot_path)
                img_width, img_height = img.size

                # 获取当前画布尺寸
                canvas_width = self.screenshot_canvas.winfo_width()
                canvas_height = self.screenshot_canvas.winfo_height()

                # 如果画布尺寸尚未确定（可能在初始化时），使用默认值
                if canvas_width <= 1 or canvas_height <= 1:
                    canvas_width = 800
                    canvas_height = 600

                # 计算宽度和高度的缩放比例（确保图片完全显示）
                width_ratio = canvas_width / img_width
                height_ratio = canvas_height / img_height

                # 取最小比例，确保图片完全显示在容器中
                scale_ratio = min(width_ratio, height_ratio)

                # 计算新尺寸，确保图片完全显示且尽可能大
                new_width = int(img_width * scale_ratio)
                new_height = int(img_height * scale_ratio)

                # 缩放图片
                img = img.resize((new_width, new_height), Image.LANCZOS)

                # 创建PhotoImage对象
                photo = ImageTk.PhotoImage(img)
                self.screenshot_label.config(image=photo)
                self.screenshot_label.image = photo

                # 居中显示
                x = (canvas_width - new_width) // 2
                y = (canvas_height - new_height) // 2
                self.screenshot_canvas.coords(self.screenshot_canvas.find_withtag("window"), x, y)

                logger.info(f"成功加载截图: {screenshot_path}, 缩放比例: {scale_ratio:.2f}")
            except Exception as e:
                logger.error(f"无法加载截图: {str(e)}")
                self.screenshot_label.config(text="无法加载截图")
        else:
            self.screenshot_label.config(text="获取失败" if data.get("status") == "获取失败" else "无截图")

    # 网站信息获取方法
    def fetch_all_site_info(self):
        """批量获取所有网站的信息和截图"""
        if not self.url_data:
            messagebox.showinfo("提示", "没有URL数据可处理")
            return

        logger.info("开始批量获取网站信息")

        # 重置状态，但保留历史修改
        for item_id, item in self.url_data.items():
            if item_id not in self.items_to_discard:
                item["processed"] = False
                # 如果没有历史修改，重置状态
                if item_id not in self.temp_title_changes and item_id not in self.temp_desc_changes:
                    item["status"] = "未处理"
                item["title"] = ""
                # 清除旧截图
                if os.path.exists(item["screenshot_path"]):
                    try:
                        os.remove(item["screenshot_path"])
                        logger.info(f"已删除旧截图: {item['screenshot_path']}")
                    except Exception as e:
                        logger.warning(f"无法删除旧截图: {str(e)}")
            else:
                item["status"] = "已丢弃"

        # 更新Treeview
        for item_id, item in self.url_data.items():
            if self.url_tree.exists(item_id):
                values = list(self.url_tree.item(item_id, "values"))
                values[4] = item["status"]
                self.url_tree.item(item_id, values=values)

        total = len([item_id for item_id in self.id_list if item_id not in self.items_to_discard])
        processed = [0]

        # 初始化线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)

        # 批量获取线程
        def batch_fetch():
            for item_id in self.id_list:
                if item_id in self.items_to_discard:
                    processed[0] += 1
                    self.root.after(0, lambda p=processed[0] / total * 100: self.progress_var.set(p))
                    continue

                self.thread_pool.submit(self.fetch_site_info, item_id, processed, total)

            # 等待所有任务完成
            while processed[0] < total:
                try:
                    update = self.update_queue.get(timeout=0.1)
                    self.root.after(0, update)
                except queue.Empty:
                    pass

            # 关闭线程池
            self.thread_pool.shutdown(wait=True)
            self.root.after(0, lambda: self.status_var.set("批量获取完成"))
            self.root.after(0, lambda: messagebox.showinfo("完成", "已完成所有网站信息的获取"))
            # 保存修改记录
            self.save_history()

        threading.Thread(target=batch_fetch).start()
        self.status_var.set("正在批量获取网站信息...")

    def fetch_site_info(self, item_id, processed, total):
        """获取单个网站的信息和截图（带URL自动修正功能）"""
        # 首先检查是否为已丢弃项，如果是则直接返回
        if item_id in self.items_to_discard:
            logger.info(f"ID {item_id} 已被标记为丢弃，跳过截图获取")
            return

        if item_id not in self.url_data:
            logger.error(f"ID {item_id} 不存在于数据中")
            return

        data = self.url_data[item_id].copy()
        target_url = data["url"]  # 记录目标URL用于验证

        success = False
        error_msg = ""
        browser = None  # 为每个任务创建独立浏览器实例

        logger.info(f"开始获取网站信息: {target_url} (ID: {item_id})")

        try:
            # 为当前任务创建独立的浏览器实例
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--no-sandbox")  # 增加稳定性
            chrome_options.add_argument("--disable-dev-shm-usage")  # 增加稳定性

            browser = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )

            # 尝试多次获取
            for attempt in range(SCREENSHOT_MAX_RETRIES):
                try:
                    logger.info(f"第 {attempt + 1} 次尝试获取 {target_url} (ID: {item_id})")
                    browser.get(target_url)
                    time.sleep(5)  # 等待页面加载完成

                    # 验证URL是否匹配
                    current_url = browser.current_url
                    target_domain = target_url.split('//')[-1].split('/')[0].split(':')[0]
                    current_domain = current_url.split('//')[-1].split('/')[0].split(':')[0]

                    # 检查域名是否匹配（忽略www.前缀差异）
                    normalized_target = target_domain.replace('www.', '')
                    normalized_current = current_domain.replace('www.', '')

                    url_needs_update = False
                    new_url = target_url

                    # 加载白名单
                    whitelist_text = self.whitelist_text.get(1.0, tk.END).strip()
                    whitelist_domains = [line.strip() for line in whitelist_text.split('\n') if line.strip()]

                    # 检查目标域名是否在白名单中
                    is_whitelisted = any(
                        normalized_target.endswith(domain) or normalized_target == domain
                        for domain in whitelist_domains
                    )

                    if is_whitelisted:
                        logger.info(f"域名 {normalized_target} 在白名单中，不进行URL修正 (ID: {item_id})")
                    elif normalized_target != normalized_current:
                        logger.warning(f"URL域名不匹配: 预期 {target_domain}，实际 {current_domain} (ID: {item_id})")
                        # 构建新的标准化URL
                        new_url = self.normalize_url(current_url)
                        url_needs_update = True
                    elif target_domain != current_domain:
                        # 处理www.前缀差异（如www.115.com和115.com）
                        logger.warning(f"URL域名前缀差异: 预期 {target_domain}，实际 {current_domain} (ID: {item_id})")
                        new_url = self.normalize_url(current_url)
                        url_needs_update = True

                    # 获取页面标题
                    page_title = browser.title
                    logger.info(f"成功获取页面标题: {page_title} (ID: {item_id}, URL: {current_url})")

                    # 截取屏幕
                    screenshot_path = os.path.join(self.screenshot_dir, f"screenshot_{item_id}.png")
                    browser.save_screenshot(screenshot_path)
                    logger.info(f"成功保存原始截图到: {screenshot_path} (ID: {item_id})")

                    # 添加标题到截图
                    self.add_title_to_screenshot(screenshot_path, page_title)

                    # 更新成功状态（包含URL修正逻辑）
                    def update_success():
                        if item_id in self.url_data:
                            # 如果需要更新URL
                            if url_needs_update:
                                self.url_data[item_id]["url"] = new_url
                                logger.info(f"已自动修正URL (ID: {item_id}): {target_url} -> {new_url}")

                                # 更新Treeview中的URL显示
                                if self.url_tree.exists(item_id):
                                    values = list(self.url_tree.item(item_id, "values"))
                                    values[2] = new_url  # 更新URL列
                                    # 如果没有历史修改，更新状态
                                    if item_id not in self.temp_title_changes and item_id not in self.temp_desc_changes:
                                        values[4] = "已修正"  # 更新状态列
                                    self.url_tree.item(item_id, values=values)
                            else:
                                # 如果没有历史修改，更新状态
                                if item_id not in self.temp_title_changes and item_id not in self.temp_desc_changes:
                                    self.url_data[item_id]["status"] = "已获取"
                                    if self.url_tree.exists(item_id):
                                        values = list(self.url_tree.item(item_id, "values"))
                                        values[4] = "已获取"
                                        self.url_tree.item(item_id, values=values)

                            self.url_data[item_id]["processed"] = True
                            self.url_data[item_id]["title"] = page_title
                            self.url_data[item_id]["screenshot_path"] = screenshot_path

                            if self.current_id == item_id:
                                self.update_display()

                    self.update_queue.put(update_success)
                    success = True
                    logger.info(f"成功完成网站信息获取: {target_url} (ID: {item_id})")
                    break
                except Exception as e:
                    error_msg = str(e)
                    logger.warning(f"第 {attempt + 1} 次尝试失败: {error_msg} (ID: {item_id})")
                    if attempt < SCREENSHOT_MAX_RETRIES - 1:
                        logger.info(f"等待 {SCREENSHOT_RETRY_DELAY} 秒后重试 (ID: {item_id})")
                        time.sleep(SCREENSHOT_RETRY_DELAY)

        finally:
            # 确保浏览器实例被关闭
            if browser:
                try:
                    browser.quit()
                    logger.info(f"已关闭ID: {item_id} 的浏览器实例")
                except Exception as e:
                    logger.warning(f"关闭浏览器失败 (ID: {item_id}): {str(e)}")

        # 处理结果
        if not success:
            logger.error(f"获取网站信息失败: {target_url} (ID: {item_id}), 错误: {error_msg}")

            def update_error_ui():
                if item_id in self.url_data:
                    # 如果没有历史修改，更新状态
                    if item_id not in self.temp_title_changes and item_id not in self.temp_desc_changes:
                        self.url_data[item_id]["status"] = "获取失败"
                    self.url_data[item_id]["processed"] = True

                    if self.url_tree.exists(item_id):
                        values = list(self.url_tree.item(item_id, "values"))
                        # 如果没有历史修改，更新状态
                        if item_id not in self.temp_title_changes and item_id not in self.temp_desc_changes:
                            values[4] = "获取失败"
                        self.url_tree.item(item_id, values=values)

                    # 清除错误截图
                    if os.path.exists(self.url_data[item_id]["screenshot_path"]):
                        try:
                            os.remove(self.url_data[item_id]["screenshot_path"])
                            logger.info(f"已删除失败的截图: {self.url_data[item_id]['screenshot_path']}")
                        except Exception as e:
                            logger.warning(f"无法删除失败的截图: {str(e)}")

                    if self.current_id == item_id:
                        self.update_display()

                processed[0] += 1
                self.progress_var.set(processed[0] / total * 100)
                self.status_var.set(f"已处理 {processed[0]}/{total}")

            self.update_queue.put(update_error_ui)
        else:
            # 更新进度
            def update_progress():
                processed[0] += 1
                self.progress_var.set(processed[0] / total * 100)
                self.status_var.set(f"已处理 {processed[0]}/{total}")

            self.update_queue.put(update_progress)

    # 工具方法
    def add_title_to_screenshot(self, screenshot_path, title):
        """在截图上方添加标题"""
        try:
            img = Image.open(screenshot_path)
            width, height = img.size

            # 创建新图像
            new_height = height + 40
            new_img = Image.new('RGB', (width, new_height), color=(240, 240, 240))
            new_img.paste(img, (0, 40))

            # 绘制标题
            draw = ImageDraw.Draw(new_img)
            try:
                font = ImageFont.truetype("simhei.ttf", 16)
            except IOError:
                font = ImageFont.load_default()
                logger.warning("无法加载SimHei字体，使用默认字体")

            draw.text((10, 10), title, fill=(0, 0, 0), font=font)
            new_img.save(screenshot_path)
            logger.info(f"成功添加标题到截图: {screenshot_path}")

        except Exception as e:
            logger.error(f"添加标题到截图失败: {str(e)}")

    def delete_temp_file(self, path):
        """删除临时文件"""
        try:
            if os.path.exists(path):
                os.unlink(path)
                logger.info(f"已删除临时文件: {path}")
        except Exception as e:
            logger.warning(f"删除临时文件失败: {str(e)}")
            self.root.after(1000, self.delete_temp_file, path)

    # 导航与操作方法
    def open_website(self):
        """打开当前选中的网站"""
        if self.current_id is None or self.current_id not in self.url_data:
            messagebox.showinfo("提示", "请先选择一个URL")
            return

        data = self.url_data[self.current_id]
        url = data["url"]

        if not url:
            messagebox.showinfo("提示", "无效的URL")
            return

        # 初始化浏览器
        if not self.browser:
            chrome_options = Options()
            chrome_options.add_argument("--start-maximized")

            try:
                self.browser = webdriver.Chrome(
                    service=Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
            except Exception as e:
                logger.error(f"初始化浏览器驱动失败: {str(e)}")
                messagebox.showerror("错误", f"无法初始化浏览器驱动: {str(e)}")
                return

        # 打开URL
        try:
            logger.info(f"打开网站: {url}")
            self.browser.get(url)
            self.status_var.set(f"已打开: {data['name']}")
        except Exception as e:
            messagebox.showerror("错误", f"打开URL失败: {str(e)}")
            logger.error(f"打开URL失败: {str(e)}")

    def prev_url(self):
        """选择上一个URL"""
        if not self.id_list:
            return

        try:
            current_pos = self.id_list.index(self.current_id)
        except ValueError:
            current_pos = 0

        # 查找上一个未被丢弃的项
        original_pos = current_pos
        current_pos = (current_pos - 1) % len(self.id_list)

        while current_pos != original_pos:
            item_id = self.id_list[current_pos]
            if item_id not in self.items_to_discard:
                self.current_id = item_id
                if self.url_tree.exists(item_id):
                    self.url_tree.selection_set(item_id)
                    self.url_tree.see(item_id)
                self.update_display()
                return
            current_pos = (current_pos - 1) % len(self.id_list)

    def next_url(self):
        """选择下一个URL"""
        if not self.id_list:
            return

        try:
            current_pos = self.id_list.index(self.current_id)
        except ValueError:
            current_pos = 0

        # 查找下一个未被丢弃的项
        original_pos = current_pos
        current_pos = (current_pos + 1) % len(self.id_list)

        while current_pos != original_pos:
            item_id = self.id_list[current_pos]
            if item_id not in self.items_to_discard:
                self.current_id = item_id
                if self.url_tree.exists(item_id):
                    self.url_tree.selection_set(item_id)
                    self.url_tree.see(item_id)
                self.update_display()
                return
            current_pos = (current_pos + 1) % len(self.id_list)

    # 键盘事件处理
    def on_up_key(self, event):
        """处理上箭头键"""
        self.prev_url()

    def on_down_key(self, event):
        """处理下箭头键"""
        self.next_url()

    def on_delete_key(self, event):
        """处理Delete键"""
        if self.current_id is not None and self.current_id in self.url_data:
            data = self.url_data[self.current_id]
            if data["processed"] and self.current_id not in self.items_to_discard:
                self.discard_item()

    # 数据编辑方法
    def update_title(self, event=None):
        """更新网站标题"""
        if self.current_id is None or self.current_id not in self.url_data:
            return

        new_title = self.title_var.get().strip()
        if not new_title:
            messagebox.showinfo("提示", "标题不能为空")
            return

        data = self.url_data[self.current_id]
        old_title = data["name"]

        if new_title != old_title:
            self.temp_title_changes[self.current_id] = new_title

            # 更新Treeview
            if self.url_tree.exists(self.current_id):
                values = list(self.url_tree.item(self.current_id, "values"))
                values[1] = new_title
                values[4] = "已修改"
                self.url_tree.item(self.current_id, values=values)

            data["status"] = "已修改"
            data["processed"] = True

            self.status_var.set(f"标题已修改（未保存）: {new_title}")
            logger.info(f"已修改标题 (ID: {self.current_id}): {old_title} -> {new_title}")
            self.update_button_states()
            # 自动保存修改记录
            self.save_history()

    def update_desc(self, event=None):
        """更新网站描述"""
        if self.current_id is None or self.current_id not in self.url_data:
            return

        new_desc = self.desc_text.get(1.0, tk.END).strip()
        data = self.url_data[self.current_id]
        old_desc = data["tips"]

        if new_desc != old_desc:
            self.temp_desc_changes[self.current_id] = new_desc

            # 更新状态
            if self.url_tree.exists(self.current_id):
                values = list(self.url_tree.item(self.current_id, "values"))
                values[4] = "已修改"
                self.url_tree.item(self.current_id, values=values)

            data["status"] = "已修改"
            data["processed"] = True

            self.status_var.set(f"描述已修改（未保存）")
            logger.info(f"已修改描述 (ID: {self.current_id})")
            self.update_button_states()
            # 自动保存修改记录
            self.save_history()

    # 数据管理方法
    def discard_item(self):
        """标记当前项为待丢弃"""
        if self.current_id is None or self.current_id not in self.url_data:
            return

        data = self.url_data[self.current_id]
        item_id = self.current_id

        if item_id in self.items_to_discard:
            return

        if messagebox.askyesno("确认", f"确定要丢弃 {data['name']} 吗？"):
            try:
                self.items_to_discard.add(item_id)
                data["status"] = "已丢弃"

                # 更新Treeview
                if self.url_tree.exists(item_id):
                    values = list(self.url_tree.item(item_id, "values"))
                    values[4] = "已丢弃"
                    self.url_tree.item(item_id, values=values)

                # 清除截图
                if os.path.exists(data["screenshot_path"]):
                    try:
                        os.remove(data["screenshot_path"])
                        logger.info(f"已删除丢弃项的截图: {data['screenshot_path']}")
                    except Exception as e:
                        logger.warning(f"无法删除丢弃项的截图: {str(e)}")

                self.status_var.set(f"已标记丢弃 {data['name']}")
                logger.info(f"已标记丢弃项 (ID: {item_id}, URL: {data['url']})")
                self.update_button_states()
                # 自动保存修改记录
                self.save_history()

                # 自动选择下一个
                self.next_url()
            except Exception as e:
                messagebox.showerror("错误", f"标记丢弃失败: {str(e)}")
                logger.error(f"标记丢弃失败: {str(e)}")

    def save_all_items(self):
        """保存所有未丢弃的项到新的SQL文件"""
        if not self.url_data:
            messagebox.showinfo("提示", "没有URL数据可保存")
            return

        # 筛选出未丢弃的项
        items_to_save = [item for item_id, item in self.url_data.items() if item_id not in self.items_to_discard]

        if not items_to_save:
            messagebox.showinfo("提示", "没有可保存的URL")
            return

        try:
            logger.info(f"开始保存 {len(items_to_save)} 条记录到 {self.save_file}")
            # 处理丢弃项的图片
            discarded_count = 0
            for item_id in self.items_to_discard:
                if item_id in self.url_data:
                    item = self.url_data[item_id]
                    # 移动图标到trash目录
                    if item["icon_file"]:
                        icon_path = os.path.join(self.icons_dir, item["icon_file"])
                        if os.path.exists(icon_path):
                            trash_path = os.path.join(self.trash_dir, item["icon_file"])
                            if os.path.exists(trash_path):
                                name, ext = os.path.splitext(item["icon_file"])
                                trash_path = os.path.join(self.trash_dir, f"{name}_{int(time.time())}{ext}")
                            os.rename(icon_path, trash_path)
                            logger.info(f"已移动丢弃项图标: {icon_path} -> {trash_path}")

                    # 删除截图
                    if os.path.exists(item["screenshot_path"]):
                        os.remove(item["screenshot_path"])
                        logger.info(f"已删除丢弃项截图: {item['screenshot_path']}")

                    discarded_count += 1

            # 写入SQL文件
            with open(self.save_file, 'w', encoding='utf-8') as f:
                f.write("-- 筛选后的URL数据\n")
                f.write("-- 生成时间: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")

                for item in items_to_save:
                    current_sql = item["sql"]

                    # 应用标题修改
                    if item["id"] in self.temp_title_changes:
                        new_title = self.temp_title_changes[item["id"]]
                        sql_pattern = re.compile(
                            r"(INSERT into `mtab`.`linkstore`\s*\([^)]*\)\s*values\s*\()'[^']*'(,\s*'[^']*',\s*'[^']*',\s*'[^']*',\s*'[^']*',\s*'[^']*',\s*[^,]*, \s*[^,]*, \s*'[^']*', \s*'[^']*', \s*[^,]*, \s*[^,]*, \s*'[^']*', \s*[^,]*, \s*[^,]*, \s*[^,]*, \s*[^,]*, \s*[^)]*\);)",
                            re.IGNORECASE)
                        sql_match = sql_pattern.match(current_sql)

                        if sql_match:
                            current_sql = f"{sql_match.group(1)}'{new_title}'{sql_match.group(2)}"

                    # 应用URL修改
                    original_url = re.search(r"INSERT.*?VALUES.*?'[^']*',\s*'[^']*',\s*'([^']+)'", current_sql,
                                             re.IGNORECASE).group(1)
                    if item["url"] != original_url:
                        sql_pattern = re.compile(
                            r"(INSERT into `mtab`.`linkstore`\s*\([^)]*\)\s*values\s*\([^']*',\s*'[^']*',\s*')([^']*)'(,\s*'[^']*',\s*'[^']*',\s*'[^']*',\s*[^,]*, \s*[^,]*, \s*'[^']*', \s*'[^']*', \s*[^,]*, \s*[^,]*, \s*'[^']*', \s*[^,]*, \s*[^,]*, \s*[^,]*, \s*[^,]*, \s*[^)]*\);)",
                            re.IGNORECASE)
                        sql_match = sql_pattern.match(current_sql)

                        if sql_match:
                            current_sql = f"{sql_match.group(1)}{item['url']}{sql_match.group(2)}"

                    # 应用描述修改
                    if item["id"] in self.temp_desc_changes:
                        new_desc = self.temp_desc_changes[item["id"]]
                        sql_pattern = re.compile(
                            r"(insert into `mtab`.`linkstore`\s*\([^)]*\)\s*values\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*, \s*[^)]*, \s*)'[^']*'(\s*,\s*'[^']*', \s*[^)]*, \s*[^)]*, \s*'[^']*', \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*\);)",
                            re.IGNORECASE)
                        sql_match = sql_pattern.match(current_sql)

                        if sql_match:
                            current_sql = f"{sql_match.group(1)}'{new_desc}'{sql_match.group(2)}"

                    f.write(current_sql + "\n\n")

            # 清空临时数据
            self.temp_title_changes.clear()
            self.temp_desc_changes.clear()
            self.items_to_discard.clear()

            # 清除历史记录
            self.clear_history(show_message=False)

            # 更新状态
            for item_id, item in self.url_data.items():
                if item["processed"] and item["status"] in ["已修改", "已修正"]:
                    item["status"] = "已保存"
                    if self.url_tree.exists(item_id):
                        values = list(self.url_tree.item(item_id, "values"))
                        values[4] = "已保存"
                        self.url_tree.item(item_id, values=values)

            self.status_var.set(f"已保存到 {self.save_file}")
            logger.info(f"成功保存 {len(items_to_save)} 条记录到 {self.save_file}")
            messagebox.showinfo("成功",
                                f"已保存 {len(items_to_save)} 条URL记录到 {self.save_file}\n"
                                f"已处理 {discarded_count} 条丢弃项的图片文件")
        except Exception as e:
            self.status_var.set("保存失败")
            messagebox.showerror("错误", f"保存文件时出错: {str(e)}")
            logger.error(f"保存文件时出错: {str(e)}")

    # 历史记录管理
    def apply_history_to_ui(self):
        """将历史记录应用到UI"""
        # 应用标题修改
        for item_id, new_title in self.temp_title_changes.items():
            if item_id in self.url_data and self.url_tree.exists(item_id):
                values = list(self.url_tree.item(item_id, "values"))
                values[1] = new_title
                values[4] = "已修改"
                self.url_tree.item(item_id, values=values)
                self.url_data[item_id]["status"] = "已修改"
                self.url_data[item_id]["processed"] = True

        # 应用描述修改
        for item_id, new_desc in self.temp_desc_changes.items():
            if item_id in self.url_data and self.url_tree.exists(item_id):
                values = list(self.url_tree.item(item_id, "values"))
                values[4] = "已修改"
                self.url_tree.item(item_id, values=values)
                self.url_data[item_id]["status"] = "已修改"
                self.url_data[item_id]["processed"] = True

        # 应用丢弃状态
        for item_id in self.items_to_discard:
            if item_id in self.url_data and self.url_tree.exists(item_id):
                values = list(self.url_tree.item(item_id, "values"))
                values[4] = "已丢弃"
                self.url_tree.item(item_id, values=values)
                self.url_data[item_id]["status"] = "已丢弃"
                self.url_data[item_id]["processed"] = True

        # 更新按钮状态
        self.update_button_states()

    def save_history(self):
        """保存修改记录到文件"""
        try:
            history_data = {
                "temp_title_changes": self.temp_title_changes,
                "temp_desc_changes": self.temp_desc_changes,
                "items_to_discard": list(self.items_to_discard)
            }

            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, ensure_ascii=False, indent=2)

            logger.info(f"已保存修改记录到 {self.history_file}")
        except Exception as e:
            logger.error(f"保存修改记录失败: {str(e)}")

    def load_history(self):
        """从文件加载修改记录并立即应用到UI"""
        if not os.path.exists(self.history_file):
            logger.info("没有找到历史记录文件")
            return

        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                history_data = json.load(f)

            # 转换数据类型并处理可能的格式问题
            self.temp_title_changes = {
                int(k): v for k, v in history_data.get("temp_title_changes", {}).items()
                if isinstance(k, (str, int)) and v and isinstance(v, str)
            }
            self.temp_desc_changes = {
                int(k): v for k, v in history_data.get("temp_desc_changes", {}).items()
                if isinstance(k, (str, int)) and v and isinstance(v, str)
            }
            self.items_to_discard = set(
                int(id) for id in history_data.get("items_to_discard", [])
                if isinstance(id, (str, int))
            )

            logger.info(f"已加载历史记录，包含 {len(self.temp_title_changes)} 个标题修改，"
                        f"{len(self.temp_desc_changes)} 个描述修改，"
                        f"{len(self.items_to_discard)} 个丢弃项")

            # 加载历史记录后立即更新UI
            self.apply_history_to_ui()

        except Exception as e:
            logger.error(f"加载历史记录失败: {str(e)}")
            # 尝试删除损坏的历史文件
            try:
                os.remove(self.history_file)
                logger.info(f"已删除损坏的历史记录文件: {self.history_file}")
            except Exception as e2:
                logger.warning(f"无法删除损坏的历史记录文件: {str(e2)}")

    def clear_history(self, show_message=True):
        """清空历史记录"""
        try:
            if os.path.exists(self.history_file):
                os.remove(self.history_file)
                logger.info(f"已清空历史记录: {self.history_file}")

            self.temp_title_changes.clear()
            self.temp_desc_changes.clear()
            self.items_to_discard.clear()

            # 更新UI
            for item_id, item in self.url_data.items():
                if self.url_tree.exists(item_id):
                    values = list(self.url_tree.item(item_id, "values"))
                    # 恢复原始状态
                    if item["status"] in ["已修改", "已丢弃"]:
                        values[1] = item["name"]
                        values[4] = "未处理" if not item["processed"] else "已获取"
                        self.url_tree.item(item_id, values=values)
                        item["status"] = "未处理" if not item["processed"] else "已获取"

            self.update_display()
            self.update_button_states()

            if show_message:
                messagebox.showinfo("成功", "已清空所有修改记录")

        except Exception as e:
            logger.error(f"清空历史记录失败: {str(e)}")
            if show_message:
                messagebox.showerror("错误", f"清空历史记录失败: {str(e)}")

    def on_closing(self):
        """处理窗口关闭事件"""
        # 保存历史记录
        self.save_history()

        # 关闭浏览器
        if self.browser:
            try:
                self.browser.quit()
                logger.info("已关闭浏览器")
            except Exception as e:
                logger.warning(f"关闭浏览器失败: {str(e)}")

        # 关闭线程池
        if self.thread_pool:
            try:
                self.thread_pool.shutdown(wait=False)
                logger.info("已关闭线程池")
            except Exception as e:
                logger.warning(f"关闭线程池失败: {str(e)}")

        logger.info("应用程序已关闭")
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SQLURLBrowser(root)
    root.mainloop()
