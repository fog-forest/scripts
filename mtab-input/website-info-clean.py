#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/07/25
# @Desc  : SQL URL浏览器与截图工具（增强版）
# @Func  : 从SQL文件中提取URL，批量获取网站信息并管理

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

# 分类映射关系
CATEGORY_IDS = {
    "ai": 1, "app": 1, "news": 2, "music": 3,
    "tech": 4, "photos": 5, "life": 6, "education": 9,
    "entertainment": 8, "shopping": 9, "social": 10, "read": 11,
    "sports": 12, "finance": 13, "others": 14
}

# 创建反向映射：ID到分类名称
ID_TO_CATEGORY = {}
for cat, id in CATEGORY_IDS.items():
    if id not in ID_TO_CATEGORY:
        ID_TO_CATEGORY[id] = cat


class SQLURLBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL URL浏览器与截图工具")
        self.root.geometry("1200x800")

        # 设置中文字体支持
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TCombobox", font=("SimHei", 10))

        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件选择区域
        self.file_frame = ttk.LabelFrame(self.main_frame, text="文件选择", padding="10")
        self.file_frame.pack(fill=tk.X, pady=5)

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, width=70)
        self.file_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = ttk.Button(self.file_frame, text="浏览...", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        self.process_button = ttk.Button(self.file_frame, text="处理SQL文件", command=self.process_file)
        self.process_button.pack(side=tk.LEFT, padx=5)

        self.fetch_info_button = ttk.Button(self.file_frame, text="批量获取网站信息", command=self.fetch_all_site_info,
                                            state=tk.DISABLED)
        self.fetch_info_button.pack(side=tk.LEFT, padx=5)

        # 数据展示区域
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

        # 为Treeview添加选择事件
        self.url_tree.bind("<<TreeviewSelect>>", self.on_url_select)

        # 操作按钮区域
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

        # 结果展示区域
        self.result_frame = ttk.LabelFrame(self.main_frame, text="结果展示", padding="10")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 左侧展示图标和截图
        self.left_frame = ttk.Frame(self.result_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 图标区域（固定大小）
        self.icon_frame = ttk.LabelFrame(self.left_frame, text="网站图标", padding="5")
        self.icon_frame.pack(fill=tk.X, pady=5)

        # 固定图标显示区域（移除ttk.Label不支持的height参数）
        self.icon_label = ttk.Label(self.icon_frame, text="图标将显示在这里", width=10)
        self.icon_label.pack(padx=5, pady=5)

        # 截图区域
        self.screenshot_frame = ttk.LabelFrame(self.left_frame, text="网站截图", padding="5")
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 使用Canvas来实现截图自动适应大小
        self.screenshot_canvas = tk.Canvas(self.screenshot_frame)
        self.screenshot_canvas.pack(fill=tk.BOTH, expand=True)
        self.screenshot_label = ttk.Label(self.screenshot_canvas, text="截图将显示在这里")
        self.screenshot_canvas.create_window((0, 0), window=self.screenshot_label, anchor="nw", tags="window")

        # 绑定大小变化事件，使截图自适应窗口
        self.screenshot_canvas.bind("<Configure>", self.on_canvas_configure)

        # 右侧展示信息和SQL
        self.right_frame = ttk.Frame(self.result_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 浏览器标签标题区域（只读参考）
        self.browser_title_frame = ttk.LabelFrame(self.right_frame, text="浏览器标签标题（参考）", padding="5")
        self.browser_title_frame.pack(fill=tk.X, pady=5)

        self.browser_title_var = tk.StringVar()
        self.browser_title_label = ttk.Label(self.browser_title_frame, textvariable=self.browser_title_var, anchor=tk.W,
                                             wraplength=400)
        self.browser_title_label.pack(fill=tk.X, padx=5, pady=5)

        # SQL标题编辑区域
        self.title_frame = ttk.LabelFrame(self.right_frame, text="SQL标题（可修改）", padding="5")
        self.title_frame.pack(fill=tk.X, pady=5)

        self.title_var = tk.StringVar()
        self.title_entry = ttk.Entry(self.title_frame, textvariable=self.title_var, width=50)
        self.title_entry.pack(fill=tk.X, padx=5, pady=5)
        self.title_entry.bind("<Return>", self.update_title)

        # 描述编辑区域（缩小尺寸）
        self.desc_frame = ttk.LabelFrame(self.right_frame, text="网站描述", padding="5")
        self.desc_frame.pack(fill=tk.X, pady=5)

        self.desc_text = ScrolledText(self.desc_frame, wrap=tk.WORD, width=40, height=3)
        self.desc_text.pack(fill=tk.X, padx=5, pady=5)
        # 绑定描述框修改事件，保存到临时存储
        self.desc_text.bind("<FocusOut>", self.update_desc)
        self.desc_text.bind("<KeyRelease>", self.update_desc)

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

        # 状态和进度条
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_frame, variable=self.progress_var, length=300)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

        # 数据存储
        self.url_data = []
        self.current_index = -1
        self.screenshot_dir = None

        # 存储临时修改
        self.temp_title_changes = {}  # {id: new_title}
        self.temp_desc_changes = {}  # {id: new_desc}

        # SQL文件目录和图标目录
        self.sql_dir = None
        self.icons_dir = None
        self.trash_dir = None

        # 保存的SQL文件
        self.save_file = os.path.join(os.getcwd(), "mtab_import_save.sql")

        # 浏览器驱动
        self.browser = None
        self.browser_pool = []
        self.max_browsers = 3  # 最大同时运行的浏览器数量
        self.thread_pool = None
        self.update_queue = queue.Queue()

        # 绑定键盘事件
        self.root.bind("<Up>", self.on_up_key)
        self.root.bind("<Down>", self.on_down_key)
        self.root.bind("<Delete>", self.on_delete_key)

    def on_canvas_configure(self, event):
        """当Canvas大小变化时调整截图标签位置"""
        self.screenshot_canvas.itemconfig(self.screenshot_canvas.find_withtag("window"), width=event.width)

    def init_browser_driver(self):
        """初始化浏览器驱动池"""
        try:
            for _ in range(self.max_browsers):
                chrome_options = Options()
                chrome_options.add_argument("--headless")  # 无头模式，后台运行
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--window-size=1920,1080")  # 增大窗口尺寸

                # 使用ChromeDriverManager自动管理驱动
                browser = webdriver.Chrome(
                    service=Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
                self.browser_pool.append(browser)

            self.thread_pool = ThreadPoolExecutor(max_workers=self.max_browsers)
            logger.info(f"初始化浏览器驱动池成功，大小: {self.max_browsers}")
        except Exception as e:
            logger.error(f"初始化浏览器驱动失败: {str(e)}")
            messagebox.showerror("错误", f"无法初始化浏览器驱动: {str(e)}\n请确保已安装Chrome浏览器")

    def get_available_browser(self):
        """获取可用的浏览器实例"""
        while True:
            for i, browser in enumerate(self.browser_pool):
                try:
                    # 检查浏览器是否可用
                    browser.title
                    return browser
                except:
                    continue
            time.sleep(0.5)  # 等待浏览器释放

    def browse_file(self):
        """浏览并选择SQL文件"""
        file_path = filedialog.askopenfilename(
            title="选择SQL文件",
            filetypes=[("SQL files", "*.sql"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            # 显示文件总行数
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
            # 获取SQL文件所在目录
            self.sql_dir = os.path.dirname(sql_file)

            # 设置图标目录为SQL文件同目录下的icons
            self.icons_dir = os.path.join(self.sql_dir, "icons")
            self.trash_dir = os.path.join(self.icons_dir, "trash")
            self.screenshot_dir = os.path.join(self.sql_dir, "screenshots")

            # 确保目录存在
            for dir_path in [self.icons_dir, self.trash_dir, self.screenshot_dir]:
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)

            self.status_var.set("正在处理SQL文件...")
            self.progress_var.set(0)

            # 清空现有数据
            for item in self.url_tree.get_children():
                self.url_tree.delete(item)
            self.url_data = []
            self.current_index = -1
            self.temp_title_changes = {}
            self.temp_desc_changes = {}

            # 读取SQL文件
            with open(sql_file, 'r', encoding='utf-8') as f:
                sql_content = f.read()

            # 使用正则表达式提取INSERT语句中的信息（更宽松的匹配模式）
            insert_pattern = re.compile(
                r"INSERT\s+INTO\s+`mtab`\.`linkstore`\s*\([^)]*\)\s*VALUES\s*\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*([^,]*),\s*([^,]*),\s*'([^']*)',\s*'([^']*)',\s*([^,]*),\s*([^,]*),\s*'([^']*)',\s*([^,]*),\s*([^,]*),\s*([^,]*),\s*([^,]*),\s*([^)]*)\);",
                re.DOTALL | re.IGNORECASE
            )

            # 统计匹配到的记录数
            matches = list(insert_pattern.finditer(sql_content))
            total_matches = len(matches)
            logger.info(f"SQL文件中匹配到 {total_matches} 条INSERT语句")

            if total_matches == 0:
                messagebox.showinfo("提示", "未在SQL文件中找到URL记录")
                self.status_var.set("就绪")
                return

            # 遍历提取数据
            for i, match in enumerate(matches):
                try:
                    name = match.group(1)
                    src = match.group(2)
                    url = match.group(3)
                    tips = match.group(9)
                    category_id = int(match.group(8))  # 提取分类ID

                    # 根据ID获取分类名称
                    category = ID_TO_CATEGORY.get(category_id, "未知")

                    # 提取图标文件名
                    icon_file = os.path.basename(src)

                    # 截图文件名
                    screenshot_file = f"screenshot_{i + 1}.png"

                    # 存储数据
                    self.url_data.append({
                        "id": i + 1,
                        "name": name,
                        "src": src,
                        "url": url,
                        "tips": tips,
                        "icon_file": icon_file,
                        "screenshot_file": screenshot_file,
                        "sql": match.group(0),
                        "processed": False,
                        "status": "未处理",
                        "title": "",
                        "screenshot_path": os.path.join(self.screenshot_dir, screenshot_file),
                        "category": category
                    })
                except Exception as e:
                    logger.error(f"处理第 {i + 1} 条记录失败: {str(e)}")
                    continue

                # 更新进度条
                self.progress_var.set((i + 1) / total_matches * 100)
                self.root.update_idletasks()

            # 在Treeview中显示数据
            for item in self.url_data:
                self.url_tree.insert("", tk.END, values=(
                    item["id"], item["name"], item["url"], item["category"], item["status"]
                ))

            # 显示提取结果统计
            extracted_count = len(self.url_data)
            skipped_count = total_matches - extracted_count
            self.status_var.set(f"处理完成，共找到 {extracted_count} 条URL记录（跳过 {skipped_count} 条）")

            # 显示详细统计信息
            message = f"已提取 {extracted_count} 条URL记录\n"
            if skipped_count > 0:
                message += f"注意：有 {skipped_count} 条记录因格式问题被跳过\n"
                message += "请查看日志了解详细信息"
            messagebox.showinfo("处理结果", message)

            # 启用获取信息按钮
            self.fetch_info_button.config(state=tk.NORMAL)

            # 如果有数据，选中第一条
            if self.url_data:
                self.url_tree.selection_set(self.url_tree.get_children()[0])
                self.on_url_select(None)

        except Exception as e:
            self.status_var.set("处理失败")
            messagebox.showerror("错误", f"处理文件时出错: {str(e)}")
            logger.error(f"处理文件时出错: {str(e)}")

    def on_url_select(self, event):
        """当在Treeview中选择URL时触发"""
        selected_items = self.url_tree.selection()
        if not selected_items:
            return

        item = selected_items[0]
        item_id = self.url_tree.item(item, "values")[0]

        # 找到对应的URL数据
        for i, data in enumerate(self.url_data):
            if data["id"] == int(item_id):
                self.current_index = i
                self.update_display()
                break

    def update_display(self):
        """更新显示内容"""
        if self.current_index < 0 or self.current_index >= len(self.url_data):
            return

        data = self.url_data[self.current_index]
        item_id = data["id"]

        # 更新浏览器标签标题（只读）
        self.browser_title_var.set(data["title"] if data["title"] else "未获取标题")

        # 更新SQL标题（可修改）
        display_title = self.temp_title_changes.get(item_id, data["name"])
        self.title_var.set(display_title)

        # 更新描述（显示临时修改）
        self.desc_text.delete(1.0, tk.END)
        desc = self.temp_desc_changes.get(item_id, data["tips"])
        self.desc_text.insert(tk.END, desc)

        # 更新URL
        self.url_var.set(data["url"])

        # 更新SQL文本
        self.sql_text.delete(1.0, tk.END)
        self.sql_text.insert(tk.END, data["sql"])

        # 更新图标显示
        self.load_icon(data)

        # 更新截图显示
        self.load_screenshot(data)

        # 更新按钮状态
        if data["processed"] and data["status"] != "已丢弃":
            self.discard_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.NORMAL)
        else:
            self.discard_button.config(state=tk.DISABLED)
            if any(item["processed"] and item["status"] != "已丢弃" for item in self.url_data):
                self.save_button.config(state=tk.NORMAL)
            else:
                self.save_button.config(state=tk.DISABLED)

    def load_icon(self, data):
        """加载并显示图标，固定大小为64x64像素"""
        # 清空现有图标
        self.icon_label.config(image="")
        self.icon_label.image = None

        if data["icon_file"]:
            icon_path = os.path.join(self.icons_dir, data["icon_file"])
            if os.path.exists(icon_path):
                try:
                    # 检查文件扩展名判断是否为SVG
                    if icon_path.lower().endswith('.svg'):
                        # 处理SVG文件
                        try:
                            drawing = svg2rlg(icon_path)
                            # 转换为临时PNG文件
                            temp_png = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
                            renderPM.drawToFile(drawing, temp_png.name, fmt='PNG')

                            # 打开并显示PNG，固定大小为64x64
                            img = Image.open(temp_png.name)
                            img.thumbnail((64, 64))  # 固定最大尺寸
                            photo = ImageTk.PhotoImage(img)

                            self.icon_label.config(image=photo)
                            self.icon_label.image = photo

                            # 清理临时文件
                            os.unlink(temp_png.name)
                        except Exception as e:
                            logger.error(f"处理SVG图标失败: {str(e)}")
                            self.icon_label.config(text="无法解析SVG图标")
                    else:
                        # 处理普通图片文件，固定大小为64x64
                        img = Image.open(icon_path)
                        img.thumbnail((64, 64))  # 固定最大尺寸
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
        """加载并显示网站截图，使其占满窗口不缩放"""
        if os.path.exists(data["screenshot_path"]):
            try:
                # 打开截图
                img = Image.open(data["screenshot_path"])

                # 获取Canvas尺寸
                canvas_width = self.screenshot_canvas.winfo_width()
                canvas_height = self.screenshot_canvas.winfo_height()

                # 如果Canvas还未渲染，使用默认尺寸
                if canvas_width == 1 or canvas_height == 1:
                    canvas_width = 800
                    canvas_height = 600

                # 计算图片缩放比例，保持原始比例但不超过Canvas尺寸
                img_width, img_height = img.size
                ratio = min(canvas_width / img_width, canvas_height / img_height)

                # 按比例缩放图片
                new_width = int(img_width * ratio)
                new_height = int(img_height * ratio)
                img = img.resize((new_width, new_height), Image.LANCZOS)

                photo = ImageTk.PhotoImage(img)

                # 更新截图标签
                self.screenshot_label.config(image=photo)
                self.screenshot_label.image = photo

                # 居中显示
                x = (canvas_width - new_width) // 2
                y = (canvas_height - new_height) // 2
                self.screenshot_canvas.coords(self.screenshot_canvas.find_withtag("window"), x, y)

            except Exception as e:
                logger.error(f"无法加载截图: {str(e)}")
                self.screenshot_label.config(text="无法加载截图")
        else:
            self.screenshot_label.config(text="无截图")

    def fetch_all_site_info(self):
        """批量获取所有网站的信息和截图"""
        if not self.url_data:
            messagebox.showinfo("提示", "没有URL数据可处理")
            return

        # 初始化浏览器驱动
        if not self.browser_pool:
            self.init_browser_driver()
            if not self.browser_pool:
                return

        # 重置所有URL状态
        for item in self.url_data:
            item["processed"] = False
            item["status"] = "未处理"
            item["title"] = ""

        # 更新Treeview显示
        for i, item in enumerate(self.url_data):
            for tree_item in self.url_tree.get_children():
                if self.url_tree.item(tree_item, "values")[0] == item["id"]:
                    values = list(self.url_tree.item(tree_item, "values"))
                    values[4] = "未处理"
                    self.url_tree.item(tree_item, values=values)
                    break

        total = len(self.url_data)
        # 使用列表存储processed，避免nonlocal问题
        processed = [0]

        # 在新线程中执行批量获取
        def batch_fetch():
            for i, item in enumerate(self.url_data):
                if item["status"] == "已丢弃":
                    processed[0] += 1
                    self.root.after(0, lambda p=processed[0] / total * 100: self.progress_var.set(p))
                    continue

                # 提交任务到线程池
                self.thread_pool.submit(self.fetch_site_info, i, processed)

            # 等待所有任务完成
            while processed[0] < total:
                try:
                    update = self.update_queue.get(timeout=0.1)
                    self.root.after(0, update)
                except queue.Empty:
                    pass

            self.root.after(0, lambda: self.status_var.set("批量获取完成"))
            self.root.after(0, lambda: messagebox.showinfo("完成", "已完成所有网站信息的获取"))

        threading.Thread(target=batch_fetch).start()
        self.status_var.set("正在批量获取网站信息...")

    def fetch_site_info(self, index, processed):
        """获取单个网站的信息和截图"""
        data = self.url_data[index]
        url = data["url"]

        try:
            browser = self.get_available_browser()

            # 打开URL
            browser.get(url)
            time.sleep(5)  # 增加等待时间，确保页面完全加载

            # 获取页面标题
            page_title = browser.title
            data["title"] = page_title

            # 截取屏幕
            browser.save_screenshot(data["screenshot_path"])

            # 添加标签页标题到截图
            self.add_title_to_screenshot(data["screenshot_path"], page_title)

            # 更新状态
            data["processed"] = True
            data["status"] = "已获取"

            # 更新UI
            def update_ui():
                processed[0] += 1
                # 更新Treeview中的状态
                for item in self.url_tree.get_children():
                    if self.url_tree.item(item, "values")[0] == data["id"]:
                        values = list(self.url_tree.item(item, "values"))
                        values[4] = "已获取"
                        self.url_tree.item(item, values=values)
                        break

                # 如果当前正在显示这个URL，更新显示
                if self.current_index == index:
                    self.update_display()

                # 更新进度
                self.progress_var.set(processed[0] / len(self.url_data) * 100)
                self.status_var.set(f"已处理 {processed[0]}/{len(self.url_data)}")

            self.update_queue.put(update_ui)

        except Exception as e:
            logger.error(f"获取网站信息失败: {url}, 错误: {str(e)}")
            data["status"] = "获取失败"

            def update_error_ui():
                processed[0] += 1
                for item in self.url_tree.get_children():
                    if self.url_tree.item(item, "values")[0] == data["id"]:
                        values = list(self.url_tree.item(item, "values"))
                        values[4] = "获取失败"
                        self.url_tree.item(item, values=values)
                        break

                # 更新进度
                self.progress_var.set(processed[0] / len(self.url_data) * 100)
                self.status_var.set(f"已处理 {processed[0]}/{len(self.url_data)}")

            self.update_queue.put(update_error_ui)

    def add_title_to_screenshot(self, screenshot_path, title):
        """在截图上方添加标签页标题"""
        try:
            # 打开截图
            img = Image.open(screenshot_path)
            width, height = img.size

            # 创建一个新的图像，高度增加40像素用于放置标题
            new_height = height + 40
            new_img = Image.new('RGB', (width, new_height), color=(240, 240, 240))

            # 将原截图粘贴到新图像的下方
            new_img.paste(img, (0, 40))

            # 在顶部绘制标题
            draw = ImageDraw.Draw(new_img)
            try:
                # 尝试加载中文字体
                font = ImageFont.truetype("simhei.ttf", 16)
            except IOError:
                # 如果找不到中文字体，使用默认字体
                font = ImageFont.load_default()

            # 绘制标题文本
            draw.text((10, 10), title, fill=(0, 0, 0), font=font)

            # 保存修改后的图像
            new_img.save(screenshot_path)

        except Exception as e:
            logger.error(f"添加标题到截图失败: {str(e)}")

    def open_website(self):
        """打开当前选中的网站"""
        if self.current_index < 0 or self.current_index >= len(self.url_data):
            messagebox.showinfo("提示", "请先选择一个URL")
            return

        data = self.url_data[self.current_index]
        url = data["url"]

        if not url:
            messagebox.showinfo("提示", "无效的URL")
            return

        # 如果浏览器未初始化，初始化一个用于显示的浏览器
        if not self.browser:
            chrome_options = Options()
            chrome_options.add_argument("--start-maximized")

            try:
                self.browser = webdriver.Chrome(
                    service=Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
                logger.info("浏览器驱动初始化成功")
            except Exception as e:
                logger.error(f"初始化浏览器驱动失败: {str(e)}")
                messagebox.showerror("错误", f"无法初始化浏览器驱动: {str(e)}\n请确保已安装Chrome浏览器")
                return

        # 打开URL
        try:
            self.browser.get(url)
            self.status_var.set(f"已打开: {data['name']}")
        except Exception as e:
            messagebox.showerror("错误", f"打开URL失败: {str(e)}")
            logger.error(f"打开URL失败: {str(e)}")

    def prev_url(self):
        """选择上一个URL"""
        if not self.url_data:
            return

        self.current_index = (self.current_index - 1) % len(self.url_data)
        item_id = self.url_data[self.current_index]["id"]

        # 在Treeview中选择对应的项
        for item in self.url_tree.get_children():
            if self.url_tree.item(item, "values")[0] == item_id:
                self.url_tree.selection_set(item)
                self.url_tree.see(item)
                break

    def next_url(self):
        """选择下一个URL"""
        if not self.url_data:
            return

        self.current_index = (self.current_index + 1) % len(self.url_data)
        item_id = self.url_data[self.current_index]["id"]

        # 在Treeview中选择对应的项
        for item in self.url_tree.get_children():
            if self.url_tree.item(item, "values")[0] == item_id:
                self.url_tree.selection_set(item)
                self.url_tree.see(item)
                break

    def on_up_key(self, event):
        """处理上箭头键"""
        self.prev_url()

    def on_down_key(self, event):
        """处理下箭头键"""
        self.next_url()

    def on_delete_key(self, event):
        """处理Delete键"""
        if self.current_index >= 0 and self.current_index < len(self.url_data):
            if self.url_data[self.current_index]["processed"] and self.url_data[self.current_index][
                "status"] != "已丢弃":
                self.discard_item()

    def update_title(self, event=None):
        """更新网站标题（仅保存在临时存储中）"""
        if self.current_index < 0 or self.current_index >= len(self.url_data):
            return

        new_title = self.title_var.get().strip()
        if not new_title:
            messagebox.showinfo("提示", "标题不能为空")
            return

        data = self.url_data[self.current_index]
        old_title = data["name"]

        if new_title != old_title:
            # 保存到临时修改存储
            self.temp_title_changes[data["id"]] = new_title

            # 更新Treeview中的标题（显示修改但不保存）
            for item in self.url_tree.get_children():
                if self.url_tree.item(item, "values")[0] == data["id"]:
                    values = list(self.url_tree.item(item, "values"))
                    values[1] = new_title
                    self.url_tree.item(item, values=values)
                    break

            self.status_var.set(f"标题已修改（未保存）: {new_title}")

    def update_desc(self, event=None):
        """更新网站描述（仅保存在临时存储中）"""
        if self.current_index < 0 or self.current_index >= len(self.url_data):
            return

        new_desc = self.desc_text.get(1.0, tk.END).strip()
        data = self.url_data[self.current_index]
        old_desc = data["tips"]

        if new_desc != old_desc:
            # 保存到临时修改存储
            self.temp_desc_changes[data["id"]] = new_desc
            self.status_var.set(f"描述已修改（未保存）")

    def discard_item(self):
        """丢弃当前项"""
        if self.current_index < 0 or self.current_index >= len(self.url_data):
            return

        data = self.url_data[self.current_index]

        if messagebox.askyesno("确认", f"确定要丢弃 {data['name']} 吗？"):
            try:
                # 移动图标到trash目录
                if data["icon_file"]:
                    icon_path = os.path.join(self.icons_dir, data["icon_file"])
                    if os.path.exists(icon_path):
                        trash_path = os.path.join(self.trash_dir, data["icon_file"])
                        os.rename(icon_path, trash_path)
                        logger.info(f"图标已移动到: {trash_path}")

                # 删除截图
                if os.path.exists(data["screenshot_path"]):
                    os.remove(data["screenshot_path"])

                # 更新状态
                data["processed"] = False
                data["status"] = "已丢弃"

                # 移除临时修改
                if data["id"] in self.temp_title_changes:
                    del self.temp_title_changes[data["id"]]
                if data["id"] in self.temp_desc_changes:
                    del self.temp_desc_changes[data["id"]]

                # 更新Treeview中的状态
                for item in self.url_tree.get_children():
                    if self.url_tree.item(item, "values")[0] == data["id"]:
                        values = list(self.url_tree.item(item, "values"))
                        values[4] = "已丢弃"
                        self.url_tree.item(item, values=values)
                        break

                self.status_var.set(f"已丢弃 {data['name']}")
                messagebox.showinfo("成功", f"已丢弃 {data['name']}")

                # 更新按钮状态
                if any(item["processed"] and item["status"] != "已丢弃" for item in self.url_data):
                    self.save_button.config(state=tk.NORMAL)
                else:
                    self.save_button.config(state=tk.DISABLED)

                # 自动选择下一个
                self.next_url()
            except Exception as e:
                messagebox.showerror("错误", f"丢弃失败: {str(e)}")
                logger.error(f"丢弃失败: {str(e)}")

    def save_all_items(self):
        """保存所有未丢弃的项到新的SQL文件，包括所有临时修改"""
        if not self.url_data:
            messagebox.showinfo("提示", "没有URL数据可保存")
            return

        # 筛选出未丢弃的项
        items_to_save = [item for item in self.url_data if item["status"] != "已丢弃"]

        if not items_to_save:
            messagebox.showinfo("提示", "没有可保存的URL")
            return

        try:
            # 写入到新的SQL文件
            with open(self.save_file, 'w', encoding='utf-8') as f:
                f.write("-- 筛选后的URL数据\n")
                f.write("-- 生成时间: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")

                for item in items_to_save:
                    # 创建SQL的副本用于修改
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

                    # 应用描述修改
                    if item["id"] in self.temp_desc_changes:
                        new_desc = self.temp_desc_changes[item["id"]]
                        sql_pattern = re.compile(
                            r"(insert into `mtab`.`linkstore`\s*\([^)]*\)\s*values\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*, \s*[^)]*, \s*)'[^']*'(\s*,\s*'[^']*', \s*[^)]*, \s*[^)]*, \s*'[^']*', \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*, \s*[^)]*\);)",
                            re.IGNORECASE)
                        sql_match = sql_pattern.match(current_sql)

                        if sql_match:
                            current_sql = f"{sql_match.group(1)}'{new_desc}'{sql_match.group(2)}"

                    f.write(current_sql + "\n\n")

            # 清空临时修改
            self.temp_title_changes = {}
            self.temp_desc_changes = {}

            self.status_var.set(f"已保存到 {self.save_file}")
            messagebox.showinfo("成功", f"已保存 {len(items_to_save)} 条URL记录到 {self.save_file}")
        except Exception as e:
            self.status_var.set("保存失败")
            messagebox.showerror("错误", f"保存文件时出错: {str(e)}")
            logger.error(f"保存文件时出错: {str(e)}")

    def on_closing(self):
        """关闭应用程序时清理资源"""
        if self.browser_pool:
            for browser in self.browser_pool:
                try:
                    browser.quit()
                except:
                    pass

        if self.browser:
            try:
                self.browser.quit()
            except:
                pass

        if self.thread_pool:
            self.thread_pool.shutdown(wait=False)

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SQLURLBrowser(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
