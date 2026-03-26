#!/usr/bin/python3
# coding=utf8
"""代理工具 - 代理配置生成与随机字符串渲染"""
import logging
import random
import re
from typing import Dict, Optional

from config import PROXY_HOST, PROXY_PORT, PROXY_USER_TPL, PROXY_PASS_TPL, RND_CHARSET

logger = logging.getLogger(__name__)


def generate_random_string(length: int) -> str:
    """从 RND_CHARSET 中随机抽取 length 个字符组成字符串，用于代理认证动态化"""
    if length <= 0:
        return ""
    return ''.join(random.choice(RND_CHARSET) for _ in range(length))


def render_template(template_str: str) -> str:
    """替换 {RND:N} 占位符为随机字符串"""
    if not template_str:
        return ""
    return re.sub(r'\{RND:(\d+)\}', lambda m: generate_random_string(int(m.group(1))), template_str)


def get_proxy_dict() -> Optional[Dict[str, str]]:
    """生成 requests 可用的代理配置字典"""
    if not all([PROXY_HOST, PROXY_PORT]):
        return None
    try:
        user = render_template(PROXY_USER_TPL)
        pwd = render_template(PROXY_PASS_TPL)

        if user and pwd:
            proxy_url = f"http://{user}:{pwd}@{PROXY_HOST}:{PROXY_PORT}"
        elif user:
            proxy_url = f"http://{user}@{PROXY_HOST}:{PROXY_PORT}"
        elif pwd:
            proxy_url = f"http://:{pwd}@{PROXY_HOST}:{PROXY_PORT}"
        else:
            proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"

        # 日志中对密码脱敏，仅显示前3位
        log_pwd = (pwd[:3] + "***") if len(pwd) > 3 else ("***" if pwd else "")
        logger.debug(f"代理: http://{user}:{log_pwd}@{PROXY_HOST}:{PROXY_PORT}")
        return {"http": proxy_url, "https": proxy_url}
    except Exception as e:
        logger.error(f"生成代理配置失败: {e}")
        return None
