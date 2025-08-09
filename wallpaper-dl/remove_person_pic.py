#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <i@linux.wf>
# @Date  : 2025/08/09
# @Desc  : 移除包含人像的图片

import os
from pathlib import Path

import cv2
import numpy as np

# ---------------------- 配置项 ----------------------
# 目标目录路径（要处理的图片所在目录）
TARGET_DIRECTORY = "D:\\DL\\科幻"  # 替换为实际的目录路径

# 支持的图片格式
SUPPORTED_IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff']

# 人脸检测参数
FACE_DETECTION_SCALE_FACTOR = 1.1  # 图像缩放比例
FACE_DETECTION_MIN_NEIGHBORS = 5  # 每个候选矩形应保留的邻居数
FACE_DETECTION_MIN_SIZE = (30, 30)  # 可能的最小人脸大小


# -----------------------------------------------------


def is_person_present(image_path):
    """检测图片中是否有人像（人脸），支持中文路径"""
    # 加载预训练的 Haar 级联分类器
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    # 读取图片（支持中文路径）
    try:
        # 使用numpy从文件读取数据，再转换为OpenCV图像
        raw_data = np.fromfile(image_path, dtype=np.uint8)
        image = cv2.imdecode(raw_data, cv2.IMREAD_COLOR)
    except Exception as e:
        print(f"读取图片 {image_path} 失败: {str(e)}")
        return False  # 无法读取图片

    if image is None:
        return False  # 无法读取图片

    # 转换为灰度图
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # 检测人脸（使用配置项参数）
    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=FACE_DETECTION_SCALE_FACTOR,
        minNeighbors=FACE_DETECTION_MIN_NEIGHBORS,
        minSize=FACE_DETECTION_MIN_SIZE
    )

    # 如果检测到人脸，返回True
    return len(faces) > 0


def process_images(directory):
    """遍历目录中的图片，删除包含人像的图片"""
    # 遍历目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 检查文件扩展名（使用配置项）
            file_ext = Path(file).suffix.lower()
            if file_ext in SUPPORTED_IMAGE_EXTENSIONS:
                file_path = os.path.join(root, file)

                # 检查文件是否存在
                if not os.path.exists(file_path):
                    print(f"文件不存在: {file_path}")
                    continue

                # 检查是否为文件
                if not os.path.isfile(file_path):
                    print(f"不是有效的文件: {file_path}")
                    continue

                try:
                    # 检测是否有人像
                    has_person = is_person_present(file_path)

                    if has_person:
                        # 直接删除包含人像的图片
                        os.remove(file_path)
                        print(f"已删除包含人像的图片: {file_path}")
                    else:
                        print(f"未检测到人像: {file_path}")
                except Exception as e:
                    print(f"处理文件 {file_path} 时出错: {str(e)}")


def main():
    # 检查目录是否存在
    if not os.path.isdir(TARGET_DIRECTORY):
        print(f"错误: 目录 '{TARGET_DIRECTORY}' 不存在。")
        return

    print(f"开始处理目录: {TARGET_DIRECTORY}")
    process_images(TARGET_DIRECTORY)
    print("处理完成。")


if __name__ == "__main__":
    main()
