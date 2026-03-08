#!/bin/sh
set -e

# 启动定时任务
echo "🚀 启动定时任务：每1小时删除被ban设备"
supercronic /app/crontab.txt &

# 启动API服务
echo "🚀 启动API服务（端口5000）..."
exec python /app/main.py
