#!/bin/sh
set -e

echo "启动 EarnApp API 服务（端口5000）..."
exec python /app/main.py
