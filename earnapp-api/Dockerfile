FROM python:3.12-alpine
LABEL authors="Kinoko"

COPY ./app /app
WORKDIR /app

RUN apk update \
    && apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && pip install --no-cache-dir -r /app/requirements.txt

# 容器默认运行的端口
EXPOSE 5000

ENTRYPOINT [ "python", "main.py" ]