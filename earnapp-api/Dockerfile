FROM python:3.12-alpine
LABEL authors="Kinoko"
ARG TARGETARCH

COPY ./app /app
WORKDIR /app

RUN set -eux \
    && apk update \
    && apk add --no-cache \
    tzdata \
    curl \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && curl -sSL "https://github.com/aptible/supercronic/releases/download/v0.2.43/supercronic-linux-$TARGETARCH" -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic \
    && mv entrypoint.sh /entrypoint.sh \
    && chmod +x /entrypoint.sh \
    && pip install --no-cache-dir -r /app/requirements.txt

# 容器默认运行的端口
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]