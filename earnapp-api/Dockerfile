FROM python:3.12-alpine
LABEL authors="Kinoko"

COPY ./app /app
WORKDIR /app

RUN set -eux \
    && apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && mv entrypoint.sh /entrypoint.sh \
    && chmod +x /entrypoint.sh \
    && pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]