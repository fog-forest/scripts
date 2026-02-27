FROM python:3.10-slim
LABEL authors="Kinoko"

WORKDIR /app
COPY ./app/* .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
