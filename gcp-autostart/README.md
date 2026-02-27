# GCP 抢占式实例自动开机脚本

## 运行容器

```bash
# 先申请GCP账号密钥，类型选JSON，

mkdir /root/key # 密钥文件放到 /root/key 里面
docker run -d --name gcp-autostart \
    -e GCP_KEY_PATH=/app/key \
    -e GCP_LOOP_INTERVAL=300 \ 
    -v /root/key:/app/key \
    fogforest/gcp-autostart
```

## 查看日志

```bash
docker logs -f gcp-autostart
```

