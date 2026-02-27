# EarnAPP 平台设备注册API

### 说明

EarnAPP 平台设备无法自动注册，需手动通过链接添加。本工具通过抓包获取注册设备的核心接口，二次封装为标准化 API，并增加 Header
Token 鉴权，提升接口安全性。

### 部署

#### 1. 环境准备

- **必要参数获取**：
    - `XSRF_TOKEN`/`OAUTH_REFRESH_TOKEN`：登录 EarnAPP 官网，按 F12 打开开发者工具 → 应用 → Cookie 中可获取；
    - `AUTH_TOKEN`：自定义的接口鉴权 Token（任意字符串，用于保护接口不被滥用）。

#### 2. 容器部署（推荐）

```bash
# 启动容器（替换下方的 your_xxx_token 为实际值）
docker run -d \
  -p 5000:5000 \
  --name earnapp-api \
  --restart=always \
  -e PORT=5000 \
  -e XSRF_TOKEN="your_xsrf_token" \
  -e OAUTH_REFRESH_TOKEN="your_oauth_token" \
  -e AUTH_TOKEN="your_custom_auth_token"  # 接口鉴权Token，必填
  fogforest/earnapp-api
```

#### 3. 接口调用

```bash
# 请求示例（必须携带鉴权Token，支持两种格式）
# 格式1：标准Bearer Token（推荐）
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_custom_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'

# 格式2：自定义Header Token
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your_custom_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'
```

#### 4. 响应说明

| 状态码 | 响应内容                                                                      | 说明               |
|-----|---------------------------------------------------------------------------|------------------|
| 202 | `{"message": "UUID received, processing will start shortly."}`            | UUID已接收，等待处理     |
| 400 | `{"error": "UUID is required"}`                                           | 请求参数缺失（未传uuid）   |
| 401 | `{"error": "Unauthorized", "message": "Invalid authentication token..."}` | 鉴权失败（Token错误/未传） |
