# EarnAPP 设备注册API服务

EarnAPP 平台设备注册自动化工具，基于官方接口二次封装，提供标准化API服务，解决批量注册场景下的稳定性、可靠性问题。

## 核心优势

| 特性       | 说明                                             |
|----------|------------------------------------------------|
| 🔒 接口鉴权  | 支持 Bearer Token / 自定义 Header Token 双重鉴权，防止接口滥用 |
| 🚀 异步处理  | UUID 加入队列异步串行处理，避免接口阻塞，支持批量提交                  |
| 🔄 智能重试  | 429限流/网络异常自动重试（最大2次），固定调用间隔防限流                 |
| 💾 状态持久化 | UUID 处理状态本地持久化，服务重启不丢失历史数据                     |
| 🚨 异常告警  | Token过期（连续3次403）自动推送QQ告警，服务启动也会推送通知            |
| 🔍 状态查询  | 支持查询单个UUID处理状态（成功/失败/处理中/队列中）                  |
| ⚡ 幂等设计   | 已成功/处理中的UUID重复提交自动过滤，避免重复处理                    |

## 快速部署

### 环境准备

#### 必要参数（必填）

| 参数名           | 获取方式                                    |
|---------------|-----------------------------------------|
| `XSRF_TOKEN`  | 登录EarnAPP官网 → F12开发者工具 → 应用 → Cookie中获取 |
| `BRD_SESS_ID` | 同上                                      |
| `AUTH_TOKEN`  | 自定义任意字符串，用于接口鉴权                         |

#### 可选告警参数（QMSG机器人）

| 参数名          | 说明                                         |
|--------------|--------------------------------------------|
| `QMSG_TOKEN` | QMSG机器人Token（获取地址：https://qmsg.zendee.cn/） |
| `QMSG_QQ`    | 接收告警的QQ号                                   |
| `QMSG_BOT`   | QMSG机器人ID（默认填12345即可）                      |

#### 可选代理参数

| 参数名              | 说明                        |
|------------------|---------------------------|
| `PROXY_HOST`     | 代理服务器地址                   |
| `PROXY_PORT`     | 代理服务器端口                   |
| `PROXY_USER_TPL` | 代理账号模板（支持{RND:N}随机字符串占位符） |
| `PROXY_PASS_TPL` | 代理密码模板（支持{RND:N}随机字符串占位符） |
| `RND_CHARSET`    | 随机字符集（默认：字母+数字）           |

### Docker部署（推荐）

```bash
# 启动容器（替换占位符为实际值）
docker run -d \
  -p 5000:5000 \
  --name earnapp-api \
  --restart=always \
  -v earnapp-data:/data \
  # 核心认证参数（必填）
  -e XSRF_TOKEN="your_xsrf_token" \
  -e BRD_SESS_ID="your_brd_sess_id" \
  -e AUTH_TOKEN="your_custom_auth_token" \
  # 代理配置（可选）
  -e PROXY_HOST="proxy.example.com" \
  -e PROXY_PORT="8080" \
  -e PROXY_USER_TPL="user_{RND:8}" \
  -e PROXY_PASS_TPL="pass_{RND:8}" \
  -e RND_CHARSET="abcdefghijklmnopqrstuvwxyz0123456789" \
  # 服务端口（可选，默认5000）
  -e PORT="5000" \
  fogforest/earnapp-api
```

### 手动部署

```bash
# 克隆代码
git clone <仓库地址>
cd earnapp-register-service

# 安装依赖
pip install flask requests

# 设置环境变量（Linux/Mac）
export XSRF_TOKEN="your_xsrf_token"
export BRD_SESS_ID="your_brd_sess_id"
export AUTH_TOKEN="your_custom_auth_token"

# 启动服务
python earnapp_register.py
```

## 接口文档

### 1. 注册UUID（核心接口）

提交UUID到处理队列，异步完成注册。

**请求地址**：`POST /api/register`  
**请求头**：

- Content-Type: application/json
- Authorization: Bearer {AUTH_TOKEN} （或 X-Auth-Token: {AUTH_TOKEN}）

**请求体**：

```json
{
  "uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"
}
```

### 2. 查询UUID状态

查询指定UUID的处理状态。

**请求地址**：`GET /api/uuid/status/{uuid}`  
**请求头**：

- Authorization: Bearer {AUTH_TOKEN} （或 X-Auth-Token: {AUTH_TOKEN}）

### 3. 健康检查

查看服务运行状态，无需鉴权。

**请求地址**：`GET /api/health`

## 响应说明

### 通用响应格式

```json
{
  "code": 0,
  "message": "描述信息",
  "data": {}
}
```

### 详细响应示例

| 场景        | HTTP状态码 | 响应示例                                                                                                                              |
|-----------|---------|-----------------------------------------------------------------------------------------------------------------------------------|
| UUID已成功注册 | 200     | `{"code":0,"message":"UUID already registered successfully","data":{"uuid":"xxx","status":"success"}}`                            |
| UUID已入队等待 | 202     | `{"code":0,"message":"UUID received, processing will start shortly","data":{"uuid":"xxx","queue_position":1,"status":"pending"}}` |
| UUID正在处理  | 202     | `{"code":0,"message":"UUID current status: processing","data":{"uuid":"xxx","status":"processing"}}`                              |
| 重复提交UUID  | 200     | `{"code":1004,"message":"UUID is already in processing queue","data":{"uuid":"xxx","status":"in_queue"}}`                         |
| 参数缺失      | 400     | `{"code":1001,"message":"Parameter error, missing required UUID field"}`                                                          |
| 鉴权失败      | 401     | `{"code":1002,"message":"Invalid authentication token"}`                                                                          |
| UUID不存在   | 404     | `{"code":1003,"message":"UUID not found"}`                                                                                        |

### 健康检查响应示例

```json
{
  "code": 0,
  "message": "Service is running normally",
  "data": {
    "service": "earnapp-uuid-register",
    "status": "running",
    "timestamp": "2026-03-03 16:00:00",
    "queue_size": 5,
    "queue_unique_count": 5,
    "recorded_uuids": 120,
    "proxy_configured": false
  }
}
```

## 告警说明

配置QMSG参数后，程序会在以下场景自动发送QQ告警：

1. **Token过期告警**：连续3次API返回403错误（Token过期），触发一次告警后不再重复推送
2. **服务启动通知**：服务启动时推送基础配置信息，确认服务正常运行

## 使用示例

### 注册UUID

```bash
# Bearer Token方式（推荐）
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'

# 自定义Header Token方式
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'
```

### 查询UUID状态

```bash
curl -X GET http://127.0.0.1:5000/api/uuid/status/sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1 \
  -H "Authorization: Bearer your_auth_token"
```

### 健康检查

```bash
curl -X GET http://127.0.0.1:5000/api/health
```

## 核心固定配置说明

以下参数为代码内置固定值，**不支持通过环境变量修改**，如需调整需修改源码后重新部署：

| 参数名                            | 固定值 | 说明                    |
|--------------------------------|-----|-----------------------|
| `API_CALL_INTERVAL`            | 5秒  | 每次API调用间隔，防止触发频率限制    |
| `MAX_PROXY_RETRY_COUNT`        | 2次  | 遇到429限流错误时的最大重试次数     |
| `TOKEN_EXPIRE_ALERT_THRESHOLD` | 3次  | 连续403错误触发Token过期告警的阈值 |

## 常见问题

### Q1: Token过期后程序会无限处理队列吗？

不会。遇到429限流错误仅重试2次，遇到403 Token过期错误会触发告警并停止计数，不会无限重试；已过期的Token需要手动更新后重启服务。

### Q2: 如何恢复Token过期后的处理？

1. 更新环境变量中的`XSRF_TOKEN`和`BRD_SESS_ID`
2. 重启服务/容器
3. 队列中的UUID会自动继续处理

### Q3: UUID状态保存在哪里？

状态文件存储在`/data/uuid_status.json`，采用原子写入机制防止文件损坏。Docker部署时建议通过`-v earnapp-data:/data`
挂载数据卷，避免数据丢失。

### Q4: 支持代理吗？

支持HTTP/HTTPS代理，用于解决429限流问题，配置示例：

```bash
-e PROXY_HOST="proxy.example.com" \
-e PROXY_PORT="8080" \
-e PROXY_USER_TPL="user_{RND:8}" \  # {RND:N}会生成N位随机字符串
-e PROXY_PASS_TPL="pass_{RND:8}" \
```

## 响应码速查表

| 响应码  | 含义               |
|------|------------------|
| 0    | 成功               |
| 1001 | 参数错误             |
| 1002 | 未授权（Token错误/未提供） |
| 1003 | UUID不存在          |
| 1004 | UUID已在队列中        |
| 9999 | 系统错误             |

### 总结

1. 该服务核心解决EarnAPP批量注册UUID的稳定性问题，提供异步处理、智能重试、状态持久化等关键能力，核心限流/重试参数为代码内置固定值
2. 部署方式支持Docker（推荐）和手动部署，核心依赖`XSRF_TOKEN`/`BRD_SESS_ID`/`AUTH_TOKEN`三个必填参数
3. 接口设计简洁，包含注册、查询、健康检查三类接口，支持双重鉴权方式，响应格式统一且易解析
4. 代理配置支持随机字符串占位符，可适配动态代理认证场景，429限流自动重试（最多2次）提升注册成功率