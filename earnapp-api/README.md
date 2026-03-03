# EarnAPP 设备注册API服务

EarnAPP 平台设备注册自动化工具，基于官方接口二次封装，提供标准化API服务，解决批量注册场景下的稳定性、可靠性问题。

## 核心优势

| 特性       | 说明                                             |
|----------|------------------------------------------------|
| 🔒 接口鉴权  | 支持 Bearer Token / 自定义 Header Token 双重鉴权，防止接口滥用 |
| 🚀 异步处理  | UUID 加入队列异步串行处理，避免接口阻塞，支持批量提交                  |
| 🔄 智能重试  | 429限流/网络异常自动重试（最大3次），可配置重试间隔                   |
| 💾 状态持久化 | UUID 处理状态本地持久化，服务重启不丢失历史数据                     |
| 🚨 异常告警  | Token过期/注册失败/长时间未处理自动推送QQ告警                    |
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

### Docker部署（推荐）

```bash
# 启动容器（替换占位符为实际值）
docker run -d \
  -p 5000:5000 \
  --name earnapp-api \
  --restart=always \
  -v earnapp-data:/data \
  # 核心认证参数
  -e XSRF_TOKEN="your_xsrf_token" \
  -e BRD_SESS_ID="your_brd_sess_id" \
  -e AUTH_TOKEN="your_custom_auth_token" \
  # 代理基础配置
  -e PROXY_HOST="proxy.example.com" \  # 代理服务器地址
  -e PROXY_PORT="8080" \               # 代理端口
  # 代理认证（根据服务商要求配置）
  -e PROXY_USER_TPL="user_{RND:8}" \   # 用户名模板（支持{RND:N}随机字符串）
  -e PROXY_PASS_TPL="pass_{RND:8}" \   # 密码模板
  -e RND_CHARSET="abcdefghijklmnopqrstuvwxyz0123456789" \  # 随机字符集
  # 重试策略优化（针对429）
  -e API_CALL_INTERVAL="10" \          # API调用间隔（默认5秒，建议改为10-15秒）
  -e MAX_PROXY_RETRY_COUNT="3" \       # 429重试次数（默认2次，建议改为3次）
  fogforest/earnapp-api
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
  // 响应码（0=成功，其他=异常）
  "message": "描述信息",
  "data": {}
  // 业务数据（可选）
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

1. **Token过期告警**：EarnApp认证Token过期（API返回403），仅发送1次避免刷屏
2. **注册失败告警**：UUID重试3次仍失败，推送失败原因+UUID
3. **长时间未处理告警**：UUID待处理超过5分钟，推送未处理列表

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

## 常见问题

### Q1: Token过期后程序会无限处理队列吗？

不会。每个UUID最多处理1次主队列+3次重试，达到最大重试次数后标记为永久失败；Token过期告警仅发送1次，避免刷屏。

### Q2: 如何恢复Token过期后的处理？

更新容器的`XSRF_TOKEN`/`BRD_SESS_ID`环境变量，重启容器即可继续处理队列中的UUID。

### Q3: UUID状态保存在哪里？

容器内`/data/uuid_status.json`文件，建议通过`-v earnapp-data:/data`挂载数据卷，避免容器重启丢失数据。

### Q4: 支持代理吗？

仅支持 SOCKS 协议，用于解决官方接口频繁429错误的问题，可通过以下环境变量配置代理：

```bash
-e PROXY_HOST="proxy.example.com" \
-e PROXY_PORT="8080" \
-e PROXY_USER_TPL="user_{RND:8}" \  # 支持{RND:N}随机字符串
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