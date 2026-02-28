# EarnAPP 平台设备注册API

### 说明

EarnAPP 平台设备无法自动注册，需手动通过链接添加。本工具通过抓包获取注册设备的核心接口，二次封装为标准化 API，增加 Header
Token 鉴权提升接口安全性，并新增**异步队列处理、失败自动重试、状态持久化、异常告警**等核心能力，解决批量注册时的稳定性和可靠性问题。

### 核心特性

- ✅ 接口鉴权：支持 Bearer Token / 自定义 Header Token 双重鉴权方式
- ✅ 异步处理：UUID 加入队列异步处理，避免接口阻塞
- ✅ 失败重试：注册失败自动重试（最多3次，间隔5/15/30秒）
- ✅ 状态持久化：UUID 处理状态保存到 /data 目录，程序重启不丢失
- ✅ 异常告警：Token 过期/UUID 永久失败/长时间未处理自动发送 QQ 告警
- ✅ 状态查询：支持查询单个 UUID 的处理状态（成功/失败/处理中）
- ✅ 幂等性：已成功/处理中的 UUID 重复提交自动过滤

### 部署

#### 1. 环境准备

- **必要参数获取**：
    - `XSRF_TOKEN`/`BRD_SESS_ID`：登录 EarnAPP 官网，按 F12 打开开发者工具 → 应用 → Cookie 中可获取；
    - `AUTH_TOKEN`：自定义的接口鉴权 Token（任意字符串，用于保护接口不被滥用），必填；
- **可选告警参数**（QMSG 机器人，用于接收异常通知）：
    - `QMSG_TOKEN`：QMSG 机器人 Token（获取地址：<https://qmsg.zendee.cn/>）；
    - `QMSG_QQ`：接收告警的 QQ 号；
    - `QMSG_BOT`：QMSG 机器人 ID（默认填 12345 即可）。

#### 2. 容器部署（推荐）

```bash
# 启动容器（替换下方的 your_xxx 为实际值）
docker run -d \
  -p 5000:5000 \
  --name earnapp-api \
  --restart=always \
  -v earnapp-data:/data  # 挂载数据卷，持久化 UUID 状态（可选但推荐）
  -e PORT=5000 \
  -e XSRF_TOKEN="your_xsrf_token" \
  -e BRD_SESS_ID="your_brd_sess_id" \
  -e AUTH_TOKEN="your_custom_auth_token" \
  # 以下为可选告警参数，不需要可删除
  -e QMSG_TOKEN="your_qmsg_token" \
  -e QMSG_QQ="your_qq_number" \
  -e QMSG_BOT="12345" \
  fogforest/earnapp-api
```

#### 3. 接口调用

##### 3.1 注册 UUID（核心接口）

```bash
# 格式1：标准 Bearer Token（推荐）
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_custom_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'

# 格式2：自定义 Header Token
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your_custom_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1"}'
```

##### 3.2 查询 UUID 处理状态

```bash
curl -X GET http://127.0.0.1:5000/api/uuid/status/sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1 \
  -H "Authorization: Bearer your_custom_auth_token"
```

#### 4. 响应说明

| 状态码 | 响应示例                                                                                                             | 说明                |
|-----|------------------------------------------------------------------------------------------------------------------|-------------------|
| 200 | `{"message":"UUID already registered successfully","uuid":"xxx","status":"success"}`                             | UUID 已注册成功        |
| 202 | `{"message":"UUID received, processing will start shortly.","uuid":"xxx","queue_position":1,"status":"pending"}` | UUID 已接收，等待处理     |
| 202 | `{"message":"UUID is being processed","uuid":"xxx","status":"processing"}`                                       | UUID 正在处理中        |
| 400 | `{"error":"UUID is required"}`                                                                                   | 请求参数缺失（未传 uuid）   |
| 401 | `{"error":"Unauthorized","message":"Invalid authentication token..."}`                                           | 鉴权失败（Token 错误/未传） |
| 404 | `{"error":"UUID not found"}`                                                                                     | UUID 未找到          |

### 告警说明

程序会在以下场景自动发送 QQ 告警（需配置 QMSG 参数）：

1. **Token 过期告警**：EarnApp 认证 Token 过期（API 返回 403），仅发送 1 次，避免刷屏；
2. **UUID 永久失败告警**：UUID 重试 3 次仍注册失败，发送失败原因+UUID；
3. **长时间未处理告警**：UUID 处于待处理状态超过 5 分钟，发送未处理 UUID 列表。

### 常见问题

1. **Token 过期后程序会无限处理队列吗？**
    - 不会。每个 UUID 最多处理 1 次主队列 + 3 次重试，达到最大重试次数后标记为永久失败，停止处理；Token 过期告警仅发送 1 次。
2. **如何恢复 Token 过期后的处理？**
    - 更新容器的 `XSRF_TOKEN`/`BRD_SESS_ID` 环境变量，重启容器即可。
3. **UUID 状态保存在哪里？**
    - 容器内 `/data/uuid_status.json`，建议挂载数据卷避免重启丢失。
