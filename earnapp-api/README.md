# EarnApp 设备注册 API 服务

基于 EarnApp 官方接口封装的设备注册自动化服务，提供标准化 HTTP API，支持多账号轮询、异步队列处理、状态持久化和异常告警，适用于批量设备注册场景。

## 特性

| 特性       | 说明                                   |
|----------|--------------------------------------|
| 🔒 接口鉴权  | 支持 Bearer Token / X-Auth-Token 双模式鉴权 |
| 👥 多账号轮询 | 多账号轮询注册，429 限流时自动切换账号+代理重试           |
| 🚀 异步队列  | UUID 入队异步串行处理，接口立即返回不阻塞              |
| 💾 状态持久化 | UUID 处理状态本地持久化，服务重启不丢失历史记录           |
| ⚡ 幂等处理   | 已成功/处理中/封禁的 UUID 重复提交自动过滤            |
| 🗑️ 自动清理 | 定时检测并删除被封禁设备，同步更新本地状态                |
| 🚨 异常告警  | 账号连续 403 达阈值时推送 QQ 告警（QMSG）          |
| 📊 定时日报  | 定时推送各账号设备数量与收益汇总                     |

## 目录

- [快速部署](#快速部署)
- [配置文件说明](#配置文件说明)
- [接口文档](#接口文档)
- [UUID 状态说明](#uuid-状态说明)
- [告警说明](#告警说明)
- [使用示例](#使用示例)
- [常见问题](#常见问题)

---

## 快速部署

### Docker 部署（推荐）

```bash
# 1. 创建数据目录并编写配置文件
mkdir -p /opt/earnapp/data
vim /opt/earnapp/data/config.yaml

# 2. 启动容器
docker run -d \
  -p 5000:5000 \
  --name earnapp-api \
  --restart=always \
  -v /opt/earnapp/data:/data \
  fogforest/earnapp-api
```

### 手动部署

```bash
# 1. 安装依赖
python -m venv venv
source venv/bin/activate
pip install flask requests pyyaml

# 2. 准备配置文件
mkdir -p /data
vim /data/config.yaml

# 3. 启动服务
cd earnapp-api/app
python main.py
```

---

## 配置文件说明

服务启动时读取 `/data/config.yaml`，完整示例如下：

```yaml
# ── 全局配置 ──────────────────────────────────────────────────
global:
  # 接口鉴权令牌，自定义字符串，所有 API 请求必须携带
  auth_token: "your_auth_token"
  # 账号版本标识（可选），用于区分不同批次的 Cookie，状态查询时返回
  account_version: "v1"

# ── 账号列表 ──────────────────────────────────────────────────
accounts:
  - name: account-01
    cookie:
      # 登录 EarnApp 官网 → F12 → 应用 → Cookie 中获取
      xsrf_token: "XSRF_TOKEN_01"
      brd_sess_id: "BRD_SESS_ID_01"
  - name: account-02
    cookie:
      xsrf_token: "XSRF_TOKEN_02"
      brd_sess_id: "BRD_SESS_ID_02"

# ── 告警配置（可选）─────────────────────────────────────────────
alarm:
  enabled: true
  qmsg:
    token: "QMSG_TOKEN"       # QMSG 机器人 Token
    qq: "1234567890"          # 接收告警的 QQ 号
    bot_id: "12345"           # QMSG 机器人 ID

# ── 代理配置（可选）─────────────────────────────────────────────
proxy:
  host: "proxy.example.com"
  port: 3010
  # 支持 {RND:N} 占位符，每次请求生成 N 位随机字符串
  user_template: "user-{RND:8}"
  password_template: "your_password"
  # 随机字符集，默认字母+数字
  random_charset: "abcdefghijklmnopqrstuvwxyz0123456789"

# ── 定时任务（可选）─────────────────────────────────────────────
scheduler:
  # 日报推送时间，24 小时制整点列表，默认 9、15、20 点
  report_hours: [ 9, 15, 20 ]
  # 自动删除被封禁设备的间隔（分钟），服务启动后首次立即执行，默认 360 分钟
  delete_banned_interval_minutes: 360
```

### 配置项说明

| 配置项                                        | 必填 | 默认值           | 说明                                         |
|--------------------------------------------|----|---------------|--------------------------------------------|
| `global.auth_token`                        | ✅  | —             | 接口鉴权令牌                                     |
| `global.account_version`                   | ❌  | 空             | 账号版本标识，状态查询时返回                             |
| `accounts[].name`                          | ✅  | —             | 账号名称，用于日志和告警区分                             |
| `accounts[].cookie.xsrf_token`             | ✅  | —             | EarnApp Cookie                             |
| `accounts[].cookie.brd_sess_id`            | ✅  | —             | EarnApp Cookie                             |
| `alarm.enabled`                            | ❌  | `false`       | 告警总开关                                      |
| `alarm.qmsg.token`                         | ❌  | —             | QMSG 机器人 Token，获取地址：https://qmsg.zendee.cn |
| `alarm.qmsg.qq`                            | ❌  | —             | 接收告警的 QQ 号                                 |
| `alarm.qmsg.bot_id`                        | ❌  | —             | QMSG 机器人 ID                                |
| `proxy.host`                               | ❌  | —             | 代理服务器地址                                    |
| `proxy.port`                               | ❌  | —             | 代理服务器端口（数字类型）                              |
| `proxy.user_template`                      | ❌  | —             | 代理账号模板，支持 `{RND:N}` 随机占位符                  |
| `proxy.password_template`                  | ❌  | —             | 代理密码模板，支持 `{RND:N}` 随机占位符                  |
| `proxy.random_charset`                     | ❌  | 字母+数字         | `{RND:N}` 随机字符集                            |
| `scheduler.report_hours`                   | ❌  | `[9, 15, 20]` | 日报推送小时列表（24 小时制整点）                         |
| `scheduler.delete_banned_interval_minutes` | ❌  | `360`         | 自动删除封禁设备间隔（分钟）                             |

> **内置固定参数**（如需调整请修改源码重新部署）：
> - `API_CALL_INTERVAL = 5`：每次注册 API 调用后等待间隔（秒）
> - `MAX_PROXY_RETRY_COUNT = 2`：429 限流时最大重试次数，每次同时切换账号+代理
> - `TOKEN_EXPIRE_ALERT_THRESHOLD = 5`：账号连续 403 触发告警的阈值

---

## 接口文档

所有需要鉴权的接口支持两种 Token 传递方式：

```
Authorization: Bearer {auth_token}
X-Auth-Token: {auth_token}
```

### POST /api/register — 注册 UUID

将 UUID 提交到处理队列，异步处理后更新状态。

**请求体**：

```json
{
  "uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1",
  "device": "minion_89f3a2_debian-host"
}
```

| 字段       | 类型     | 必填 | 说明                                             |
|----------|--------|----|------------------------------------------------|
| `uuid`   | string | ✅  | 设备 UUID                                        |
| `device` | string | ✅  | 设备标识，可为空字符串但字段必须存在；UUID 已存在但 device 不一致时自动更新记录 |

**响应说明**：

| 场景    | HTTP | code | 说明                     |
|-------|------|------|------------------------|
| 成功入队  | 202  | 0    | UUID 已加入队列，等待处理        |
| 已成功注册 | 200  | 0    | UUID 之前已注册成功，直接返回      |
| 处理中   | 202  | 0    | UUID 正在处理或排队等待中        |
| 已被封禁  | 200  | 0    | UUID 对应设备已封禁，拒绝重新注册    |
| 已在队列  | 200  | 1004 | UUID 已在队列中，勿重复提交       |
| 参数缺失  | 400  | 1001 | 请求体缺少 uuid 或 device 字段 |
| 鉴权失败  | 401  | 1002 | Token 错误或未提供           |

**入队成功响应**：

```json
{
  "code": 0,
  "message": "UUID received, processing will start shortly",
  "data": {
    "uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1",
    "queue_position": 3,
    "status": "pending"
  }
}
```

**设备已封禁响应**：

```json
{
  "code": 0,
  "message": "UUID is banned",
  "data": {
    "uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1",
    "status": "banned",
    "message": "Device banned: abuse"
  }
}
```

---

### GET /api/uuid/status/{uuid} — 查询 UUID 状态

查询指定 UUID 的当前处理状态。

**正常状态响应**：

```json
{
  "code": 0,
  "message": "UUID status query successful",
  "data": {
    "status": "success",
    "message": "UUID registered successfully",
    "device": "minion_89f3a2_debian-host",
    "account_version": "v1"
  }
}
```

**封禁状态响应**：

```json
{
  "code": 0,
  "message": "UUID is banned",
  "data": {
    "status": "banned",
    "message": "Device banned: abuse",
    "device": "minion_89f3a2_debian-host",
    "account_version": "v1"
  }
}
```

---

### GET /api/health — 健康检查

无需鉴权，返回服务运行状态。

**响应示例**：

```json
{
  "code": 0,
  "message": "Service is running normally",
  "data": {
    "service": "earnapp-uuid-register",
    "status": "running",
    "timestamp": "2025-01-01 12:00:00",
    "queue_size": 5,
    "queue_unique_count": 5,
    "recorded_uuids": 120,
    "proxy_configured": true,
    "account_count": 2,
    "alarm_enabled": true
  }
}
```

---

## UUID 状态说明

| 状态           | 含义       | 再次提交注册接口的行为  |
|--------------|----------|--------------|
| `pending`    | 已入队，等待处理 | 返回当前状态，不重复入队 |
| `processing` | 处理中      | 返回当前状态，不重复入队 |
| `success`    | 注册成功     | 直接返回成功，不重复入队 |
| `failed`     | 注册失败     | 重新初始化入队重试    |
| `banned`     | 设备已封禁    | 拒绝入队，返回封禁信息  |

---

## 告警说明

配置 QMSG 后，以下事件会自动推送 QQ 消息：

| 事件         | 触发条件                                               |
|------------|----------------------------------------------------|
| 服务启动通知     | 每次服务启动时推送，包含账号数、代理状态等基础信息                          |
| Token 过期告警 | 单个账号连续 403 达到阈值（默认 5 次），每个账号只告警一次，Token 恢复后自动重置计数  |
| 定时日报       | 按 `scheduler.report_hours` 配置的时间推送，包含各账号设备数量、收益余额等 |

---

## 使用示例

### 注册 UUID

```bash
# Bearer Token 方式（推荐）
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1", "device": "minion_89f3a2_debian-host"}'

# X-Auth-Token 方式
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: your_auth_token" \
  -d '{"uuid": "sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1", "device": "minion_89f3a2_debian-host"}'
```

### 查询 UUID 状态

```bash
curl http://127.0.0.1:5000/api/uuid/status/sdk-node-7a3b43f516a3490d8ba4c3d459bb34b1 \
  -H "Authorization: Bearer your_auth_token"
```

### 健康检查

```bash
curl http://127.0.0.1:5000/api/health
```

---

## 响应码速查

| code | 含义                 |
|------|--------------------|
| 0    | 成功                 |
| 1001 | 参数错误               |
| 1002 | 鉴权失败（Token 错误或未提供） |
| 1003 | UUID 不存在           |
| 1004 | UUID 已在队列中         |
| 9999 | 系统错误               |

---

## 常见问题

**Q：失败的 UUID 如何重新注册？**
直接再次调用 `/api/register` 接口即可，`failed` 状态的 UUID 会自动重新入队处理。

**Q：被封禁的 UUID 可以重新注册吗？**
不可以。`banned` 状态的 UUID 会被拒绝入队，需要更换设备 UUID。

**Q：如何更新账号 Cookie？**
修改 `config.yaml` 中对应账号的 `xsrf_token` 和 `brd_sess_id` 后重启服务即可。

**Q：UUID 状态数据存在哪里？**
存储在 `/data/uuid_status.json`，采用原子写入防止文件损坏。Docker 部署时需挂载数据卷，否则容器重启后数据丢失。

**Q：多账号有数量限制吗？**
无限制，按需配置，服务自动轮询分配。

**Q：代理支持什么格式？**
支持 HTTP/HTTPS 代理，账号密码均支持 `{RND:N}` 动态随机字符串，适配隧道代理等需要每次不同账号的场景