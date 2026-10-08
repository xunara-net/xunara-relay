# Xunara Relay 注册协议（v1）

> 状态：契约已冻结，Relay 端与服务端均已实现。服务端见 `xunara-server` 的
> `control/relay_api.go`（`POST /api/relay/v1/enroll`、`/heartbeat`，配额走
> `plan.MaxRelays`）与 ADR-0006；Relay 端见 `registration/`。

## 1. 身份模型

```text
Enrollment Token   一次性，管理员/用户在控制台创建，仅用于首次注册
Relay Identity     长期凭证：relay_id + relay_token，保存在 0600 文件
```

- Enrollment Token 消费后失效；重复使用返回 `409 RELAY_ALREADY_ENROLLED`。
- Relay Token 只在 `Authorization: Bearer` 头中传输，绝不出现在 URL、argv
  或日志。
- 撤销（revoked）后心跳返回 `403 RELAY_REVOKED`，Relay 应停止服务。

## 2. 注册

```http
POST /api/relay/v1/enroll
Authorization: Bearer <enrollment-token>
Content-Type: application/json

{
  "name": "hk-1",
  "region_code": "hk",
  "region_name": "Hong Kong",
  "hostname": "hk1.example.com",
  "node_key": "nodekey:...",
  "version": "0.1.0",
  "derp_port": 443,
  "stun_port": 3478,
  "visibility": "private"
}
```

```json
200 OK
{
  "relay_id": "relay-01H...",
  "relay_token": "relay_...",
  "control_url": "https://control.example.com",
  "name": "hk-1"
}
```

错误：

| 状态 | code | 含义 |
| --- | --- | --- |
| 401 | `RELAY_TOKEN_INVALID` | 令牌不存在 |
| 409 | `RELAY_ALREADY_ENROLLED` | 一次性令牌已被消费 |
| 410 | `RELAY_ENROLLMENT_EXPIRED` | 令牌过期 |
| 403 | `RELAY_LIMIT_REACHED` | 套餐中继数量已达上限 |

## 3. 心跳与远程配置

```http
POST /api/relay/v1/heartbeat
Authorization: Bearer <relay-token>

{
  "version": "0.1.0",
  "healthy": true,
  "uptime_seconds": 3600,
  "connected_clients": 12,
  "bytes_in": 123456,
  "bytes_out": 654321
}
```

```json
200 OK
{
  "desired_state": "online",
  "config_version": "7",
  "bandwidth_limit": 10485760,
  "region_name": "Hong Kong"
}
```

- `config_version` 变化才应用配置，重复下发不重启数据面。
- `desired_state`：`online` / `maintenance` / `disabled` / `revoked`。
- `bandwidth_limit`：0 保持本地配置，-1 取消限速，正数为每连接字节/秒。

## 4. 兼容性

- 路径带版本（`/api/relay/v1`），新增字段必须向后兼容：Relay 忽略未知字段，
  服务端不得依赖旧字段的缺失。
- Relay 在控制面不可达时继续服务；心跳失败只记录日志并退避重试。
- Relay 不代理业务 API：数据面只有 DERP/STUN。
