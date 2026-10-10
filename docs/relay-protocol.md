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
  "region_id": 40001,
  "cert_name": "sha256-raw:<64-hex-digits>",
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
  "relay_token": "xrelay-token-...",
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
| 403 | `RELAY_VISIBILITY_FORBIDDEN` | 接入请求与令牌授权的可见范围不同 |
| 409 | `RELAY_REGION_CONFLICT` | 区域编号已被静态地图或租户节点使用 |

`region_id` / `cert_name` 为可选兼容扩展。旧客户端省略时保存为区域 0 / 空 pin，
不自动加入托管地图；非零区域需有效 DERP 公钥、合法主机和 1–65535 的未占用编号。
`cert_name` 可省略以使用系统信任的域名证书；填写时只接受 SHA-256 原始证书 pin。
可见范围省略时继承接入令牌，不能由服务身份覆盖管理员的授权。

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

- `config_version` 是 opaque token；相同配置在本进程应用成功后才跳过。失败或重启仍需重试，不重启数据面。
- `desired_state`：`online` / `maintenance` / `disabled` / `revoked`。
- `bandwidth_limit`：0 保持本地配置，-1 取消限速，正数为每连接字节/秒。

## 4. 兼容性

- 路径带版本（`/api/relay/v1`），新增字段必须向后兼容：Relay 忽略未知字段，
  服务端不得依赖旧字段的缺失。
- 运行中的 Relay 在控制面短暂故障时保持当前配置和既有连接；新进程不能凭缓存开放 DERP。
- `401 RELAY_TOKEN_INVALID` / `403 RELAY_REVOKED` 是身份终态，主动断开数据面、停止心跳并持久化撤销，不当作普通网络故障。
- Relay 不代理业务 API：数据面只有 DERP/STUN。
- 注册上报来自实际 DERP map / TLS 证书，不把展示区域名当作地区编号。
  控制面仅将租户私有或组织节点加入该租户有效地图，不全局广播公共接入记录。
  官方客户端 wire 类型未改变；决策见服务端 ADR-0019。

## 5. 运行时执行与回执（可选兼容扩展）

决策见服务端 [ADR-0021](https://github.com/xunara-net/xunara-server/blob/main/docs/adr/ADR-0021-relay-runtime-execution.md)。
先升级控制面，再升级托管 Relay；独立公共中继仍按本地设置运行。

心跳响应可增加 `config_revision`（正整数），只用于持久版本高水位；不改变
`config_version` 的等值语义。旧 Xunara 规范十进制 token 可作为兼容序号；无法
确定序号时拒绝猜测顺序。同序号异配置和倒序拒绝；失败可以重试相同配置。
`region_name` 为空回到进程启动时的本地名称，不更换地区 ID、证书或节点密钥。

| 状态 | 新 DERP 连接 | 既有连接 |
| --- | --- | --- |
| online | 允许，仍需上游准入 | 保留 |
| maintenance | 拒绝 | 保留 |
| disabled | 拒绝 | 主动断开；恢复启用不重启 |
| revoked | 拒绝 | 主动断开；需重新配置服务身份 |

健康/探测及 STUN 不使用新的专有协议。限速对 TCP 双向共用一个每连接桶，覆盖
TLS 与 mesh；大包逐段完整计费，热更唤醒旧等待并遵守读写 deadline。
0 每次恢复启动本地限速，-1 不限速，正值覆盖；不是总节点/租户/用户/方向额度。

新版心跳可增加：

```json
{
  "execution": {
    "config_version": "7",
    "applied_version": "7",
    "status": "applied",
    "state": "online",
    "bandwidth_limit": 10485760
  }
}
```

`status` 仅为 `applied` / `failed`；`state` 是本次实际运行状态，失败时允许 `pending`。
`bandwidth_limit` 是实际非负速率，0 表示实际不限速，而不是响应中的“使用本地设置”。
失败报告可省略 `applied_version`；存在时表示本进程上次成功版本。固定 `error_code`
为 `cache_write_failed` / `apply_failed` / `config_invalid` / `version_conflict`，不包含原始异常。
非法/倒序响应无法产生可靠回执时省略报告，不伪造版本或成功事实。

缓存位于身份文件旁的 `.config` 文件（0600），绑定服务 ID、控制面根地址、凭据
摘要及 DERP 公钥。损坏/错配拒绝启动；缓存不是本次授权和执行证明。磁盘故障
不能抵消维护/停用/撤销，新进程始终先拒绝 DERP；撤销缓存跨重启保留终态。

控制面在租户心跳事务里复查 token hash、撤销、版本与必需字段；遥测、报告、
服务端接收时间及回执事实变化审计一起提交，失败回滚。存储故障返回可重试 503，
不伪装为 401。旧 Relay 省略报告仍可心跳，但清为执行未知；重复报告不重复审计。
管理 API 的 `execution` 保留上述 snake_case，接收时间为 `executionReportedAt`。
管理页展示“中继上报已应用”，超过三分钟标为旧回执；服务自报不替代真实连接验证。
撤销端点返回 403，不声称已收到停机 ACK；删除/撤销动作不能依靠历史回执证明断连。

控制面整库回退的版本如果低于中继高水位，将被拒绝。必须一致恢复授权状态/版本，
或经审查重新签发服务身份；不能删除缓存绕过撤销或回退校验。
