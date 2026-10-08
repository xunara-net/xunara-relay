# Xunara Relay（玄序 · 中继平台）

Xunara Relay 是 Xunara 的网络边缘：一个兼容官方 Tailscale 客户端的
**DERP + STUN** 中继服务，同时是自己会「注册上线」的托管节点。

```text
用户/管理员创建 Relay → Xunara 生成一次性 Enrollment Token
        ↓
服务器安装 xunara-relay → relay enroll（换取长期身份，0600 保存）
        ↓
DERP + STUN 数据面开始服务（控制面不可用时继续服务）
        ↓
heartbeat → 控制面下发期望状态/限速/名称（未来：灰度升级、故障转移）
```

## 能力

- **DERP 协议**：官方 Tailscale 客户端可直接作为中继使用（与上游 derper
  相同的 `/derp` 升级处理器）。
- **STUN**：端点发现（默认 UDP 3478）。
- **准入控制**：`-verify-url` 指向控制面 `/derp/admit`，只中继本网络的
  节点密钥。
- **TLS**：手工证书、Let's Encrypt（ACME TLS-ALPN-01）或自签名（发布
  SHA-256 指纹，适合按 IP 访问的节点）。
- **限速**：`-bandwidth-limit` 每连接令牌桶。
- **组网**：多台中继之间用 `-mesh-key-env` 组网（密钥只从环境变量读取）。
- **托管注册**：`-control-url` + `-enroll-token-env` 完成注册；身份保存在
  `<state-dir>/relay-identity.json`（0600），之后按 `-heartbeat-interval` 心跳。

## 快速开始

### 独立 DERP 中继

```bash
xunara-relay -listen :3340 -hostname relay.example.com \
  -cert-mode selfsigned -stun \
  -verify-url https://control.example.com/derp/admit \
  -derp-map-out /etc/xunara/relay.json
```

把生成的 map 交给控制面（`xunarad -derp-map`），或写入控制面的 DERP 配置。

### 托管中继（注册到控制面）

```bash
export XUNARA_RELAY_TOKEN='enroll-...'
xunara-relay -listen :443 -hostname hk1.example.com \
  -control-url https://control.example.com \
  -enroll-token-env XUNARA_RELAY_TOKEN \
  -relay-name hk-1 -relay-visibility private \
  -cert-mode letsencrypt -cert-dir /var/lib/xunara-relay
```

首次启动消费一次性令牌并落盘长期身份；再次启动直接用心跳上线。
身份存在时忽略 `-enroll-token-env`。

### 仅生成 DERP map（不服务）

```bash
xunara-relay -hostname relay.example.com -derp-map-out - -derp-map-only
```

## 端口

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 3340 / 443 | TCP | DERP（HTTPS） |
| 3478 | UDP | STUN |
| 80 | TCP | ACME TLS-ALPN-01 需要 443 即可；80 仅用于跳转（可选） |

## 注册协议

见 [docs/relay-protocol.md](docs/relay-protocol.md)。服务端实现位于
[xunara-server](https://github.com/xunara-net/xunara-server) 的
`control/relay_api.go`：`POST /api/relay/v1/enroll` 与 `POST /api/relay/v1/heartbeat`，
配额由套餐 `max_relays` 控制，决策记录见 ADR-0006。

## 构建与测试

```bash
go build ./cmd/xunara-relay
go test ./...
go vet ./...
```

## 仓库关系

| 仓库 | 职责 |
| --- | --- |
| `xunara-relay` | 中继数据面 + 注册客户端（本仓库） |
| `xunara-server` | 中继注册/心跳/配置/流量的控制面实现 |
| `xunara-deploy` | 部署单元与容器编排 |
| `xunara-docs` | 规范与运维文档 |
