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
read -r -s -p '一次性接入令牌: ' XUNARA_RELAY_TOKEN; printf '\n'
export XUNARA_RELAY_TOKEN
xunara-relay -listen :443 -hostname hk1.example.com \
  -state-dir /var/lib/xunara-relay -region-id 40001 \
  -control-url https://control.example.com \
  -enroll-token-env XUNARA_RELAY_TOKEN \
  -relay-name hk-1 -relay-visibility private \
  -cert-mode letsencrypt -cert-dir /var/lib/xunara-relay
unset XUNARA_RELAY_TOKEN
```

首次启动消费一次性令牌并落盘长期身份；再次启动直接用心跳上线。
身份存在时忽略 `-enroll-token-env`。

以上命令在已安装二进制的主机上用 Bash 执行；不把令牌写入参数或 shell 历史。
选择未占用的区域编号并开放 TCP 443 / UDP 3478。托管模式必须配置 TLS；按 IP 调试
可用 `-cert-mode selfsigned`，注册会自动提交证书 SHA-256 pin，不关闭 TLS 验证。
长期身份损坏或控制面 URL 非法会报错，不降级为开放的独立中继。

未显式设置 `-verify-url` 时，托管模式自动使用持久租户地址下的 `/derp/admit`，重启
仍校验准入。单独部署的公共中继应显式指定已配置的准入地址。控制面地址只接受根
HTTP(S) URL，无查询、用户信息或片段；注册/心跳不会跟随重定向重放服务凭据。

新版控制面将健康、最近心跳且启用的私有节点并入本租户标准 DERPMap；删除、维护、
停用或过期后退出地图。旧记录缺少区域 / pin 时不猜测发布，需升级后重新接入。
地图不是端口探测；自签证书轮换必须同步新 pin，不能只替换证书后仍用旧记录。

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
