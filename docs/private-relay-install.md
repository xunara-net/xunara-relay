# 私有中继安装与分层健康

## 前置条件

用户中心先签发本租户的一次性接入令牌。目标服务器需要 Linux systemd、root/sudo、
Bash、Python 3、curl、OpenSSL、sha256sum、基础账户管理工具和公网可达的 TCP/TLS
端口；勾选 STUN 还需相应 UDP 端口。安装仅支持 AMD64 / ARM64 / ARMv7。
Windows/macOS 使用预编译程序，不是 Linux 服务安装器。

推荐在「我的中继 → 接入指南」生成参数化命令。固定版本来自本组织 GitHub Release，
先校验脚本再执行；完整性校验不是独立发布签名。接入令牌不进入复制命令或 URL。
不要用未知来源脚本、关闭 TLS 校验或把平台管理员令牌当接入令牌。

手动方式：先从同次 Release 下载脚本与 SHA256SUMS 到空目录并核实校验。
以下在该目录执行，参数需替换为自己的公共配置：

```bash
sudo bash ./install-private-relay.sh --control-url https://control.example.com \
  --hostname relay.example.com --port 9091 --region-id 40001 --stun --stun-port 3478
```

终端隐藏读取接入令牌。自动化可使用 `--token-file /root/relay-enrollment`，文件
必须为 root 所有、0600、普通文件；原文件不会自动删除，应自行保管/销毁。
自签测试控制面先核实公有 CA，再加 `--control-ca-file /root/control-ca.crt`。
脚本不会修改系统信任库，只配置专用进程的 `SSL_CERT_FILE`。

## 独立安装与升级

- 服务：`xunara-private-relay`，专用低权限用户，不操作 `xunara-relay` 默认公共服务。
- 程序：`/opt/xunara-private-relay/`；状态：`/var/lib/xunara-private-relay/`（0700）。
- 配置：`/etc/xunara-private-relay/`；复制的令牌环境文件为 root 0600。
- 身份、证书与 `.config` 高水位必须一并备份；成功注册及本地 TLS 探测后清空短期令牌。

相同命令加 `--upgrade`，不要提供新令牌；控制面、公网主机、端口、区域和 STUN
配置必须与原安装一致。升级保留身份、证书和执行高水位；失败恢复原程序/专用 CA。
升级不是改地址向导、解除撤销或凭据轮换。服务缺身份或陌生已有目录会拒绝覆盖。

首次安装失败不会删除已写身份或重复注册。先在服务器本地检查
`sudo systemctl status xunara-private-relay` 与服务日志，核实证书、防火墙及令牌。
不要把凭据文件或未脱敏日志发到公开 issue；未确认接入时不会清除复制的令牌。

## 三种不同观察

1. 心跳健康：中继本机真实 TCP/TLS `/derp/probe`，停用/维护不报告健康。
2. 用户中心「私有中继 → 健康检测」：控制面向已登记公网节点发起 TLS/HTTP 探测。
   它要求网络管理员、持久限流及审计，拒绝内网、混合 DNS、代理和重定向。
3. 设备连接报告/`tailscale status` 或 `tailscale ping`：客户端视角与实际连接路径。

前两项不保证 STUN、节点准入、真实用户端公网可达或端到端数据传输。
控制面检测不覆写心跳或自动修改配置；健康结果仅对应当时的配置版本。

## 验证安装器

从本仓库根目录执行，需 Go、Docker 及可获取 Ubuntu 基础镜像：

```bash
bash -n scripts/install-private-relay.sh
bash scripts/test-private-relay-installer.sh
```

安装器的系统目录只在一次性容器中操作。测试真实程序、私有文件、TLS 本地探测、
身份保留升级和失败 CA 恢复；CDN、systemd 与控制响应为显式夹具，不冒充生产部署。
