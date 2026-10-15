# UDP / STUN 启用与验收

DERP 加密业务中继使用 TLS / TCP；STUN 使用 UDP 做打洞与地址发现。**开启 STUN 不等于实现 UDP 业务中继或官方 Peer Relay。** Peer Relay 需要客户端节点、访问授权和专用端点分配协议，不能用一个公开 UDP 转发端口代替。

## 配置

```sh
xunara-relay -listen :9091 -hostname relay.example.com \
  -state-dir /var/lib/xunara-relay -cert-mode selfsigned \
  -stun=true -stun-port 9091
```

在原有准入 / 托管参数上追加 UDP 设置；不要删掉 `-verify-url`、服务身份或运行时配置缓存。TCP 和 UDP 可以使用同一数字端口，但公网转发、防火墙和安全组必须分别配置。映射 `9091/TCP` 并不自动映射 `9091/UDP`。

公网尚未就绪时加 `-stun-unadvertised`：UDP 仍运行，本机健康检测仍发真实 STUN 请求，但 DERP map 中 `STUNPort=-1`，不会把不可用地址广播为可用。已有 TCP DERP 不受此标记影响。

## 真实探测

```sh
xunara-relay -check-stun 127.0.0.1:9091
xunara-relay -check-stun relay.example.com:9091
```

第一条在中继主机执行；第二条必须在外部网络执行。成功输出 `STUN UDP binding verified`，验证 Binding Response 的格式、事务 ID 与映射地址。仅有 `ss -lun` / UDP 扫描结果或 HTTP 200 不能证明公网 UDP 通路。

公网验证通过后去掉 `-stun-unadvertised`，重新生成 map，并按控制面的加载方式刷新地图。静态 `-derp-map` 文件不应被误认为已自动热加载；先检查部署方式，再安排重载 / 重启。

## 失败处理与兼容性

- UDP 端口绑定失败时启动直接失败，不再仅记录错误却报告 TCP 已就绪。
- 已启用 UDP 时，托管心跳的本机健康检测包含真实 UDP STUN 请求。
- TCP 初始化失败、正常停止和 `Close` 都取消并回收 UDP listener；不留下幽灵监听。
- 继续使用固定 Tailscale 上游 STUN 编码与源地址选择，不更改 DERP、Disco 或官方客户端 wire。
- 私钥、证书、DERP 公钥和证书 pin 不因启用 UDP 重新生成。
