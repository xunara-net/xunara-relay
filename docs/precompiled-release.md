# 预编译 Xunara Relay

下载后即可运行，不需要安装 Go 或自行编译。Linux/macOS 请先 `chmod +x`。

| 系统 | 架构 | 文件 |
| --- | --- | --- |
| Linux | x86-64 / AMD64 | `xunara-relay_linux_amd64` |
| Linux | ARM64 / AArch64 | `xunara-relay_linux_arm64` |
| Linux | ARMv7（32 位） | `xunara-relay_linux_armv7` |
| macOS | Intel x86-64 | `xunara-relay_darwin_amd64` |
| macOS | Apple Silicon ARM64 | `xunara-relay_darwin_arm64` |
| Windows | x86-64 / AMD64 | `xunara-relay_windows_amd64.exe` |
| Windows | ARM64 | `xunara-relay_windows_arm64.exe` |

选择中继服务器的系统与架构，不是浏览器所在手机的系统。Windows 可在 PowerShell
运行；当前是命令行程序，不是 Windows 服务安装器。macOS 二进制尚无 Apple
Developer 签名/公证，系统可能拦截；不要一键关闭系统安全保护。

先从同一次发布下载 `SHA256SUMS`，用 Linux `sha256sum`、macOS `shasum -a 256`、
Windows `Get-FileHash -Algorithm SHA256` 对照目标文件。校验和用于检验文件完整性，
不是独立签名认证。`BUILD.txt` 记录版本和对应源码提交。

本矩阵经过无 CGO 交叉编译；Linux AMD64 验证版本输出及 Go 测试/竞态/协议回归，
不声称所有平台均完成现场运行验收。预览版不提供自动升级、签名更新或计费保证。

托管接入需一次性令牌、租户控制面地址、公网 TLS 端口及 UDP STUN 端口。按照
仓库 README 或用户中心「中继 → 接入指南」操作，令牌只能经隐藏输入/环境变量，
不要放入命令参数、下载链接或日志。长期身份与配置缓存应一并备份。

## preview.2：Linux 私有中继安装器

发布资产新增 `install-private-relay.sh`，与七种二进制同列 `SHA256SUMS`。
在用户中心「我的中继 → 接入指南」填写公网地址、端口、区域编号，勾选 STUN
生成命令：先下载校验固定版本脚本，再提权；脚本隐藏读取一次性接入令牌。
Linux AMD64 / ARM64 / ARMv7 自动选择预编译文件，不需要 Go。

专用服务 `xunara-private-relay` 与独立目录不覆盖部署默认公共中继。
`--upgrade` 仅允许原身份和相同公网配置，失败恢复旧二进制与进程专用 CA；
不自动重新注册或解除撤销。测试控制面可用已核实的公有 CA 文件，信任范围
只影响该服务。注册、TLS 本地探测成功后清空复制的短期令牌文件。

心跳健康现在探测实际本地监听与 TLS `/derp/probe`；不再仅依赖地址对象。
它不证明公网、STUN、准入或点对点数据面可用。控制面主动检测按钮是另一视角。

验证包括全量 Go build/vet/test/race、官方 DERP 数据面回归、ShellCheck 与
一次性 Docker 安装/升级/CA 恢复夹具。夹具运行真实二进制与 TLS，CDN、systemd
和控制面响应为显式替身，不能据此声称所有架构或实际 Linux 发行版均现场验证。
详细前置条件、失败处理与运维见 [私有中继安装手册](private-relay-install.md)。
