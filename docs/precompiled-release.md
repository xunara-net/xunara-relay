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
