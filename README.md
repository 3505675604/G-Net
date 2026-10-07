# 服务器工具

Windows 本地使用的 Linux 服务器管理工具集：一个 Web 管理面板（服务器管家）+ 若干独立部署脚本。

## 功能一览

**server-manager（服务器管家 Web 面板）**
- 多台服务器管理（添加 / 删除 / 连接测试 / 系统信息查看）
- 一键工具箱：环境体检、开启 BBR、安装 Node.js / dsh / Claude Code / Codex CLI / Xray Reality 节点 / 远程桌面（XFCE + xrdp）
- 节点搭建：VLESS+Reality、VLESS+WS、VMess+WS、Shadowsocks，支持直连与中继（落地）两种模式，增量部署不覆盖现有配置
- 远程文件管理（浏览 / 预览 / 下载 / 搜索）
- Web 终端、一键远程桌面（mstsc）

**根目录独立脚本**（通过环境变量传入连接信息，见下文）
| 脚本 | 作用 |
| --- | --- |
| `deploy_xray.py` | 在服务器上从零部署 VLESS+Reality 多端口节点（含 BBR 调优） |
| `tune_xray.py` | 对已有 Xray 服务器做 TCP/BBR + sockopt 提速调优 |
| `install_desktop.py` | 安装 XFCE + xrdp + Chrome + Edge 远程桌面环境 |
| `install_dsh.py` | 安装 DeepSeek Harness (dsh) 命令行工具 |
| `fix_xrdp.py` | 修复 xrdp 残留会话 / 关闭 xfwm4 合成器 |

## 环境要求

- Windows 10/11
- Python 3.9 或更高版本（https://www.python.org/downloads/ ，安装时勾选 "Add python.exe to PATH"）
- 被管理的服务器：Debian / Ubuntu 等主流 Linux；安装功能需要 root 或免密 sudo
- 本轮验证环境为 Windows、Python 3.11.9。远程桌面浏览器安装目前只支持 Debian/Ubuntu amd64

## 安装（一键）

双击运行 **`一键安装.bat`**，脚本会自动完成：

1. 检查 Python 及版本（缺失或版本过低会给出明确提示）
2. 在当前目录创建虚拟环境 `venv`
3. 安装 `requirements.txt` 中的依赖（Flask / flask-sock / paramiko）
4. 生成初始配置文件（`servers.json`、`settings.json`）和启动脚本

安装失败时会显示原因与解决办法（如网络问题可换国内镜像源，脚本中有提示）。

## 运行

双击 **`启动-服务器管家.bat`**，浏览器会自动打开面板：http://127.0.0.1:8620。启动器只复用本项目实例；端口被其他程序占用时提示失败，不会强制杀进程。

也可以命令行运行：

```bat
venv\Scripts\python.exe launch_manager.py
```

首次使用：在面板中点击「添加服务器」，填入 IP、端口（默认 22）、用户名（一般 root）和密码即可。

## 独立脚本用法

根目录脚本通过环境变量传入服务器信息（密码不落盘）：

```bat
set SSHPASS=你的服务器密码
set SSH_HOST=服务器IP
python install_desktop.py
```

- `deploy_xray.py` 还支持 `XRAY_PORTS`（如 `443,8443`）和 `XRAY_SNI`（伪装域名，默认 www.amazon.com）
- `fix_xrdp.py` 用 `SSH_HOSTS` 指定一台或多台服务器（逗号分隔），密码统一用 `SSHPASS`
- 所有脚本均通过 `SSH_HOST` / `SSHPASS` 环境变量指定目标服务器和密码，代码中不含任何服务器信息
- 可选 `SSH_USER`（默认 root）、`SSH_PORT`（默认 22）、`SSH_KNOWN_HOSTS`（主机身份文件路径）；非 root 安装用户须有免密 sudo
- `tune_xray.py` 直接读取并更新服务器现有配置，不再依赖本地结果文件，也不重建其他节点或路由

## 配置与安全

- `servers.json` 的密码和 `settings.json` 的 API Key 使用 Windows DPAPI 加密。旧明文在下次被程序读取时自动迁移；本轮修复未读取或改写你的实际配置。加密配置依赖当前 Windows 用户/设备环境，不能直接复制到另一账户或电脑；当前还没有跨设备加密导出与恢复功能。
- 设置页只返回密钥是否已设置。留空保存保留旧 Key，勾选清除再保存才会删除。
- 面板只监听 `127.0.0.1:8620`。API 和 WebSocket 校验本地地址、Origin 和页面会话令牌；不要直接把本地面板发布到公网。
- SSH 首次连接采用 TOFU，记录到项目根目录 `known_hosts`；已知主机密钥变化会拒绝连接。首次连接尚无人工指纹确认界面，请在可信网络建立首次身份记录。
- 节点删除校验读取时的服务器与完整节点配置；切换服务器或配置发生变化后需重新读取。
- Xray 更新先验证唯一候选文件、验证备份，再替换和重启；启动或所需 TCP/UDP 监听失败会恢复原配置及原运行状态。中继失败只清除本任务新增的出口入站。配置锁只协调遵守同一锁的程序，外部直接编辑仍可能产生竞争。
- 软件包安装、BBR、系统服务及防火墙变更不属于 Xray 配置回滚范围。TCP 连通性检查不代表代理协议或 UDP 的端到端验证。
- 前端依赖已固定并放入 `server-manager/static/vendor`，页面不再运行 CDN 脚本；许可证随文件保存。
- 文件预览限 512 KiB，下载限 2 GiB；后端使用临时文件分块接收，前端仍通过 Blob 保存，大文件建议使用专业 SFTP 客户端。
- `.gitignore` 排除实际配置、主机身份、日志和 Xray 导出文件。`xray_config_*.json` 含私钥，分享链接和 `xray_result_*.json` 也属于敏感凭据，仍需妥善保管。
- root 桌面浏览器需要 `--no-sandbox`；面向商业用户应提供独立非 root 桌面账户。Windows 远程桌面快捷入口会写入系统凭据管理器。

## 本地验证

```bat
venv\Scripts\python.exe -B -m unittest discover -s tests -v
node server-manager\tests\test_frontend.js
venv\Scripts\python.exe -m pip check
```

测试使用临时配置和模拟 SSH，不连接你的服务器。部分事务测试使用 Git for Windows 自带 Bash 模拟远端服务；缺少 Bash 时这些测试会跳过。真实服务器、云平台安全组及远端桌面仍需集成验收。

`requirements-lock.txt` 记录本轮 Windows/Python 3.11 实际验证的完整运行依赖，便于复现；`requirements.txt` 保留兼容范围。商业发布还需要依赖审查、安装包签名与持续更新。
