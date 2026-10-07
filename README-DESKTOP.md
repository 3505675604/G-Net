# G-Network Windows 桌面版 0.4.0

桌面版将现有服务器管理面板与本地 Python 运行时封装在独立窗口中。用户不需要安装 Python、Node.js，也不需要打开命令行。首次启动为空的服务器列表，每位用户添加自己的服务器。

发布者：Gloria。官网下载域名为 https://glorianet.fun/ 。0.4.0 为未签名候选功能版本；更新源和发布者代码签名证书尚未配置，自动更新保持禁用。网站已上线不等于本地新版本已上传。

## 0.4.0 Clash 配置工作区

在“配置来源”粘贴多个分享链接、Base64 订阅文本或上传 YAML，先预览，再选择合并节点或编辑完整配置。支持 VLESS、VMess、SS、Trojan、Hysteria2 与 TUIC。部分协议需要 Mihomo，旧 Clash 不支持。未支持的 providers、逻辑规则和扩展字段会明确提示，不能完整编辑时仅允许合并基础节点。

在“链式代理”排列入口与出口；策略组及路由规则可选择整条链。批量域名规则和业务预设会追加、去重；DNS 面板可编辑解析方案及高级 JSON。节点专属直连名单仍独立保存与导出，DIRECT 使用客户端本机网络，不能保证本机位于国外时变成国内出口。

在“生成与保存”导出新 YAML 或加密保存本机工作区；在“配置来源”打开已保存配置继续编辑。本机 `clash-profiles.json` 包含 DPAPI 加密后的节点凭据，只能由原 Windows 用户恢复。下载的 YAML 含连接凭据，应自行保管；本轮不会自动写入 Clash Verge 或修改其全局 DNS。

## 0.3.1 新增功能

- 每个节点可独立保存直连域名名单，支持批量输入、去重、删除与启停。域名及其子域名直连，其余流量固定经过该节点。
- 专属分流提供 Clash / Mihomo YAML 和 Xray 客户端 JSON；每份配置只含当前节点，不把其他节点的名单合并进来。
- 重新读取节点后恢复本机保存的名单；未保存草稿只留在当前页面。已保存名单不包含节点或 SSH 凭据。

## 已有功能

- 独立 Clash 工作区：跨服务器批量读取和选择节点，单份 YAML 最多 128 个节点。
- 策略组支持手动选择、自动测速、故障转移和负载均衡；可编辑组成员，最多 16 组。
- 可视化编辑和排序域名、IP 网段、GEOIP、目标端口等路由规则，最多 200 条（含末尾 MATCH）；提供模板、YAML 预览和导入链接。
- APP 默认自动替换已知服务器的旧 SSH 指纹，在设置中可关闭；首次未知身份仍需核对确认。
- 安装器智能选择默认目录，并在首次安装和升级时显示目录选择页。

## 保留的修复

修复安装远程桌面时，重复导入 Edge 仓库密钥需要交互终端而失败的问题。APP 与独立安装脚本共用非交互导入流程，先下载并转换临时密钥，成功后才原子替换仓库 keyring；下载或转换失败时保留原有 keyring。

包含 0.2.1 的 Xray 临时配置格式修复：验证命令显式指定 JSON，保留配置验证、原子替换、失败回滚与现有入站保护。已用 Xray 26.3.27 核心及隔离回归验证；实际服务器部署与远程桌面连接仍需单独验收。

## 下载后的使用方法

- 普通安装版：运行 `G-Network-0.3.1-windows-x64-Setup.exe`，按向导完成安装，从开始菜单打开 G-Network。安装器自动选择目录，也可在“选择目标位置”页点击“浏览”更改；升级同样显示此页并默认沿用原有位置。缺少 WebView2 时需要联网安装官方运行时。
- 完整安装版：`G-Network-0.3.1-windows-x64-Full-Setup.exe` 包含经签名验证的官方 x64 WebView2 运行时，方便缺少该组件的电脑安装。
- 便携版：将 `G-Network-0.3.1-windows-x64.zip` **完整解压**，进入 `GNetwork` 文件夹，运行 `GNetwork.exe`。需要保留同目录的 `_internal` 文件夹，不可单独复制 EXE；系统仍需要 WebView2。
- 系统要求：Windows 10 1809 或更新版本 / Windows 11，x64，并安装 Microsoft Edge WebView2 Evergreen Runtime。建议使用仍在受支持范围内的 Windows 系统。
- WebView2 缺失时，从 [Microsoft 官方页面](https://developer.microsoft.com/microsoft-edge/webview2/) 下载 Evergreen Runtime；安装器和应用会给出提示。如果发布包包含经签名校验的官方 bootstrapper，安装器会在缺失时安装该组件。

界面资源随安装包提供。管理远程服务器时需要网络及有效的 SSH 凭据；远程工具安装仍需要目标服务器的相应权限和网络。

## 登录、引导与兼容性

首次启动有四步引导，也可从使用帮助重新打开。服务器支持密码、内存私钥和本机 SSH Agent 三种显式认证方式；支持受口令保护的 RSA、Ed25519、ECDSA PEM / OpenSSH 私钥。不接受任意本机私钥路径，不生成明文私钥临时文件。

首次连接前显示完整 SSH SHA256 指纹，需通过云控制台或可信管理员核对并确认，才会发送认证凭据。默认开启“SSH 指纹自动更新”：已知地址与端口的主机身份变化时，自动替换 APP 记录并提示；代表信任当前握手观察到的新密钥，不能证明变更来自管理员。在设置中关闭后，变化会拒绝连接。实际连接仍检查刚观察的密钥，二次变化会在认证前阻止。手动输入的新节点目标，应先添加到服务器列表并核对指纹；手动表单不能绕过信任验证。

国内阿里云 Linux ECS 可通过可访问的地址、实际 SSH 端口和有效凭据加入。普通 SSH、终端、文件管理与安装脚本的支持范围不同。工具箱显示系统、架构与权限要求，后端操作前重新检查；能力探测不等于验证所有远程下载源可达。

## 备份、恢复与诊断

- 普通备份只含服务器连接元数据，导入后通过编辑连接补充凭据。
- 加密备份使用 AES-256-GCM 与 Scrypt，可跨电脑恢复秘密；口令至少 12 个字符，遗失后无法恢复。
- 导入先预览再确认安全合并，已有同地址/端口/用户名连接不覆盖，已有 API Key 默认保留。备份不包含可信主机身份。双文件导入使用加密事务记录，支持中断恢复。
- 诊断不含服务器地址、名称、用户名、秘密、路径、任务输出和原始日志，不自动上传。任务历史仅保留固定类别、状态和时间，最多 100 条，不等于完整远程审计日志。

## V2Ray 与 Clash 配置

添加服务器只保存 SSH 管理信息，完成节点部署后才生成客户端配置。“节点搭建”保留原始 VLESS / VMess / Shadowsocks 分享链接。“Clash 配置”独立工作区可选择多台服务器，读取后筛选节点并批量加入配置。

Clash 工作区可设置代理端口、策略组和有序路由规则，生成后预览整份 YAML、复制本机配置 URL 或客户端导入 URI，并下载 YAML 文件。重名节点会自动区分；策略组循环引用、无效规则和过期节点会拒绝导出。修改草稿后需重新生成。本机链接仅供同一电脑上的 Clash 客户端拉取，需保持 G-Network 运行；程序退出、链接过期或重新读取节点后需要重新复制。成功导入后的 YAML 可由客户端本地保存。跨设备请传输下载的 YAML；当前并未生成公网订阅服务。

### 节点专属域名分流

读取节点后，点击对应节点的“专属分流”，添加例如 `baidu.com`、`example.cn` 的域名，再保存并生成专属配置。名单中的域名与子域名通过 DIRECT 使用本机网络；其余访问固定走该节点。DIRECT 是否属于国内出口取决于客户端电脑所在网络。未添加域名时，该专属配置全部走节点；不会自动加入国内 GeoIP 或局域网直连。

Clash / Mihomo 使用专属 YAML 并切换到规则模式；Xray 使用包含入站、出站和 routing 的完整客户端 JSON，在支持完整配置的客户端导入。原生 VLESS、VMess 或 SS 分享链接只携带节点参数，不能把分流规则带进客户端。每个节点的名单分别保存，切换节点时使用该节点自己的专属配置。普通多节点工作区继续采用其可视化全局路由。

保存名单位于用户数据目录的 `node-routing.json`，通过节点稳定身份关联；修改节点凭据或连接参数后需要重新设置，避免把旧名单附到不同节点。该文件不随当前服务器凭据备份跨设备迁移，跨设备使用已导出的 YAML / JSON。

协议支持由客户端内核决定：VMess 和普通 Shadowsocks AEAD 兼容较广；VLESS、Reality、Shadowsocks 2022 需要对应支持的 Mihomo / Clash Meta 内核。Reality 还需核对服务端与客户端版本，Mihomo 官方目前不保证与 Xray v26.7.11+ 的 Reality 互通；本版本不会为了导出而降级或修改远端服务器。配置卡会标出这些限制，不承诺所有历史版本客户端均可使用。

导出文件与本机链接包含节点连接凭据，请仅交给授权使用者。它们不包含 SSH 管理密码或 Reality 私钥。参考：[Mihomo 协议配置](https://wiki.metacubex.one/config/proxies/)、[Reality 兼容说明](https://wiki.metacubex.one/config/proxies/tls/#reality-opts)、[Clash Verge Rev 导入方法](https://www.clashverge.dev/guide/profile.html)。

## 每位用户的数据

为兼容旧版升级，用户数据目录继续为 `%LOCALAPPDATA%\FLNetwork\data`，WebView2 缓存目录为 `%LOCALAPPDATA%\FLNetwork\webview`。首次安装自动选择 `%LOCALAPPDATA%\Programs\GNetwork`；安装向导允许改为当前用户可写的其他目录。升级自动识别原有安装位置并允许修改，建议沿用原目录，以免旧目录残留程序文件。安装前的确认页会显示最终路径。

安装只针对当前 Windows 用户，不请求管理员权限；选择系统保护目录时可能没有写入权限。安装目录可以包含中文和空格。更改程序安装位置不迁移或删除个人数据，服务器配置仍保存在上述固定用户数据目录；便携版可通过自行解压到指定目录来选择位置。

服务器列表、API 设置、SSH 主机身份记录与日志保存在用户数据目录。Windows 下保存的秘密使用当前 Windows 用户的 DPAPI 保护；不要把加密的配置文件当作跨电脑的通用导出文件。发行包不携带项目工作目录已有的服务器、密码、API Key 或主机记录。

升级与卸载保留用户数据。需要彻底移除个人数据时，先关闭应用，确认已备份所需信息，再自行删除 `%LOCALAPPDATA%\FLNetwork`；卸载器不会主动删除该目录。

## 从源码构建

构建环境：Windows、Python 3.11 x64，以及可选的 [Inno Setup 6.3+](https://jrsoftware.org/isinfo.php)。构建应使用干净的 Python 虚拟环境，所有 Python 依赖从官方 PyPI 安装并精确锁定在 `requirements-lock.txt` 与 `requirements-desktop.txt`。

在项目根目录运行 PowerShell：

```powershell
py -3.11 -m venv .venv-desktop
.\scripts\build_windows.ps1 -Python .\.venv-desktop\Scripts\python.exe
```

指定编译器并要求同时生成安装版：

```powershell
.\scripts\build_windows.ps1 -Python .\.venv-desktop\Scripts\python.exe `
  -IsccPath "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" -RequireInstaller
```

若自行从 Microsoft 获取了官方 WebView2 bootstrapper，可加 `-WebView2Bootstrapper "完整文件路径"`。脚本会校验该文件的 Authenticode 签名及 Microsoft 发布者后才允许打入安装器；脚本不自动下载它。

可用 `-WebView2Standalone` 指定官方 `MicrosoftEdgeWebView2RuntimeInstallerX64.exe`，同时生成完整安装版。提供自己的代码签名证书后，可加 `-SigningCertificateThumbprint`、`-SignToolPath`、`-TimestampUrl` 与 `-RequireSigning`。证书须配置在当前用户签名环境，私钥不得存入项目或发送到聊天。脚本使用 SHA256 与 RFC3161 时间戳，签名后重新计算校验值。

构建流程安装锁定依赖、检查依赖兼容性、按资源白名单生成 EXE，检查发行目录不含私人配置，然后运行冻结应用的隔离自检，再压缩便携版并编译安装器。`-SkipDependencies` 适用于已准备好的构建环境；`-SkipSelfTest` 只用于诊断，跳过后的包需要另行验证。

构建产物：

| 路径 | 内容 |
| --- | --- |
| `dist\GNetwork\` | 可独立运行的完整应用目录 |
| `release\G-Network-0.3.1-windows-x64.zip` | 用户可下载的便携版 |
| `release\G-Network-0.3.1-windows-x64-Setup.exe` | 由 Inno Setup 编译的当前用户安装版 |
| `release\G-Network-0.3.1-windows-x64-Full-Setup.exe` | 可包含官方 x64 WebView2 运行时的完整安装版 |
| `release\SHA256SUMS.txt` | 实际发行文件的 SHA-256 校验值 |
| `release\build-manifest.json` | 本次是否生成安装器及完成自检的记录 |
| `.build\windows\self-test-report.json` | 冻结应用自检报告 |

没有找到 Inno Setup 时，脚本仍生成便携 ZIP，并明确报告安装器未生成；`-RequireInstaller` 会让这类构建以失败状态退出。具体产物以本次构建清单为准。

## 验证与发布

发布前在没有 Python 的干净 Windows 机器上验证首次空列表启动、添加个人服务器、终端、文件、设置，以及关闭后的后台资源释放；还应验证 WebView2 缺失场景、安装升级和卸载保留数据。自动自检使用独立临时数据，检查打包资源、服务启动及关闭等基础能力，不替代真实远程功能与桌面窗口验收。

更新已实现主动 HTTPS 检查、公开地址解析验证、同源下载、禁止重定向、大小/超时限制、SHA256 与发布者 Authenticode 指纹及时间戳校验，下载不会自动运行。发行配置来自随包提供的 `packaging/release-config.json`，不能由用户设置、备份或 API 改写。更新源/签名指纹缺失时相应功能明确禁用。Windows 验证的发布者名称取决于证书里的审核身份，界面显示 Gloria 不能代替签名；签名后的新应用仍可能出现信誉提示。

应用名 G-Network、发布者 Gloria 与官网 https://glorianet.fun/ 已确定。最终许可、支持联系方式与签名证书待提供。`stable` 通道会阻止缺签名、发行资料或冻结自检的构建；当前仅构建候选版本。还需在干净 Windows 10/11 设备、缺少 WebView2 的设备、不同缩放比例及授权服务器完成真实验收。

执行 `python scripts/build_download_site.py` 可生成完整 `release/download-site/`，包含官网下载页、实际安装文件、版本说明、隐私、许可、帮助与 SHA256。仅在签名证书、发布者校验指纹与正式更新地址完成后用 `--base-url` 生成更新清单；当前候选版不生成清单。工具不自动上传或公开部署。

## 技术参考

- [pywebview Windows 打包说明](https://pywebview.flowrl.com/guide/freezing)
- [pywebview Web engine](https://pywebview.flowrl.com/guide/web_engine)
- [PyInstaller 官方文档](https://pyinstaller.org/en/stable/)
- [Microsoft WebView2 分发与安装检测](https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution)
- [Inno Setup 当前用户安装模式](https://jrsoftware.org/ishelp/topic_admininstallmode.htm)
