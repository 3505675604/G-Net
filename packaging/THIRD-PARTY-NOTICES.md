# G-Network 第三方组件说明

G-Network Windows 发行包包含 Python 运行时、Flask / Werkzeug / Jinja2、flask-sock / simple-websocket、Paramiko 及密码学依赖、PyYAML（MIT），以及 pywebview / pythonnet 等组件。各组件的版本、作者和许可信息保留在随包提供的 `*.dist-info` 元数据及其 `licenses` 目录中；Python 许可位于 `_internal/licenses/python/LICENSE.txt`。

界面使用的 xterm.js、xterm-addon-fit 和 QRCode.js 为本地资源，其许可文本位于 `_internal/server-manager/static/vendor/LICENSE-*.txt`。

Microsoft Edge WebView2 Runtime 是 Microsoft 提供和更新的独立系统组件，依照 Microsoft 的许可分发。本应用不会将开发者电脑上已有的 WebView2 用户缓存打入发行包。

WebView2 Runtime 官方许可原文位于 `_internal/packaging/WEBVIEW2-LICENSE.txt`，安装向导包含相应条款。其默认 SmartScreen、数据处理及更新行为见应用隐私说明与 Microsoft 隐私政策。本项目的许可准备稿不改变第三方许可。

发行前请核对所有随包组件的许可文件，保留要求的署名、版权与许可文本。本说明不替代各组件完整许可。
