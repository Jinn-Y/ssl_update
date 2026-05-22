# 代理说明

## 项目概览

这个仓库是一个 SSL 证书同步工具。

- `scp_cert.sh` 是最初的 Shell 脚本版本，用于通过 SSH/SCP 将 acme.sh 生成的证书复制到远程服务器。
- `web_cert_sync/` 是当前主要的 Flask Web 应用，用于管理同步目标服务器、证书、认证方式和同步操作。

Web 应用的目标是把本机 ACME 证书文件分发到多台远程服务器，并在此基础上提供更安全、可视化的运维操作界面。

## 主要组件

- `web_cert_sync/app.py`：Flask 路由、登录认证、TOTP、Passkey、服务器 API、证书 API 和同步接口。
- `web_cert_sync/ssh_utils.py`：SSH/SFTP 同步逻辑，以及远程证书到期时间探测逻辑。
- `web_cert_sync/server_repository.py`：SQLite 数据持久化，保存服务器、应用设置和 Passkey。
- `web_cert_sync/config.py`：基于环境变量的配置管理。
- `web_cert_sync/templates/index.html`：登录后的主界面。
- `web_cert_sync/templates/login.html`：登录页面。
- `web_cert_sync/static/app.js`：前端状态、API 调用、弹窗、日志、表格渲染和同步交互。
- `web_cert_sync/static/style.css`：应用布局、卡片、表格、弹窗、日志和响应式样式。
- `web_cert_sync/docker-compose.yml`：Docker Compose 部署配置，包含 CPU 和内存限制。
- `web_cert_sync/Dockerfile`：生产容器镜像，使用 Gunicorn 运行 Flask 应用。

## 本地运行

进入 `web_cert_sync/` 目录：

```bash
python app.py
```

应用默认监听：

```text
http://127.0.0.1:5000
```

本地演示时建议使用：

```bash
DRY_RUN=True
DEMO_MODE=true
```

Windows PowerShell 示例：

```powershell
$env:DRY_RUN='True'
$env:DEMO_MODE='true'
python app.py
```

默认开发登录账号由环境变量控制，未设置时通常为：

```text
admin / admin
```

## Docker 部署

进入 `web_cert_sync/` 目录：

```bash
docker compose up -d --build
```

Compose 文件已设置默认资源限制：

```yaml
cpus: "1.0"
mem_limit: 512m
memswap_limit: 512m
pids_limit: 256
```

Gunicorn worker 数量可通过以下环境变量配置：

```text
GUNICORN_WORKERS
```

默认值为 `2`。

## 重要环境变量

- `SERVER_LIST_PATH`：旧版服务器列表路径，用于首次导入。
- `SERVER_DB_PATH`：SQLite 数据库路径。
- `ACME_CERT_ROOT`：acme.sh 证书根目录，通常是 `/root/.acme.sh`。
- `REMOTE_USER`：连接目标服务器时使用的 SSH 用户名。
- `REMOTE_DIR_BASE`：远程服务器上保存证书的基础目录。
- `MAX_JOBS`：最大并发同步任务数。
- `CERT_DIR_SUFFIX`：证书目录后缀，默认 `_ecc`。
- `POST_SYNC_CMD`：证书复制完成后可选执行的远程命令。
- `DRY_RUN`：为 true 时不会执行真实 SSH/SFTP 操作。
- `DEMO_MODE`：当没有真实证书时注入演示域名。
- `BASIC_AUTH_USERNAME`、`BASIC_AUTH_PASSWORD`：登录账号密码的兜底配置。
- `PASSKEY_RP_ID`、`PASSKEY_ORIGIN`：使用反向代理或域名访问时建议显式设置。

## 数据与安全注意事项

- `web_cert_sync/servers.db` 是 SQLite 数据库，可能包含真实运维数据。
- 不要提交真实私钥、SSH 密钥、ACME 账号数据、生产 `.env` 文件或真实服务器清单，除非用户明确要求。
- 当 `DRY_RUN=False` 时，应用会执行真实 SSH/SFTP 操作。
- 修改同步路径、同步后命令或认证相关代码时要格外谨慎。
- 使用 Passkey 且经过反向代理访问时，RP ID 和 Origin 必须与浏览器访问地址匹配。

## 前端注意事项

- UI 是 Flask 渲染模板加前端 JavaScript 状态管理的单页式界面。
- 服务器管理使用弹窗完成新增/编辑服务器，以及单机证书探测时的域名选择。
- 布局风格应保持克制、清晰，偏运维控制台，不要改成营销页面或装饰性很强的界面。
- 修改前端后，应刷新 `http://127.0.0.1:5000/` 并验证：
  - 登录仍然可用
  - 服务器表格能正常加载
  - 新增/编辑服务器弹窗能打开
  - 单机探测会弹出域名选择弹窗
  - 同步/探测日志能正常渲染

## 常用验证命令

进入 `web_cert_sync/` 目录后执行：

```bash
node --check static/app.js
python -m py_compile app.py config.py server_repository.py ssh_utils.py
```

如果当前环境可用 Docker：

```bash
docker compose config
docker compose up -d --build
docker compose logs -f cert-sync
```

## 当前开发注意事项

- 当前仓库已经积累了一些 UI 和部署改动，继续修改前请先查看 `git diff`。
- 不要主动删除备份模板文件，除非用户明确要求。
- 优先在 `templates/index.html`、`static/app.js`、`static/style.css` 中做小范围、聚焦的改动。
- 本地运行用于查看时，除非用户明确要求真实同步，否则使用 `DRY_RUN=True`。
