# 证书同步管理系统

一个基于 Python Flask 的 Web 应用，用于将 ACME.sh 生成的 SSL 证书同步到多台远程服务器。

## 功能特性

- 🌐 **Web 界面操作**：通过浏览器轻松管理证书同步
- 🚀 **并行同步**：支持多线程并发同步，提高效率
- 📊 **实时日志**：使用 Server-Sent Events 实时显示同步进度
- 🎯 **灵活目标**：支持同步到所有服务器或指定服务器
- 🧪 **Dry Run 模式**：测试环境下无需实际 SSH 连接

## 项目结构

```
web_cert_sync/
├── app.py              # Flask 主应用
├── config.py           # 配置管理
├── ssh_utils.py        # SSH/SCP 同步逻辑
├── requirements.txt    # Python 依赖
├── .env.example        # 环境变量模板
└── templates/
    └── index.html      # Web 界面
```

## 安装部署

### 1. 安装依赖

```bash
cd web_cert_sync
pip install -r requirements.txt
```

### 2. 配置环境变量

复制 `.env.example` 为 `.env` 并根据实际情况修改：

```bash
cp .env.example .env
```

关键配置项：

- `SERVER_LIST_PATH`: 服务器列表文件路径
- `ACME_CERT_ROOT`: ACME 证书根目录
- `REMOTE_USER`: SSH 远程用户名
- `DRY_RUN`: 设置为 `True` 启用测试模式

### 3. 准备服务器列表

创建服务器列表文件（如 `/export0/shell/scp_cert/servers.txt`）：

```
192.168.1.100:22
192.168.1.101
10.0.0.50:2222
```

每行一个服务器，格式为 `IP:PORT` 或 `IP`（默认端口 22）。

### 4. 启动应用

```bash
python app.py
```

访问 `http://localhost:5000` 即可使用。

## 使用说明

1. **输入域名**：填写需要同步的证书域名（如 `example.com`）
2. **选择目标**：
   - **所有服务器**：从配置文件读取服务器列表
   - **指定服务器**：手动输入服务器地址
3. **开始同步**：点击按钮后实时查看同步日志

## 测试模式

在 `.env` 中设置 `DRY_RUN=True` 可启用测试模式，此时不会实际执行 SSH 连接，仅模拟同步过程并输出日志。

## 原始脚本

本项目基于 Shell 脚本 `scp_cert.sh` 改造而来，保留了原有的核心功能并增强了用户体验。

## 技术栈

- **后端**: Flask + Paramiko
- **前端**: HTML5 + CSS3 + JavaScript (Fetch API + EventSource)
- **并发**: ThreadPoolExecutor

## Docker 部署

### 使用 Docker Compose（推荐）

1. **准备环境配置**

编辑 `.env` 文件，设置生产环境配置：

```bash
DRY_RUN=False
SERVER_LIST_PATH=/app/servers.txt
ACME_CERT_ROOT=/root/.acme.sh
REMOTE_USER=root
```

2. **构建并启动容器**

```bash
docker-compose up -d
```

3. **查看日志**

```bash
docker-compose logs -f
```

4. **停止服务**

```bash
docker-compose down
```

### 手动 Docker 部署

1. **构建镜像**

```bash
docker build -t cert-sync-web .
```

2. **运行容器**

```bash
docker run -d \
  --name cert-sync \
  -p 5000:5000 \
  -v ~/.ssh:/root/.ssh:ro \
  -v /root/.acme.sh:/root/.acme.sh:ro \
  -v /export0/shell/scp_cert/servers.txt:/app/servers.txt:ro \
  -e DRY_RUN=False \
  cert-sync-web
```

### 重要挂载说明

- `~/.ssh:/root/.ssh:ro`: SSH 密钥目录（只读），用于连接远程服务器
- `/root/.acme.sh:/root/.acme.sh:ro`: ACME 证书目录（只读）
- `/export0/shell/scp_cert/servers.txt:/app/servers.txt:ro`: 服务器列表文件（只读）

### Nginx 反向代理配置示例

```nginx
server {
    listen 80;
    server_name cert-sync.example.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # SSE 支持
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }
}
```

## 注意事项

- 确保运行应用的服务器已配置好到目标服务器的 SSH 密钥认证
- 生产环境建议使用 Gunicorn 或 uWSGI 部署
- 建议配置 Nginx 反向代理并启用 HTTPS
