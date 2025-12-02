# Docker 部署指南

## 快速开始

### 1. 准备配置文件

确保以下文件已正确配置：

- `.env`: 环境变量配置
- `servers.txt`: 服务器列表（或使用现有的 `/export0/shell/scp_cert/servers.txt`）

### 2. 启动服务

```bash
cd web_cert_sync
docker-compose up -d
```

### 3. 访问应用

打开浏览器访问: `http://服务器IP:5000`

## 配置说明

### 环境变量 (.env)

```bash
# 生产环境配置
DRY_RUN=False
SERVER_LIST_PATH=/app/servers.txt
ACME_CERT_ROOT=/root/.acme.sh
REMOTE_USER=root
REMOTE_DIR_BASE=/etc/ssl
MAX_JOBS=10
```

### 卷挂载

docker-compose.yml 中已配置以下卷挂载：

1. **SSH 密钥**: `~/.ssh:/root/.ssh:ro`
   - 用于 SSH 连接到远程服务器
   - 只读模式，确保安全

2. **ACME 证书**: `/root/.acme.sh:/root/.acme.sh:ro`
   - 证书文件所在目录
   - 只读模式

3. **服务器列表**: `/export0/shell/scp_cert/servers.txt:/app/servers.txt:ro`
   - 目标服务器列表
   - 只读模式

### 端口映射

- 容器端口: 5000
- 主机端口: 5000（可在 docker-compose.yml 中修改）

## 常用命令

### 查看日志

```bash
docker-compose logs -f cert-sync
```

### 重启服务

```bash
docker-compose restart
```

### 停止服务

```bash
docker-compose down
```

### 重新构建

```bash
docker-compose up -d --build
```

### 进入容器

```bash
docker exec -it cert-sync-web bash
```

## 生产环境建议

### 1. 使用 Nginx 反向代理

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

### 2. 启用 HTTPS

使用 Let's Encrypt 或其他 SSL 证书：

```bash
certbot --nginx -d cert-sync.example.com
```

### 3. 资源限制

在 docker-compose.yml 中添加资源限制：

```yaml
services:
  cert-sync:
    # ... 其他配置
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### 4. 日志管理

配置日志轮转：

```yaml
services:
  cert-sync:
    # ... 其他配置
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## 故障排查

### 容器无法启动

```bash
# 查看详细日志
docker-compose logs cert-sync

# 检查配置文件
docker-compose config
```

### SSH 连接失败

1. 检查 SSH 密钥是否正确挂载
2. 确保密钥权限正确（600）
3. 验证目标服务器的 SSH 配置

### 证书文件找不到

1. 检查 ACME_CERT_ROOT 路径是否正确
2. 确认证书文件确实存在
3. 验证卷挂载路径

## 安全建议

1. **限制访问**: 使用防火墙或 Nginx 限制访问 IP
2. **HTTPS**: 生产环境必须使用 HTTPS
3. **密钥保护**: SSH 密钥以只读模式挂载
4. **定期更新**: 定期更新 Docker 镜像和依赖包
