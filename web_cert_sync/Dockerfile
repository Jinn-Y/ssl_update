FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖（SSH 客户端）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建 SSH 密钥目录
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# 暴露端口
EXPOSE 5000

# 设置环境变量
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# 使用 gunicorn 运行（生产环境）
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
