#!/bin/bash
# sync_cert_parallel.sh
# (最终修复版: 解决 'all' 成功而指定IP失败的问题)
# 用于将 acme.sh 生成的证书同步到多个远程服务器

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info()  { echo -e "${GREEN}[INFO]${NC} $(date '+%F %T') $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $(date '+%F %T') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%F %T') $1"; }
log_step()  { echo -e "${BLUE}==> $1${NC}"; }

# 使用帮助
usage() {
  echo -e "${BLUE}用法:${NC}"
  echo "  $0 --domain <域名> [all | IP1[:PORT1] IP2[:PORT2] ...]"
  echo
  echo "参数说明："
  echo "  --domain <域名>   必填，指定要同步的证书域名（例如：251123.xyz）"
  echo "  all               同步到 'servers.txt' 中的所有服务器（默认）"
  echo "  IP[:PORT]         仅同步到命令行指定的一个或多个服务器"
  exit 1
}

# --- 配置区 ---
MAX_JOBS=10
REMOTE_DIR_BASE="/etc/ssl"
SERVER_LIST="/export0/shell/scp_cert/servers.txt"
REMOTE_USER="root"
ACME_CERT_ROOT="/root/.acme.sh"
# --- 配置区结束 ---

# 解析参数
DOMAIN=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      DOMAIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

# 参数校验
if [[ -z "$DOMAIN" ]]; then
  log_error "必须指定 --domain 参数。"
  usage
fi

CERT_DIR="${ACME_CERT_ROOT}/${DOMAIN}_ecc"
CERT_FILE="${CERT_DIR}/fullchain.cer"
KEY_FILE="${CERT_DIR}/${DOMAIN}.key"
REMOTE_DIR="${REMOTE_DIR_BASE}/${DOMAIN}_ecc"

# 检查本地证书文件
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  log_error "找不到证书文件，请检查路径：$CERT_DIR"
  exit 1
fi

# 判断目标服务器
SERVER_LINES=""
if [ ${#POSITIONAL[@]} -eq 0 ] || [[ "${POSITIONAL[0]}" == "all" ]]; then
  log_info "目标为 'all'，从文件 ${SERVER_LIST} 读取服务器列表。"
  if [ ! -f "$SERVER_LIST" ]; then
    log_error "服务器列表文件 ${SERVER_LIST} 不存在。"
    exit 1
  fi
  SERVER_LINES=$(grep -Ev '^\s*#|^\s*$' "$SERVER_LIST")
else
  log_info "目标为命令行指定的服务器。"
  SERVER_LINES=$(printf "%s\n" "${POSITIONAL[@]}")
fi

# 创建一个临时目录来存放失败任务的标记文件
TMP_DIR=$(mktemp -d -t sync_cert_failures.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# 定义单个服务器的同步函数
sync_single_server() {
  local server_line="$1"
  local host port canonical_line
  
  host=$(echo "$server_line" | cut -d':' -f1)
  port=$(echo "$server_line" | cut -s -d':' -f2)
  [ -z "$port" ] && port=22

  # 规范化地址，用于日志和失败标记，确保信息一致
  canonical_line="${host}:${port}"

  log_info "开始同步到 ${canonical_line} ..."

  # 1. 尝试在远程创建目录
  # **关键修复：加入 -T 选项，强制 ssh 进入非交互模式，禁止分配 TTY**
  if ! timeout 10s ssh -T -p "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${REMOTE_USER}@${host}" "mkdir -p ${REMOTE_DIR}" >/dev/null 2>&1; then
    log_error "在 ${canonical_line} 上创建目录 ${REMOTE_DIR} 失败或 SSH 连接失败！"
    touch "${TMP_DIR}/${canonical_line}"
    return 1
  fi

  # 2. 复制证书文件
  if ! timeout 10s scp -P "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$CERT_FILE" "$KEY_FILE" "${REMOTE_USER}@${host}:${REMOTE_DIR}/" >/dev/null 2>&1; then
    log_error "复制证书到 ${canonical_line} 失败！"
    touch "${TMP_DIR}/${canonical_line}"
    return 1
  fi

  log_info "成功同步到 ${canonical_line}"
}

log_step "开始并行同步域名 ${DOMAIN} 的证书，最大并发数: ${MAX_JOBS}"

while IFS= read -r SERVER_LINE; do
  [[ -z "$SERVER_LINE" || "$SERVER_LINE" =~ ^#.* ]] && continue
  while [[ $(jobs -r -p | wc -l) -ge $MAX_JOBS ]]; do
    sleep 1
  done
  sync_single_server "$SERVER_LINE" &
done <<< "$SERVER_LINES"

log_step "等待所有同步任务完成..."
wait
log_info "所有同步任务已执行完毕。"

# --- 失败报告 ---
FAILED_LIST=()
if [ -d "$TMP_DIR" ] && [ "$(ls -A "$TMP_DIR")" ]; then
  for f in "$TMP_DIR"/*; do
    FAILED_LIST+=("$(basename "$f")")
  done
fi

if [ ${#FAILED_LIST[@]} -gt 0 ]; then
  log_warn "共有 ${#FAILED_LIST[@]} 台服务器同步失败："
  for FAILED_HOST in "${FAILED_LIST[@]}"; do
    echo -e "  - ${RED}${FAILED_HOST}${NC}"
  done
  exit 2
else
  log_info "全部服务器同步成功！"
fi

exit 0