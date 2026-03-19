import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SERVER_LIST_PATH = os.getenv("SERVER_LIST_PATH", "/export0/shell/scp_cert/servers.txt")
    SERVER_DB_PATH = os.getenv("SERVER_DB_PATH", os.path.join(BASE_DIR, "servers.db"))
    SERVER_PAGE_SIZE_DEFAULT = int(os.getenv("SERVER_PAGE_SIZE_DEFAULT", 20))
    SERVER_PAGE_SIZE_MAX = int(os.getenv("SERVER_PAGE_SIZE_MAX", 100))

    REMOTE_USER = os.getenv('REMOTE_USER', 'root')

    # ACME cert root
    ACME_CERT_ROOT = os.getenv("ACME_CERT_ROOT", "/root/.acme.sh")

    # SSH Configuration
    SSH_PORT_DEFAULT = int(os.getenv('SSH_PORT_DEFAULT', 22))
    SSH_CONNECT_TIMEOUT = int(os.getenv('SSH_CONNECT_TIMEOUT', 10))
    SSH_EXEC_TIMEOUT = int(os.getenv('SSH_EXEC_TIMEOUT', 30))

    # Sync Configuration
    REMOTE_DIR_BASE = os.getenv('REMOTE_DIR_BASE', '/etc/nginx/ssl')
    MAX_JOBS = int(os.getenv('MAX_JOBS', 5))
    CERT_DIR_SUFFIX = os.getenv('CERT_DIR_SUFFIX', '_ecc')
    POST_SYNC_CMD = os.getenv('POST_SYNC_CMD', '')

    # Security Configuration
    BASIC_AUTH_USERNAME = os.getenv('BASIC_AUTH_USERNAME', 'admin')
    BASIC_AUTH_PASSWORD = os.getenv('BASIC_AUTH_PASSWORD', 'admin')

    # Dry Run Mode (for testing without actual connections)
    DRY_RUN = os.getenv("DRY_RUN", "False").lower() in ('true', '1', 't')
