import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Default values from the shell script
    MAX_JOBS = int(os.getenv("MAX_JOBS", 10))
    # Default to a local path for testing on Windows if not specified, 
    # but in prod it should be /etc/ssl
    REMOTE_DIR_BASE = os.getenv("REMOTE_DIR_BASE", "/etc/ssl")
    
    # Path to the servers list file
    # Defaulting to the path in the script, but likely needs override on Windows
    SERVER_LIST_PATH = os.getenv("SERVER_LIST_PATH", "/export0/shell/scp_cert/servers.txt")
    
    REMOTE_USER = os.getenv("REMOTE_USER", "root")
    
    # ACME cert root
    ACME_CERT_ROOT = os.getenv("ACME_CERT_ROOT", "/root/.acme.sh")
    
    # SSH Configuration
    SSH_PORT_DEFAULT = 22
    SSH_CONNECT_TIMEOUT = 5
    SSH_EXEC_TIMEOUT = 10
    
    # Dry Run Mode (for testing without actual connections)
    DRY_RUN = os.getenv("DRY_RUN", "False").lower() in ('true', '1', 't')
