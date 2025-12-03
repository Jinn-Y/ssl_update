import os
import paramiko
import concurrent.futures
import logging
import time
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SyncManager:
    def __init__(self):
        self.config = Config()

    def get_server_list(self):
        """Reads the server list from the configured file."""
        server_list_path = self.config.SERVER_LIST_PATH
        servers = []
        
        if not os.path.exists(server_list_path):
            if self.config.DRY_RUN:
                logger.warning(f"[Dry Run] Server list file not found at {server_list_path}. Returning dummy list.")
                return ["192.168.1.101:22", "192.168.1.102"]
            logger.error(f"Server list file not found: {server_list_path}")
            return []

        try:
            with open(server_list_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        servers.append(line)
        except Exception as e:
            logger.error(f"Error reading server list: {e}")
        
        return servers

    def _sync_single_server(self, server_line, domain, cert_file, key_file, log_queue=None):
        """
        Syncs certificate to a single server.
        log_queue: Optional queue to put log messages for web streaming.
        """
        def log(message, level="INFO"):
            msg = f"[{level}] {message}"
            logger.info(msg)
            if log_queue:
                log_queue.put(msg)

        parts = server_line.split(':')
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else self.config.SSH_PORT_DEFAULT
        
        canonical_line = f"{host}:{port}"
        remote_dir = f"{self.config.REMOTE_DIR_BASE}/{domain}{self.config.CERT_DIR_SUFFIX}"
        
        log(f"Starting sync to {canonical_line} ...")

        if self.config.DRY_RUN:
            time.sleep(0.5) # Simulate network delay
            log(f"[Dry Run] Would connect to {host}:{port} as {self.config.REMOTE_USER}")
            log(f"[Dry Run] Would mkdir -p {remote_dir}")
            log(f"[Dry Run] Would scp {cert_file} and {key_file} to {remote_dir}")
            
            if self.config.POST_SYNC_CMD:
                log(f"[Dry Run] Would execute post-sync command: {self.config.POST_SYNC_CMD}")
                
            log(f"Successfully synced to {canonical_line} (Dry Run)")
            return True

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 1. Connect and create directory
            ssh.connect(host, port=port, username=self.config.REMOTE_USER, timeout=self.config.SSH_CONNECT_TIMEOUT)
            
            mkdir_cmd = f"mkdir -p {remote_dir}"
            stdin, stdout, stderr = ssh.exec_command(mkdir_cmd, timeout=self.config.SSH_EXEC_TIMEOUT)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                err = stderr.read().decode().strip()
                log(f"Failed to create directory on {canonical_line}: {err}", "ERROR")
                ssh.close()
                return False

            # 2. SCP files
            sftp = ssh.open_sftp()
            sftp.put(cert_file, f"{remote_dir}/fullchain.cer")
            sftp.put(key_file, f"{remote_dir}/{domain}.key")
            sftp.close()
            
            # 3. Execute Post-Sync Command
            if self.config.POST_SYNC_CMD:
                log(f"Executing post-sync command: {self.config.POST_SYNC_CMD}")
                stdin, stdout, stderr = ssh.exec_command(self.config.POST_SYNC_CMD, timeout=self.config.SSH_EXEC_TIMEOUT)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    err = stderr.read().decode().strip()
                    log(f"Post-sync command failed on {canonical_line}: {err}", "WARN")
                else:
                    log(f"Post-sync command executed successfully")
            
            ssh.close()
            log(f"Successfully synced to {canonical_line}")
            return True

        except Exception as e:
            log(f"Error syncing to {canonical_line}: {str(e)}", "ERROR")
            return False

    def run_sync(self, domain, targets, log_queue=None):
        """
        Orchestrates the sync process.
        targets: List of server strings (e.g., ["1.1.1.1", "2.2.2.2:2222"])
        """
        cert_dir = f"{self.config.ACME_CERT_ROOT}/{domain}{self.config.CERT_DIR_SUFFIX}"
        cert_file = f"{cert_dir}/fullchain.cer"
        key_file = f"{cert_dir}/{domain}.key"

        # Check local files
        if not self.config.DRY_RUN:
            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                msg = f"Certificate files not found at {cert_dir}"
                logger.error(msg)
                if log_queue:
                    log_queue.put(f"[ERROR] {msg}")
                return False
        else:
             if log_queue:
                log_queue.put(f"[Dry Run] Checking certificate files at {cert_dir} (Skipped)")

        max_jobs = self.config.MAX_JOBS
        failed_hosts = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_jobs) as executor:
            future_to_server = {
                executor.submit(self._sync_single_server, server, domain, cert_file, key_file, log_queue): server
                for server in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    success = future.result()
                    if not success:
                        failed_hosts.append(server)
                except Exception as exc:
                    logger.error(f"{server} generated an exception: {exc}")
                    if log_queue:
                        log_queue.put(f"[ERROR] {server} exception: {exc}")
                    failed_hosts.append(server)

        if failed_hosts:
            msg = f"Sync completed with failures on: {', '.join(failed_hosts)}"
            logger.warning(msg)
            if log_queue:
                log_queue.put(f"[WARN] {msg}")
            return False, failed_hosts
        else:
            msg = "All servers synced successfully!"
            logger.info(msg)
            if log_queue:
                log_queue.put(f"[INFO] {msg}")
            return True, []
