from flask import Flask, render_template, request, Response, stream_with_context, jsonify
import queue
import threading
import os
import re
from ssh_utils import SyncManager
from config import Config

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
def get_domains():
    """API endpoint to get available domains from ACME certificate directory."""
    config = Config()
    acme_root = config.ACME_CERT_ROOT
    domains = []
    
    try:
        if os.path.exists(acme_root):
            # List all directories in ACME root
            for item in os.listdir(acme_root):
                item_path = os.path.join(acme_root, item)
                # Check if it's a directory and ends with _ecc
                if os.path.isdir(item_path) and item.endswith('_ecc'):
                    # Extract domain name (remove _ecc suffix)
                    domain = item[:-4]  # Remove last 4 characters (_ecc)
                    
                    # Verify that certificate files exist
                    cert_file = os.path.join(item_path, 'fullchain.cer')
                    key_file = os.path.join(item_path, f'{domain}.key')
                    
                    if os.path.exists(cert_file) and os.path.exists(key_file):
                        domains.append(domain)
        
        domains.sort()  # Sort alphabetically
        return jsonify({'success': True, 'domains': domains})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/servers', methods=['GET'])
def get_servers():
    """API endpoint to get server list from servers.txt file."""
    config = Config()
    server_list_path = config.SERVER_LIST_PATH
    servers = []
    
    try:
        if os.path.exists(server_list_path):
            with open(server_list_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        servers.append(line)
        
        return jsonify({'success': True, 'servers': servers})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/servers', methods=['POST'])
def update_servers():
    """API endpoint to update server list in servers.txt file."""
    config = Config()
    server_list_path = config.SERVER_LIST_PATH
    
    try:
        data = request.get_json()
        servers = data.get('servers', [])
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(server_list_path), exist_ok=True)
        
        # Write servers to file
        with open(server_list_path, 'w', encoding='utf-8') as f:
            f.write('# Server list for certificate sync\n')
            f.write('# Format: IP:PORT or IP (default port 22)\n\n')
            for server in servers:
                if server.strip():
                    f.write(f"{server.strip()}\n")
        
        return jsonify({'success': True, 'message': 'Server list updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/sync', methods=['POST'])
def sync():
    """Endpoint to trigger certificate sync with streaming logs."""
    domain = request.form.get('domain', '').strip()
    target_mode = request.form.get('target_mode', 'all')
    specific_ips = request.form.get('specific_ips', '').strip()
    
    if not domain:
        return Response("Error: Domain is required", status=400)
    
    sync_manager = SyncManager()
    
    # Determine target servers
    if target_mode == 'all':
        targets = sync_manager.get_server_list()
        if not targets:
            return Response("Error: No servers found in server list", status=400)
    else:
        # Parse specific IPs (one per line or comma-separated)
        targets = [ip.strip() for ip in specific_ips.replace(',', '\n').split('\n') if ip.strip()]
        if not targets:
            return Response("Error: No target servers specified", status=400)
    
    # Create a queue for log messages
    log_queue = queue.Queue()
    
    def run_sync_task():
        """Run sync in background thread."""
        try:
            success, failed_hosts = sync_manager.run_sync(domain, targets, log_queue)
            if success:
                log_queue.put("[SUCCESS]")
            else:
                # Send failed hosts as part of the FAILED message
                failed_str = ", ".join(failed_hosts) if failed_hosts else "Unknown"
                log_queue.put(f"[FAILED] {failed_str}")
            log_queue.put("[DONE]")
        except Exception as e:
            log_queue.put(f"[ERROR] Exception: {str(e)}")
            log_queue.put("[FAILED]")
            log_queue.put("[DONE]")
    
    # Start sync in background thread
    sync_thread = threading.Thread(target=run_sync_task)
    sync_thread.daemon = True
    sync_thread.start()
    
    def generate():
        """Generator function to stream logs to client."""
        while True:
            try:
                msg = log_queue.get(timeout=1)
                if msg == "[DONE]":
                    yield f"data: {msg}\n\n"
                    break
                yield f"data: {msg}\n\n"
            except queue.Empty:
                # Send keepalive
                yield f"data: [KEEPALIVE]\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
