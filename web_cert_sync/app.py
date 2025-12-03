from flask import Flask, render_template, request, Response, stream_with_context, jsonify, session, redirect, url_for
import queue
import threading
import os
import re
import datetime
import subprocess
from ssh_utils import SyncManager
from config import Config

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key-change-in-production')

# Auth Helper
def check_auth(username, password):
    config = Config()
    return username == config.BASIC_AUTH_USERNAME and password == config.BASIC_AUTH_PASSWORD

def requires_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_auth(username, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = '用户名或密码错误'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# Input Validation Helper
def is_valid_ip_or_domain(target):
    # Allow IP (v4), IP:Port, or Domain
    # Simple regex for IP/Domain
    pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:[0-9]{1,5})?$')
    return bool(pattern.match(target))


@app.route('/')
@requires_auth
def index():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
@requires_auth
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

@app.route('/api/cert_info/<domain>', methods=['GET'])
@requires_auth
def get_cert_info(domain):
    """API endpoint to get certificate expiration info."""
    config = Config()
    cert_path = os.path.join(config.ACME_CERT_ROOT, f"{domain}{config.CERT_DIR_SUFFIX}", "fullchain.cer")
    
    if not os.path.exists(cert_path):
        return jsonify({'success': False, 'error': 'Certificate not found'}), 404
        
    try:
        # Use openssl to get expiration date
        cmd = ['openssl', 'x509', '-enddate', '-noout', '-in', cert_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return jsonify({'success': False, 'error': 'Failed to parse certificate'}), 500
            
        # Output format: notAfter=Mar 12 12:34:56 2024 GMT
        date_str = result.stdout.strip().split('=')[1]
        
        # Parse date
        # OpenSSL date format: %b %d %H:%M:%S %Y %Z
        expiry_date = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.datetime.now()).days
        
        return jsonify({
            'success': True, 
            'domain': domain,
            'expiry_date': date_str,
            'days_left': days_left
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/servers', methods=['GET'])
@requires_auth
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
@requires_auth
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
                    if not is_valid_ip_or_domain(server.strip()):
                        return jsonify({'success': False, 'error': f'Invalid server format: {server}'}), 400
                    f.write(f"{server.strip()}\n")
        
        return jsonify({'success': True, 'message': 'Server list updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/sync', methods=['POST'])
@requires_auth
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
        
        # Validate targets
        for target in targets:
             if not is_valid_ip_or_domain(target):
                 return Response(f"Error: Invalid target format: {target}", status=400)
                 
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
