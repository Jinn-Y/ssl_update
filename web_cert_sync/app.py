from flask import Flask, render_template, request, Response, stream_with_context, jsonify, session, redirect, url_for
import queue
import threading
import os
import re
import datetime
import subprocess
import sqlite3
try:
    from .ssh_utils import SyncManager
    from .config import Config
    from .server_repository import ServerRepository
except ImportError:
    from ssh_utils import SyncManager
    from config import Config
    from server_repository import ServerRepository

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


def is_valid_host(host):
    pattern = re.compile(
        r'^(localhost|'
        r'(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)'
        r'(\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*'
        r'|\d{1,3}(\.\d{1,3}){3}))$'
    )
    if not pattern.match(host):
        return False

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        parts = host.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    return True


def normalize_server_payload(data, config):
    host = (data.get('host') or '').strip()
    port_value = data.get('port', config.SSH_PORT_DEFAULT)
    group_name = (data.get('group_name') or 'default').strip() or 'default'
    remark = (data.get('remark') or '').strip()
    enabled_value = data.get('enabled', True)

    if isinstance(enabled_value, str):
        enabled = enabled_value.lower() in ('true', '1', 'yes', 'on')
    else:
        enabled = bool(enabled_value)

    if not host or not is_valid_host(host):
        raise ValueError('Invalid host format')

    try:
        port = int(port_value)
    except (TypeError, ValueError):
        raise ValueError('Port must be a number')

    if port < 1 or port > 65535:
        raise ValueError('Port must be between 1 and 65535')

    return {
        'host': host,
        'port': port,
        'group_name': group_name,
        'remark': remark,
        'enabled': enabled,
    }


def stream_sync_response(domain, targets):
    sync_manager = SyncManager()
    log_queue = queue.Queue()

    def run_sync_task():
        """Run sync in background thread."""
        try:
            success, failed_hosts = sync_manager.run_sync(domain, targets, log_queue)
            if success:
                log_queue.put("[SUCCESS]")
            else:
                failed_str = ", ".join(failed_hosts) if failed_hosts else "Unknown"
                log_queue.put(f"[FAILED] {failed_str}")
            log_queue.put("[DONE]")
        except Exception as e:
            log_queue.put(f"[ERROR] Exception: {str(e)}")
            log_queue.put("[FAILED]")
            log_queue.put("[DONE]")

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
                yield f"data: [KEEPALIVE]\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

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
    parsed = ServerRepository.parse_server_value(target, Config().SSH_PORT_DEFAULT)
    if not parsed:
        return False
    return is_valid_host(parsed['host']) and 1 <= parsed['port'] <= 65535


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
    """API endpoint to get paginated server list from SQLite."""
    config = Config()
    repository = ServerRepository(config)

    try:
        page = request.args.get('page', default=1, type=int)
        page_size = request.args.get('page_size', default=config.SERVER_PAGE_SIZE_DEFAULT, type=int)
        search = request.args.get('search', default='', type=str)
        result = repository.list_servers(page=page, page_size=page_size, search=search)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/servers', methods=['POST'])
@requires_auth
def update_servers():
    """API endpoint to create a server record."""
    config = Config()
    repository = ServerRepository(config)

    try:
        data = request.get_json()
        payload = normalize_server_payload(data or {}, config)
        server = repository.create_server(**payload)
        return jsonify({'success': True, 'message': 'Server created successfully', 'server': server}), 201
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Server already exists'}), 409
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/servers/<int:server_id>', methods=['PUT'])
@requires_auth
def replace_server(server_id):
    """API endpoint to update a server record."""
    config = Config()
    repository = ServerRepository(config)

    try:
        data = request.get_json()
        payload = normalize_server_payload(data or {}, config)
        server = repository.update_server(server_id, **payload)
        if not server:
            return jsonify({'success': False, 'error': 'Server not found'}), 404
        return jsonify({'success': True, 'message': 'Server updated successfully', 'server': server})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Server already exists'}), 409
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@requires_auth
def delete_server(server_id):
    """API endpoint to delete a server record."""
    repository = ServerRepository(Config())

    try:
        deleted = repository.delete_server(server_id)
        if not deleted:
            return jsonify({'success': False, 'error': 'Server not found'}), 404
        return jsonify({'success': True, 'message': 'Server deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/servers/<int:server_id>/sync', methods=['POST'])
@requires_auth
def sync_single_server(server_id):
    """Trigger certificate sync for a single saved server."""
    config = Config()
    repository = ServerRepository(config)
    domain = request.form.get('domain', '').strip()

    if not domain:
        return Response("Error: Domain is required", status=400)

    try:
        server = repository.get_server(server_id)
        if not server:
            return Response("Error: Server not found", status=404)
        if not server['enabled']:
            return Response("Error: Server is disabled", status=400)
        target = f"{server['host']}:{server['port']}"
        return stream_sync_response(domain, [target])
    except Exception as e:
        return Response(f"Error: {str(e)}", status=500)

@app.route('/sync', methods=['POST'])
@requires_auth
def sync():
    """Endpoint to trigger certificate sync with streaming logs."""
    domain = request.form.get('domain', '').strip()
    target_mode = request.form.get('target_mode', 'all')
    specific_ips = request.form.get('specific_ips', '').strip()
    
    if not domain:
        return Response("Error: Domain is required", status=400)
    
    # Determine target servers
    sync_manager = SyncManager()
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
    
    return stream_sync_response(domain, targets)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
