from flask import Flask, render_template, request, Response, stream_with_context, jsonify, session, redirect, url_for, send_file
import queue
import threading
import os
import re
import datetime
import subprocess
import sqlite3
import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote
from werkzeug.security import generate_password_hash, check_password_hash
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
FAVICON_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'secret.png')
TOTP_VALID_WINDOW = 1
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_ISSUER = os.getenv('TOTP_ISSUER', 'Certificate Sync Console')
TOTP_PENDING_TIMEOUT_SECONDS = 300

# Auth Helper
def check_auth(username, password):
    config = Config()
    repository = ServerRepository(config)
    password_hash = repository.get_setting('auth_password_hash')

    if username != config.BASIC_AUTH_USERNAME:
        return False

    if password_hash:
        return check_password_hash(password_hash, password)

    return password == config.BASIC_AUTH_PASSWORD


def get_repository():
    return ServerRepository(Config())


def get_totp_secret():
    return get_repository().get_setting('auth_totp_secret')


def is_totp_enabled():
    return bool(get_repository().get_setting('auth_totp_enabled', '0') == '1' and get_totp_secret())


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def normalize_totp_secret(secret):
    normalized = re.sub(r'\s+', '', (secret or '').upper())
    if not normalized:
        raise ValueError('2FA secret is missing')
    padding = '=' * ((8 - len(normalized) % 8) % 8)
    return normalized + padding


def hotp_token(secret, counter, digits=TOTP_DIGITS):
    key = base64.b32decode(normalize_totp_secret(secret), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp_code(secret, code, valid_window=TOTP_VALID_WINDOW, time_step=TOTP_STEP_SECONDS):
    if not secret:
        return False

    candidate = re.sub(r'\s+', '', (code or ''))
    if not re.fullmatch(r'\d{6}', candidate):
        return False

    current_counter = int(time.time() // time_step)
    try:
        for offset in range(-valid_window, valid_window + 1):
            if hmac.compare_digest(hotp_token(secret, current_counter + offset), candidate):
                return True
    except (binascii.Error, ValueError):
        return False
    return False


def build_totp_uri(username, secret):
    account_name = quote(f'{TOTP_ISSUER}:{username}')
    issuer = quote(TOTP_ISSUER)
    return f'otpauth://totp/{account_name}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}'


def clear_pending_2fa():
    session.pop('pending_2fa_user', None)
    session.pop('pending_2fa_at', None)


def start_authenticated_session(username):
    clear_pending_2fa()
    session['logged_in'] = True
    session['auth_username'] = username


def is_pending_2fa_valid():
    pending_user = session.get('pending_2fa_user')
    pending_at = session.get('pending_2fa_at')
    if not pending_user or not pending_at:
        return False
    if time.time() - pending_at > TOTP_PENDING_TIMEOUT_SECONDS:
        clear_pending_2fa()
        return False
    return True

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
    requires_2fa = is_totp_enabled()
    pending_2fa = is_pending_2fa_valid()

    if request.method == 'POST':
        step = request.form.get('step', 'password')
        if step == 'totp':
            otp_code = request.form.get('otp_code', '')
            pending_user = session.get('pending_2fa_user')
            if not pending_user or not is_pending_2fa_valid():
                error = '验证码已过期，请重新输入用户名和密码'
            elif verify_totp_code(get_totp_secret(), otp_code):
                start_authenticated_session(pending_user)
                return redirect(url_for('index'))
            else:
                error = '动态验证码错误'
                pending_2fa = True
        else:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            if check_auth(username, password):
                if requires_2fa:
                    session['pending_2fa_user'] = username
                    session['pending_2fa_at'] = time.time()
                    pending_2fa = True
                else:
                    start_authenticated_session(username)
                    return redirect(url_for('index'))
            else:
                error = '用户名或密码错误'
    return render_template(
        'login.html',
        error=error,
        pending_2fa=pending_2fa,
        requires_2fa=requires_2fa,
        pending_username=session.get('pending_2fa_user', Config().BASIC_AUTH_USERNAME),
    )

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('auth_username', None)
    clear_pending_2fa()
    return redirect(url_for('login'))


def validate_new_password(new_password, confirm_password):
    if len(new_password) < 8:
        raise ValueError('New password must be at least 8 characters long')
    if new_password != confirm_password:
        raise ValueError('Password confirmation does not match')

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


@app.route('/favicon.png')
def favicon_png():
    return send_file(FAVICON_PATH, mimetype='image/png')


@app.route('/favicon.ico')
def favicon_ico():
    return send_file(FAVICON_PATH, mimetype='image/png')

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


@app.route('/api/account/password', methods=['POST'])
@requires_auth
def change_password():
    config = Config()
    repository = ServerRepository(config)

    try:
        data = request.get_json() or {}
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')

        if not check_auth(config.BASIC_AUTH_USERNAME, current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400

        validate_new_password(new_password, confirm_password)
        repository.set_setting('auth_password_hash', generate_password_hash(new_password))
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/account/2fa/status', methods=['GET'])
@requires_auth
def get_2fa_status():
    config = Config()
    repository = ServerRepository(config)
    secret = repository.get_setting('auth_totp_secret')
    enabled = repository.get_setting('auth_totp_enabled', '0') == '1' and bool(secret)

    return jsonify({
        'success': True,
        'enabled': enabled,
        'secret_configured': bool(secret),
        'issuer': TOTP_ISSUER,
        'account_name': config.BASIC_AUTH_USERNAME,
    })


@app.route('/api/account/2fa/setup', methods=['POST'])
@requires_auth
def setup_2fa():
    config = Config()
    repository = ServerRepository(config)
    data = request.get_json() or {}
    current_password = data.get('current_password', '')

    if not check_auth(config.BASIC_AUTH_USERNAME, current_password):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400

    secret = generate_totp_secret()
    repository.set_setting('auth_totp_pending_secret', secret)

    return jsonify({
        'success': True,
        'secret': secret,
        'issuer': TOTP_ISSUER,
        'account_name': config.BASIC_AUTH_USERNAME,
        'otpauth_uri': build_totp_uri(config.BASIC_AUTH_USERNAME, secret),
    })


@app.route('/api/account/2fa/enable', methods=['POST'])
@requires_auth
def enable_2fa():
    config = Config()
    repository = ServerRepository(config)
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    otp_code = data.get('otp_code', '')

    if not check_auth(config.BASIC_AUTH_USERNAME, current_password):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400

    pending_secret = repository.get_setting('auth_totp_pending_secret')
    if not pending_secret:
        return jsonify({'success': False, 'error': 'No pending 2FA setup found'}), 400

    if not verify_totp_code(pending_secret, otp_code):
        return jsonify({'success': False, 'error': 'Dynamic verification code is incorrect'}), 400

    repository.set_setting('auth_totp_secret', pending_secret)
    repository.set_setting('auth_totp_enabled', '1')
    repository.set_setting('auth_totp_pending_secret', '')
    return jsonify({'success': True, 'message': '2FA has been enabled'})


@app.route('/api/account/2fa/disable', methods=['POST'])
@requires_auth
def disable_2fa():
    config = Config()
    repository = ServerRepository(config)
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    otp_code = data.get('otp_code', '')
    secret = repository.get_setting('auth_totp_secret')

    if not check_auth(config.BASIC_AUTH_USERNAME, current_password):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400

    if not secret or repository.get_setting('auth_totp_enabled', '0') != '1':
        return jsonify({'success': False, 'error': '2FA is not enabled'}), 400

    if not verify_totp_code(secret, otp_code):
        return jsonify({'success': False, 'error': 'Dynamic verification code is incorrect'}), 400

    repository.set_setting('auth_totp_enabled', '0')
    repository.set_setting('auth_totp_secret', '')
    repository.set_setting('auth_totp_pending_secret', '')
    return jsonify({'success': True, 'message': '2FA has been disabled'})


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


@app.route('/api/servers/<int:server_id>/remote-cert-info', methods=['GET'])
@requires_auth
def get_remote_cert_info(server_id):
    """Inspect deployed certificate expiry date on a remote server."""
    config = Config()
    repository = ServerRepository(config)
    domain = request.args.get('domain', '').strip()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'}), 400

    try:
        server = repository.get_server(server_id)
        if not server:
            return jsonify({'success': False, 'error': 'Server not found'}), 404

        target = f"{server['host']}:{server['port']}"
        sync_manager = SyncManager()
        result = sync_manager.inspect_remote_certificate(target, domain)

        if not result.get('success'):
            return jsonify(result), 500

        return jsonify(result)
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
