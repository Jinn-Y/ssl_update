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
import json
import secrets
import struct
import time
from urllib.parse import quote
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from werkzeug.middleware.proxy_fix import ProxyFix
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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
FAVICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'secret.png')
TOTP_VALID_WINDOW = 1
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_ISSUER = os.getenv('TOTP_ISSUER', 'Certificate Sync Console')
TOTP_PENDING_TIMEOUT_SECONDS = 300
PASSKEY_CHALLENGE_TIMEOUT_SECONDS = 300
PASSKEY_RP_NAME = os.getenv('PASSKEY_RP_NAME', 'Certificate Sync Console')
PASSKEY_RP_ID_OVERRIDE = os.getenv('PASSKEY_RP_ID', '').strip()
PASSKEY_ORIGIN_OVERRIDE = os.getenv('PASSKEY_ORIGIN', '').strip()

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
    clear_passkey_state()
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


def base64url_encode(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def base64url_decode(value):
    if not value:
        return b''
    padding_chars = '=' * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding_chars).encode('ascii'))


def get_passkey_rp_id():
    if PASSKEY_RP_ID_OVERRIDE:
        return PASSKEY_RP_ID_OVERRIDE
    return (request.host.split(':', 1)[0] or 'localhost').lower()


def get_passkey_origin():
    if PASSKEY_ORIGIN_OVERRIDE:
        return PASSKEY_ORIGIN_OVERRIDE
    return f'{request.scheme}://{request.host}'


def sha256_bytes(value):
    return hashlib.sha256(value).digest()


def current_unix_time():
    return int(time.time())


def clear_passkey_state():
    session.pop('passkey_registration', None)
    session.pop('passkey_authentication', None)


def create_passkey_challenge():
    return base64url_encode(secrets.token_bytes(32))


def set_passkey_registration_state(challenge, rp_id, origin):
    session['passkey_registration'] = {
        'challenge': challenge,
        'rp_id': rp_id,
        'origin': origin,
        'expires_at': current_unix_time() + PASSKEY_CHALLENGE_TIMEOUT_SECONDS,
    }


def get_valid_passkey_registration_state():
    state = session.get('passkey_registration')
    if not state:
        return None
    if state.get('expires_at', 0) < current_unix_time():
        session.pop('passkey_registration', None)
        return None
    return state


def set_passkey_authentication_state(challenge, rp_id, origin):
    session['passkey_authentication'] = {
        'challenge': challenge,
        'rp_id': rp_id,
        'origin': origin,
        'expires_at': current_unix_time() + PASSKEY_CHALLENGE_TIMEOUT_SECONDS,
    }


def get_valid_passkey_authentication_state():
    state = session.get('passkey_authentication')
    if not state:
        return None
    if state.get('expires_at', 0) < current_unix_time():
        session.pop('passkey_authentication', None)
        return None
    return state


def cbor_decode(data, start_index=0):
    if start_index >= len(data):
        raise ValueError('Unexpected end of CBOR data')

    initial = data[start_index]
    major_type = initial >> 5
    additional = initial & 0x1F
    index = start_index + 1

    def read_length():
        nonlocal index
        if additional < 24:
            return additional
        if additional == 24:
            length = data[index]
            index += 1
            return length
        if additional == 25:
            length = struct.unpack('>H', data[index:index + 2])[0]
            index += 2
            return length
        if additional == 26:
            length = struct.unpack('>I', data[index:index + 4])[0]
            index += 4
            return length
        if additional == 27:
            length = struct.unpack('>Q', data[index:index + 8])[0]
            index += 8
            return length
        raise ValueError('Unsupported CBOR length encoding')

    if major_type == 0:
        return read_length(), index
    if major_type == 1:
        return -1 - read_length(), index
    if major_type == 2:
        length = read_length()
        value = data[index:index + length]
        return value, index + length
    if major_type == 3:
        length = read_length()
        value = data[index:index + length].decode('utf-8')
        return value, index + length
    if major_type == 4:
        length = read_length()
        items = []
        for _ in range(length):
            value, index = cbor_decode(data, index)
            items.append(value)
        return items, index
    if major_type == 5:
        length = read_length()
        mapping = {}
        for _ in range(length):
            key, index = cbor_decode(data, index)
            value, index = cbor_decode(data, index)
            mapping[key] = value
        return mapping, index
    if major_type == 6:
        _ = read_length()
        return cbor_decode(data, index)
    if major_type == 7:
        if additional == 20:
            return False, index
        if additional == 21:
            return True, index
        if additional == 22:
            return None, index
        raise ValueError('Unsupported CBOR simple value')

    raise ValueError('Unsupported CBOR major type')


def cose_key_to_pem(cose_key):
    key_type = cose_key.get(1)
    algorithm = cose_key.get(3)

    if key_type == 2 and algorithm == -7:
        x_coord = cose_key.get(-2)
        y_coord = cose_key.get(-3)
        if not x_coord or not y_coord:
            raise ValueError('Invalid EC passkey public key')
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_coord, 'big'),
            int.from_bytes(y_coord, 'big'),
            ec.SECP256R1(),
        )
        public_key = public_numbers.public_key()
    elif key_type == 3 and algorithm == -257:
        modulus = cose_key.get(-1)
        exponent = cose_key.get(-2)
        if not modulus or not exponent:
            raise ValueError('Invalid RSA passkey public key')
        public_numbers = rsa.RSAPublicNumbers(
            int.from_bytes(exponent, 'big'),
            int.from_bytes(modulus, 'big'),
        )
        public_key = public_numbers.public_key()
    else:
        raise ValueError('Unsupported passkey algorithm')

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')


def verify_passkey_signature(public_key_pem, signature, signed_bytes):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
        return

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        return

    raise ValueError('Unsupported passkey public key type')


def parse_authenticator_data(auth_data, expect_attested_data=False):
    if len(auth_data) < 37:
        raise ValueError('Authenticator data is too short')

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack('>I', auth_data[33:37])[0]
    index = 37

    result = {
        'rp_id_hash': rp_id_hash,
        'flags': flags,
        'sign_count': sign_count,
    }

    if expect_attested_data:
        if not (flags & 0x40):
            raise ValueError('Passkey attested credential data is missing')
        if len(auth_data) < index + 18:
            raise ValueError('Attested credential data is incomplete')
        aaguid = auth_data[index:index + 16]
        index += 16
        credential_id_length = struct.unpack('>H', auth_data[index:index + 2])[0]
        index += 2
        credential_id = auth_data[index:index + credential_id_length]
        index += credential_id_length
        cose_key, _ = cbor_decode(auth_data, index)
        result.update({
            'aaguid': aaguid,
            'credential_id': credential_id,
            'credential_public_key': cose_key,
        })

    return result


def ensure_webauthn_client_data(client_data_json_b64, expected_type, expected_challenge, expected_origin):
    client_data_json = base64url_decode(client_data_json_b64)
    client_data = json.loads(client_data_json.decode('utf-8'))

    if client_data.get('type') != expected_type:
        raise ValueError('Unexpected passkey operation type')
    if client_data.get('challenge') != expected_challenge:
        raise ValueError('Passkey challenge mismatch')
    if client_data.get('origin') != expected_origin:
        raise ValueError('Passkey origin mismatch')

    return client_data_json, client_data


def build_passkey_descriptor(passkey):
    descriptor = {
        'id': passkey['credential_id'],
        'type': 'public-key',
    }
    transports = [item for item in (passkey.get('transports') or '').split(',') if item]
    if transports:
        descriptor['transports'] = transports
    return descriptor

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
    clear_passkey_state()
    return redirect(url_for('login'))


@app.route('/api/passkeys/status', methods=['GET'])
def get_passkey_public_status():
    repository = get_repository()
    return jsonify({
        'success': True,
        'available': len(repository.list_passkeys()) > 0,
    })


@app.route('/api/passkeys/auth/options', methods=['POST'])
def begin_passkey_login():
    repository = get_repository()
    passkeys = repository.list_passkeys()
    if not passkeys:
        return jsonify({'success': False, 'error': 'No passkeys are registered yet'}), 400

    rp_id = get_passkey_rp_id()
    origin = get_passkey_origin()
    challenge = create_passkey_challenge()
    set_passkey_authentication_state(challenge, rp_id, origin)

    return jsonify({
        'success': True,
        'publicKey': {
            'challenge': challenge,
            'rpId': rp_id,
            'timeout': 60000,
            'userVerification': 'preferred',
            'allowCredentials': [build_passkey_descriptor(passkey) for passkey in passkeys],
        },
    })


@app.route('/api/passkeys/auth/verify', methods=['POST'])
def complete_passkey_login():
    repository = get_repository()
    state = get_valid_passkey_authentication_state()
    if not state:
        return jsonify({'success': False, 'error': 'Passkey login has expired, please try again'}), 400

    try:
        data = request.get_json() or {}
        credential_id = data.get('id') or data.get('rawId') or ''
        response = data.get('response') or {}

        if data.get('type') != 'public-key' or not credential_id:
            raise ValueError('Invalid passkey response')

        passkey = repository.get_passkey_by_credential_id(credential_id)
        if not passkey:
            raise ValueError('Passkey credential was not found')

        client_data_json, _ = ensure_webauthn_client_data(
            response.get('clientDataJSON', ''),
            'webauthn.get',
            state['challenge'],
            state['origin'],
        )

        authenticator_data = base64url_decode(response.get('authenticatorData', ''))
        parsed_auth_data = parse_authenticator_data(authenticator_data)
        if parsed_auth_data['rp_id_hash'] != sha256_bytes(state['rp_id'].encode('utf-8')):
            raise ValueError('Passkey RP ID mismatch')
        if not (parsed_auth_data['flags'] & 0x01):
            raise ValueError('Passkey user presence check failed')

        signature = base64url_decode(response.get('signature', ''))
        signed_bytes = authenticator_data + sha256_bytes(client_data_json)
        verify_passkey_signature(passkey['public_key_pem'], signature, signed_bytes)

        new_sign_count = parsed_auth_data['sign_count']
        if passkey['sign_count'] and new_sign_count and new_sign_count <= passkey['sign_count']:
            raise ValueError('Passkey sign counter check failed')

        repository.update_passkey_usage(passkey['id'], max(passkey['sign_count'], new_sign_count))
        clear_passkey_state()
        start_authenticated_session(Config().BASIC_AUTH_USERNAME)
        return jsonify({'success': True, 'redirect': url_for('index')})
    except (InvalidSignature, ValueError, KeyError, json.JSONDecodeError, binascii.Error) as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


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
    import time
    return render_template('index.html', cache_bust=int(time.time()))


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
            for item in os.listdir(acme_root):
                item_path = os.path.join(acme_root, item)
                if os.path.isdir(item_path) and item.endswith('_ecc'):
                    domain = item[:-4]
                    cert_file = os.path.join(item_path, 'fullchain.cer')
                    key_file = os.path.join(item_path, f'{domain}.key')
                    if os.path.exists(cert_file) and os.path.exists(key_file):
                        domains.append(domain)
        
        # 本地开发模式：如果没有找到真实域名，注入演示数据
        if not domains and os.environ.get('DEMO_MODE', '').lower() in ('1', 'true', 'yes'):
            domains = ['example.com', 'api.example.com', 'cdn.example.com']
        
        domains.sort()
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
        # 本地开发模式：返回演示证书数据
        if os.environ.get('DEMO_MODE', '').lower() in ('1', 'true', 'yes'):
            import random
            demo_days = {'example.com': 58, 'api.example.com': 12, 'cdn.example.com': 3}
            days = demo_days.get(domain, random.randint(5, 90))
            return jsonify({'success': True, 'domain': domain, 'expiry_date': 'Jun 25 12:00:00 2026 GMT', 'days_left': days})
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


@app.route('/api/account/passkeys', methods=['GET'])
@requires_auth
def list_account_passkeys():
    repository = get_repository()
    passkeys = repository.list_passkeys()
    return jsonify({
        'success': True,
        'items': [
            {
                'id': item['id'],
                'label': item['label'],
                'credential_id': item['credential_id'],
                'sign_count': item['sign_count'],
                'last_used_at': item['last_used_at'],
                'created_at': item['created_at'],
                'updated_at': item['updated_at'],
                'transports': [value for value in (item.get('transports') or '').split(',') if value],
            }
            for item in passkeys
        ],
    })


@app.route('/api/account/passkeys/register/options', methods=['POST'])
@requires_auth
def begin_passkey_registration():
    repository = get_repository()
    rp_id = get_passkey_rp_id()
    origin = get_passkey_origin()
    challenge = create_passkey_challenge()
    set_passkey_registration_state(challenge, rp_id, origin)

    user_id = base64url_encode(Config().BASIC_AUTH_USERNAME)
    passkeys = repository.list_passkeys()

    return jsonify({
        'success': True,
        'publicKey': {
            'challenge': challenge,
            'rp': {
                'name': PASSKEY_RP_NAME,
                'id': rp_id,
            },
            'user': {
                'id': user_id,
                'name': Config().BASIC_AUTH_USERNAME,
                'displayName': Config().BASIC_AUTH_USERNAME,
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},
                {'type': 'public-key', 'alg': -257},
            ],
            'timeout': 60000,
            'attestation': 'none',
            'authenticatorSelection': {
                'residentKey': 'preferred',
                'userVerification': 'preferred',
            },
            'excludeCredentials': [build_passkey_descriptor(passkey) for passkey in passkeys],
        },
    })


@app.route('/api/account/passkeys/register/verify', methods=['POST'])
@requires_auth
def complete_passkey_registration():
    repository = get_repository()
    state = get_valid_passkey_registration_state()
    if not state:
        return jsonify({'success': False, 'error': 'Passkey registration has expired, please try again'}), 400

    try:
        data = request.get_json() or {}
        response = data.get('response') or {}
        label = (data.get('label') or '').strip() or f'Passkey {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}'

        if data.get('type') != 'public-key':
            raise ValueError('Invalid passkey registration type')

        client_data_json, _ = ensure_webauthn_client_data(
            response.get('clientDataJSON', ''),
            'webauthn.create',
            state['challenge'],
            state['origin'],
        )
        _ = client_data_json
        attestation_object = base64url_decode(response.get('attestationObject', ''))
        attestation, _ = cbor_decode(attestation_object)
        auth_data = attestation.get('authData')
        if not auth_data:
            raise ValueError('Passkey attestation data is missing')

        parsed_auth_data = parse_authenticator_data(auth_data, expect_attested_data=True)
        if parsed_auth_data['rp_id_hash'] != sha256_bytes(state['rp_id'].encode('utf-8')):
            raise ValueError('Passkey RP ID mismatch')
        if not (parsed_auth_data['flags'] & 0x01):
            raise ValueError('Passkey user presence check failed')

        credential_id = base64url_encode(parsed_auth_data['credential_id'])
        if repository.get_passkey_by_credential_id(credential_id):
            raise ValueError('This passkey is already registered')

        public_key_pem = cose_key_to_pem(parsed_auth_data['credential_public_key'])
        transports = ','.join(data.get('transports') or [])
        passkey = repository.create_passkey(
            label=label,
            credential_id=credential_id,
            public_key_pem=public_key_pem,
            sign_count=parsed_auth_data['sign_count'],
            transports=transports,
        )
        session.pop('passkey_registration', None)
        return jsonify({
            'success': True,
            'message': 'Passkey has been registered',
            'passkey': {
                'id': passkey['id'],
                'label': passkey['label'],
                'credential_id': passkey['credential_id'],
                'sign_count': passkey['sign_count'],
                'created_at': passkey['created_at'],
            },
        })
    except (ValueError, KeyError, json.JSONDecodeError, binascii.Error) as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'This passkey is already registered'}), 409
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/account/passkeys/<int:passkey_id>', methods=['DELETE'])
@requires_auth
def remove_passkey(passkey_id):
    repository = get_repository()
    deleted = repository.delete_passkey(passkey_id)
    if not deleted:
        return jsonify({'success': False, 'error': 'Passkey was not found'}), 404
    return jsonify({'success': True, 'message': 'Passkey has been removed'})


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
