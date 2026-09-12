"""Central HTTP security boundary, applied outside every legacy route."""
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import secrets
import time
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from http_api.request_limits import get_request_body
from http_api.utils import send_json
from security.policy import allowed, external_read
from security.store import SecurityError

LOGGER = logging.getLogger(__name__)
PUBLIC = {'/login.html', '/auth_frontend.js', '/security_ui.js'}
PAGES = PUBLIC | {'/account.html', '/accounts.html', '/audit.html'}


class HttpSecurity:
    """One service per listening server; identity remains request-local."""
    def __init__(self, store, origin='', insecure=False, trusted_proxies=(),
                 allow_insecure_remote_http=False):
        self.store = store
        self.origin = origin.rstrip('/')
        self.insecure = insecure
        self.allow_insecure_remote_http = allow_insecure_remote_http
        self.trusted_proxies = {str(ipaddress.ip_address(ip)) for ip in trusted_proxies}
        self.key = secrets.token_bytes(32)
        self.audit_error = False
        if store is not None and not insecure and not self.origin.startswith('https://'):
            raise ValueError('HTTPS --public-origin is required (or explicit loopback development mode)')
        if self.origin:
            parsed = urlsplit(self.origin)
            if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                    or parsed.password or parsed.path or parsed.query or parsed.fragment):
                raise ValueError('public origin must contain only scheme and authority')

    def csrf(self, token):
        return hmac.new(self.key, token.encode(), hashlib.sha256).hexdigest()

    def cookie(self, handler, name, value, delete=False):
        flags = '; Path=/; HttpOnly; SameSite=Lax' + ('' if self.insecure else '; Secure')
        flags += '; Max-Age=0' if delete else ( '; Max-Age=600' if name == 'td_pre' else '')
        handler._security_cookies.append(f'{name}={value}{flags}')

    def event(self, handler, action, outcome, **kwargs):
        try:
            result = self.store.audit(handler.principal, action, outcome=outcome,
                                      request_id=handler.request_id, source_ip=handler.source_ip, **kwargs)
            self.audit_error = False
            return result
        except Exception:
            self.audit_error = True
            LOGGER.error('Audit write failed; request_id=%s', handler.request_id)
            raise SecurityError('Audit storage unavailable', 503) from None

    def transport(self, handler):
        peer = str(ipaddress.ip_address(handler.client_address[0]))
        if self.insecure and not self.allow_insecure_remote_http and not ipaddress.ip_address(peer).is_loopback:
            raise SecurityError('Development HTTP requires loopback', 403)
        origin = self.origin or f'http://127.0.0.1:{handler.server.server_port}'
        if handler.headers.get('Host') != urlsplit(origin).netloc:
            raise SecurityError('Invalid host', 403)
        handler.source_ip = peer
        if peer in self.trusted_proxies:
            forwarded = handler.headers.get('X-Forwarded-For', '')
            if forwarded:
                # Proxy must replace this header, not append arbitrary client values.
                handler.source_ip = str(ipaddress.ip_address(forwarded))
        handler.expected_origin = origin

    @staticmethod
    def cookies(handler):
        try:
            jar = SimpleCookie(handler.headers.get('Cookie', ''))
            return {name: item.value for name, item in jar.items()}
        except Exception:
            return {}

    def dispatch(self, handler, original):
        handler.principal = None
        handler.security_store = self.store
        handler.security_service = self
        handler.request_id = uuid.uuid4().hex
        handler.source_ip = handler.client_address[0]
        handler._security_cookies = []
        handler._security_status = 500
        handler.close_connection = True
        parsed = urlsplit(handler.path)
        path, qs = parsed.path, parse_qs(parsed.query, keep_blank_values=True)
        try:
            self.transport(handler)
            if handler.command == 'GET' and path in PUBLIC:
                return self.page(handler, path)
            if self.store is None:
                raise SecurityError('Security database unavailable', 503)
            jar = self.cookies(handler)
            token = jar.get('td_session', '')
            handler.session_token = token
            if path == '/auth/csrf' and handler.command == 'GET':
                principal = self.store.authenticate(token)
                if principal:
                    return send_json(handler, {'csrf_token': self.csrf(token)})
                pre = str(int(time.time())) + '.' + secrets.token_urlsafe(24)
                signed = pre + '.' + self.csrf(pre)
                self.cookie(handler, 'td_pre', signed)
                return send_json(handler, {'csrf_token': self.csrf(signed)})
            data = {}
            if handler.command in ('POST', 'PUT', 'DELETE', 'PATCH'):
                raw, rejected = get_request_body(handler, max_length=(16384 if path.startswith(('/auth/', '/admin/'))
                                                                      else handler.max_body_bytes))
                if rejected:
                    return
                try:
                    data = json.loads(raw) if raw else {}
                    if not isinstance(data, dict):
                        raise ValueError()
                except (ValueError, UnicodeError):
                    raise SecurityError('JSON object required', 400) from None
                handler.rfile = io.BytesIO(raw)
                if handler.headers.get('Origin') != handler.expected_origin:
                    raise SecurityError('Invalid origin', 403)
            if path == '/auth/login' and handler.command == 'POST':
                pre = jar.get('td_pre', '')
                try:
                    seed, signature = pre.rsplit('.', 1)
                    age = time.time() - int(seed.split('.')[0])
                    valid = 0 <= age <= 600 and hmac.compare_digest(signature, self.csrf(seed))
                except (ValueError, IndexError):
                    valid = False
                if not valid or not hmac.compare_digest(handler.headers.get('X-CSRF-Token', ''), self.csrf(pre)):
                    raise SecurityError('Invalid CSRF token', 403)
                new_token, user = self.store.login(data.get('username'), data.get('password'),
                                                   handler.source_ip, handler.request_id)
                if token:
                    self.store.logout(token, handler.request_id, handler.source_ip)
                self.cookie(handler, 'td_session', new_token)
                self.cookie(handler, 'td_pre', '', delete=True)
                return send_json(handler, {'user': user, 'csrf_token': self.csrf(new_token)})
            handler.principal = self.store.authenticate(token)
            if not handler.principal:
                if handler.command == 'GET' and (path == '/' or path.endswith('.html')):
                    handler.send_response(303)
                    handler.send_header('Location', '/login.html')
                    handler.end_headers()
                    return
                raise SecurityError('Authentication required', 401)
            needs_csrf = handler.command != 'GET' or external_read(path, qs)
            if needs_csrf and not hmac.compare_digest(handler.headers.get('X-CSRF-Token', ''), self.csrf(token)):
                raise SecurityError('Invalid CSRF token', 403)
            if not allowed(handler.principal['role'], handler.command, path, qs, data):
                raise SecurityError('Permission denied', 403)
            if handler.principal.get('must_change_password') and path not in {
                    '/auth/me', '/auth/logout', '/auth/password', '/account.html',
                    '/auth_frontend.js', '/security_ui.js'}:
                raise SecurityError('Password change required', 403)
            if path in PAGES:
                return self.page(handler, path)
            if path.startswith(('/auth/', '/admin/')):
                from http_api.auth_handlers import handle_security_route
                return handle_security_route(self, handler, path, data, qs)
            # Intent must be durable before any legacy mutation or external lookup.
            audited = handler.command != 'GET' or external_read(path, qs)
            action = handler.command.lower() + ':' + path
            if audited:
                self.event(handler, action, 'started', target=path,
                           details={'fields': sorted(set(data) - {'password', 'token'})})
            original(handler)
            if audited:
                self.event(handler, action, 'success' if handler._security_status < 400 else 'failure',
                           target=path, status=handler._security_status)
        except SecurityError as exc:
            if exc.status in (401, 403) and self.store is not None:
                try:
                    self.event(handler, 'access.denied', 'denied', target=path, status=exc.status)
                except SecurityError:
                    exc = SecurityError('Audit storage unavailable', 503)
            if not getattr(handler, '_headers_sent', False):
                send_json(handler, {'error': str(exc), 'request_id': handler.request_id}, exc.status)
        except Exception:
            LOGGER.error('Request failed; request_id=%s', handler.request_id)
            if not getattr(handler, '_headers_sent', False):
                send_json(handler, {'error': 'Service unavailable', 'request_id': handler.request_id}, 503)

    @staticmethod
    def page(handler, path):
        file = Path(__file__).resolve().parents[1] / path.lstrip('/')
        try:
            content = file.read_bytes()
        except OSError:
            return send_json(handler, {'error': 'Page unavailable'}, 404)
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/javascript; charset=utf-8' if path.endswith('.js')
                            else 'text/html; charset=utf-8')
        handler.send_header('Content-Length', str(len(content)))
        handler.end_headers()
        handler.wfile.write(content)


def secure_handler(handler_class, service):
    """Install one boundary around all HTTP entry points, including future methods."""
    old_headers = handler_class.end_headers
    old_response = handler_class.send_response

    def send_response(self, code, message=None):
        self._security_status = code
        old_response(self, code, message)

    def end_headers(self):
        for cookie in getattr(self, '_security_cookies', []):
            self.send_header('Set-Cookie', cookie)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
        self.send_header('X-Request-ID', getattr(self, 'request_id', ''))
        old_headers(self)
        self._headers_sent = True

    def wrap(original):
        def guarded(self):
            return service.dispatch(self, original)
        return guarded

    def unavailable(self):
        send_json(self, {'error': 'Method not allowed'}, 405)

    for method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'):
        name = 'do_' + method
        setattr(handler_class, name, wrap(getattr(handler_class, name, unavailable)))
    from security.redaction import sanitize
    handler_class.sanitize_response = lambda self, obj, code: (
        {'error': 'Service unavailable', 'request_id': self.request_id} if code >= 500
        else sanitize(obj, self.shared_config))
    handler_class.send_response = send_response
    handler_class.end_headers = end_headers
    # Standard access logging includes raw query strings; use structured audit instead.
    handler_class.log_message = lambda self, fmt, *args: None
    return handler_class
