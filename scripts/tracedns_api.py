#!/usr/bin/env python3
"""Standalone stdlib client for TraceDNS v1. Credentials/cookies stay in memory."""
import argparse
import getpass
import http.cookiejar
import ipaddress
import json
import math
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


class APIError(RuntimeError):
    """Deliberately excludes response/URL text which may contain credentials."""
    def __init__(self, status, request_id=''):
        self.status = status
        self.request_id = request_id if isinstance(request_id, str) and len(request_id) == 32 and all(
            c in '0123456789abcdef' for c in request_id
        ) else ''
        super().__init__(f'TraceDNS HTTP {status}' + (f' (request_id={self.request_id})' if self.request_id else ''))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TraceDNSClient:
    """Use one instance per thread/account. No redirects, retries or disk cookies."""
    def __init__(self, base_url, *, timeout=30, allow_loopback_http=False, ca_file=None,
                 max_response_bytes=16 * 1024 * 1024):
        parsed = urlsplit(base_url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or any(c.isspace() for c in base_url)):
            raise ValueError('base_url must be an HTTP(S) origin without credentials, path, query or fragment')
        try:
            parsed.port
            loopback = parsed.hostname == 'localhost' or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            # Validate port separately; a DNS hostname need not be an IP literal.
            parsed.port
            loopback = False
        if parsed.scheme == 'http' and not (allow_loopback_http and loopback):
            raise ValueError('HTTPS required; HTTP is allowed only with explicit loopback opt-in')
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('timeout must be finite and positive')
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 64 * 1024 * 1024:
            raise ValueError('max_response_bytes must be between 1 byte and 64 MiB')
        self.origin = base_url.rstrip('/')
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.cookies = http.cookiejar.CookieJar()
        self.csrf = ''
        self.authenticated = False
        self.opener = build_opener(ProxyHandler({}), _NoRedirect(), HTTPCookieProcessor(self.cookies),
                                   HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self.response_headers = {}

    def request(self, method, path, data=None, *, params=None):
        """Return JSON or JSONL text. Never automatically replay a failed write."""
        return self._request(method, path, data, params=params, max_response_bytes=self.max_response_bytes)

    def _request(self, method, path, data=None, *, params=None, max_response_bytes):
        self.response_headers = {}
        method = method.upper()
        if method not in ('GET', 'POST', 'PATCH', 'PUT', 'DELETE'):
            raise ValueError('Unsupported HTTP method')
        parsed = urlsplit(path)
        if (not path.startswith('/') or path.startswith('//') or parsed.scheme or parsed.netloc
                or parsed.fragment or '\\' in path or any(ord(c) < 32 for c in path)
                or '..' in parsed.path.split('/')):
            raise ValueError('path must be a relative API path such as /config')
        if data is not None and (method == 'GET' or not isinstance(data, dict)):
            raise ValueError('Request body must be a JSON object on a write method')
        query = urlencode(params, doseq=True) if params else ''
        url = self.origin + '/api/v1' + path + (('&' if parsed.query else '?') + query if query else '')
        headers = {'Accept': 'application/json', 'Origin': self.origin}
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        body = None
        if method != 'GET':
            body = json.dumps(data if data is not None else {}, allow_nan=False).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        try:
            with self.opener.open(Request(url, data=body, headers=headers, method=method), timeout=self.timeout) as response:
                self.response_headers = {
                    key: response.headers[key]
                    for key in ('X-Request-ID', 'X-Total-Count', 'X-Next-Offset', 'Content-Type')
                    if key in response.headers
                }
                raw = response.read(max_response_bytes + 1)
                if len(raw) > max_response_bytes:
                    raise ValueError('Response exceeded configured byte limit; request a smaller page')
                if response.headers.get_content_type() == 'application/x-ndjson':
                    return raw.decode('utf-8')
                return json.loads(raw)
        except HTTPError as exc:
            request_id = exc.headers.get('X-Request-ID', '')
            exc.close()
            raise APIError(exc.code, request_id) from None
        except (URLError, TimeoutError, OSError):
            raise RuntimeError('TraceDNS transport failed; outcome may be unknown. Do not blindly retry writes.') from None

    def login(self, username, password):
        if self.authenticated:
            raise ValueError('Already logged in; close this session before logging in again')
        self.csrf = self.request('GET', '/auth/csrf')['csrf_token']
        result = self.request('POST', '/auth/login', {'username': username, 'password': password})
        self.csrf = result['csrf_token']
        self.authenticated = True
        return result['user']

    def close(self):
        try:
            # Cookie processing precedes body decoding: a failed login response
            # can still have established a real session that must be revoked.
            if self.authenticated or any(c.name == 'td_session' and c.value for c in self.cookies):
                try:
                    if not self.authenticated:
                        self.csrf = self._request('GET', '/auth/csrf', max_response_bytes=16384)['csrf_token']
                    self._request('POST', '/auth/logout', {}, max_response_bytes=16384)
                except APIError as exc:
                    if exc.status != 401:  # already expired/revoked is also closed
                        raise
        finally:
            self.cookies.clear()
            self.csrf = ''
            self.authenticated = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except Exception:
            if exc_type is None:
                raise
            print('Warning: TraceDNS logout unconfirmed; revoke this session if necessary.', file=sys.stderr)


def _public_output(value):
    """The CLI must not print authentication material returned by /auth/me."""
    if isinstance(value, dict):
        return {k: _public_output(v) for k, v in value.items()
                if k not in {'csrf_token', 'password', 'current_password', 'new_password', 'token'}}
    if isinstance(value, list):
        return [_public_output(v) for v in value]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default=os.environ.get('TRACEDNS_BASE_URL'), help='HTTPS origin (no /api/v1 suffix)')
    parser.add_argument('--username', default=os.environ.get('TRACEDNS_USERNAME'))
    parser.add_argument('--allow-loopback-http', action='store_true', help='Development only; never permits remote HTTP')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--ca-file', default=os.environ.get('TRACEDNS_CA_FILE'))
    parser.add_argument('--json-file', help='JSON object body from a file, or - for stdin; never pass secrets as arguments')
    parser.add_argument('method', choices=['GET', 'POST', 'PATCH', 'PUT', 'DELETE'])
    parser.add_argument('path', help='Relative API path, e.g. /ips?include_vt=0&limit=100')
    args = parser.parse_args(argv)
    if not args.base_url or not args.username:
        parser.error('Set TRACEDNS_BASE_URL and TRACEDNS_USERNAME, or supply their flags')
    try:
        data = None
        if args.json_file:
            if args.json_file == '-':
                data = json.load(sys.stdin)
            else:
                with open(args.json_file, encoding='utf-8') as stream:
                    data = json.load(stream)
        password = os.environ.get('TRACEDNS_PASSWORD')
        if password is None:
            if not sys.stdin.isatty():
                raise ValueError('Noninteractive use requires TRACEDNS_PASSWORD from a secret manager')
            password = getpass.getpass('TraceDNS password: ')
        with TraceDNSClient(args.base_url, timeout=args.timeout, allow_loopback_http=args.allow_loopback_http,
                            ca_file=args.ca_file) as client:
            user = client.login(args.username, password)
            del password
            if user.get('must_change_password') and args.path.split('?')[0] not in ('/auth/me', '/auth/password', '/auth/logout'):
                raise ValueError('Password change required; change it then log in again')
            result = client.request(args.method, args.path, data)
        if isinstance(result, str):
            print(result, end='' if result.endswith('\n') else '\n')
        else:
            print(json.dumps(_public_output(result), ensure_ascii=False, indent=2))
        return 0
    except APIError as exc:
        print(str(exc), file=sys.stderr)
    except (ValueError, OSError, RuntimeError, EOFError):
        # Raw exceptions can contain an untrusted URL, JSON input or credential.
        print('TraceDNS request failed: check input, credentials, TLS and connectivity. '
              'Outcome may be unknown; read back before retrying a write.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
