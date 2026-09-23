"""Versioned, allowlisted adapters; legacy handlers remain the state owners."""
import re

from security.store import SecurityError

PREFIX = '/api/v1'
ROUTES = {
    '/': {'GET': 'GET'},
    '/openapi.json': {'GET': 'GET'},
    '/config': {'GET': 'GET', 'POST': 'POST', 'PATCH': 'POST'},
    '/settings': {'GET': 'GET', 'POST': 'POST', 'PATCH': 'POST'},
    '/results': {'GET': 'GET'},
    '/domains': {'GET': 'GET'},
    '/history': {'GET': 'GET'},
    '/ips': {'GET': 'GET'},
    '/ip': {'GET': 'GET', 'POST': 'POST'},
    '/domain-analysis': {'GET': 'GET'},
    '/resolve': {'POST': 'POST'},
    '/analyze': {'POST': 'POST'},
    '/domain-precheck': {'POST': 'POST'},
    '/ip-list-analysis': {'POST': 'POST'},
    '/ip-relationship-analysis': {'POST': 'POST'},
    '/ip-relationship-jobs': {'POST': 'POST'},
    '/ip-relationship-jobs/{job_id}': {'GET': 'GET'},
    '/ip-relationship-jobs/{job_id}/cancel': {'POST': 'POST'},
    '/decoders': {'GET': 'GET'},
    '/decoders/custom': {'GET': 'GET', 'POST': 'POST', 'PUT': 'PUT', 'DELETE': 'DELETE'},
    '/decoders/custom/preview': {'POST': 'POST'},
    '/misp/search': {'GET': 'GET', 'POST': 'POST'},
    '/misp/event-ips': {'POST': 'POST'},
    '/auth/csrf': {'GET': 'GET'},
    '/auth/login': {'POST': 'POST'},
    '/auth/logout': {'POST': 'POST'},
    '/auth/me': {'GET': 'GET'},
    '/auth/password': {'POST': 'POST'},
    '/auth/activity': {'GET': 'GET'},
    '/auth/sessions': {'GET': 'GET'},
    '/auth/sessions/revoke': {'POST': 'POST'},
    '/admin/users': {'GET': 'GET', 'POST': 'POST'},
    '/admin/users/{user_id}/update': {'POST': 'POST'},
    '/admin/users/{user_id}/reset': {'POST': 'POST'},
    '/admin/users/{user_id}/revoke': {'POST': 'POST'},
    '/admin/audit': {'GET': 'GET'},
    '/admin/audit/export': {'POST': 'POST'},
}
PATTERNS = {
    '{job_id}': r'[a-f0-9]{32}',
    '{user_id}': r'[a-zA-Z0-9-]+',
}


def resolve_route(path: str, method: str) -> tuple[str, str]:
    """Return canonical path/method; never mount pages or arbitrary paths."""
    if path == PREFIX:
        relative = '/'
    elif path.startswith(PREFIX + '/'):
        relative = path[len(PREFIX):]
    else:
        raise SecurityError('Unknown API route', 404)
    methods = ROUTES.get(relative)
    if methods is None:
        for template, candidates in ROUTES.items():
            if '{' not in template:
                continue
            pattern = re.escape(template)
            for name, rule in PATTERNS.items():
                pattern = pattern.replace(re.escape(name), rule)
            if re.fullmatch(pattern, relative):
                methods = candidates
                break
    if methods is None:
        raise SecurityError('Unknown API route', 404)
    if method not in methods:
        raise SecurityError('Method not allowed', 405)
    return '/api-info' if relative == '/' else relative, methods[method]


def discovery():
    return {
        'name': 'TraceDNS', 'api_version': 'v1', 'base_path': PREFIX,
        'openapi': PREFIX + '/openapi.json',
        'authentication': 'session cookie + X-CSRF-Token; Origin required on writes',
        'legacy_routes_supported': True,
    }
