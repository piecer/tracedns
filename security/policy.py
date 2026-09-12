"""Explicit method/route RBAC; unknown routes are denied."""
import re

READ = {'/config', '/results', '/decoders', '/decoders/custom', '/history', '/ip', '/ips',
        '/domains', '/domain-analysis'}
OPERATE = {'/resolve', '/ip', '/analyze', '/verify', '/domain-precheck', '/ip-list-analysis',
           '/ip-relationship-jobs', '/ip-relationship-analysis', '/misp/search', '/misp/event-ips'}
PAGES = {'/', '/dns_frontend.html', '/dns_dashboard.html', '/dns_frontend.js', '/dns_frontend.css',
         '/auth_frontend.js', '/security_ui.js', '/account.html', '/audit.html',
         '/country_centroids.json', '/cytoscape.min.js', '/world_countries_110m.geojson'}
SELF_GET = {'/auth/me', '/auth/csrf', '/auth/activity', '/auth/sessions'}
SELF_POST = {'/auth/logout', '/auth/password', '/auth/sessions/revoke'}


def external_read(path, qs):
    """Match the existing include_vt semantics conservatively."""
    if path == '/misp/search':
        return True
    if path in ('/ips', '/domain-analysis'):
        default = '1' if path == '/domain-analysis' else '0'
        return qs.get('include_vt', [default])[0] != '0'
    return False


def allowed(role, method, path, qs=None, body=None):
    """Field-sensitive authorization, independent of user-supplied IDs."""
    if role not in ('admin', 'operator', 'viewer'):
        return False
    qs = qs or {}
    if method == 'GET' and path in PAGES | SELF_GET:
        return True
    if method == 'POST' and path in SELF_POST:
        return True
    if method == 'GET' and path in READ:
        return role != 'viewer' or not external_read(path, qs)
    if re.fullmatch(r'/ip-relationship-jobs/[a-f0-9]{32}', path) and method == 'GET':
        return role in ('admin', 'operator')
    if re.fullmatch(r'/ip-relationship-jobs/[a-f0-9]{32}/cancel', path) and method == 'POST':
        return role in ('admin', 'operator')
    if method == 'POST' and path == '/config':
        return role == 'admin' or (role == 'operator' and isinstance(body, dict)
                                  and set(body) <= {'domains', 'revision'} and 'domains' in body)
    if method == 'POST' and path in OPERATE or method == 'GET' and path == '/misp/search':
        return role in ('admin', 'operator')
    if role != 'admin':
        return False
    if path in ('/settings', '/settings.html', '/accounts.html') and method == 'GET':
        return True
    if path == '/settings' and method == 'POST':
        return True
    if path == '/decoders/custom' and method in ('POST', 'PUT', 'DELETE'):
        return True
    if path == '/decoders/custom/preview' and method == 'POST':
        return True
    if path in ('/admin/users', '/admin/audit') and method == 'GET':
        return True
    if path in ('/admin/users', '/admin/audit/export') and method == 'POST':
        return True
    return method == 'POST' and bool(re.fullmatch(r'/admin/users/[a-zA-Z0-9-]+/(update|reset|revoke)', path))
