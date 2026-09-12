"""Authenticated account and audit routes; no legacy shared identity state."""
import json
import math

from http_api.utils import send_json
from security.store import SecurityError


def filters(data):
    """Allow only bounded filters, never arbitrary SQL/order clauses."""
    out = {k: data[k] for k in ('user_id', 'action', 'outcome', 'target') if data.get(k) not in ('', None)}
    for key, default in (('limit', 50), ('offset', 0)):
        try:
            out[key] = int(data.get(key, default))
        except (TypeError, ValueError):
            raise SecurityError('Invalid pagination') from None
    if not 1 <= out['limit'] <= 1000 or not 0 <= out['offset'] <= 10000000:
        raise SecurityError('Invalid pagination')
    for key in ('since', 'until'):
        if data.get(key) not in ('', None):
            try:
                out[key] = float(data[key])
                if not math.isfinite(out[key]):
                    raise ValueError()
            except (TypeError, ValueError):
                raise SecurityError('Invalid timestamp') from None
    if out.get('since', 0) > out.get('until', float('inf')):
        raise SecurityError('Invalid time range')
    return out


def audit_page(store, opts):
    result = store.audit_list(**opts)
    for event in result['events']:
        event.update(ts=event.get('timestamp'), actor_id=event.get('actor_user_id'),
                     actor_name=event.get('actor_username', event.get('actor_name')))
    result.update(limit=opts['limit'], offset=opts['offset'])
    return result


def handle_security_route(service, handler, path, data, qs):
    store, user = service.store, handler.principal
    metadata = {'actor': user, 'request_id': handler.request_id, 'source_ip': handler.source_ip}
    method = handler.command
    if path == '/auth/me':
        return send_json(handler, {'user': user, 'csrf_token': service.csrf(handler.session_token),
                                   'audit_available': not service.audit_error})
    if path == '/auth/logout':
        store.logout(handler.session_token, handler.request_id, handler.source_ip)
        service.cookie(handler, 'td_session', '', delete=True)
        return send_json(handler, {'status': 'ok'})
    if path == '/auth/password':
        store.change_password(user['id'], data.get('current_password'), data.get('new_password'), **metadata)
        service.cookie(handler, 'td_session', '', delete=True)
        return send_json(handler, {'status': 'ok'})
    if path == '/auth/sessions':
        rows = store.sessions(user['id'])
        for row in rows:
            row['created_at'] = row.get('created')
            row['current'] = row['id'] == user.get('session_id')
        return send_json(handler, {'sessions': rows})
    if path == '/auth/sessions/revoke':
        store.revoke_sessions(user['id'], session_id=data.get('session_id'), **metadata)
        return send_json(handler, {'status': 'ok'})
    if path == '/admin/users':
        if method == 'GET':
            return send_json(handler, {'users': store.list_users()})
        created = store.create_user(data.get('username'), data.get('password'), data.get('role', 'viewer'), **metadata)
        return send_json(handler, {'user': created}, 201)
    if path.startswith('/admin/users/'):
        user_id, action = path.split('/')[3:5]
        if action == 'revoke':
            store.revoke_sessions(user_id, **metadata)
            return send_json(handler, {'status': 'ok'})
        if action == 'reset':
            if not data.get('password'):
                raise SecurityError('Password required')
            updated = store.update_user(user_id, password=data['password'], **metadata)
        else:
            if not data or not set(data) <= {'role', 'active'}:
                raise SecurityError('Only role and active may be updated')
            updated = store.update_user(user_id, **data, **metadata)
        return send_json(handler, {'user': updated})
    if path in ('/admin/audit', '/auth/activity', '/admin/audit/export'):
        raw = data if method == 'POST' else {k: v[0] for k, v in qs.items()}
        opts = filters(raw)
        if path == '/auth/activity':
            opts['user_id'] = user['id']
        if path.endswith('/export'):
            # Export one explicit bounded page, with a total header for continuation.
            service.event(handler, 'audit.export', 'started', target='audit')
            result = audit_page(store, opts)
            body = ''.join(json.dumps(e, ensure_ascii=False) + '\n' for e in result['events']).encode()
            service.event(handler, 'audit.export', 'success', target='audit',
                          details={'count': len(result['events'])})
            handler.send_response(200)
            handler.send_header('Content-Type', 'application/x-ndjson; charset=utf-8')
            handler.send_header('Content-Disposition', 'attachment; filename="tracedns-audit.jsonl"')
            handler.send_header('Content-Length', str(len(body)))
            handler.send_header('X-Total-Count', str(result['total']))
            handler.send_header('X-Next-Offset', str(opts['offset'] + len(result['events'])))
            handler.end_headers()
            return handler.wfile.write(body)
        return send_json(handler, audit_page(store, opts))
    raise SecurityError('Unknown route', 404)