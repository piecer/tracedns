"""OpenAPI contract generated from the actual versioned mount registry.

Flexible legacy observation/analysis payloads deliberately allow extra fields.
This is documentation, not a second validation or authorization implementation.
"""
import copy

from http_api.rest import PATTERNS, PREFIX, ROUTES

STRING = {'type': 'string'}
INTEGER = {'type': 'integer'}
BOOLEAN = {'type': 'boolean'}
OBJECT = {'type': 'object', 'additionalProperties': True}
STRINGS = {'type': 'array', 'items': STRING}
REVISION = {'type': 'integer', 'minimum': 0, 'description': 'Latest GET /config or /settings revision; stale/missing => 409.'}
DOMAIN = {
    'type': 'object', 'required': ['name'], 'additionalProperties': True,
    'properties': {
        'name': STRING, 'type': {'type': 'string', 'description': 'DNS record type (A, AAAA, TXT, MX, CNAME, NS, SOA, SRV, CAA, etc.), ENS or SNS.'},
        **{name: STRING for name in ('txt_decode', 'a_decode', 'a_xor_key', 'ens_text_key', 'ens_decode',
                                    'ens_node', 'ens_resolver', 'ens_xor_byte', 'sns_decode')},
        'ens_options': OBJECT, 'sns_options': OBJECT,
    },
}
DOMAINS = {'type': 'array', 'items': {'oneOf': [STRING, DOMAIN]},
           'description': 'Complete desired list, not an append. Keep all existing target identities/options. Removal purges history.'}
IP_INPUT = {'oneOf': [STRING, STRINGS], 'description': 'IP list or comma/whitespace-separated text.'}


def obj(properties, required=()):
    result = {'type': 'object', 'properties': properties, 'additionalProperties': True}
    if required:
        result['required'] = list(required)
    return result


AUDIT_FILTERS = {
    **{key: STRING for key in ('user_id', 'action', 'outcome', 'target')},
    'since': {'type': 'number', 'description': 'UTC epoch seconds'},
    'until': {'type': 'number', 'description': 'UTC epoch seconds'},
    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 1000, 'default': 50},
    'offset': {'type': 'integer', 'minimum': 0, 'maximum': 10000000, 'default': 0},
}
RELATIONSHIP = obj({
    'ips': IP_INPUT, 'include_vt': {'type': 'boolean', 'default': True},
    'lookback_days': {'type': 'integer', 'minimum': 0, 'maximum': 365, 'default': 30},

    'vt_budget': {'type': 'integer', 'minimum': 0, 'maximum': 5000, 'default': 2000},
    'vt_workers': {'type': 'integer', 'minimum': 1, 'maximum': 32, 'default': 8},
    'top_pairs': {'type': 'integer', 'minimum': 1, 'maximum': 5000, 'default': 200},
    'min_score': {'type': 'integer', 'minimum': 0, 'maximum': 100, 'default': 40},
    'max_neighbors_per_ip': INTEGER, 'candidate_limit': INTEGER,
    'candidate_work_limit': INTEGER, 'bucket_max': INTEGER,
    'pair_gate_enabled': BOOLEAN, 'pair_gate_strong_min': INTEGER,
    'pair_gate_mid_min': INTEGER, 'pair_gate_fallback_score': INTEGER,
    'bucket_overflow_mode': {'enum': ['truncate', 'skip'], 'default': 'truncate'},
}, ('ips',))
CONFIG = obj({
    'revision': REVISION, 'domains': DOMAINS, 'servers': {'type': 'array', 'items': STRING, 'maxItems': 64},
    'interval': {'type': 'integer', 'minimum': 1, 'maximum': 86400},
    'max_workers': {'type': 'integer', 'minimum': 1, 'maximum': 64},
    'ens_rpc_url': {'type': 'string', 'writeOnly': True}, 'DEFAULT_SNS_PROXY_HOSTS': STRINGS,
    'clear_fields': {'type': 'array', 'items': {'enum': ['ens_rpc_url', 'DEFAULT_SNS_PROXY_HOSTS']}},
    'custom_decoders': {'type': 'array', 'items': OBJECT},
    'custom_a_decoders': {'type': 'array', 'items': OBJECT},
}, ('revision',))
DECODER = obj({'name': STRING, 'decoder_type': {'enum': ['TXT', 'A'], 'default': 'TXT'},
               'steps': {'type': 'array', 'items': OBJECT}}, ('name', 'steps'))
BODIES = {
    '/auth/login': obj({'username': STRING, 'password': {'type': 'string', 'writeOnly': True}}, ('username', 'password')),
    '/auth/logout': obj({}),
    '/auth/password': obj({key: {'type': 'string', 'writeOnly': True} for key in ('current_password', 'new_password')},
                          ('current_password', 'new_password')),
    '/auth/sessions/revoke': obj({'session_id': STRING}),
    '/config': CONFIG,
    '/settings': obj({'revision': REVISION, 'alerts': OBJECT, 'clear_fields': STRINGS}, ('revision', 'alerts')),
    '/resolve': obj({'domains': {**DOMAINS, 'maxItems': 64}, 'domain': STRING,
                     'servers': {'type': 'array', 'items': STRING, 'minItems': 1, 'maxItems': 64}}),
    '/ip': obj({'ip': STRING}, ('ip',)),
    '/analyze': obj({'domain': STRING, 'txt': STRING, 'sample': STRING}, ('domain',)),
    '/domain-precheck': obj({**{k: v for k, v in DOMAIN['properties'].items() if k != 'name'}, 'domain': STRING,
                             'type': {'enum': ['AUTO', 'A', 'TXT', 'ENS', 'SNS'], 'default': 'AUTO'},
                             'servers': {'oneOf': [STRING, STRINGS]},
                             'ens_rpc_url': {'type': 'string', 'writeOnly': True},
                             'include_vt': {'type': 'boolean', 'default': True}, 'analyze_decoders': BOOLEAN,
                             'decoder_top_n': INTEGER, 'vt_lookup_budget': INTEGER, 'vt_workers': INTEGER}, ('domain',)),
    '/ip-list-analysis': obj({'ips': IP_INPUT, 'attributes': {'type': 'array', 'items': OBJECT},
                              'include_vt': {'type': 'boolean', 'default': True},
                              'row_limit': INTEGER, 'vt_lookup_budget': INTEGER, 'vt_workers': INTEGER}),
    '/ip-relationship-analysis': RELATIONSHIP,
    '/ip-relationship-jobs': obj({**RELATIONSHIP['properties'], 'misp_event_id': {'oneOf': [STRING, INTEGER]}}, ('ips',)),
    '/ip-relationship-jobs/{job_id}/cancel': obj({}),
    '/decoders/custom': DECODER,
    '/decoders/custom/preview': obj({'steps': {'type': 'array', 'items': OBJECT}, 'sample': STRING,
                                    'decoder_type': {'enum': ['TXT', 'A'], 'default': 'TXT'}}, ('steps',)),
    '/misp/search': obj({'value': STRING}, ('value',)),
    '/misp/event-ips': obj({'event_id': {'oneOf': [INTEGER, STRING], 'description': 'Omitted: configured alerts.push_event_id.'}}),
    '/admin/users': obj({'username': STRING, 'password': {'type': 'string', 'writeOnly': True},
                         'role': {'enum': ['admin', 'operator', 'viewer'], 'default': 'viewer'}}, ('username', 'password')),
    '/admin/users/{user_id}/update': obj({'role': {'enum': ['admin', 'operator', 'viewer']}, 'active': BOOLEAN}),
    '/admin/users/{user_id}/reset': obj({'password': {'type': 'string', 'writeOnly': True}}, ('password',)),
    '/admin/users/{user_id}/revoke': obj({}),
    '/admin/audit/export': obj(AUDIT_FILTERS),
}
BODIES['/resolve']['anyOf'] = [{'required': ['domains']}, {'required': ['domain']}]
BODIES['/analyze']['anyOf'] = [{'required': ['txt']}, {'required': ['sample']}]
QUERIES = {
    '/results': {'aggregate': {'type': 'boolean', 'default': False}, 'include_raw': BOOLEAN},
    '/history': {'domain': STRING}, '/ip': {'ip': STRING},
    '/ips': {'since': {'type': 'integer', 'description': 'Relative age in seconds, NOT an epoch timestamp.'},
             'offset': {'type': 'integer', 'minimum': 0, 'maximum': 10000000, 'default': 0},
             'limit': {'type': 'integer', 'minimum': 1, 'maximum': 5000, 'default': 500},
             'include_vt': {'enum': ['0', '1'], 'default': '0'},
             'vt_budget': INTEGER, 'vt_workers': INTEGER,
             'vt_mode': {'enum': ['sync', 'background'], 'default': 'sync',
                         'description': 'background returns published reports and bounded enrichment admission status without waiting for VT.'}},
    '/domain-analysis': {'include_vt': {'enum': ['0', '1'], 'default': '1'},
                         'vt_mode': {'enum': ['sync', 'background'], 'default': 'sync'},
                         'vt_budget': {'type': 'integer', 'minimum': 0, 'maximum': 5000, 'default': 200}},
    '/ip-relationship-jobs/{job_id}': {'result': {'enum': ['0', '1'], 'default': '0'}},
    '/misp/search': {'value': STRING},
    '/auth/activity': AUDIT_FILTERS, '/admin/audit': AUDIT_FILTERS,
}
PREPARED_PATHS = ('/results', '/ips', '/domain-analysis')
for _path in PREPARED_PATHS:
    QUERIES[_path].update({
        'read_mode': {'enum': ['sync', 'background'], 'default': 'sync',
                      'description': 'background reads prepared snapshots; 202 is not empty success. See docs/API.md.'},
        'if_version': {'type': 'string', 'description': 'Opaque view_version for this exact query; unchanged responses omit row data.'},
        'q': {'type': 'string', 'maxLength': 253, 'description': 'Prepared results/domain name substring filter.'},
    })
    QUERIES[_path].setdefault('offset', {'type': 'integer', 'minimum': 0, 'maximum': 10000000, 'default': 0})
    QUERIES[_path].setdefault('limit', {'type': 'integer', 'minimum': 1, 'maximum': 200, 'default': 100})
QUERIES['/ips']['valid_only'] = {'type': 'boolean', 'default': False, 'description': 'Filter before prepared pagination.'}
QUERIES['/ips']['limit']['description'] = 'Legacy: max 5000/default 500. Prepared: max 200/default 100, further reduced by byte budget.'
DESCRIPTIONS = {
    '/': 'Discover the versioned API. No process start/stop or arbitrary shell execution API is provided.',
    '/openapi.json': 'Read this OpenAPI document. Requires an authenticated account.',
    '/config': 'Read or merge configuration. Writes require revision. domains replaces the entire list; removed targets/history are purged. Operator writes may contain ONLY domains and revision. PATCH and POST are equivalent (not JSON Patch).',
    '/settings': 'Admin-only alert/integration settings. GET returns settings.alerts and revision. Writes merge alerts. Secret values are blank on reads, configured flags indicate presence; blank writes preserve secrets, clear_fields explicitly removes them.',
    '/results': 'Read current results/results_agg/domain_meta. aggregate=1 omits raw results unless include_raw=1. Observed values are not a maliciousness verdict.',
    '/domains': 'Read domains with resolving/last_ts/samples and NXDOMAIN state. resolving is a historical observation hint, not a current health guarantee.',
    '/history': 'Read history for an exact storage-name domain. Preserve bracketed ENS/SNS identities; URL-encode query values.',
    '/ips': 'Read paginated stored IP rows (ips,ips_total_count,ips_displayed_count,ips_offset,ips_limit,ips_truncated). include_vt=1 performs external enrichment, needs operator/admin and CSRF.',
    '/ip': 'GET: read IP-related history/current observations. POST: search only current observations (matches).',
    '/domain-analysis': 'Read grouped domain analysis. DEFAULT include_vt=1 causes external lookups. Use include_vt=0 for stored-only viewer-safe reads.',
    '/resolve': 'Queue force-resolve for configured targets/servers only. Supply domains OR domain (A shorthand). 200 requested=true means accepted, NOT completed. Correlate job_id with /auth/activity action=force.resolve and target=job_id (outcome=completed or failure), then read /results and /history. May trigger configured alerts/MISP writes.',
    '/analyze': 'Analyze supplied TXT locally with built-in decoders. Requires domain and txt (or sample); no DNS lookup.',
    '/domain-precheck': 'Run DNS/ENS/SNS queries and optionally VT before registration; does not add a monitoring target. DEFAULT include_vt=true. Prefer explicit false unless external sharing is authorized. AUTO queries TXT+A. Inspect by_server errors/can_add; HTTP 200 is not successful DNS. vt_lookup_budget only bounds decoder-candidate sweep, not initial selected-IP enrichment.',
    '/ip-list-analysis': 'Analyze IP inputs or MISP-style attributes. DEFAULT include_vt=true. Returns rows and counts; enrichment may be partial.',
    '/ip-relationship-analysis': 'Synchronous relationship analysis; prefer async jobs. IP input limits: 20000 tokens, 10000 unique valid IPs. Set include_vt=false for no VT lookup.',
    '/ip-relationship-jobs': 'Create asynchronous relationship analysis. 202 is acceptance, not completion. Poll job_id. misp_event_id fetches external MISP context even if include_vt=false.',
    '/ip-relationship-jobs/{job_id}': 'Poll own job (admin may inspect any). result=1 includes result when completed. States: queued,running,completed,failed,cancelled. Jobs/results are in-memory and can expire/be evicted or disappear on restart; 404 is not success.',
    '/ip-relationship-jobs/{job_id}/cancel': 'Request cancellation of own job. Running work may not stop immediately; read back status. Do not infer cancellation from HTTP success alone.',
    '/decoders': 'Read built-in decoder names and registered custom definitions.',
    '/decoders/custom': 'GET returns allowed_ops/decoder_types, not registered definitions (use /decoders). Admin POST creates, PUT upserts, DELETE removes by name/decoder_type. These legacy writes do not use config revision and persistence failures may not be surfaced. PUT can unregister the old runtime decoder before replacement fails. Read back /decoders; do not claim durable persistence without separate restart verification.',
    '/decoders/custom/preview': 'Admin-only local preview of constrained decoder DSL, not arbitrary Python. Inspect decoded_count and error as well as HTTP status.',
    '/misp/search': 'External MISP lookup by value; requires operator/admin and CSRF even on GET.',
    '/misp/event-ips': 'Fetch IPs and context for a MISP event ID. External read; no implicit event write.',
    '/auth/csrf': 'Unauthenticated: creates td_pre cookie and CSRF for login. Authenticated: returns session CSRF. Keep cookies; tokens are not API keys.',
    '/auth/login': 'First GET /auth/csrf, retain td_pre cookie, then send Origin and X-CSRF-Token. Returns user,csrf_token and sets td_session cookie. No Bearer/API-key authentication.',
    '/auth/me': 'Read user, csrf_token and audit_available. must_change_password restricts work until password change and re-login.',
    '/auth/logout': 'Revoke current session and expire its cookie.',
    '/auth/password': 'Change own password; revokes all sessions. Re-login before further operations.',
    '/auth/activity': 'Read own audit events,total,limit,offset. Any supplied user_id is overridden with authenticated identity.',
    '/auth/sessions': 'List own session metadata, never raw session tokens.',
    '/auth/sessions/revoke': 'Revoke one session_id, or ALL own sessions if omitted. Re-login when current session is revoked.',
    '/admin/users': 'Admin list/create accounts. Created accounts require password change before use.',
    '/admin/users/{user_id}/update': 'Admin change role/active; only these fields permitted. Protects last active administrator.',
    '/admin/users/{user_id}/reset': 'Admin reset password and revoke sessions; user must change password.',
    '/admin/users/{user_id}/revoke': 'Admin revoke all sessions belonging to user_id.',
    '/admin/audit': 'Admin read bounded audit pages. Timestamps and since/until are UTC epoch seconds.',
    '/admin/audit/export': 'Admin export ONE bounded JSONL page; X-Total-Count and X-Next-Offset allow continuation. Not a JSON object.',
}


USER = obj({'id': STRING, 'username': STRING, 'role': {'enum': ['admin', 'operator', 'viewer']},
            'active': BOOLEAN, 'must_change_password': BOOLEAN}, ('id', 'username', 'role'))
CONFIG_READ = obj({'revision': REVISION, 'domains': DOMAINS, 'domain_metadata': OBJECT,
                   'servers': STRINGS, 'interval': INTEGER, 'max_workers': INTEGER, 'configured': OBJECT},
                  ('revision', 'domains', 'servers'))
JOB = obj({'job_id': STRING, 'status': {'enum': ['queued', 'running', 'completed', 'failed', 'cancelled']},
           'created_at': {'type': 'number'}, 'done_at': {'type': ['number', 'null']},
           'status_code': {'type': ['integer', 'null']}, 'error': {'type': ['string', 'null']},
           'audit_status': STRING, 'result': {'type': ['object', 'null']}}, ('job_id', 'status'))
READ_RESPONSES = {
    '/auth/csrf': obj({'csrf_token': STRING}, ('csrf_token',)),
    '/auth/me': obj({'user': USER, 'csrf_token': STRING, 'audit_available': BOOLEAN}, ('user', 'csrf_token')),
    '/auth/sessions': obj({'sessions': {'type': 'array', 'items': OBJECT}}, ('sessions',)),
    '/config': CONFIG_READ,
    '/settings': obj({'settings': obj({'alerts': OBJECT}, ('alerts',)), 'revision': REVISION}, ('settings', 'revision')),
    '/results': obj({'results': OBJECT, 'results_agg': OBJECT, 'domain_meta': OBJECT}, ('results_agg', 'domain_meta')),
    '/domains': obj({'domains': {'type': 'array', 'items': OBJECT}}, ('domains',)),
    '/history': obj({'domain': STRING, 'history': OBJECT}, ('domain', 'history')),
    '/ips': obj({'ips': {'type': 'array', 'items': OBJECT},
                 **{key: INTEGER for key in ('ips_total_count', 'ips_displayed_count', 'ips_offset', 'ips_limit')},
                 'ips_truncated': BOOLEAN, 'include_vt': BOOLEAN},
                ('ips', 'ips_total_count', 'ips_displayed_count', 'ips_offset', 'ips_limit', 'ips_truncated')),
    '/ip': obj({'ip': STRING, 'matches': {'type': 'array', 'items': OBJECT}}, ('ip', 'matches')),
    '/ip-relationship-jobs/{job_id}': JOB,
    '/admin/users': obj({'users': {'type': 'array', 'items': USER}}, ('users',)),
    **{path: obj({'events': {'type': 'array', 'items': OBJECT}, 'total': INTEGER,
                  'limit': INTEGER, 'offset': INTEGER}, ('events', 'total', 'limit', 'offset'))
       for path in ('/auth/activity', '/admin/audit')},
}
WRITE_RESPONSES = {
    '/auth/login': obj({'user': USER, 'csrf_token': STRING}, ('user', 'csrf_token')),
    '/config': obj({'status': STRING, 'revision': REVISION, 'config': OBJECT}, ('status', 'revision', 'config')),
    '/settings': obj({'status': STRING, 'revision': REVISION, 'alerts': OBJECT}, ('status', 'revision', 'alerts')),
    '/resolve': obj({'status': STRING, 'requested': BOOLEAN, 'job_id': STRING}, ('status', 'requested', 'job_id')),
    '/ip-relationship-jobs': obj({'status': {'const': 'queued'}, 'job_id': STRING}, ('status', 'job_id')),
    '/admin/users': obj({'user': USER}, ('user',)),
}


def roles(path, method):
    if path.startswith('/admin/') or path == '/settings' or (path.startswith('/decoders/custom') and method != 'GET'):
        return ['admin']
    if path.startswith('/auth/') or path in ('/', '/openapi.json'):
        return ['viewer', 'operator', 'admin']
    if method != 'GET' or path.startswith(('/ip-relationship-', '/misp/')):
        return ['operator', 'admin']
    return ['viewer', 'operator', 'admin']


def openapi_document():
    """Build a fresh document so per-response redaction cannot alter later calls."""
    paths = {}
    for path, methods in ROUTES.items():
        paths[path] = {}
        for method in methods:
            success = '202' if path == '/ip-relationship-jobs' else '201' if path == '/admin/users' and method == 'POST' else '200'
            operation = {
                'operationId': method.lower() + '_' + (path.strip('/').replace('/', '_').replace('-', '_').replace('.', '_').replace('{', '').replace('}', '') or 'discovery'),
                'summary': method + ' ' + path,
                'description': DESCRIPTIONS[path],
                'x-roles': roles(path, method),
                'responses': {success: {'description': 'Accepted' if success == '202' else 'Success',
                                         'content': {'application/json': {'schema': (READ_RESPONSES if method == 'GET' else WRITE_RESPONSES).get(path, OBJECT)}}},
                              **{str(code): {'description': text, 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}}}
                                 for code, text in ((400, 'Invalid request'), (401, 'Authentication required'),
                                                    (403, 'Role, CSRF, origin, host or password-change restriction'),
                                                    (404, 'Unknown route/resource or expired/inaccessible job'),
                                                    (405, 'Method not allowed'), (409, 'Revision conflict'),
                                                    (413, 'Body too large'), (429, 'Login or queue capacity limit'),
                                                    (500, 'Internal failure'), (503, 'Service/audit unavailable'))}},
            }
            # Framing/body limits precede JSON dispatch; worker saturation can be an empty 503.
            for status in ('400', '413'):
                operation['responses'][status]['content']['text/plain'] = {'schema': STRING}
            operation['responses']['503']['description'] += '; worker saturation may return an empty body'
            if path in PREPARED_PATHS and method == 'GET':
                operation['description'] += ' read_mode=background is bounded to 200 display units and 1 MiB; follow page.next_offset. Domain display units are IP-role rows (empty domain counts one).'
                original = operation['responses']['200']['content']['application/json']['schema']
                operation['responses']['200']['content']['application/json']['schema'] = {'anyOf': [
                    original, obj({'unchanged': {'const': True}, 'view_version': STRING,
                                   'snapshot': OBJECT, 'page': OBJECT, 'enrichment': OBJECT},
                                  ('unchanged', 'view_version', 'snapshot', 'page'))]}
                operation['responses']['202'] = {'description': 'Prepared snapshot not ready; retain prior UI data with a warning.',
                    'content': {'application/json': {'schema': obj({'snapshot': OBJECT}, ('snapshot',))}}}
                operation['responses']['422'] = {'description': 'A complete entry cannot fit the prepared response budget; use explicit legacy JSON download.',
                    'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}}}
            if path.endswith('/cancel'):
                operation['responses']['409']['description'] = 'Already running or already finished; cancelled=false'
                operation['responses']['409']['content']['application/json']['schema'] = OBJECT
            params = []
            for token, pattern in PATTERNS.items():
                if token in path:
                    params.append({'name': token[1:-1], 'in': 'path', 'required': True,
                                   'schema': {'type': 'string', 'pattern': '^' + pattern + '$'}})
            if method == 'GET':
                for key, schema in QUERIES.get(path, {}).items():
                    params.append({'name': key, 'in': 'query', 'required': path in ('/history', '/ip', '/misp/search'), 'schema': schema})
            else:
                params.append({'name': 'Origin', 'in': 'header', 'required': True, 'schema': STRING,
                               'description': 'Exact server public origin, scheme + authority; no path.'})
                body = BODIES[path]
                if path == '/decoders/custom' and method == 'DELETE':
                    body = obj({'name': STRING, 'decoder_type': {'enum': ['TXT', 'A'], 'default': 'TXT'}}, ('name',))
                operation['requestBody'] = {'required': True, 'content': {'application/json': {'schema': body}}}
                operation['security'] = [{'session': [], 'csrf': []}]
            if path == '/auth/csrf':
                operation['security'] = []
            elif path == '/auth/login':
                operation['security'] = [{'prelogin': [], 'csrf': []}]
            elif path == '/misp/search':
                operation['security'] = [{'session': [], 'csrf': []}]
            if path in ('/ips', '/domain-analysis'):
                operation['description'] += ' CSRF is required when include_vt is enabled; this conditional is described here rather than as unconditional OpenAPI security.'
            if path == '/admin/audit/export':
                operation['responses']['200'] = {
                    'description': 'One JSONL page',
                    'headers': {name: {'schema': INTEGER} for name in ('X-Total-Count', 'X-Next-Offset')},
                    'content': {'application/x-ndjson': {'schema': STRING}},
                }
            if params:
                operation['parameters'] = params
            paths[path][method.lower()] = operation
    return copy.deepcopy({
        'openapi': '3.1.0',
        'info': {'title': 'TraceDNS REST API', 'version': '1.0.0',
                 'description': 'Versioned facade over existing UI services. HTTPS required remotely. Cookie/CSRF authentication and existing RBAC/audit are shared. No CORS, Bearer tokens or process-control endpoint. See docs/API.md and SKILL.md.'},
        'servers': [{'url': PREFIX}], 'security': [{'session': []}], 'paths': paths,
        'components': {
            'securitySchemes': {
                'session': {'type': 'apiKey', 'in': 'cookie', 'name': 'td_session'},
                'prelogin': {'type': 'apiKey', 'in': 'cookie', 'name': 'td_pre'},
                'csrf': {'type': 'apiKey', 'in': 'header', 'name': 'X-CSRF-Token'},
            },
            'schemas': {'Domain': DOMAIN, 'Error': obj({'error': STRING, 'request_id': STRING, 'revision': INTEGER}, ('error',))},
        },
    })


if __name__ == '__main__':
    import json
    print(json.dumps(openapi_document(), ensure_ascii=False, indent=2, sort_keys=True))
