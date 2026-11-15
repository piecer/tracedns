"""Documented local-AI wire grammar; task validators also enforce byte budgets."""
from local_ai.contracts import ERROR_STATUS


def closed(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


KINDS = ['decoder_suggest', 'relationship_pair', 'delivery']
STATES = ['queued', 'running', 'cancel_pending', 'completed', 'failed', 'cancelled']
JOB_ID = {'type': 'string', 'pattern': '^[a-f0-9]{32}$', 'minLength': 32, 'maxLength': 32}
LANGUAGE = {'type': 'string', 'enum': ['ko', 'en']}
IP = {'type': 'string', 'format': 'ipv4', 'minLength': 7, 'maxLength': 15,
      'description': 'Canonical dotted-decimal IPv4 only; never normalized or contacted.'}
SAMPLE = closed({'data': {'type': 'string', 'maxLength': 2048, 'description': 'Raw string; also <=2048 UTF-8 bytes. No trimming.'},
                 'expected_ips': {'type': 'array', 'minItems': 1, 'maxItems': 8, 'uniqueItems': True, 'items': IP},
                 'usage': {'type': 'string', 'enum': ['example', 'validation']},
                 'complete_expected': {'type': 'boolean'}})
REQUEST_SCHEMA = {'oneOf': [
    closed({'kind': {'const': 'delivery'}, 'language': LANGUAGE}),
    closed({'kind': {'const': 'relationship_pair'}, 'language': LANGUAGE,
            'source': closed({'job_id': JOB_ID, 'a': IP, 'b': IP})}),
    closed({'kind': {'const': 'decoder_suggest'}, 'language': LANGUAGE,
            'decoder_type': {'type': 'string', 'enum': ['TXT', 'A']}, 'generate': {'type': 'boolean'},
            'samples': {'type': 'array', 'minItems': 1, 'maxItems': 6, 'items': SAMPLE,
                        'contains': {'type': 'object', 'properties': {'usage': {'const': 'example'}}, 'required': ['usage']},
                        'description': 'At least one example; duplicate raw data across all rows refused. Validation data/answers/feedback never sent to the model. Examples must also fit the8KiB projection cap.'}}),
]}
EMPTY_SCHEMA = closed({})
ACTIVE_JOB = closed({'job_id': JOB_ID, 'kind': {'enum': KINDS}, 'status': {'enum': STATES}})
ACTIVE_JOB['description'] = 'Owned unfinished lifecycle; terminal execution may still await audit. Read the job and require audit_status=success before using a result.'
STATUS_SCHEMA = closed({'enabled': {'type': 'boolean'}, 'accepting': {'type': 'boolean'},
                        'provider_state': {'enum': ['ready', 'busy', 'unsettled', 'unavailable', 'disabled', 'stopped']},
                        'queued': {'type': 'integer', 'minimum': 0, 'maximum': 2},
                        'active_job': {'anyOf': [{'type': 'null'}, ACTIVE_JOB]}})
JOB_FIELDS = {
    'job_id': JOB_ID, 'kind': {'enum': KINDS}, 'language': LANGUAGE,
    'status': {'enum': STATES},
    'created_at': {'type': 'integer', 'minimum': 0},
    'deadline_at': {'type': 'integer', 'minimum': 0},
    'audit_status': {'enum': ['pending', 'success', 'failed']},
    'error': {'anyOf': [{'type': 'null'}, {'type': 'string', 'enum': list(ERROR_STATUS)}]},
    'result': {'anyOf': [{'type': 'null'}, {'type': 'object'}],
               'description': 'Engine-validated bounded result: snapshot, snapshot_digest, source_revision, model; explanation adds interpretation; decoder adds catalog/generated/proposal. No result before successful terminal audit. Citation syntax is not semantic proof.'},
    'cancel_requested': {'type': 'boolean'},
}
JOB_SCHEMA = closed(JOB_FIELDS)
CANCEL_SCHEMA = closed({**JOB_FIELDS, 'cancellation_requested': {'type': 'boolean'},
                        'cancellation_confirmed': {'type': 'boolean'}})
ERROR_SCHEMA = closed({'error': {'type': 'string', 'enum': list(ERROR_STATUS)},
                       'code': {'type': 'string', 'enum': list(ERROR_STATUS)},
                       'request_id': {'type': 'string'}})
