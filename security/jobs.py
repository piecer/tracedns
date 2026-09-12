"""Identity propagation for in-process forced DNS work."""
import logging
import uuid
from functools import wraps

from http_api.utils import send_json


def prepare_force(handler, job, queue):
    actor = getattr(handler, 'principal', None)
    store = getattr(handler, 'security_store', None)
    if actor is None:
        return True  # Pure monitor/unit call; not exposed without the HTTP guard.
    if sum((q.get('actor') or {}).get('id') == actor['id'] for q in queue) >= 4:
        send_json(handler, {'error': 'User resolve queue is full'}, 429)
        return False
    job.update(actor=dict(actor), job_id=uuid.uuid4().hex, _security_store=store,
               request_id=handler.request_id, source_ip=handler.source_ip)
    audit_force(job, 'started')
    return True


def audit_force(job, outcome):
    store = job.get('_security_store')
    if store is not None:
        store.audit(job.get('actor'), 'force.resolve', target=job['job_id'], outcome=outcome,
                    request_id=job['request_id'], source_ip=job['source_ip'], job_id=job['job_id'])


def audited_force(function):
    @wraps(function)
    def run(**kwargs):
        job = kwargs.get('force_req') or {}
        outcome = 'completed'
        try:
            return function(**kwargs)
        except Exception:
            outcome = 'failure'
            raise
        finally:
            if job.get('actor'):
                try:
                    audit_force(job, outcome)
                except Exception:
                    logging.getLogger(__name__).error('Forced resolve audit completion failed')
    return run
