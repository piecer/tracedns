"""Bounded authority reads and private leases; never enrichment or config writes."""
from contextlib import contextmanager
from dataclasses import dataclass
import math
import threading
import time

from http_api.read_model import BackgroundReadModel
from local_ai.contracts import AIError
from monitor.config_service import ConfigService
from monitor.projection_authority import security_projection_revision

_LOCK_TYPES = (type(threading.Lock()), type(threading.RLock()))
MAX_LOCK_WAIT = 0.02


def check_deadline(deadline):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise AIError('invalid_request')
    if time.monotonic() >= deadline:
        raise AIError('deadline_exceeded')


@contextmanager
def bounded_lock(lock, deadline):
    check_deadline(deadline)
    if type(lock) not in _LOCK_TYPES:
        raise AIError('source_unavailable')
    if not lock.acquire(timeout=min(MAX_LOCK_WAIT, max(0, deadline - time.monotonic()))):
        check_deadline(deadline)
        raise AIError('source_unavailable')
    try:
        check_deadline(deadline)
        yield
        check_deadline(deadline)
    finally:
        lock.release()


def principal_identity(principal, *, decoder=False):
    if type(principal) is not dict or principal.get('role') not in (('admin',) if decoder else ('admin', 'operator')):
        raise AIError('source_revoked')
    values = tuple(principal.get(key) for key in ('id', 'session_id'))
    if any(type(value) is not str or not 1 <= len(value) <= 128 for value in values):
        raise AIError('source_revoked')
    return values


@dataclass(frozen=True)
class Authority:
    revision: int
    security_revision: int
    model_id: str
    hard_epoch: int


def capture_authority(ctx, deadline):
    check_deadline(deadline)
    try:
        config, lock, model = ctx.shared_config, ctx.config_lock, ctx.read_model
        if type(config) is not dict or type(model) is not BackgroundReadModel:
            raise AIError('source_unavailable')
        with bounded_lock(lock, deadline):
            revision = config.get('_config_revision', config.get('config_revision', 0))
            if type(revision) is not int or not 0 <= revision <= 9007199254740991:
                raise AIError('source_unavailable')
            service = config.get('_config_service')
            if service is not None and (type(service) is not ConfigService or service.read_model is not model):
                raise AIError('source_unavailable')
            security_revision = security_projection_revision(config)
            model_id, epoch = model.publication_authority(timeout=min(MAX_LOCK_WAIT, max(0, deadline - time.monotonic())))
            if type(epoch) is not int or not 0 <= epoch <= 9007199254740991:
                raise AIError('source_unavailable')
        return Authority(revision, security_revision, model_id, epoch)
    except AIError:
        raise
    except Exception:
        check_deadline(deadline)
        raise AIError('source_unavailable') from None


@dataclass(frozen=True)
class RelationshipStamp:
    authority: Authority
    user_id: str
    session_id: str
    has_misp_context: bool


def capture_relationship_stamp(ctx, principal, data):
    """Call before the ORIGINAL job's context preparation, never on AI lookup."""
    user_id, session_id = principal_identity(principal)
    if type(data) is not dict:
        raise AIError('invalid_request')
    return RelationshipStamp(capture_authority(ctx, time.monotonic() + 0.1), user_id, session_id,
                             data.get('misp_event_id') not in (None, ''))


def validate_relationship_stamp(ctx, stamp):
    """Original admission fence; missing stamps can never be backfilled."""
    if type(stamp) is not RelationshipStamp:
        raise AIError('source_unavailable')
    if capture_authority(ctx, time.monotonic() + 0.1) != stamp.authority:
        raise AIError('source_revoked')


def secret_free(ctx, payload, deadline, *, max_bytes=8192):
    from local_ai.decoder import DecoderError, _bounded_json
    from local_ai.privacy import PrivacyError, require_secret_free
    check_deadline(deadline)
    try:
        # Separate product byte refusal from secret-plan unavailability. This
        # meter bounds scalars/shape before encoding; no digest is taken here.
        _bounded_json(payload, max_bytes)
    except DecoderError as exc:
        raise AIError(exc.code) from None
    try:
        encoded = require_secret_free(payload, ctx.shared_config, ctx.config_lock, ctx.read_model,
                                      deadline, max_bytes=max_bytes)
    except PrivacyError as exc:
        check_deadline(deadline)
        raise AIError('sensitive_input' if exc.code == 'sensitive_input' else 'privacy_unavailable') from None
    check_deadline(deadline)
    return encoded


class SourceLease:
    """Retain scalar provenance only, not raw job/results/config snapshots.

    Context/service references point to the existing server owners. A dispose
    fence is independent of their locks and invalidates every late continuation.
    """

    def __init__(self, ctx, authority, *, jobs=None, selector=None, identity=None, digest=None, producers=None):
        self._lock = threading.Lock()
        self._ctx, self._authority = ctx, authority
        self._jobs, self._selector = jobs, selector
        self._identity, self._digest = identity, digest
        self._producers = producers
        self._disposed = False

    def check(self, deadline):
        import hashlib
        from http_api.relationship_handlers import _read_ai_pair
        with self._lock:
            if self._disposed:
                raise AIError('source_revoked')
            ctx, authority, producers = self._ctx, self._authority, self._producers
            jobs, selector, identity, digest = self._jobs, self._selector, self._identity, self._digest
        if capture_authority(ctx, deadline) != authority:
            raise AIError('source_revoked')
        if identity is not None:
            stamp = identity[2]
            _, _, _, projected = _read_ai_pair(jobs, selector, stamp.user_id, stamp.session_id,
                                               deadline, retained=identity)
            safe = secret_free(ctx, projected, deadline)
            if hashlib.sha256(safe).hexdigest() != digest:
                raise AIError('source_revoked')
            # Re-read only this index after the slower privacy work. Compare
            # bounded bytes, never hash an unchecked replacement projection.
            import json
            _, _, _, current = _read_ai_pair(jobs, selector, stamp.user_id, stamp.session_id,
                                             deadline, retained=identity)
            if json.dumps(current, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                          allow_nan=False).encode('utf-8') != safe:
                raise AIError('source_revoked')
        # Privacy work can span an authority transition; fence its continuation.
        if capture_authority(ctx, deadline) != authority:
            raise AIError('source_revoked')
        if producers is not None and any(getattr(ctx, key, None) is not value for key, value in producers.items()):
            raise AIError('source_revoked')
        check_deadline(deadline)
        with self._lock:
            if self._disposed:
                raise AIError('source_revoked')

    def private_metadata(self):
        from dataclasses import asdict
        with self._lock:
            if self._disposed:
                raise AIError('source_revoked')
            result = {'authority': asdict(self._authority)}
            if self._producers is not None:
                result['producers'] = {key: id(value) for key, value in self._producers.items()}
            if self._identity is not None:
                index, identity, stamp = self._identity
                result.update(selector=self._selector, index=index, identity=identity,
                              stamp=asdict(stamp), digest=self._digest)
            return result

    def dispose(self):
        with self._lock:
            self._disposed = True
            self._ctx = self._authority = self._jobs = self._selector = self._identity = self._digest = None
            self._producers = None


def capture_decoder(ctx, request, deadline):
    from local_ai.decoder import DecoderError, capture_catalog
    authority = capture_authority(ctx, deadline)
    try:
        with bounded_lock(ctx.config_lock, deadline):
            catalog = capture_catalog(ctx.shared_config, request['decoder_type'])
    except DecoderError as exc:
        raise AIError(exc.code) from None
    # All retained inputs are checked, but holdouts never enter the snapshot.
    secret_free(ctx, {'samples': request['samples']}, deadline, max_bytes=16384)
    secret_free(ctx, catalog, deadline, max_bytes=32768)
    snapshot = {'version': 1, 'kind': 'decoder_suggest', 'decoder_type': request['decoder_type'],
                'examples': [row for row in request['samples'] if row['usage'] == 'example']}
    encoded = secret_free(ctx, snapshot, deadline)
    lease = SourceLease(ctx, authority)
    try:
        lease.check(deadline)
        return lease, encoded, {'catalog': catalog, 'samples': request['samples'],
                               'generate': request['generate'], 'decoder_type': request['decoder_type']}
    except BaseException:
        lease.dispose()
        raise


def capture_delivery(ctx, deadline):
    from local_ai.evidence import project_delivery
    authority = capture_authority(ctx, deadline)
    try:
        producers = {'delivery_diagnostics': ctx.delivery_diagnostics, 'delivery_health': ctx.delivery_health}
        diagnostics = producers['delivery_diagnostics']()
        diagnostics_at = int(time.time() * 1000)
        check_deadline(deadline)
        progress = producers['delivery_health'](include_progress=True)
        progress_at = int(time.time() * 1000)
        check_deadline(deadline)
        projection = project_delivery(diagnostics, progress, diagnostics_captured_at=diagnostics_at,
                                      progress_captured_at=progress_at)
    except AIError:
        raise
    except Exception:
        check_deadline(deadline)
        raise AIError('source_unavailable') from None
    encoded = secret_free(ctx, projection, deadline)
    lease = SourceLease(ctx, authority, producers=producers)
    try:
        lease.check(deadline)
        return lease, encoded
    except BaseException:
        lease.dispose()
        raise


def capture_pair(ctx, jobs, selector, actor, deadline):
    import hashlib
    from http_api.relationship_handlers import _read_ai_pair
    user_id, session_id = principal_identity(actor)
    authority = capture_authority(ctx, deadline)
    index, identity, stamp, projected = _read_ai_pair(jobs, selector, user_id, session_id, deadline)
    if authority != stamp.authority:
        raise AIError('source_revoked')
    encoded = secret_free(ctx, projected, deadline)
    digest = hashlib.sha256(encoded).hexdigest()
    lease = SourceLease(ctx, authority, jobs=jobs, selector=dict(selector),
                        identity=(index, identity, stamp), digest=digest)
    try:
        lease.check(deadline)
        return lease, encoded
    except BaseException:
        lease.dispose()
        raise
