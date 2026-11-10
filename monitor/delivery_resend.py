"""Explicit saved-source resend; independent of automatic observation state."""
from dataclasses import dataclass, field
import ipaddress
import json
import math
import sqlite3
import time
import uuid
import weakref

from config_manager import domain_identity
from .delivery_store import _TransactionResolution
from .delivery_types import encode, size, encode_body, TeamsPayloadTooLarge, valid_binding
from .repository import TargetLease
from .runtime_state import state_lock
from .state_utils import collect_domain_managed_ips
from .targets import providers_for


class _Refusal(ValueError):
    pass


def bounded_source(value, limit):
    """Bound traversal before cloning/encoding saved (including legacy) data."""
    remaining = limit
    def visit(item, depth):
        nonlocal remaining
        remaining -= 8
        if remaining < 0 or depth > 32:
            raise _Refusal('delivery_capacity')
        if isinstance(item, (dict, list, tuple)):
            if len(item) > remaining:
                raise _Refusal('delivery_capacity')
            if isinstance(item, dict):
                for key, child in item.items():
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > remaining:
                raise _Refusal('delivery_capacity')
            remaining -= len(item.encode('utf-8'))
        elif item is not None and type(item) not in (bool, int, float):
            raise _Refusal('no_managed_ips')
        elif type(item) is int and item.bit_length() > 64:
            raise _Refusal('delivery_capacity')
        elif type(item) is float and not math.isfinite(item):
            raise _Refusal('no_managed_ips')
        if remaining < 0:
            raise _Refusal('delivery_capacity')
    visit(value, 0)


def confirmation(status, reason=None, *, request_id=None, ip_count=0, receipt_count=0,
                 channels=(), retry_after=None):
    return {'status': status, 'reason': reason, 'request_id': request_id,
            'ip_count': ip_count, 'receipt_count': receipt_count,
            'channels': list(channels), 'retry_after': retry_after}


def preview_reply(reason=None, *, request_id=None, target=None, source_type=None, ips=(),
                  observed_at=None, retained=True, channels=(), retry_after=None):
    return {'status': 'ready' if reason is None else 'not_ready', 'reason': reason,
            'request_id': request_id, 'target': target, 'source_type': source_type,
            'ips': list(ips), 'observed_at': observed_at, 'retained': retained,
            'channels': list(channels), 'expires_in_seconds': 300 if reason is None else 0,
            'retry_after': retry_after}


@dataclass
class Intent:
    request_id: str
    actor_id: str
    target: str
    revision: int
    owner: object
    generation: int
    version: int
    current_id: int
    history_id: int
    source: dict
    bindings: list
    deadline: float
    uncertain: bool = False
    # No global result cache: lifetime follows the bounded preview owner.
    resolution: _TransactionResolution = field(default_factory=_TransactionResolution)


class ResendCoordinator:
    def __init__(self, runtime):
        self.runtime = runtime
        self.monotonic = time.monotonic
        self.intents = {}

    def capture(self, target):
        # Targeted real lease without capture()'s all-target setdefault writes.
        repository = self.runtime.repository
        owner = repository._targets.get(target)
        if owner is None or not owner.active:
            return None
        return TargetLease(target, owner, repository.current.get(target, {}),
                           repository.history.get(target, {}))

    def source(self, lease):
        runtime = self.runtime
        cfg = runtime.config.raw
        domain = lease.target.definition
        providers = providers_for(domain, cfg.get('servers', []), cfg.get('ens_rpc_url'),
            cfg.get('DEFAULT_SNS_PROXY_HOSTS', cfg.get('DEFAULT_SOLAR_PROXY_HOSTS', [])))
        meta = lease.history.get('meta', {})
        # Raw evidence has a fixed scan budget; delivery unit_bytes independently
        # budgets the admitted entry payload in preflight, not source freshness.
        bounded_source([lease.current, meta, lease.target.failures], 65536)
        ips = sorted(collect_domain_managed_ips({lease.name: lease.current}, lease.name,
                                              rtype=domain.type, active_servers=providers))
        if len(ips) > min(256, runtime.store.limits['unit_items']):
            raise _Refusal('delivery_capacity')
        try:
            if not ips or any('%' in ip or not ipaddress.ip_address(ip) for ip in ips):
                raise ValueError()
        except ValueError:
            raise _Refusal('no_managed_ips') from None
        times = [snap.get('ts') for provider, snap in lease.current.items()
                 if provider in providers and isinstance(snap, dict) and type(snap.get('ts')) is int
                 and 0 < snap['ts'] < 2**53]
        from .delivery_runtime import digest
        source_digest = digest([lease.current, meta, lease.target.failures, runtime.signature(lease),
                                lease.target.lookup_failed, lease.target.lookup_uncertain])
        failed = bool(meta.get('dns_cycle_error_count') or meta.get('dns_error_only_active')
                      or isinstance(meta.get('rpc_observation'), dict)
                      and meta['rpc_observation'].get('status') != 'authenticated'
                      or isinstance(meta.get('dht_observation'), dict)
                      and not meta['dht_observation'].get('confirmed_in_this_run'))
        return {'ips': ips, 'source_type': domain.type, 'observed_at': min(times) if times else None,
                'retained': bool(lease.target.lookup_failed or lease.target.lookup_uncertain or failed
                                 or len(times) != len(providers)),
                'digest': source_digest}

    def destinations(self, channels):
        runtime = self.runtime
        if runtime._pending_bindings is not None or runtime.registry is None:
            return None
        bindings = [b for b in runtime.bindings() if b['channel'] in channels]
        if len(bindings) != len(channels) or any(not b['enabled'] or not b['ready'] or b['error'] for b in bindings):
            return None
        return bindings

    def guard(self, intent):
        runtime = self.runtime
        if runtime.stopping:
            return 'runtime_unavailable'
        if self.monotonic() >= intent.deadline:
            return 'preview_expired'
        if runtime.revision() != intent.revision:
            return 'configuration_changed'
        with state_lock():
            lease = self.capture(intent.target)
            if lease is None:
                return 'target_not_found'
            if (lease.target is not intent.owner() or runtime.repository.generation != intent.generation
                    or lease.target.version != intent.version or id(lease.current) != intent.current_id
                    or id(lease.history) != intent.history_id or not runtime.repository.valid(lease)):
                return 'snapshot_changed'
            try:
                if self.source(lease) != intent.source:
                    return 'snapshot_changed'
            except (ValueError, TypeError, KeyError, OverflowError):
                return 'snapshot_changed'
        if self.destinations([b['channel'] for b in intent.bindings]) != intent.bindings:
            return 'destination_unavailable'
        # Deadline and stop are volatile even while all source ownership is held.
        if runtime.stopping:
            return 'runtime_unavailable'
        if self.monotonic() >= intent.deadline:
            return 'preview_expired'
        return None

    def preview(self, target, channels, revision, actor_id):
        runtime = self.runtime
        if (not valid_text(target, runtime.store.limits['label_bytes']) or not valid_text(actor_id, 128)
                or type(revision) is not int or not 0 <= revision < 2**53
                or type(channels) is not list or not 1 <= len(channels) <= 2
                or any(type(c) is not str or c not in ('teams', 'misp') for c in channels)
                or len(set(channels)) != len(channels)):
            return preview_reply('invalid_request')
        channels = [c for c in ('teams', 'misp') if c in channels]
        with runtime.config.lock, runtime.repository._coord:
            if runtime.stopping:
                return preview_reply('runtime_unavailable')
            if revision != runtime.revision():
                return preview_reply('configuration_changed')
            with state_lock():
                # Public identity is not the display/storage label (ENS/SNS/RPC).
                name = next((name for name, owner in runtime.repository._targets.items()
                             if owner.active and domain_identity(vars(owner.definition)) == target), None)
                lease = self.capture(name)
                if lease is None:
                    return preview_reply('target_not_found')
                try:
                    source = self.source(lease)
                except _Refusal as error:
                    return preview_reply(str(error))
                except (ValueError, TypeError, KeyError, OverflowError):
                    return preview_reply('no_managed_ips')
            bindings = self.destinations(channels)
            if bindings is None:
                return preview_reply('destination_unavailable')
            now = self.monotonic()
            self.intents = {key: value for key, value in self.intents.items() if now < value.deadline}
            if len(self.intents) >= 128:
                return preview_reply('preview_capacity')
            request_id = uuid.uuid4().hex
            intent = Intent(request_id, actor_id, lease.name, revision, weakref.ref(lease.target),
                runtime.repository.generation, lease.target.version, id(lease.current), id(lease.history),
                source, bindings, now + 300)
            try:
                with runtime.store._lock:
                    reason, retry_after = preflight(runtime.store, intent, runtime.clock())
            except (sqlite3.Error, OSError, ValueError):
                return preview_reply('delivery_storage')
            if reason:
                return preview_reply(reason, retry_after=retry_after)
            self.intents[request_id] = intent
            public = {key: value for key, value in source.items() if key != 'digest'}
            return preview_reply(request_id=request_id, target=target, channels=channels, **public)

    def confirm(self, request_id, actor_id):
        runtime = self.runtime
        if (type(request_id) is not str or len(request_id) != 32
                or any(c not in '0123456789abcdef' for c in request_id) or not valid_text(actor_id, 128)):
            return confirmation('not_queued', 'invalid_request')
        with runtime.config.lock, runtime.repository._coord:
            try:
                row = runtime.store.resend_status(request_id)
            except (sqlite3.Error, OSError, ValueError, TypeError):
                return confirmation('unknown', 'delivery_unknown', request_id=request_id)
            if row is not None:
                if row['actor_id'] != actor_id:
                    return confirmation('not_queued', 'invalid_request', request_id=request_id)
                if not valid_marker(row, request_id):
                    return confirmation('unknown', 'delivery_unknown', request_id=request_id)
                self.intents.pop(request_id, None)
                return confirmation('already_queued', request_id=request_id, ip_count=row['ip_count'],
                                    receipt_count=row['receipt_count'], channels=json.loads(row['channels']))
            intent = self.intents.get(request_id)
            if intent is None:
                return confirmation('not_queued', 'preview_expired', request_id=request_id)
            if intent.actor_id != actor_id:
                return confirmation('not_queued', 'invalid_request', request_id=request_id)
            if intent.uncertain:
                rolled_back = intent.resolution.rolled_back
                return confirmation('not_queued' if rolled_back else 'unknown',
                    'delivery_storage' if rolled_back else 'delivery_unknown', request_id=request_id)
            reason = self.guard(intent)
            if reason:
                return confirmation('not_queued', reason, request_id=request_id)
            try:
                result = runtime.store.admit_resend(intent, guard=lambda: self.guard(intent))
            except (sqlite3.Error, OSError, ValueError):
                result = confirmation('not_queued', 'delivery_storage', request_id=request_id)
            if result['status'] in ('queued', 'already_queued'):
                self.intents.pop(request_id, None)
            elif result['status'] == 'unknown':
                intent.uncertain = True
        if result['status'] == 'queued':
            runtime.worker.wake()
        return result


def valid_text(value, limit):
    if type(value) is not str or not value or len(value) > limit or '\x00' in value:
        return False
    try:
        return len(value.encode('utf-8')) <= limit
    except UnicodeError:
        return False


def valid_marker(row, request_id):
    """Saved counts are authority only when their complete envelope is coherent."""
    try:
        channels = json.loads(row['channels'])
        provenance = json.loads(row['source'])
        source = provenance['source']
        bindings = provenance['bindings']
        return (row['request_id'] == request_id and valid_text(row['target'], 1024)
                and type(row['ip_count']) is int and 1 <= row['ip_count'] <= 256
                and type(row['receipt_count']) is int and 1 <= row['receipt_count'] <= 512
                and channels in (['teams'], ['misp'], ['teams', 'misp'])
                and row['receipt_count'] == row['ip_count'] * len(channels)
                and type(bindings) is list and len(bindings) == len(channels)
                and all(valid_binding(b) and b['enabled'] and b['ready'] and b['error'] is None for b in bindings)
                and [b['channel'] for b in bindings] == channels
                and type(source['ips']) is list and len(source['ips']) == row['ip_count']
                and all(type(ip) is str and '%' not in ip and ipaddress.ip_address(ip) for ip in source['ips'])
                and len(set(source['ips'])) == row['ip_count']
                and source['source_type'] in ('A', 'TXT', 'ENS', 'SNS', 'DHT', 'RPC')
                and type(source['digest']) is str and len(source['digest']) == 64
                and all(c in '0123456789abcdef' for c in source['digest'])
                and type(provenance['revision']) is int and 0 <= provenance['revision'] < 2**53
                and valid_text(provenance['target_identity'], 1024))
    except (ValueError, TypeError, KeyError):
        return False


# Markers outlive terminal receipts. Reclaim only expired, fully terminal requests.
# Materialize the bounded operation set once, not a receipt scan per marker;
# this preserves existing receipt indexes/claim plans and works on old ledgers.
EXPIRED_MARKERS = ("created<=? AND 'manual:'||request_id NOT IN (SELECT operation FROM receipt)")


def entries_for(intent):
    return [[ip, intent.target, intent.source['source_type']] for ip in intent.source['ips']]


def reservation(store, intent, entry, channel):
    # Same conservative provider/progress/batch reservation as automatic work.
    return (size({'entries': [entry]}) + 4096 + size([intent.target, None, intent.source['digest']])
            + (store.limits['batch_bytes'] if channel == 'teams' else 0))


def preflight(store, intent, now):
    if (store._closed or store._stopping or not store._ready or store._db is None
            or store._claims_halted or store._unresolved is not None or not math.isfinite(now)):
        return 'delivery_storage', None
    latest = store._one('SELECT MAX(created) FROM manual_resend WHERE target=?', (intent.target,))[0]
    if latest is not None and now < latest + 30:
        return 'resend_cooldown', min(30, math.ceil(latest + 30 - now))
    for binding in intent.bindings:
        # Authentication is channel-wide; changing binding never repairs old work.
        if store._one("SELECT 1 FROM receipt WHERE channel=? AND state='blocked_config' "
                      "AND error IN ('provider_auth','old_binding_blocked') LIMIT 1", (binding['channel'],)):
            return 'destination_unavailable', None
        for ip in intent.source['ips']:
            if store._one('SELECT 1 FROM receipt WHERE channel=? AND ip=? '
                          'AND (binding=? OR source_target=?) LIMIT 1',
                          (binding['channel'], ip, binding['binding_id'], intent.target)):
                return 'delivery_pending', None
    live = store._one('SELECT COUNT(*) FROM manual_resend WHERE NOT (' + EXPIRED_MARKERS + ')', (now - 86400,))[0]
    entries = entries_for(intent)
    used, used_bytes = store._one('SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM receipt')
    reserved = sum(reservation(store, intent, entry, b['channel']) for entry in entries for b in intent.bindings)
    if (live >= 256 or len(entries) > min(256, store.limits['unit_items'])
            or size(entries) > store.limits['unit_bytes']
            or not valid_text(intent.target, store.limits['label_bytes'])
            or used + len(entries) * len(intent.bindings) > store.limits['receipts']
            or used_bytes + reserved > store.limits['payload_bytes']):
        return 'delivery_capacity', None
    return None, None


def render_batches(store, entries, created):
    """Freeze fitting complete prefixes before SQL; never terminally lose a row."""
    batches = []
    offset = 0
    while offset < len(entries):
        accepted, body = [], None
        for entry in entries[offset:offset + store.limits['batch_items']]:
            candidate = accepted + [entry]
            try:
                rendered = store._render(candidate, 'Added', created)
                if (type(rendered) is not dict or set(rendered) != {'title', 'text'}
                        or any(type(value) is not str for value in rendered.values())):
                    raise ValueError('invalid rendered body')
                if len(encode_body(rendered)) > store.limits['batch_bytes']:
                    break
            except TeamsPayloadTooLarge:
                break
            accepted, body = candidate, rendered
        if not accepted:
            raise TeamsPayloadTooLarge()
        batches.append((offset, len(accepted), encode({'entries': accepted, 'body': body})))
        offset += len(accepted)
    return batches


def admit(store, intent, guard):
    channels = [b['channel'] for b in intent.bindings]
    entries = entries_for(intent)
    created = store._clock()
    operation = 'manual:' + intent.request_id
    with store._lock:
        reason, retry_after = preflight(store, intent, created)
        if reason:
            return confirmation('not_queued', reason, request_id=intent.request_id, retry_after=retry_after)
        try:
            batches = render_batches(store, entries, created) if 'teams' in channels else []
        except TeamsPayloadTooLarge:
            return confirmation('not_queued', 'delivery_capacity', request_id=intent.request_id)
        except Exception:
            return confirmation('not_queued', 'delivery_storage', request_id=intent.request_id)
        provenance = {'source': intent.source, 'revision': intent.revision, 'bindings': intent.bindings,
                      'target_identity': domain_identity(vars(intent.owner().definition)),
                      'incarnation': store.cursor_incarnation(intent.target),
                      'generation': intent.generation, 'version': intent.version}
        expected = {'request_id': intent.request_id, 'actor_id': intent.actor_id, 'target': intent.target,
                    'created': created, 'source': encode(provenance), 'channels': encode(channels),
                    'ip_count': len(entries), 'receipt_count': len(entries) * len(channels)}
        inserted = False
        request_id = intent.request_id
        def readback():
            # Do not retain the preview/source owner through the recovery hook.
            if inserted and store.read_resend(request_id) != expected:
                raise ValueError('manual request identity mismatch')
        rejection = None
        def cancelled():
            nonlocal rejection
            rejection = guard()
            return rejection is not None
        def apply():
            nonlocal inserted
            reason, retry_after = preflight(store, intent, store._clock())
            if reason:
                return reason, retry_after
            store._execute('DELETE FROM manual_resend WHERE ' + EXPIRED_MARKERS, (created - 86400,))
            store._execute('INSERT INTO manual_resend VALUES(?,?,?,?,?,?,?,?)',
                           tuple(expected.values()))
            inserted = True
            team_ids = []
            for entry in entries:
                payload = encode({'entries': [entry]})
                for binding in intent.bindings:
                    channel = binding['channel']
                    store._execute('INSERT INTO receipt(operation,channel,binding,action,ip,payload,state,'
                        'created,reserved,cycle,source_target,source_signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                        (operation, channel, binding['binding_id'], 'Added', entry[0], payload,
                         'pending', created, reservation(store, intent, entry, channel), operation,
                         intent.target, intent.source['digest']))
                    # NULL source_incarnation deliberately denies automatic failed-addition authority.
                    if channel == 'teams':
                        team_ids.append(store._one('SELECT last_insert_rowid()')[0])
            for offset, count, payload in batches:
                members = team_ids[offset:offset + count]
                store._execute('INSERT INTO batch VALUES(?,?,?)', (members[0], payload, created))
                for member in members:
                    store._execute('UPDATE receipt SET batch_id=? WHERE id=?', (members[0], member))
            return None
        ok, result, uncertain = store._transaction(operation, apply, kind='manual', cancelled=cancelled,
            allow_noop=True, readback=readback, resolution=intent.resolution)
        if result == 'cancelled':
            return confirmation('not_queued', rejection, request_id=intent.request_id)
        if not ok:
            return confirmation('unknown' if uncertain else 'not_queued',
                                'delivery_unknown' if uncertain else 'delivery_storage',
                                request_id=intent.request_id)
        if result is not None:
            return confirmation('not_queued', result[0], request_id=intent.request_id, retry_after=result[1])
        # The transaction's independent readback verified this entire exact marker.
        return confirmation('queued', request_id=intent.request_id, ip_count=len(entries),
                            receipt_count=expected['receipt_count'], channels=channels)
