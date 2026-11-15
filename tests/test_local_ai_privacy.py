"""Secret-free guard: real bounded discovery/projection, no provider or runtime IO."""
import importlib
import json
from pathlib import Path
import threading
import time

import pytest

from http_api.read_model import BackgroundReadModel


CANARY = 'synthetic-credential-do-not-publish'


def api():
    assert (Path(__file__).parents[1] / 'local_ai/privacy.py').is_file(), 'privacy guard missing'
    return importlib.import_module('local_ai.privacy')


def owners(config=None):
    return (config if config is not None else {'api_key': CANARY},
            threading.RLock(), BackgroundReadModel(lambda previous: None, lambda value: {}))


@pytest.mark.parametrize('payload', [
    {'Data': CANARY},
    {CANARY: 'citation'},
    {'text': 'prefix-' + CANARY + '-suffix'},
    {'snapshot_digest': 'clean', 'summary': [{'text': CANARY, 'evidence_ids': ['e1']}]},
], ids=['value', 'key', 'substring', 'nested-prose'])
def test_changed_sensitive_data_is_rejected_not_repaired(payload, caplog):
    m = api()
    original = json.dumps(payload)
    with pytest.raises(m.PrivacyError) as caught:
        m.require_secret_free(payload, *owners(), time.monotonic() + 5)
    assert caught.value.code == 'sensitive_input'
    assert str(caught.value) == 'sensitive_input'
    assert CANARY not in repr(caught.value) + caplog.text
    assert json.dumps(payload) == original


def test_clean_projection_returns_detached_canonical_utf8():
    m = api()
    payload = {'z': ['한국어', 7, True, None, 1.5], 'a': {'b': 'clean'}}
    expected = json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':')).encode('utf8')
    out = m.require_secret_free(payload, *owners(), time.monotonic() + 5)
    assert type(out) is bytes
    assert out == expected
    assert m.require_secret_free({'a': {'b': 'clean'}, 'z': payload['z']}, *owners(),
                                 time.monotonic() + 5) == out
    payload['z'].append('later')
    payload['a']['b'] = CANARY
    assert out == expected


@pytest.mark.parametrize('value', [
    'x' * 8191, 'é' * 4096, '\x00' * 1366, [None] * 1700, ('not-json',),
], ids=['ascii-plus-one', 'unicode-overflow', 'escaped-overflow', 'aggregate-overflow', 'tuple'])
def test_invalid_or_oversized_payload_rejected_before_encoding(value, monkeypatch):
    m = api()
    calls = []
    original = m.Encoding

    def encode(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(m, 'Encoding', encode)
    with pytest.raises(m.PrivacyError) as caught:
        m.require_secret_free(value, *owners(), time.monotonic() + 5)
    assert caught.value.code == 'privacy_failed'
    assert calls == []


@pytest.mark.parametrize('value', ['é', '😀', '\x00', '"\\\n', 'x' * 8190, 'x' * 32766])
def test_exact_encoded_bytes_and_plus_one(value):
    m = api()
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf8')
    assert m.require_secret_free(value, *owners(), time.monotonic() + 5, max_bytes=len(encoded)) == encoded
    with pytest.raises(m.PrivacyError):
        m.require_secret_free(value, *owners(), time.monotonic() + 5, max_bytes=len(encoded) - 1)


@pytest.mark.parametrize('limit', [0, -1, True, 8.0, '8192', 32769])
def test_invalid_byte_limit(limit):
    m = api()
    with pytest.raises(m.PrivacyError) as caught:
        m.require_secret_free({}, *owners(), time.monotonic() + 5, max_bytes=limit)
    assert str(caught.value) == 'privacy_failed'


def test_json_node_limit_at_and_beyond_boundary():
    m = api()
    payload = [0] * 4095  # root + children = 4096 nodes
    result = m.require_secret_free(payload, *owners(), time.monotonic() + 5, max_bytes=32768)
    assert json.loads(result) == payload
    with pytest.raises(m.PrivacyError):
        m.require_secret_free(payload + [0], *owners(), time.monotonic() + 5, max_bytes=32768)


@pytest.mark.parametrize('change', ['config', 'security', 'hard', 'stopped', 'root-key'])
@pytest.mark.parametrize('phase', ['plan', 'encoded'])
def test_authority_change_during_check_fails_closed(change, phase, monkeypatch):
    m = api()
    config, lock, model = owners()
    fired = []
    target = m.Builder if phase == 'plan' else m.Encoding
    original = target.take
    calls = []

    def take(self):
        result = original(self)
        calls.append(True)
        if len(calls) == (1 if phase == 'plan' else 2):
            with lock:
                if change == 'config':
                    config['_config_revision'] = 1
                elif change == 'security':
                    config['_security_projection_revision'] = 1
                elif change == 'hard':
                    model.invalidate(hard=True)
                elif change == 'stopped':
                    model.stop_admission()
                else:
                    config[False] = 'unsupported-config-key'
            fired.append(True)
        return result

    monkeypatch.setattr(target, 'take', take)
    with pytest.raises(m.PrivacyError) as caught:
        m.require_secret_free({'Data': 'clean'}, config, lock, model, time.monotonic() + 5)
    assert caught.value.code == 'privacy_failed'
    assert fired == [True]


def test_deadline_is_checked_after_detached_copy(monkeypatch):
    m = api()
    import builtins
    clock = [0.0]
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    fired = []

    class LateCopy:
        def __init__(self, value):
            self.value = value

        def tobytes(self):
            value = builtins.memoryview(self.value).tobytes()
            clock[0] = 2.0
            fired.append(True)
            return value

    monkeypatch.setattr(m, 'memoryview', LateCopy, raising=False)
    with pytest.raises(m.PrivacyError):
        m.require_secret_free({'Data': 'clean'}, *owners(), 1.0)
    assert fired == [True]


@pytest.mark.parametrize('argument', ['payload', 'config', 'config_lock', 'read_model', 'deadline', 'max_bytes'])
def test_untrusted_types_do_not_invoke_callbacks(argument):
    m = api()
    calls = []

    class TrapMeta(type):
        def __eq__(cls, other):
            calls.append('eq')
            raise RuntimeError(CANARY)

        def __hash__(cls):
            calls.append('hash')
            raise RuntimeError(CANARY)

    class Trap(metaclass=TrapMeta):
        def __repr__(self):
            calls.append('repr')
            raise RuntimeError(CANARY)

    cfg, lock, model = owners()
    args = dict(payload={}, config=cfg, config_lock=lock, read_model=model,
                deadline=time.monotonic() + 5, max_bytes=8192)
    args[argument] = Trap()
    with pytest.raises(m.PrivacyError) as caught:
        m.require_secret_free(**args)
    assert caught.value.code == 'privacy_failed'
    assert caught.value.__cause__ is caught.value.__context__ is None
    assert calls == []


@pytest.fixture
def observed_resources(monkeypatch):
    """Observe real owners without changing their types or normalization."""
    m = api()
    from security import derived_redaction as foundation
    budgets, operations, handles = [], [], []
    budget_class = foundation.RedactionBudget

    def budget(**kwargs):
        value = budget_class(**kwargs)
        budgets.append(value)
        return value

    monkeypatch.setattr(m, 'RedactionBudget', budget)
    for name in ('Builder', 'Projector', 'Encoding'):
        cls = getattr(foundation, name)
        original_take = cls.take

        def take(self, original=original_take):
            value = original(self)
            if value is not None:
                handles.append(value)
            return value

        def create(*args, original=cls, **kwargs):
            value = original(*args, **kwargs)
            operations.append(value)
            return value

        monkeypatch.setattr(cls, 'take', take)
        monkeypatch.setattr(m, name, create)
    original_admit = foundation.OwnedPayload.admit

    def admit(cls, value, *, budget):
        handle = original_admit(value, budget=budget)
        handles.append(handle)
        return handle

    monkeypatch.setattr(foundation.OwnedPayload, 'admit', classmethod(admit))
    yield budgets, operations, handles
    assert len(budgets) == 1
    ledger = budgets[0].counters()
    assert ledger['closed'] and not ledger['active']
    assert ledger['worker_bytes'] == ledger['metadata_bytes'] == 0
    assert ledger['hold_worker_bytes'] == ledger['hold_metadata_bytes'] == 0
    assert ledger['worker_peak'] <= foundation.WORKER
    assert ledger['metadata_peak'] <= foundation.METADATA
    assert ledger['visits'] <= foundation.VISITS
    for operation in operations:
        assert operation.budget is budgets[0]
        assert operation._lease is None
        assert operation.result is None
        assert not operation._running
        assert getattr(operation, 'gen', None) is None
        assert getattr(operation, 'config', None) is None
        assert getattr(operation, 'model', None) is None
        assert not getattr(operation, 'found', None)
    for handle in handles:
        assert handle.budget is budgets[0]
        assert handle._value is None
        assert handle._lease.closed


@pytest.mark.parametrize('kind', [
    'clean', 'sensitive', 'expansion', 'overflow', 'cycle', 'unsupported',
    'config-cycle', 'config-count', 'config-secret-bytes', 'config-subclass', 'expired',
    'lock-busy', 'model-stopped', 'exception', 'interrupt', 'memory',
])
def test_all_handles_and_shared_budget_are_retired(kind, observed_resources, monkeypatch, caplog):
    m = api()
    config, lock, model = owners()
    payload = {'Data': 'clean'}
    deadline = time.monotonic() + 5
    max_bytes = 8192
    if kind == 'sensitive':
        payload['Data'] = CANARY
    elif kind == 'expansion':
        config['api_key'] = 'four'
        payload, max_bytes = 'four', 20
    elif kind == 'overflow':
        payload = 'x' * 8191
    elif kind == 'cycle':
        payload['cycle'] = payload
    elif kind == 'unsupported':
        payload['bad'] = object()
    elif kind == 'config-cycle':
        config['cycle'] = config
    elif kind == 'config-count':
        config['api_key'] = [f'synthetic-{i}' for i in range(257)]
    elif kind == 'config-secret-bytes':
        config['api_key'] = 'é' * 32769
    elif kind == 'config-subclass':
        class Unsupported(dict):
            pass
        config['nested'] = Unsupported()
    elif kind == 'expired':
        deadline = time.monotonic() - 1
    elif kind == 'lock-busy':
        lock = threading.Lock()
        lock.acquire()
    elif kind == 'model-stopped':
        model.stop_admission()
    elif kind in ('exception', 'interrupt', 'memory'):
        def fail(*args, **kwargs):
            if kind == 'interrupt':
                raise KeyboardInterrupt('cancelled')
            if kind == 'memory':
                raise MemoryError(CANARY)
            raise RuntimeError(CANARY)
        monkeypatch.setattr(m, 'Projector', fail)
    try:
        if kind == 'clean':
            out = m.require_secret_free(payload, config, lock, model, deadline, max_bytes=max_bytes)
            assert out == b'{"Data":"clean"}'
        elif kind == 'interrupt':
            with pytest.raises(KeyboardInterrupt, match='cancelled'):
                m.require_secret_free(payload, config, lock, model, deadline)
        else:
            with pytest.raises(m.PrivacyError) as caught:
                m.require_secret_free(payload, config, lock, model, deadline, max_bytes=max_bytes)
            assert str(caught.value) in ('sensitive_input', 'privacy_failed')
            assert caught.value.__cause__ is caught.value.__context__ is None
            assert CANARY not in str(caught.value) + repr(caught.value) + caplog.text
    finally:
        if kind == 'lock-busy':
            lock.release()


@pytest.mark.parametrize('nth', range(1, 13))
def test_cleanup_registration_failure_retires_unregistered_owner(nth, observed_resources, monkeypatch):
    m = api()
    calls = []
    fired = []

    class FailingStack(m.ExitStack):
        def callback(self, callback, *args, **kwargs):
            calls.append(True)
            if len(calls) == nth:
                fired.append(True)
                raise MemoryError(CANARY)
            return super().callback(callback, *args, **kwargs)

    monkeypatch.setattr(m, 'ExitStack', FailingStack)
    with pytest.raises(m.PrivacyError, match='privacy_failed'):
        m.require_secret_free({'text': 'clean'}, *owners(), time.monotonic() + 5)
    assert fired == [True]


def test_changed_output_exact_and_plus_one():
    m = api()
    cfg = {'api_key': 'four'}
    # Actual legacy replacement is 'redacted-' plus 12 hex chars, plus quotes.
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free('four', *owners(cfg), time.monotonic() + 5, max_bytes=23)
    with pytest.raises(m.PrivacyError, match='privacy_failed'):
        m.require_secret_free('four', *owners(cfg), time.monotonic() + 5, max_bytes=22)


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), 1 << 129,
                                   b'bytes', {1: 'not-a-string-key'}, '\ud800'])
def test_unsupported_json_scalars(value):
    m = api()
    with pytest.raises(m.PrivacyError, match='privacy_failed'):
        m.require_secret_free(value, *owners(), time.monotonic() + 5)


def test_depth_exact_plus_one_and_shared_noncyclic_child():
    m = api()
    value = 0
    for _ in range(32):
        value = [value]
    assert json.loads(m.require_secret_free(value, *owners(), time.monotonic() + 5)) == value
    with pytest.raises(m.PrivacyError):
        m.require_secret_free([value], *owners(), time.monotonic() + 5)
    shared = {'name': 'public'}
    assert json.loads(m.require_secret_free([shared, shared], *owners(), time.monotonic() + 5)) == [shared, shared]


@pytest.mark.parametrize('deadline', [True, float('inf'), float('nan'), -1, 0])
def test_invalid_or_expired_deadlines(deadline):
    m = api()
    with pytest.raises(m.PrivacyError, match='privacy_failed'):
        m.require_secret_free({}, *owners(), deadline)


def test_real_runtime_service_and_opaque_config_are_accepted():
    m = api()
    from monitor.config_service import ConfigService
    cfg, lock, model = owners({'api_key': ('short', CANARY), '_monitor_condition': threading.Condition()})
    cfg['_config_service'] = ConfigService(cfg, lock, '', read_model=model)
    result = m.require_secret_free({'text': 'public'}, cfg, lock, model, time.monotonic() + 5)
    assert result == b'{"text":"public"}'
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free({'Data': CANARY}, cfg, lock, model, time.monotonic() + 5)
    cfg['_config_service'].read_model = owners()[2]
    with pytest.raises(m.PrivacyError, match='privacy_failed'):
        m.require_secret_free({}, cfg, lock, model, time.monotonic() + 5)


@pytest.mark.parametrize('key', ['Data', 'snapshot_digest', 'evidence_ids'])
def test_fixed_schema_key_collisions_are_rejected(key):
    m = api()
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free({key: 'clean'}, *owners({'api_key': key}), time.monotonic() + 5)


def test_nested_config_secrets_and_short_secret_policy():
    m = api()
    config = {'runtime': [{'teams_webhook': {'nested': [CANARY, 'abc']}}]}
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free(CANARY, *owners(config), time.monotonic() + 5)
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free('abc', *owners(config), time.monotonic() + 5)
    # Existing policy substitutes short secrets only on whole-string equality.
    assert m.require_secret_free('xabcx', *owners(config), time.monotonic() + 5) == b'"xabcx"'


def test_unicode_secret_and_key_collision_are_not_repaired():
    m = api()
    import hashlib
    secret = '합성-비밀-😀'
    replacement = 'redacted-' + hashlib.sha256(secret.encode('utf8')).hexdigest()[:12]
    for payload in ({'text': 'prefix-' + secret}, {secret: 1, replacement: 2}):
        with pytest.raises(m.PrivacyError, match='sensitive_input'):
            m.require_secret_free(payload, *owners({'api_key': secret}), time.monotonic() + 5)


def test_secret_discovery_at_configured_count_boundary():
    m = api()
    config = {'api_key': [f'synthetic-{i}' for i in range(256)]}
    with pytest.raises(m.PrivacyError, match='sensitive_input'):
        m.require_secret_free('synthetic-255', *owners(config), time.monotonic() + 5)
    assert m.require_secret_free({'Data': 'clean'}, *owners(config), time.monotonic() + 5) == b'{"Data":"clean"}'


def test_final_detached_bytes_are_not_a_borrowed_encoded_handle(monkeypatch):
    m = api()
    original = m.Encoding.take
    values = []

    def take(self):
        handle = original(self)
        if handle is not None:
            values.append(handle.value)
        return handle

    monkeypatch.setattr(m.Encoding, 'take', take)
    result = m.require_secret_free({'Data': 'clean'}, *owners(), time.monotonic() + 5)
    assert len(values) == 2
    assert values[0] == values[1] == result
    assert result is not values[0] and result is not values[1]
