"""Closed decoder inputs and deterministic, bounded verification (no model I/O)."""
import ipaddress
import threading


# One physical verifier slot per process, including an unretired failed child.
_worker_lock = threading.Lock()
_active_child = None


class DecoderError(ValueError):
    """Sanitized failure suitable for translation by the owning service."""

    def __init__(self, code='invalid_request', status=None):
        self.code = code
        self.status = status if status is not None else {
            'too_large': 413, 'verification_failed': 503, 'busy': 429,
            'deadline_exceeded': 408, 'source_unavailable': 409,
        }.get(code, 400)
        super().__init__(code)


def _text(value, limit):
    if type(value) is not str:
        raise DecoderError()
    if len(value) > limit:
        raise DecoderError('too_large')
    try:
        if len(value.encode('utf-8')) > limit:
            raise DecoderError('too_large')
    except UnicodeError:
        raise DecoderError() from None
    return value


def validate_samples(samples):
    """Return owned rows without stripping, repairing or truncating input.

    Duplicate raw inputs (even agreeing labels) are refused: the report counts
    distinct inputs, never claims that repeated observations are independent.
    """
    if type(samples) is not list or not samples:
        raise DecoderError()
    if len(samples) > 6:
        raise DecoderError('too_large')
    owned, seen = [], set()
    for sample in samples:
        if type(sample) is not dict or set(sample) != {'data', 'expected_ips', 'usage', 'complete_expected'}:
            raise DecoderError()
        data = _text(sample['data'], 2048)
        if data in seen:
            raise DecoderError()
        seen.add(data)
        usage, complete = sample['usage'], sample['complete_expected']
        if usage not in ('example', 'validation') or type(complete) is not bool:
            raise DecoderError()
        ips = sample['expected_ips']
        if type(ips) is not list or not ips:
            raise DecoderError()
        if len(ips) > 8:
            raise DecoderError('too_large')
        valid_ips = []
        for ip in ips:
            if type(ip) is not str or len(ip) > 15:
                raise DecoderError()
            try:
                if str(ipaddress.IPv4Address(ip)) != ip or ip in valid_ips:
                    raise DecoderError()
            except ipaddress.AddressValueError:
                raise DecoderError() from None
            valid_ips.append(ip)
        owned.append({'data': data, 'expected_ips': valid_ips, 'usage': usage, 'complete_expected': complete})
    if not any(s['usage'] == 'example' for s in owned):
        raise DecoderError()
    return owned


def _kind(kind):
    if type(kind) is not str or kind not in ('TXT', 'A'):
        raise DecoderError()
    return kind


def generated_step_schema(kind):
    """One closed, disjoint JSON Schema alternative per supported operation."""
    _kind(kind)
    choices = []
    for op in ('base64', 'urlsafe_b64', 'extract_ip_prefix', 'ascii', 'xor_hex', 'xor32_ipv4'):
        if op == 'xor32_ipv4' and kind != 'A':
            continue
        properties = {'op': {'const': op}}
        if op == 'xor_hex':
            properties['key'] = {'type': 'string', 'minLength': 2, 'maxLength': 128,
                                 'pattern': r'^(?:[0-9a-fA-F]{2})+(?![\s\S])'}
        elif op == 'xor32_ipv4':
            properties['key'] = {'type': 'string', 'minLength': 10, 'maxLength': 10,
                                 'pattern': '^0x[0-9a-fA-F]{8}$'}
        choices.append({'type': 'object', 'properties': properties,
                        'required': list(properties), 'additionalProperties': False})
    return {'oneOf': choices}


def validate_generated_steps(kind, steps):
    """Validate, never repair. Legacy factories intentionally remain broader."""
    import re
    schema = generated_step_schema(kind)
    if type(steps) is not list or not 1 <= len(steps) <= 12:
        raise DecoderError('invalid_model_output')
    allowed = {s['properties']['op']['const']: s for s in schema['oneOf']}
    owned = []
    for step in steps:
        if type(step) is not dict or type(step.get('op')) is not str:
            raise DecoderError('invalid_model_output')
        spec = allowed.get(step['op'])
        if spec is None or set(step) != set(spec['required']):
            raise DecoderError('invalid_model_output')
        if 'key' in spec['properties']:
            key, rule = step['key'], spec['properties']['key']
            if (type(key) is not str or not rule['minLength'] <= len(key) <= rule['maxLength']
                    or re.fullmatch(rule['pattern'], key) is None):
                raise DecoderError('invalid_model_output')
        owned.append(dict(step))
    return owned


def _bounded_json(value, limit):
    """Meter compact UTF-8 JSON *before* encoding/copying untrusted scalars.

    Structural and depth bounds also stop cycles, giant collections and deeply
    nested ignored legacy fields before a serializer can allocate their copies.
    """
    import json
    import math
    remaining = limit

    def charge(amount):
        nonlocal remaining
        remaining -= amount
        if remaining < 0:
            raise DecoderError('too_large')

    def visit(item, depth=0):
        if depth > 64:
            raise DecoderError('too_large')
        if type(item) is str:
            if len(item) > remaining:
                raise DecoderError('too_large')
            charge(2)
            for char in item:
                n = ord(char)
                if 0xD800 <= n <= 0xDFFF:
                    raise DecoderError()
                charge(2 if char in '\"\\\b\f\n\r\t' else
                       6 if n < 32 else 1 if n < 128 else 2 if n < 2048 else 3 if n < 65536 else 4)
        elif item is None or type(item) is bool:
            charge(4 if item is None or item is True else 5)
        elif type(item) is int:
            if item.bit_length() > remaining * 4:
                raise DecoderError('too_large')
            try:
                charge(len(str(item)))
            except ValueError:
                raise DecoderError('too_large') from None
        elif type(item) is float and math.isfinite(item):
            charge(len(repr(item)))
        elif type(item) in (list, dict):
            charge(2 + max(0, len(item) - 1))
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DecoderError()
                    visit(key, depth + 1)
                    charge(1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        else:
            raise DecoderError()

    visit(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _builtins(kind):
    _kind(kind)
    if kind == 'TXT':
        from txt_decoder import _BUILTIN_DECODE_METHODS
        return sorted(_BUILTIN_DECODE_METHODS)
    from a_decoder import _BUILTIN_A_DECODE_METHODS
    return sorted(_BUILTIN_A_DECODE_METHODS)


def capture_catalog(config, kind):
    """Caller MUST hold configuration ownership until this owned snapshot returns.

    Snapshot only selected persisted definitions, not live closures or unrelated
    config. Compilation and execution belong exclusively to the fresh worker.
    """
    import json
    import re
    builtin = _builtins(kind)
    if type(config) is not dict:
        raise DecoderError('source_unavailable')
    definitions = config.get('custom_decoders' if kind == 'TXT' else 'custom_a_decoders', [])
    if type(definitions) is not list:
        raise DecoderError('source_unavailable')
    if len(definitions) + len(builtin) > 32:
        raise DecoderError('too_large')
    # Small reference-only projection. No nested copy or traversal yet.
    selected = []
    for definition in definitions:
        if type(definition) is not dict:
            raise DecoderError('source_unavailable')
        selected.append({'name': definition.get('name'), 'steps': definition.get('steps'),
                         'decoder_type': definition.get('decoder_type', kind)})
    catalog = {'kind': kind, 'builtins': builtin, 'definitions': selected}
    encoded = _bounded_json(catalog, 32768)
    names = set(builtin)
    for definition in selected:
        name = definition['name']
        if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_\-]+', name) or name in names
                or type(definition['decoder_type']) is not str or definition['decoder_type'].upper() != kind):
            raise DecoderError('source_unavailable')
        names.add(name)
    return json.loads(encoded)


def _cutoff(deadline):
    import math
    import time
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise DecoderError()
    now = time.monotonic()
    if deadline <= now:
        raise DecoderError('deadline_exceeded')
    return min(deadline, now + 5.0)


def _spawn_worker(cutoff):
    import os
    from pathlib import Path
    import subprocess
    import sys
    import time
    command = [sys.executable, '-I', '-B', '-S', str(Path(__file__).with_name('decoder_worker.py'))]
    environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8'}
    if time.monotonic() >= cutoff:
        raise DecoderError('verification_failed')
    return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=0, close_fds=True, env=environment)


def _pump(child, encoded, cutoff):
    """Nonblocking pipe pump; never communicate()/buffer an unbounded stream."""
    import os
    import selectors
    import time
    output, stderr_size, sent = bytearray(), 0, 0
    with selectors.DefaultSelector() as selector:
        for stream, event in ((child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ),
                              (child.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        while selector.get_map():
            remaining = cutoff - time.monotonic()
            if remaining <= 0:
                raise DecoderError('verification_failed')
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                if stream is child.stdin:
                    sent += os.write(stream.fileno(), encoded[sent:sent + 4096])
                    if sent == len(encoded):
                        selector.unregister(stream)
                        stream.close()
                else:
                    limit = 65536 - len(output) if stream is child.stdout else 4096 - stderr_size
                    # One sentinel byte detects overflow without retaining it.
                    chunk = os.read(stream.fileno(), min(4096, limit + 1))
                    if len(chunk) > limit:
                        raise DecoderError('verification_failed')
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                    elif stream is child.stdout:
                        output.extend(chunk)
                    else:
                        stderr_size += len(chunk)  # discard content; never log it
    child.wait(timeout=max(0, cutoff - time.monotonic()))
    if child.returncode != 0 or time.monotonic() >= cutoff:
        raise DecoderError('verification_failed')
    return output


def _retire(child):
    """Separate bounded reap allowance. Failed retirement keeps custody/slot."""
    import subprocess
    clean = True
    try:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        clean = False
    finally:
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except OSError:
                clean = False
    return clean and child.poll() is not None


def _strict_load(raw):
    import json
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DecoderError('verification_failed')
            result[key] = value
        return result
    def constant(value):
        raise DecoderError('verification_failed')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)


def _validate_report(report, payload):
    """Require complete inventory and internally consistent facts, never prose."""
    from local_ai.decoder_worker import _rank, _summary
    samples, mode, kind = payload['samples'], payload['mode'], payload['kind']
    if mode == 'catalog':
        inventory = {name: ('builtin', None) for name in payload['catalog']['builtins']}
        inventory.update({d['name']: ('custom', d['steps']) for d in payload['catalog']['definitions']})
    else:
        inventory = {f'generated_{i + 1}': ('generated', c['steps']) for i, c in enumerate(payload['candidates'])}
    examples = sum(s['usage'] == 'example' for s in samples)
    limitations = ['candidate_not_proof', 'distinct_inputs_not_independent_observations']
    if mode == 'catalog':
        limitations.append('builtin_defaults_only')
    if examples == len(samples):
        limitations.append('no_validation_samples')
    expected = {'kind': kind, 'mode': mode, 'complete': True, 'distinct_inputs': len(samples),
                'example_count': examples, 'validation_count': len(samples) - examples,
                'evaluations': len(inventory) * len(samples),
                'ranking_basis': 'examples_only' if mode == 'catalog' else 'fixed_generation_order',
                'limitations': limitations}
    if type(report) is not dict or set(report) != set(expected) | {'candidates'}:
        raise DecoderError('verification_failed')
    if any(type(report[k]) is not type(v) or report[k] != v for k, v in expected.items()):
        raise DecoderError('verification_failed')
    candidates = report['candidates']
    if type(candidates) is not list or len(candidates) != len(inventory):
        raise DecoderError('verification_failed')
    seen = []
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate) != {'name', 'source', 'steps', 'examples', 'validation'}:
            raise DecoderError('verification_failed')
        name = candidate['name']
        if type(name) is not str or name not in inventory or name in seen:
            raise DecoderError('verification_failed')
        seen.append(name)
        if (candidate['source'], candidate['steps']) != inventory[name]:
            raise DecoderError('verification_failed')
        for phase, usage in (('examples', 'example'), ('validation', 'validation')):
            summary = candidate[phase]
            indices = [i for i, s in enumerate(samples) if s['usage'] == usage]
            if type(summary) is not dict or type(summary.get('results')) is not list:
                raise DecoderError('verification_failed')
            results = summary['results']
            if len(results) != len(indices):
                raise DecoderError('verification_failed')
            for result, index in zip(results, indices):
                keys = ('matched_ips', 'missing_ips', 'unexpected_ips', 'unverified_extra_ips')
                if type(result) is not dict or set(result) != set(keys) | {'sample_index', 'passed'}:
                    raise DecoderError('verification_failed')
                if type(result['sample_index']) is not int or result['sample_index'] != index:
                    raise DecoderError('verification_failed')
                for key in keys:
                    ips = result[key]
                    if type(ips) is not list:
                        raise DecoderError('verification_failed')
                    for ip in ips:
                        if type(ip) is not str or str(ipaddress.IPv4Address(ip)) != ip:
                            raise DecoderError('verification_failed')
                    if ips != sorted(set(ips)):
                        raise DecoderError('verification_failed')
                matched, missing, unexpected, unverified = (set(result[k]) for k in keys)
                sample = samples[index]
                if (matched & missing or matched | missing != set(sample['expected_ips'])
                        or (unexpected | unverified) & (matched | missing)
                        or (unverified if sample['complete_expected'] else unexpected)
                        or type(result['passed']) is not bool or result['passed'] != (not missing and not unexpected)):
                    raise DecoderError('verification_failed')
            canonical = _summary(results)
            if summary != canonical or any(type(summary[k]) is not type(v) for k, v in canonical.items()):
                raise DecoderError('verification_failed')
    if mode == 'catalog':
        if candidates != sorted(candidates, key=_rank):
            raise DecoderError('verification_failed')
    elif seen != list(inventory):
        raise DecoderError('verification_failed')
    return report


def _exchange(payload, cutoff):
    import subprocess
    import time
    global _active_child
    encoded = _bounded_json(payload, 65536)
    if not _worker_lock.acquire(blocking=False):
        raise DecoderError('busy')
    try:
        if _active_child is not None:
            if _active_child.poll() is None:
                raise DecoderError('verification_failed')
            _active_child = None
        try:
            _active_child = _spawn_worker(cutoff)
            try:
                report = _validate_report(_strict_load(_pump(_active_child, encoded, cutoff)), payload)
            finally:
                if _retire(_active_child):
                    _active_child = None
            if _active_child is not None or time.monotonic() >= cutoff:
                raise DecoderError('verification_failed')
            return report
        except (OSError, ValueError, TypeError, RecursionError, subprocess.TimeoutExpired):
            raise DecoderError('verification_failed') from None
    finally:
        _worker_lock.release()


def evaluate_catalog(kind, catalog, samples, deadline):
    """Complete deterministic catalog report, or an explicit typed failure.

    Catalog ranking is frozen on examples before *any* validation evaluation.
    The caller must never generate after verification_failed/incomplete search.
    """
    cutoff = _cutoff(deadline)
    _kind(kind)
    if type(catalog) is not dict or set(catalog) != {'kind', 'builtins', 'definitions'}:
        raise DecoderError()
    if catalog['kind'] != kind or catalog['builtins'] != _builtins(kind):
        raise DecoderError()
    key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
    owned = capture_catalog({key: catalog['definitions']}, kind)
    return _exchange({'mode': 'catalog', 'kind': kind, 'catalog': owned,
                      'samples': validate_samples(samples)}, cutoff)


def evaluate_generated(kind, candidates, samples, deadline):
    """Verify a fixed list of {steps} objects, never regenerate using holdouts."""
    cutoff = _cutoff(deadline)
    _kind(kind)
    if type(candidates) is not list or len(candidates) > 3:
        raise DecoderError('invalid_model_output')
    owned = []
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate) != {'steps'}:
            raise DecoderError('invalid_model_output')
        owned.append({'steps': validate_generated_steps(kind, candidate['steps'])})
    return _exchange({'mode': 'generated', 'kind': kind, 'candidates': owned,
                      'samples': validate_samples(samples)}, cutoff)
