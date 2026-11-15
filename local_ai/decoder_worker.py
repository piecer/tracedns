"""Private fresh-exec verifier. No pickle, dynamic code, registry writes or I/O tools.

Only this process constructs/runs saved or generated decoder closures. The owner
bounds wall time and all three pipes, and owns termination/reap on every exit.
"""
import ipaddress
import json
from pathlib import Path
import sys

if __name__ == '__main__':
    # -I -S avoids ambient PYTHONPATH/site hooks. Admit only this source tree.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from local_ai.decoder import DecoderError, _bounded_json


def _summary(results):
    return {
        'tested': len(results), 'passed': sum(r['passed'] for r in results),
        'known_matches': sum(len(r['matched_ips']) for r in results),
        'missing_expected': sum(len(r['missing_ips']) for r in results),
        'unexpected_outputs': sum(len(r['unexpected_ips']) for r in results),
        'unverified_extra_outputs': sum(len(r['unverified_extra_ips']) for r in results),
        'results': results,
    }


def _evaluate(fn, indexed_samples):
    results = []
    for index, sample in indexed_samples:
        observed = fn([sample['data']], domain=None)
        if type(observed) is not list:
            raise DecoderError('verification_failed')
        _bounded_json(observed, 65536)
        for ip in observed:
            if type(ip) is not str or str(ipaddress.IPv4Address(ip)) != ip:
                raise DecoderError('verification_failed')
        observed, expected = set(observed), set(sample['expected_ips'])
        missing, extras = sorted(expected - observed), sorted(observed - expected)
        unexpected = extras if sample['complete_expected'] else []
        results.append({'sample_index': index, 'matched_ips': sorted(expected & observed),
                        'missing_ips': missing, 'unexpected_ips': unexpected,
                        'unverified_extra_ips': [] if sample['complete_expected'] else extras,
                        'passed': not missing and not unexpected})
    return _summary(results)


def _rank(candidate):
    example = candidate['examples']
    return (-example['passed'], -example['known_matches'], example['missing_expected'],
            example['unexpected_outputs'], candidate['name'])


def verify(payload):
    import a_decoder
    import txt_decoder
    from http_api.decoder_crud import _validate_steps
    kind, mode, samples = payload['kind'], payload['mode'], payload['samples']
    factory = txt_decoder.create_custom_decoder if kind == 'TXT' else a_decoder.create_custom_a_decoder
    methods = txt_decoder.TXT_DECODE_METHODS if kind == 'TXT' else a_decoder.A_DECODE_METHODS
    candidates, callables = [], {}
    if mode == 'catalog':
        for name in payload['catalog']['builtins']:
            candidates.append({'name': name, 'source': 'builtin', 'steps': None})
            callables[name] = methods[name]
        definitions = payload['catalog']['definitions']
    else:
        definitions = [{'name': f'generated_{i + 1}', 'steps': c['steps']}
                       for i, c in enumerate(payload['candidates'])]
    # Freeze the complete list before evaluating any sample (no iterative search).
    for definition in definitions:
        steps = definition['steps']
        valid, _ = _validate_steps(steps, kind)
        if not valid:
            raise DecoderError('verification_failed')
        fn = factory(steps)
        if fn is None:
            raise DecoderError('verification_failed')
        name = definition['name']
        candidates.append({'name': name, 'source': 'custom' if mode == 'catalog' else 'generated', 'steps': steps})
        callables[name] = fn
    examples = [(i, s) for i, s in enumerate(samples) if s['usage'] == 'example']
    validation = [(i, s) for i, s in enumerate(samples) if s['usage'] == 'validation']
    for candidate in candidates:
        candidate['examples'] = _evaluate(callables[candidate['name']], examples)
    if mode == 'catalog':
        candidates.sort(key=_rank)
    # Ranking/selection is now fixed. Validation cannot change it.
    for candidate in candidates:
        candidate['validation'] = _evaluate(callables[candidate['name']], validation)
    limitations = ['candidate_not_proof', 'distinct_inputs_not_independent_observations']
    if mode == 'catalog':
        limitations.append('builtin_defaults_only')
    if not validation:
        limitations.append('no_validation_samples')
    return {'kind': kind, 'mode': mode, 'complete': True, 'distinct_inputs': len(samples),
            'example_count': len(examples), 'validation_count': len(validation),
            'evaluations': len(candidates) * len(samples),
            'ranking_basis': 'examples_only' if mode == 'catalog' else 'fixed_generation_order',
            'candidates': candidates, 'limitations': limitations}


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            return 1
        report = verify(json.loads(raw))
        sys.stdout.buffer.write(_bounded_json(report, 65536))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Raw samples, regex failures and runtime details never escape to logs.
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
