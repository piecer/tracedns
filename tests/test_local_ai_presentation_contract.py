"""Producer bytes through the shipped JS validators (VM, not app acceptance)."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from local_ai_presentation_fixture import build_fixtures, decoder_result, digest, sample
from test_local_ai_facts_summary import delivery_snapshot, pair_snapshot

ROOT = Path(__file__).resolve().parents[1]
VM = r"""
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
const source=fs.readFileSync('local_ai_frontend.js','utf8');
const sandbox={window:{},TextEncoder,AbortController};
vm.createContext(sandbox);
vm.runInContext(source.replace('window.TraceLocalAI=Object.freeze({mount});',
  'window.TraceLocalAI=Object.freeze({mount,validResult,validEnvelope});'),sandbox);
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
for(const c of cases){
  let hooks=0;
  const sidecar=c.result.facts_summary || c.result.model_input;
  if(c.rawMutation==='hidden-extra')Object.defineProperty(sidecar,'hidden',{value:null});
  if(c.rawMutation==='symbol-extra')sidecar[Symbol('unknown')]=1;
  if(c.rawMutation==='getter')Object.defineProperty(sidecar,'version',{enumerable:true,get(){hooks++;return 1;}});
  if(c.rawMutation==='toJSON')Object.defineProperty(sidecar,'toJSON',{value(){hooks++;return {};}});
  if(c.rawMutation==='inherited')Object.setPrototypeOf(sidecar,{extra:'PRIVATE'});
  if(c.rawMutation==='inherited-null-toJSON'){
    const proto=Object.create(null);proto.toJSON=function(){hooks++;return {};};
    Object.setPrototypeOf(sidecar,proto);
  }
  if(c.rawMutation==='array-inherited-toJSON'){
    const proto=Object.create(Array.prototype);proto.toJSON=function(){hooks++;return [];};
    Object.setPrototypeOf(sidecar.summary,proto);
  }
  if(c.rawMutation==='sparse')delete sidecar.summary[0];
  const before=c.rawMutation?null:JSON.stringify(c.result);
  assert.equal(sandbox.window.TraceLocalAI.validResult(c.result,c.request),c.accept,c.name);
  if(c.rawMutation){
    const job={job_id:'b'.repeat(32),kind:c.request.kind,language:c.request.language,status:'completed',
      created_at:1,deadline_at:2,audit_status:'success',error:null,result:c.result,cancel_requested:false};
    assert.equal(sandbox.window.TraceLocalAI.validEnvelope(job,c.request),false,'raw envelope '+c.rawMutation);
  }
  assert.equal(hooks,0,'closed boundary must not execute getter/toJSON hooks');
  if(!c.rawMutation)assert.equal(JSON.stringify(c.result),before,'validation must not repair '+c.name);
}
console.log(JSON.stringify({cases:cases.length,passed:true}));
"""


def check(cases):
    result = subprocess.run(['node', '-e', VM], input=json.dumps(cases), cwd=ROOT,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'cases': len(cases), 'passed': True}


def explanation(snapshot, language='en'):
    kind = snapshot['kind']
    commitment = digest(snapshot)
    request = {'kind': kind, 'language': language}
    if kind == 'relationship_pair':
        request['source'] = {key: snapshot['source'][key] for key in ('job_id', 'a', 'b')}
    result = {'snapshot': snapshot, 'snapshot_digest': commitment,
              'source_revision': 7, 'model': {'model': 'controlled-fixture', 'model_digest': 'c' * 64},
              'interpretation': {'version': 1, 'kind': kind, 'language': language,
                                 'snapshot_digest': commitment,
                                 'summary': [{'text': 'Unverified fixture prose',
                                              'evidence_ids': [snapshot['facts'][0]['id']]}],
                                 'counterpoints': [], 'limitations': [], 'next_checks': []}}
    result['facts_summary'] = build_fixtures({'snapshots': {'case': snapshot}})['facts_summary']['case'][language]
    return request, result


def test_required_server_facts_accept_producer_and_reject_legacy():
    cases = []
    for snapshot in (pair_snapshot(), delivery_snapshot()):
        for language in ('en', 'ko'):
            request, result = explanation(snapshot, language)
            cases.append({'name': snapshot['kind'] + language, 'request': request,
                          'result': result, 'accept': True})
            old = copy.deepcopy(result)
            del old['facts_summary']
            cases.append({'name': 'missing required server facts', 'request': request,
                          'result': old, 'accept': False})
    check(cases)


def mutation_case(request, result, name, path, replacement=None, delete=False):
    changed = copy.deepcopy(result)
    target = changed
    for key in path[:-1]:
        target = target[key]
    if delete:
        del target[path[-1]]
    else:
        target[path[-1]] = replacement
    return {'name': name, 'request': request, 'result': changed, 'accept': False}


def test_server_facts_closed_shapes_scope_codes_and_specific_citations():
    cases = []
    for snapshot in (pair_snapshot(), delivery_snapshot()):
        # IDs and order are not semantics. Resolve expected citations by key.
        for index, fact in enumerate(reversed(snapshot['facts']), 20):
            fact['id'] = f'e{index}'
        snapshot['facts'].reverse()
        request, result = explanation(snapshot)
        cases.append({'name': 'reordered fact handles', 'request': request, 'result': result, 'accept': True})
        summary = result['facts_summary']
        cases.append(mutation_case(request, result, 'model identity required', ['model'], None))
        for key in summary:
            cases.append(mutation_case(request, result, 'missing ' + key, ['facts_summary', key], delete=True))
        for key, value in [('extra', 'PRIVATE'), ('version', True), ('kind', 'decoder_suggest'),
                           ('language', 'ko'), ('snapshot_digest', 'f' * 64), ('summary', None),
                           ('counterpoints', {}), ('limitations', [])]:
            cases.append(mutation_case(request, result, 'invalid ' + key, ['facts_summary', key], value))
        for section in ('summary', 'counterpoints', 'limitations'):
            claims = summary[section]
            cases.append(mutation_case(request, result, 'extra claim', ['facts_summary', section],
                                       claims + [copy.deepcopy(summary['summary'][0])]))
            if not claims:
                continue
            for key in claims[0]:
                cases.append(mutation_case(request, result, 'missing claim ' + key,
                                           ['facts_summary', section, 0, key], delete=True))
            for key, value in [('extra', 'PRIVATE'), ('code', 'unknown'), ('code', ['pair_scope']),
                               ('text', ''), ('text', ['PRIVATE']), ('text', '가' * 171),
                               ('text', '\ud800'), ('evidence_ids', []), ('evidence_ids', ['e999']),
                               ('evidence_ids', [None]), ('evidence_ids', claims[0]['evidence_ids'] * 2)]:
                cases.append(mutation_case(request, result, 'invalid claim ' + key,
                                           ['facts_summary', section, 0, key], value))
            wrong = next(f['id'] for f in snapshot['facts'] if f['id'] not in claims[0]['evidence_ids'])
            cases.append(mutation_case(request, result, 'existing but wrong semantic citation',
                                       ['facts_summary', section, 0, 'evidence_ids'], [wrong]))
            if len(claims) > 1:
                cases.append(mutation_case(request, result, 'ordered mandatory codes',
                                           ['facts_summary', section], list(reversed(claims))))
        # Escaping can exceed the total budget while all individual texts fit.
        oversized = copy.deepcopy(result)
        for section in ('summary', 'counterpoints', 'limitations'):
            for claim in oversized['facts_summary'][section]:
                claim['text'] = '\x00' * 512
        cases.append({'name': 'encoded summary cap', 'request': request, 'result': oversized, 'accept': False})
    check(cases)



@pytest.fixture(scope='module')
def decoder_pair():
    return decoder_result([sample('192.0.2.1'), sample('192.0.2.2', 'validation')])


def test_required_model_input_and_model_identity(decoder_pair):
    request, result = decoder_pair
    cases = [{'name': 'real producer model input', 'request': request, 'result': result, 'accept': True}]
    cases.append(mutation_case(request, result, 'legacy missing model_input', ['model_input'], delete=True))
    cases.append(mutation_case(request, result, 'generated null input', ['model_input'], None))
    cases.append(mutation_case(request, result, 'generated null model', ['model'], None))
    request = {**request, 'generate': False}
    catalog = {**result, 'model_input': None, 'model': None, 'generated': None, 'proposal': None}
    cases.append({'name': 'catalog only explicit null', 'request': request, 'result': catalog, 'accept': True})
    cases.append(mutation_case(request, catalog, 'catalog model input forbidden', ['model_input'], result['model_input']))
    cases.append(mutation_case(request, catalog, 'catalog model forbidden', ['model'], result['model']))
    cases.append(mutation_case(request, catalog, 'catalog input required', ['model_input'], delete=True))
    check(cases)


@pytest.mark.parametrize('texts', [
    ['x' * n] for n in (1023, 1024, 1025)
] + [
    [token * (1300 // len(token.encode('utf-8')))]
    for token in ('é', '한', '🙂', 'e\u0301', '"', '\\', '\n', '\x00', '<>&', '\u2028\u2029')
] + [['ok', 'A' * 1600, 'A' * 800 + 'B' + 'A' * 799],
     [f'192.0.2.{i}|'.ljust(1800, chr(64 + i)) for i in range(1, 5)]])
def test_model_input_matches_exact_producer_utf8_allocation(texts):
    request, result = decoder_result([sample(text) for text in texts] + [sample('HOLDOUT NEVER SHOWN', 'validation')])
    cases = [{'name': 'actual UTF8 producer allocation', 'request': request, 'result': result, 'accept': True}]
    coverage = result['model_input']['coverage']
    for key, value in coverage.items():
        cases.append(mutation_case(request, result, 'wrong coverage ' + key,
                                   ['model_input', 'coverage', key], value + 1))
    row = result['model_input']['view']['examples'][0]
    if 'excerpt' in row:
        for key, value in row['excerpt'].items():
            cases.append(mutation_case(request, result, 'wrong excerpt ' + key,
                                       ['model_input', 'view', 'examples', 0, 'excerpt', key],
                                       value + 1 if isinstance(value, int) else value + 'x'))
        # A self-consistent byte count is not a canonical allocation.
        forged = copy.deepcopy(result)
        excerpt = forged['model_input']['view']['examples'][0]['excerpt']
        removed = len(excerpt['prefix'][0].encode('utf-8'))
        excerpt['prefix'] = excerpt['prefix'][1:]
        excerpt['omitted_utf8_bytes'] += removed
        forged['model_input']['coverage']['shown_utf8_bytes'] -= removed
        forged['model_input']['coverage']['omitted_utf8_bytes'] += removed
        cases.append({'name': 'coherent but noncanonical allocation', 'request': request, 'result': forged, 'accept': False})
    else:
        cases.append(mutation_case(request, result, 'altered complete raw data',
                                   ['model_input', 'view', 'examples', 0, 'data'], row['data'] + '!'))
    check(cases)


def test_model_input_closed_nested_shapes_and_scope(decoder_pair):
    request, result = decoder_pair
    cases = []
    paths = [['model_input'], ['model_input', 'view'], ['model_input', 'coverage'],
             ['model_input', 'view', 'examples', 0]]
    for path in paths:
        value = result
        for key in path:
            value = value[key]
        for key in value:
            cases.append(mutation_case(request, result, 'missing ' + str(path + [key]), path + [key], delete=True))
        cases.append(mutation_case(request, result, 'extra nested field', path + ['extra'], 'PRIVATE'))
    for key, value in [('version', True), ('policy', 'other'), ('source_snapshot_digest', 'f' * 64),
                       ('messages_schema_bytes', 0), ('messages_schema_bytes', 16385),
                       ('messages_schema_bytes', 1.5), ('messages_schema_bytes', '100'),
                       ('messages_schema_digest', 'G' * 64), ('view', None), ('coverage', [])]:
        cases.append(mutation_case(request, result, 'invalid model_input ' + key, ['model_input', key], value))
    for key, value in [('usage', 'validation'), ('complete_expected', False), ('expected_ips', ['192.0.2.2'])]:
        cases.append(mutation_case(request, result, 'foreign example labels',
                                   ['model_input', 'view', 'examples', 0, key], value))
    cases.append(mutation_case(request, result, 'holdout in model view', ['model_input', 'view', 'examples'],
                               result['model_input']['view']['examples'] + [request['samples'][1]]))
    check(cases)


def test_sidecars_are_closed_before_copy_or_serialization(decoder_pair):
    cases = []
    for request, result in (decoder_pair, explanation(pair_snapshot())):
        mutations = ['hidden-extra', 'symbol-extra', 'getter', 'toJSON', 'inherited']
        if 'facts_summary' in result:
            mutations.append('sparse')
        for name in mutations:
            cases.append({'name': name, 'request': request, 'result': result, 'accept': False, 'rawMutation': name})
    check(cases)


@pytest.mark.parametrize('mutation', ['inherited-null-toJSON', 'array-inherited-toJSON'])
def test_inherited_serialization_hooks_never_run(mutation):
    request, result = explanation(pair_snapshot())
    check([{'name': mutation, 'request': request, 'result': result, 'accept': False, 'rawMutation': mutation}])


def test_abstaining_generation_still_requires_actual_empty_verifier_report():
    import time
    from local_ai.decoder import evaluate_generated
    request, result = decoder_result([sample('192.0.2.1')])
    result['generated'] = evaluate_generated('TXT', [], request['samples'], time.monotonic() + 15)
    check([{'name': 'empty verified proposal', 'request': request, 'result': result, 'accept': True},
           mutation_case(request, result, 'missing generated verification', ['generated'], None)])


def test_fixture_cli_is_deterministic_and_uses_exact_caller_snapshots(decoder_pair):
    from local_ai_presentation_fixture import canonical
    from local_ai.facts_summary import SUMMARY_CODES

    supplied = {'snapshots': {'pair': pair_snapshot(), 'delivery': delivery_snapshot()},
                'decoder_snapshots': {'decoder': decoder_pair[1]['snapshot']}}
    expected = canonical(build_fixtures(supplied)) + b'\n'
    outputs = []
    for _ in range(2):
        command = [sys.executable, '-B', str(ROOT / 'tests/local_ai_presentation_fixture.py')]
        completed = subprocess.run(command, input=canonical(supplied), cwd=ROOT,
                                   capture_output=True, timeout=20)
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout)
    assert outputs == [expected, expected]
    sidecars = json.loads(expected)
    for source, languages in sidecars['facts_summary'].items():
        snapshot = supplied['snapshots'][source]
        for summary in languages.values():
            assert summary['snapshot_digest'] == digest(snapshot)
            for section, codes in SUMMARY_CODES[snapshot['kind']].items():
                assert tuple(row['code'] for row in summary[section]) == codes
    for data in sidecars['decoder']['decoder'].values():
        import hashlib
        checked = data['checked_bundle'].encode('utf-8')
        assert data['model_input']['messages_schema_bytes'] == len(checked)
        assert data['model_input']['messages_schema_digest'] == hashlib.sha256(checked).hexdigest()
