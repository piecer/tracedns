"""Parent closure of mounted settings/OpenAPI and existing inference consumers."""
import json
from pathlib import Path
import subprocess

import jsonschema
import pytest

from http_api import ai_settings_schema as schema
from local_ai.contracts import AIError, ERROR_STATUS
from local_ai.provider_settings import public_settings, normalize_settings


@pytest.mark.parametrize('digest', ['', 'a' * 64, '\n', 'a' * 64 + '\n'])
@pytest.mark.parametrize('surface', ['request', 'get', 'post'])
def test_settings_digest_schema_preserves_exact_complete_token(surface, digest):
    accepted = digest in ('', 'a' * 64)
    settings = {**public_settings(None), 'model_digest': digest}
    if surface == 'request':
        document = {'revision': 0, 'settings': {'model_digest': digest}}
        contract = schema.REQUEST_SCHEMA
    else:
        document = {'revision': 0, 'settings': settings,
                    'runtime': {'applied': True, 'state': 'disabled'}}
        contract = schema.GET_SCHEMA
        if surface == 'post':
            document.update(status='ok', warnings=[])
            contract = schema.POST_SCHEMA
    assert jsonschema.Draft202012Validator(contract).is_valid(document) == accepted
    if accepted:
        assert normalize_settings({'provider': 'ollama', 'model_digest': digest})['model_digest'] == digest
    else:
        with pytest.raises(AIError):
            normalize_settings({'provider': 'ollama', 'model_digest': digest})


def test_openapi_registers_closed_admin_settings_without_inference_role_or_body_budget():
    from http_api.openapi import openapi_document
    document = openapi_document()
    route = document['paths']['/ai/settings']
    assert set(route) == {'get', 'post'}
    for method, success in [('get', schema.GET_SCHEMA), ('post', schema.POST_SCHEMA)]:
        op = route[method]
        assert op['x-roles'] == ['admin']
        assert op['x-max-body-bytes'] == op['x-max-response-bytes'] == 16384
        assert op['responses']['200']['content']['application/json']['schema'] == success
        for code in ('400', '409', '413', '500', '503'):
            assert schema.ERROR_SCHEMA in op['responses'][code]['content']['application/json']['schema']['anyOf']
    assert route['post']['requestBody']['content']['application/json']['schema'] == schema.REQUEST_SCHEMA
    assert route['post']['security'] == [{'session': [], 'csrf': []}]
    assert document['paths']['/ai/status']['get']['x-roles'] == ['operator', 'admin']


def test_all_producer_error_codes_reach_the_shipped_job_envelope_parser():
    source = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const text=fs.readFileSync('local_ai_frontend.js','utf8'),box={window:{},TextEncoder,AbortController};
vm.createContext(box);assert.equal(text.split('window.TraceLocalAI=Object.freeze({mount});').length,2);
vm.runInContext(text.replace('window.TraceLocalAI=Object.freeze({mount});',
 'window.TraceLocalAI=Object.freeze({mount,validEnvelope});'),box);
const codes=JSON.parse(fs.readFileSync(0,'utf8'));
for(const code of [...codes,'unknown-error']){
 const job={job_id:'a'.repeat(32),kind:'delivery',language:'en',status:'failed',created_at:1,
 deadline_at:2,audit_status:'success',error:code,result:null,cancel_requested:false};
 assert.equal(box.window.TraceLocalAI.validEnvelope(job,{kind:'delivery',language:'en'}),code!=='unknown-error',code);
}
"""
    result = subprocess.run(['node', '-e', source], input=json.dumps(list(ERROR_STATUS)), text=True,
                            capture_output=True, cwd=Path(__file__).resolve().parents[1], timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
