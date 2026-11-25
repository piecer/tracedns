"""Unintercepted authenticated UI -> settings -> compatible/native peers -> result."""
import json
import os
from pathlib import Path
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from test_ai_settings_api import app as app_fixture
from test_local_ai_openai_provider import KEY, envelope, no_proxy as no_proxy, peer, response

app = app_fixture
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('scenario', ['delivery-en', 'delivery-ko', 'decoder', 'auth-error',
                                     'request-error', 'rate-error', 'uncertain', 'reconfigure'])
def test_actual_ai_settings_application_browser(app, tmp_path, scenario):
    upstream = {'auth-error': 401, 'request-error': 400, 'rate-error': 429, 'uncertain': 500}.get(scenario, 200)

    def answer(sock, stop):
        from local_ai import openai_provider, resolver
        assert Path(openai_provider.__file__).resolve() == ROOT / 'local_ai/openai_provider.py'
        assert Path(resolver.__file__).resolve() == ROOT / 'local_ai/resolver.py'
        message = json.loads(requests[-1]['body'])
        assert [m['role'] for m in message['messages']] == ['system', 'user']
        assert message['stream'] is False and message['store'] is False and message['n'] == 1
        schema = json.loads(message['messages'][0]['content'].split('\nRequired JSON Schema: ', 1)[1])
        props = schema.get('oneOf', [schema])[0]['properties']
        value = {k: props[k]['const'] for k in ('version', 'kind', 'language', 'snapshot_digest')}
        if value['kind'] == 'decoder_suggest':
            value.update(candidates=[{'steps': [{'op': 'base64'}, {'op': 'ascii'}]}], insufficient_reason=None)
            assert 'MTk4LjUxLjEwMC4xNw==' not in message['messages'][1]['content']
        else:
            value.update(summary=[{'text': '보존된 근거를 확인하세요.' if value['language'] == 'ko'
                                   else 'Inspect retained evidence.', 'evidence_ids': ['e1']}],
                         counterpoints=[], limitations=[], next_checks=[])
        reply = envelope(json.dumps(value))
        reply['choices'][0]['message'].update(annotations=[], audio=None, function_call=None, tool_calls=[])
        if scenario.startswith('delivery'):
            reply.pop('usage')  # Missing observations must not become invented zero counters.
        sock.sendall(response(reply if upstream == 200 else b'SYNTHETIC upstream failure', upstream))

    with peer(answer) as (url, requests):
        class Observer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = json.dumps({'compatible_calls': len(requests), 'native_calls': len(app.native_requests),
                                   'revision': app.config['config_revision'],
                                   'custom_names': [x['name'] for x in app.config.get('custom_decoders', [])],
                                   'blocked': app.store.llm_provider_state()['blocked']}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        observer = ThreadingHTTPServer(('127.0.0.1', 0), Observer)
        thread = threading.Thread(target=observer.serve_forever)
        try:
            thread.start()
            result = subprocess.run(['node', 'tests/ai_settings_application_browser.js',
                                     f'http://127.0.0.1:{app.client.port}',
                                     f'http://127.0.0.1:{observer.server_port}', url + '/v1',
                                     scenario, str(tmp_path)], cwd=ROOT,
                                    env={**os.environ, 'AI_TEST_NATIVE_SETTINGS': json.dumps(app.native)},
                                    capture_output=True, text=True, timeout=100)
            assert result.returncode == 0, result.stdout + result.stderr
            receipt = json.loads((tmp_path / 'acceptance.json').read_text())
            assert receipt['scope'] == 'authenticated-real-api-controlled-provider'
            assert receipt['page_errors'] == []
            assert requests and requests[0]['headers']['Authorization'] == 'Bearer ' + KEY
            assert all(KEY not in row['body'].decode() for row in requests)
            if scenario == 'reconfigure':
                assert len(requests) == 2 and 'Authorization' not in requests[-1]['headers']
                assert [x['path'] for x in app.native_requests] == ['/api/tags', '/api/chat']
            else:
                assert len(requests) == 1 and not app.native_requests
            assert app.store.llm_provider_state()['blocked'] is (scenario == 'uncertain')
        finally:
            if thread.is_alive():
                observer.shutdown()
            observer.server_close()
            thread.join(5)
            assert not thread.is_alive()
