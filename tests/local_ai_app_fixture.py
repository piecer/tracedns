"""Real authenticated app and native-protocol peer; no model or external I/O.

Only native content and explicit audit/source fault barriers are controlled.
HTTP routes, jobs, engine, projections, decoder subprocesses and stores are real.
"""
import copy
import json
from pathlib import Path
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as ControlServer
from types import SimpleNamespace

from test_local_ai_provider import DIGEST, MODEL, envelope, http_response, peer
from test_local_ai_sources import InlineExecutor
from test_stage3_core_runtime import app_factory


@contextmanager
def application(root, monkeypatch, *, enabled=True):
    from http_api import relationship_handlers as rh
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore

    prior_threads = set(threading.enumerate())
    cleanup = {}
    native_gate = threading.Event()
    audit_gate = threading.Event()
    native_gate.set()
    audit_gate.set()
    state = {"native_mode": "normal", "audit_mode": "normal", "native_entered": 0,
             "audit_entered": 0, "store_failure": False, "misp_fixture_reads": 0, "forbidden": [], "http": []}

    def forbidden(*args, **kwargs):
        state["forbidden"].append("external provider")
        raise AssertionError("No external provider allowed in the application fixture")

    def reply(sock, stop):
        state["native_entered"] += 1
        while not native_gate.wait(.05):
            if stop.is_set():
                return
        request = json.loads(native_requests[-1]["body"])
        schema = request["format"]
        props = schema.get("oneOf", [schema])[0]["properties"]
        value = {key: props[key]["const"] for key in ("version", "kind", "language", "snapshot_digest")}
        if state["native_mode"] == "invalid":
            value = {"PRIVATE_PROVIDER_PROSE": "never display or retry"}
        elif value["kind"] == "decoder_suggest":
            value.update(candidates=[{"steps": [{"op": "base64"}, {"op": "ascii"}]}],
                         insufficient_reason=None)
        else:
            check = "inspect_pair_coverage" if value["kind"] == "relationship_pair" else "inspect_delivery_progress"
            value.update(summary=[{"text": "보존된 근거를 확인하세요. 귀속 증거가 아닙니다."
                                   if value["language"] == "ko" else
                                   "Inspect retained evidence; this is not attribution.",
                                   "evidence_ids": ["e1"]}],
                         counterpoints=[], limitations=[],
                         next_checks=[{"code": check, "evidence_ids": ["e1"]}])
        sock.sendall(http_response(envelope(json.dumps(value))))

    with peer(chat=reply) as (origin, native_requests, _):
        config = {"domains": [], "servers": [], "interval": 60, "config_revision": 0,
                  "alerts": {}, "custom_decoders": [
                      {"name": f"fixture_{i}", "steps": [{"op": "base64"}, {"op": "ascii"}]}
                      for i in range(6)],
                  "local_ai": {"enabled": True, "origin": origin, "model": MODEL, "model_digest": DIGEST}}
        if not enabled:
            config['local_ai'] = {'enabled': False}
        # The ordinary runtime also owns its sightings side-stream. Isolate it
        # before constructing the application, without relying on caller env.
        monkeypatch.setenv("MISP_SIGHTING_BATCH_FILE", str(root / "sightings.json"))
        core = app_factory(root / "ledger", config=config)
        server = control = server_thread = control_thread = None
        try:
            store = SecurityStore(root / "security" / "auth.db", create=True)
            store.bootstrap("fixture", "fixture-only-password")
            original_audit = store.audit_llm_lifecycle
            original_provider_state = store.llm_provider_state

            def provider_state():
                if state['store_failure']:
                    raise OSError('private store fault')
                return original_provider_state()

            monkeypatch.setattr(store, 'llm_provider_state', provider_state)

            def audit(*args, **kwargs):
                if kwargs["outcome"] == "completed":
                    state["audit_entered"] += 1
                    assert audit_gate.wait(15), "test must release terminal audit"
                    if state["audit_mode"] == "failed":
                        raise OSError("private fixture audit failure")
                return original_audit(*args, **kwargs)

            monkeypatch.setattr(store, "audit_llm_lifecycle", audit)
            handler = make_handler(config, core.cfg.lock, str(root / "ledger" / "config"),
                                   str(root / "history"), core.current, core.history,
                                   security_store=store, insecure_http=True,
                                   state_repository=core.repo, config_service=core.service,
                                   delivery_diagnostics=core.delivery.store.diagnostics_snapshot,
                                   delivery_health=core.delivery.health_snapshot)
            checkout = Path(__file__).resolve().parents[1]
            modules = ['http_server', 'http_api_handlers', 'security.store']
            if enabled:
                modules += ['local_ai.engine', 'local_ai.service', 'local_ai.sources',
                            'local_ai.provider', 'local_ai.decoder']
            for name in modules:
                filename = sys.modules[name].__file__
                assert filename is not None
                assert Path(filename).resolve() == checkout / (name.replace('.', '/') + '.py')

            class Producer(InlineExecutor):
                def __init__(self):
                    self._processes = {}

                def shutdown(self, **kwargs):
                    pass  # Inline execution creates no pool or processes.

            handler.relationship_jobs.executor = Producer()
            for name in ("begin_cache_batch", "end_cache_batch", "get_vt_runtime_config"):
                monkeypatch.setattr(rh, name, None)
            monkeypatch.setattr(rh, "_load_geoip_reader", lambda path: None)
            monkeypatch.setattr(rh, "get_ip_report", forbidden)
            # Only the exclusion test uses this in-memory source. No MISP
            # transport/client is constructed; normalization/scoring stay real.
            import mispupdate_code

            def synthetic_event(event_id):
                assert event_id == 17
                state['misp_fixture_reads'] += 1
                return {'Event': {'id': '17', 'distribution': '3', 'Attribute': []}}

            monkeypatch.setattr(mispupdate_code, 'misp', SimpleNamespace(get_event=synthetic_event))

            class ObservedHandler(handler):
                def send_response(self, code, message=None):
                    state["http"].append({"method": self.command, "path": self.path, "status": code})
                    return super().send_response(code, message)

                def log_message(self, *args):
                    pass

            def snapshot():
                return {**copy.deepcopy(state),
                        "native": [{"path": r["path"], "body": r["body"].decode()} for r in native_requests],
                        "config": {k: copy.deepcopy(v) for k, v in config.items()
                                   if k in ("config_revision", "custom_decoders", "custom_a_decoders")},
                        "interlock": original_provider_state()}

            class Control(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    body = json.dumps(snapshot()).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_POST(self):
                    value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    action = value["action"]
                    if action == "native":
                        state["native_mode"] = value["mode"]
                        (native_gate.clear if value["mode"] == "gate" else native_gate.set)()
                    elif action == "audit":
                        state["audit_mode"] = value["mode"]
                        (audit_gate.clear if value["mode"] == "gate" else audit_gate.set)()
                    elif action == 'availability':
                        if value['mode'] == 'unavailable':
                            state['store_failure'] = True
                        elif value['mode'] == 'stopped':
                            handler.local_ai.stop_admission()
                        elif value['mode'] == 'unsettled':
                            assert store.begin_llm_provider('f' * 32, store.list_users()[0])
                        else:
                            raise AssertionError('unknown availability fault')
                    else:
                        raise AssertionError("unknown fixture control")
                    self.do_GET()

            server = ThreadingHTTPServer(("127.0.0.1", 0), ObservedHandler)
            control = ControlServer(("127.0.0.1", 0), Control)
            server_thread = threading.Thread(target=server.serve_forever)
            control_thread = threading.Thread(target=control.serve_forever)
            server_thread.start()
            control_thread.start()
            assert native_requests == []
            yield SimpleNamespace(origin=f"http://127.0.0.1:{server.server_port}",
                                  control=f"http://127.0.0.1:{control.server_port}", snapshot=snapshot, cleanup=cleanup)
        finally:
            native_gate.set()
            audit_gate.set()
            for listener in (control, server):
                if listener is not None:
                    listener.shutdown()
                    listener.server_close()
            for thread in (control_thread, server_thread):
                if thread is not None:
                    thread.join(5)
                    assert not thread.is_alive()
            core.delivery.stop()
            assert not state["forbidden"], state["forbidden"]
            from local_ai import decoder
            assert decoder._active_child is None
            if server is not None:
                cleanup['background_shutdown'] = server.background_shutdown
                assert all(row is None or not isinstance(row, dict) or row.get('complete', True)
                           for row in server.background_shutdown)
    cleanup['remaining_owned_threads'] = [thread.name for thread in threading.enumerate()
                                           if thread not in prior_threads and thread.is_alive()]
    cleanup['decoder_child'] = None
    cleanup['native_peer_retired'] = True  # peer's own join/assert completed above.
    assert cleanup['remaining_owned_threads'] == []
