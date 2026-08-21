import io
import json
import threading
from unittest import mock

import http_api_handlers
import mispupdate_code


class FakeHandler:
    def __init__(self, body):
        self.rfile = io.BytesIO(json.dumps(body).encode("utf-8"))
        self.headers = {"Content-Length": str(len(self.rfile.getvalue()))}
        self.wfile = io.BytesIO()
        self.status_code = None

    def send_response(self, code, message=None):
        self.status_code = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass


def _attach_handler():
    class Handler(FakeHandler):
        pass

    http_api_handlers.attach_api_handlers(
        Handler,
        frontend_html="dns_frontend.html",
        shared_config={},
        config_lock=threading.RLock(),
        config_path="",
        history_dir="",
        current_results={},
        history={},
        purge_removed_domains_state=lambda *_args, **_kwargs: None,
    )
    return Handler


class FakeMispClient:
    def get_event(self, event_id):
        assert event_id == 42
        return {
            "Event": {
                "id": "42",
                "info": "Restricted campaign",
                "distribution": "0",
                "Orgc": {"name": "Sensitive producer"},
                "Tag": [{"name": "internal:campaign=secret"}],
                "Attribute": [
                    {
                        "type": "ip-src",
                        "value": "8.8.8.8",
                        "to_ids": True,
                    },
                    {
                        "type": "ip-src|port",
                        "value": "1.1.1.1|443",
                        "to_ids": True,
                    },
                ],
            }
        }


def test_restricted_misp_loader_returns_ips_but_keeps_context_redacted():
    handler_cls = _attach_handler()
    handler = handler_cls({"event_id": 42})

    with mock.patch.object(mispupdate_code, "misp", FakeMispClient()):
        getattr(handler, "_handle_misp_event_ips")()

    response = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert handler.status_code == 200
    assert response["status"] == "ok"
    assert response["event_id"] == 42
    assert response["count"] == 2
    assert response["ips"] == ["8.8.8.8", "1.1.1.1"]
