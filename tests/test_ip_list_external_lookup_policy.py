import io
import json
import threading
from unittest import mock

import http_api_handlers
import pytest


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


def _attach_handler(current_results=None, history=None):
    class Handler(FakeHandler):
        pass

    http_api_handlers.attach_api_handlers(
        Handler,
        frontend_html="dns_frontend.html",
        shared_config={},
        config_lock=threading.RLock(),
        config_path="",
        history_dir="",
        current_results=current_results or {},
        history=history or {},
        purge_removed_domains_state=lambda *_args, **_kwargs: None,
    )
    return Handler


def test_ip_list_analysis_only_sends_global_addresses_to_virustotal():
    handler_cls = _attach_handler()
    calls = []

    def vt_spy(ip, cache_only=False):
        calls.append((ip, cache_only))
        return {"raw": {"data": {"attributes": {}}}}

    handler = handler_cls({
        "ips": ["10.0.0.1", "8.8.8.8", "::1", "2606:4700:4700::1111"],
        "include_vt": True,
        "vt_workers": 1,
        "vt_lookup_budget": 1,
    })
    with (
        mock.patch.object(http_api_handlers, "get_ip_report", side_effect=vt_spy),
        mock.patch.object(http_api_handlers, "begin_cache_batch"),
        mock.patch.object(http_api_handlers, "end_cache_batch"),
    ):
        getattr(handler, "_handle_ip_list_analysis")()

    response = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert calls == [
        ("2606:4700:4700::1111", True),
        ("8.8.8.8", False),
    ]
    assert response["vt_eligible_count"] == 2
    assert response["vt_skipped_non_global"] == 2
    assert response["vt_lookup_attempted"] == 1
    rows = {row["ip"]: row for row in response["ips"]}
    assert rows["10.0.0.1"]["vt_source"] == "skipped_non_global"
    assert rows["::1"]["vt_source"] == "skipped_non_global"


def test_external_lookup_scope_helper_rejects_non_global_addresses():
    assert http_api_handlers._is_global_external_lookup_ip("8.8.8.8") is True
    assert http_api_handlers._is_global_external_lookup_ip("2606:4700:4700::1111") is True
    for ip in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "fc00::1", "invalid"):
        assert http_api_handlers._is_global_external_lookup_ip(ip) is False


def test_domain_analysis_never_sends_non_global_addresses_to_virustotal():
    handler_cls = _attach_handler(current_results={
        "example.test": {
            "resolver": {
                "type": "A",
                "values": ["10.0.0.1", "8.8.8.8"],
                "decoded_ips": ["127.0.0.1"],
                "ts": 1,
            }
        }
    })
    calls = []
    handler = handler_cls({})
    with (
        mock.patch.object(http_api_handlers, "get_ip_report", side_effect=lambda ip: calls.append(ip) or {}),
        mock.patch.object(http_api_handlers, "begin_cache_batch"),
        mock.patch.object(http_api_handlers, "end_cache_batch"),
    ):
        getattr(handler, "_handle_domain_analysis")({"include_vt": ["1"]})

    assert calls == ["8.8.8.8"]


@pytest.mark.parametrize("vt_workers", [1, 4])
def test_ips_page_only_sends_global_addresses_to_virustotal(vt_workers):
    handler_cls = _attach_handler()
    handler = handler_cls({})
    addresses = [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "192.0.2.1",
        "fc00::1",
        "8.8.8.8",
        "2606:4700:4700::1111",
    ]
    setattr(
        handler,
        "_gather_ip_rows",
        lambda: [{"ip": ip, "last_ts": 1} for ip in addresses],
    )
    calls = []

    with (
        mock.patch.object(
            http_api_handlers,
            "get_ip_report",
            side_effect=lambda ip: calls.append(ip) or {},
        ),
        mock.patch.object(http_api_handlers, "begin_cache_batch"),
        mock.patch.object(http_api_handlers, "end_cache_batch"),
    ):
        getattr(handler, "_handle_ips")({
            "include_vt": ["1"],
            "vt_workers": [str(vt_workers)],
            "vt_budget": ["8"],
        })

    response = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert set(calls) == {"8.8.8.8", "2606:4700:4700::1111"}
    assert response["vt_eligible_count"] == 2
    assert response["vt_skipped_non_global"] == 6
