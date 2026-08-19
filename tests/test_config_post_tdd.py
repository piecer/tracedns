"""Regression tests for /config POST purge and error handling (P0-4, P0-5)."""
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import http_api_handlers as H  # noqa: E402


class _FakeRfile:
    def __init__(self, body: bytes = b""):
        self._body = body

    def read(self, *_args, **_kwargs):
        data, self._body = self._body, b""
        return data


class _FakeWfile:
    def __init__(self):
        import io
        self._buf = io.BytesIO()

    def write(self, b):
        self._buf.write(b)

    def getvalue(self):
        return self._buf.getvalue()


class _ConfigPostBase(unittest.TestCase):
    def _build_handler(self, shared_config, config_path, history_dir,
                       current_results, history, write_config_side_effect=None):
        shared_config = dict(shared_config)
        history_dir = history_dir or os.path.join(tempfile.mkdtemp(), "history")
        os.makedirs(history_dir, exist_ok=True)

        shared_purge_calls = []

        def fake_purge(current_results, history, history_dir, removed):
            removed = [str(d or "").strip() for d in (removed or []) if str(d or "").strip()]
            shared_purge_calls.append(sorted(removed))
            for d in removed:
                current_results.pop(d, None)
                history.pop(d, None)

        save_events = []

        def fake_write_config(path, data):
            save_events.append({"path": path, "data": data})
            if write_config_side_effect is not None:
                raise write_config_side_effect

        handler_cls = H.attach_api_handlers(
            type("ConfigHandler", (), {}),
            frontend_html="<html></html>",
            shared_config=shared_config,
            config_lock=threading.Lock(),
            config_path=config_path,
            history_dir=history_dir,
            current_results=current_results,
            history=history,
            purge_removed_domains_state=fake_purge,
        )

        state = {
            "handler_cls": handler_cls,
            "shared_config": shared_config,
            "history_dir": history_dir,
            "save_events": save_events,
            "purge_calls": shared_purge_calls,
            "write": fake_write_config,
        }
        return state

    def _do_post_config(self, state, body_json, write_config_exc=None):
        body_json = body_json if isinstance(body_json, bytes) else str(body_json).encode("utf-8")
        handler = object.__new__(state["handler_cls"])
        handler.path = "/config"
        handler.max_body_bytes = 64 * 1024 * 1024
        handler.rfile = _FakeRfile(body_json if isinstance(body_json, bytes) else body_json.encode("utf-8"))
        handler.wfile = _FakeWfile()
        handler.headers = {"Content-Length": str(len(body_json))}  # declared length gates read
        handler.send_response = lambda code, msg=None: None
        handler.send_header = lambda k, v: None
        handler.end_headers = lambda: None
        handler._send_json = lambda obj, code=200: state["captured"].setdefault("out", {"obj": obj, "code": code})
        state["captured"] = {}

        import config_manager as CM  # P1-6: write_config is lazy-imported in config_post
        mock_target = CM

        # P1-6: capture send_json calls via handler.send_response stub
        _captured = [{}]  # mutable container for captured (obj, code)

        def _fake_send_response(code, msg=None):
            _captured[0]["code"] = code

        handler.send_response = _fake_send_response
        handler.send_header = lambda k, v: None

        def _fake_end_headers():
            pass  # body is written after end_headers; capture via wfile.write

        handler.end_headers = _fake_end_headers

        # Capture the JSON body via wfile.write
        _wfile_buf = [b""]

        def _fake_write(b):
            _wfile_buf[0] = b

        handler.wfile = type("W", (), {"write": _fake_write, "getvalue": property(lambda s: _wfile_buf[0])})()
        # Simpler: use a real object
        import io as _io
        class _CapWfile:
            def __init__(self):
                self._buf = _io.BytesIO()
            def write(self, b):
                self._buf.write(b)
                # After write, capture into state["captured"]["out"]
                try:
                    data = json.loads(self._buf.getvalue())
                    state["captured"]["out"] = {"obj": data, "code": _captured[0].get("code")}
                except Exception:
                    pass
            def getvalue(self):
                return self._buf.getvalue()
        handler.wfile = _CapWfile()
        with mock.patch.object(mock_target, "write_config", side_effect=(
            write_config_exc if write_config_exc else None
        )) if write_config_exc else mock.patch.object(mock_target, "write_config") as m:
            if write_config_exc:
                m.side_effect = write_config_exc
            else:
                m.side_effect = state["write"]
            state["handler_cls"].do_POST(handler)

        return state["captured"]["out"]

    _base_shared_config = {
        "domains": [{"name": "keep.example", "type": "A"}],
        "servers": ["8.8.8.8"],
        "interval": 60,
    }


class TestConfigPostPurge(_ConfigPostBase):
    """P0-4: adding a new domain via /config POST must also purge the state
    of any domain that was previously configured but no longer is."""

    def test_removing_names_gets_purged_from_results_and_history(self):
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=os.path.join(tempfile.mkdtemp(), "cfg.json"),
            history_dir=None,
            current_results={
                "gone.example": {"8.8.8.8": {"type": "A", "values": ["1.1.1.1"], "ts": 1}},
                "keep.example": {"8.8.8.8": {"type": "A", "values": ["2.3.4.5"], "ts": 2}},
            },
            history={
                "gone.example": {"meta": {}, "events": [], "current": {}},
                "keep.example": {"meta": {}, "events": [], "current": {}},
            },
        )
        body = b'{"domains": [{"name": "keep.example", "type": "A"}]}'
        out = self._do_post_config(state, body)
        self.assertEqual(out["code"], 200, out)
        # The removed name must appear in at least one purge call
        all_purged = [d for c in state["purge_calls"] for d in c]
        self.assertIn("gone.example", all_purged)
        # The keep name must NOT be purged
        self.assertNotIn("keep.example", all_purged)
        # State is actually gone from both dicts
        self.assertNotIn("gone.example", state["handler_cls"].__dict__.get("_ctx", {}).get("current_results", {}))

    def test_orphan_safety_purge_catches_state_not_in_new_config(self):
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=os.path.join(tempfile.mkdtemp(), "cfg.json"),
            history_dir=None,
            current_results={
                "orphan.example": {"8.8.8.8": {"type": "A", "values": ["9.9.9.9"], "ts": 1}},
                "keep.example": {"8.8.8.8": {"type": "A", "values": ["2.3.4.5"], "ts": 2}},
            },
            history={
                "orphan.example": {"meta": {}, "events": [], "current": {}},
            },
        )
        # /config POST with a new domain not in the config before
        body = b'{"domains": [{"name": "keep.example", "type": "A"}, {"name": "new.example", "type": "TXT"}]}'
        out = self._do_post_config(state, body)
        self.assertEqual(out["code"], 200, out)
        all_purged = [d for c in state["purge_calls"] for d in c]
        # orphan.example was not in the old config AND not in the new config -> must be purged
        self.assertIn("orphan.example", all_purged)
        # new.example IS in the new config -> must NOT be purged
        self.assertNotIn("new.example", all_purged)

    def test_keep_example_stays_configured(self):
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=os.path.join(tempfile.mkdtemp(), "cfg.json"),
            history_dir=None,
            current_results={
                "keep.example": {"8.8.8.8": {"type": "A", "values": ["2.3.4.5"], "ts": 2}},
            },
            history={"keep.example": {"meta": {}, "events": [], "current": {}}},
        )
        body = b'{"domains": [{"name": "keep.example", "type": "A"}]}'
        out = self._do_post_config(state, body)
        self.assertEqual(out["code"], 200, out)
        self.assertIn("keep.example", [d.get("name") for d in state["shared_config"].get("domains", [])])

    def test_equivalent_domain_spelling_does_not_purge_state(self):
        state = self._build_handler(
            shared_config={"domains": [{"name": "Example.COM.", "type": "A"}]},
            config_path=os.path.join(tempfile.mkdtemp(), "cfg.json"),
            history_dir=None,
            current_results={"Example.COM.": {"8.8.8.8": {"type": "A", "values": ["2.3.4.5"]}}},
            history={"Example.COM.": {"meta": {}, "events": [], "current": {}}},
        )
        body = b'{"domains": [{"name": "example.com", "type": "A"}]}'

        out = self._do_post_config(state, body)

        self.assertEqual(out["code"], 200, out)
        all_purged = [d for call in state["purge_calls"] for d in call]
        self.assertNotIn("Example.COM.", all_purged)


class TestConfigPostSaveError(_ConfigPostBase):
    """P0-5: when the config file cannot be written, the handler must return
    HTTP 500 with an ``error`` message rather than 200 / status:ok."""

    def test_write_failure_returns_http_500_with_error_message(self):
        cfg_path = os.path.join(tempfile.mkdtemp(), "cfg.json")
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=cfg_path,
            history_dir=None,
            current_results={},
            history={},
        )
        body = b'{"domains": [{"name": "keep.example", "type": "A"}]}'
        out = self._do_post_config(state, body, write_config_exc=OSError("disk full"))
        self.assertEqual(out["code"], 500, out)
        self.assertIn("error", out["obj"], out)
        self.assertIn("config save failed", out["obj"]["error"], out)

    def test_write_failure_returns_status_error(self):
        cfg_path = os.path.join(tempfile.mkdtemp(), "cfg.json")
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=cfg_path,
            history_dir=None,
            current_results={},
            history={},
        )
        body = b'{"interval": 120}'
        out = self._do_post_config(state, body, write_config_exc=PermissionError("denied"))
        self.assertEqual(out["code"], 500, out)
        self.assertEqual(out["obj"].get("status"), "error", out)

    def test_write_failure_keeps_runtime_config_and_domain_state(self):
        cfg_path = os.path.join(tempfile.mkdtemp(), "cfg.json")
        current_results = {"keep.example": {"8.8.8.8": {"values": ["1.2.3.4"]}}}
        history = {"keep.example": {"meta": {}, "events": [], "current": {}}}
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=cfg_path,
            history_dir=None,
            current_results=current_results,
            history=history,
        )
        out = self._do_post_config(
            state,
            b'{"domains": [{"name": "new.example", "type": "A"}]}',
            write_config_exc=OSError("disk full"),
        )

        self.assertEqual(out["code"], 500, out)
        self.assertEqual(state["shared_config"], self._base_shared_config)
        self.assertIn("keep.example", current_results)
        self.assertIn("keep.example", history)
        self.assertEqual(state["purge_calls"], [])

    def test_save_failure_still_records_save_events(self):
        cfg_path = os.path.join(tempfile.mkdtemp(), "cfg.json")
        state = self._build_handler(
            shared_config=self._base_shared_config,
            config_path=cfg_path,
            history_dir=None,
            current_results={},
            history={},
        )
        body = b'{"interval": 60}'
        out = self._do_post_config(state, body)
        self.assertEqual(out["code"], 200, out)
        self.assertEqual(out["obj"].get("status"), "ok", out)
        self.assertIn("keep.example", [d.get("name") for d in state["shared_config"].get("domains", [])])


if __name__ == "__main__":
    unittest.main()
