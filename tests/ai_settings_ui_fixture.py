"""Component-only AI settings bytes from the real pure producer.

Not the HTTP settings API or runtime integration. The browser intercepts only
/ai/settings; authentication and the other console routes use the real app.
Runtime observations below are explicitly controlled, never provider evidence.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from local_ai.provider_settings import merge_settings, normalize_settings, public_settings  # noqa: E402


def produce(value):
    stored = normalize_settings(value.get("stored"))
    revision = value.get("revision", 0)
    post = "patch" in value
    if post:
        stored = merge_settings(stored, value["patch"], value.get("clear_fields", []))
        revision += 1
    receipt = {"revision": revision, "settings": public_settings(stored),
               "runtime": value.get("runtime", {"applied": True, "state": "disabled"})}
    if post:
        receipt.update(status="ok", warnings=[])
    return {"stored": stored, "revision": revision,
            "wire": json.dumps(receipt, ensure_ascii=True, separators=(",", ":")) + "\n"}


if __name__ == "__main__":
    print(json.dumps(produce(json.load(sys.stdin))))
