import subprocess
from pathlib import Path


SOURCE = (Path(__file__).parents[1] / "dns_frontend.js").read_text(encoding="utf-8")


def test_domain_config_identity_preserves_ens_text_key_case():
    source = SOURCE[
        SOURCE.index("function normalizeDomainName"):
        SOURCE.index("function buildDecoderNameList")
    ]
    script = f"""
const assert = require('assert');
{source}
assert.notStrictEqual(
  domainConfigIdentity({{name: 'example.eth', type: 'ENS', ens_text_key: 'Host'}}),
  domainConfigIdentity({{name: 'example.eth.', type: 'ENS', ens_text_key: 'host'}}),
);
"""
    completed = subprocess.run(["node", "-e", script], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
