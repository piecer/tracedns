"""Deployment examples must not silently monitor observed infrastructure."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_example_is_inert_until_explicit_configuration():
    config = json.loads((ROOT / 'dns_config.json_example').read_text())
    assert config['domains'] == []
    assert config['ens_rpc_url'] == ''
    assert config['servers'] == ['127.0.0.1']
    assert all(not value for value in config['alerts'].values())


def test_quick_start_initializes_auth_and_uses_local_sample():
    readme = (ROOT / 'README.md').read_text()
    quick_start = readme.split('## Quick Start', 1)[1].split('## Multi-user', 1)[0]
    assert 'cp -n dns_config.json_example dns_config.json' in quick_start
    assert 'security.cli' in quick_start
    assert quick_start.index('bootstrap admin') < quick_start.index('dns_monitor.py')
    assert '--http-host 127.0.0.1' in quick_start
    assert '--insecure-http' in quick_start
    assert '.eth' not in quick_start
    assert 'make security-regression' in readme
    assert '[MIT](LICENSE)' in readme
