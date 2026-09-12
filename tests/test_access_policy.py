"""Authorization contract: no route is public by accident."""
import pytest


def test_policy_requires_explicit_routes_and_roles():
    from security.policy import allowed
    assert allowed('viewer', 'GET', '/results')
    assert not allowed('viewer', 'POST', '/resolve')
    assert allowed('operator', 'POST', '/resolve')
    assert not allowed('operator', 'POST', '/settings')
    assert allowed('admin', 'POST', '/settings')
    assert not allowed('admin', 'GET', '/unknown')


@pytest.mark.parametrize('path', ['/ips', '/domain-analysis'])
def test_viewer_external_lookup_requires_explicit_off(path):
    from security.policy import allowed
    assert not allowed('viewer', 'GET', path, {'include_vt': ['1']})
    assert allowed('viewer', 'GET', path, {'include_vt': ['0']})


def test_operator_config_is_domains_only():
    from security.policy import allowed
    assert allowed('operator', 'POST', '/config', body={'domains': [], 'revision': '1'})
    assert not allowed('operator', 'POST', '/config', body={'domains': [], 'servers': []})
    assert not allowed('viewer', 'GET', '/misp/search')
