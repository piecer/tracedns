"""Publication cleanup cannot roll back commits or revive obsolete history."""
from unittest.mock import patch

import pytest

from history_manager import history_file_path, load_history_files, persist_history_entry
from monitor.repository import MonitorStateRepository


def test_failed_postcommit_cleanup_warns_and_blocks_readd_until_retry(tmp_path):
    cfg = {'domains': ['old.test'], 'servers': ['dns']}
    current, history = {}, {}
    repo = MonitorStateRepository(current, history, str(tmp_path), cfg['domains'])
    repo.configure(cfg)
    lease = repo.capture()['old.test']
    persist_history_entry(str(tmp_path), 'old.test', lease.history)
    with patch('monitor.repository.os.unlink', side_effect=PermissionError('secret path')):
        assert repo.configure({'domains': []}) == ['history_cleanup_pending']
        assert not repo.valid(lease)
        assert current == history == {}
        with pytest.raises(ValueError, match='history_cleanup_pending'):
            repo.validate_config(cfg)
    assert repo.retry_cleanup() == []
    repo.validate_config(cfg)
    repo.configure(cfg)
    replacement = repo.capture()['old.test']
    assert replacement.target is not lease.target
    persist_history_entry(str(tmp_path), 'old.test', replacement.history)
    assert repo.retry_cleanup() == []
    assert load_history_files(str(tmp_path)) == {'old.test': replacement.history}


def test_startup_excludes_orphans_and_blocks_readd_across_restart(tmp_path):
    persist_history_entry(str(tmp_path), 'deleted.test', {'events': [], 'current': {}})
    # Even malformed orphan files must not escape cleanup discovery.
    with open(history_file_path(str(tmp_path), 'broken.test'), 'w') as stream:
        stream.write('{')
    for _ in range(2):
        history = load_history_files(str(tmp_path))
        current = {'deleted.test': {'dns': {'values': ['192.0.2.1']}}}
        with patch('monitor.repository.os.unlink', side_effect=PermissionError()):
            repo = MonitorStateRepository(current, history, str(tmp_path), [], startup=True)
            assert current == history == {}
            with pytest.raises(ValueError, match='history_cleanup_pending'):
                repo.validate_config({'domains': ['deleted.test']})
            with pytest.raises(ValueError, match='history_cleanup_pending'):
                repo.validate_config({'domains': ['broken.test']})
    assert repo.retry_cleanup() == []
    assert list(tmp_path.iterdir()) == []


def test_query_failure_threshold_does_not_leak_into_readded_generation(tmp_path):
    from models import QueryResult, DomainSpec
    from monitor.collect import Collected
    from monitor.engine import run_domain_cycle
    cfg = {'domains': ['x.test'], 'servers': ['dns']}
    repo = MonitorStateRepository({}, {}, str(tmp_path), cfg['domains'])
    repo.configure(cfg)
    failures = {}

    def fail_once():
        with patch('monitor.engine.collect_snapshot', return_value=Collected(
                QueryResult('dns', 'x.test', 'A', 'error', []), None)):
            run_domain_cycle(domain=DomainSpec('x.test'), servers=['dns'],
                             current_results=repo.current, history=repo.history,
                             history_dir=str(tmp_path), query_fail_counts=failures,
                             state_repository=repo, target_lease=repo.capture()['x.test'])

    fail_once()
    fail_once()
    repo.configure({'domains': []})
    repo.configure(cfg)
    fresh = repo.capture()['x.test']
    fresh.current['dns'] = {'type': 'A', 'values': ['192.0.2.1']}
    fresh.history['current']['dns'] = dict(fresh.current['dns'])
    fail_once()
    assert 'dns' in fresh.current
    fail_once()
    assert 'dns' in fresh.current
    fail_once()
    assert 'dns' not in fresh.current
