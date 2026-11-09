"""Persistent legal-schedule regression, separate from uninstrumented signal cases."""
from signal_retirement_schedule import run_schedule


def test_missing_authority_legal_presignal_schedule(tmp_path):
    result = run_schedule(tmp_path / 'legal-schedule')
    assert result['classification'] == 'GREEN', result
