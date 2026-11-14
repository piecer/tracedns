"""Real relationship producer with synthetic VT observations, never a live provider."""
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from http_api import relationship_handlers as rh


class Handler:
    def __init__(self, data):
        raw = json.dumps(data).encode()
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.shared_config = {}
        self.result = None
        self.status = None

    def _send_json(self, data, code=200):
        self.result, self.status = data, code


def report(ip, cache_only=False):
    malicious = 2 if int(ip.rsplit('.', 1)[1]) % 2 else 0
    return {'asn': 64500, 'as_owner': 'Synthetic hosting',
            'country': 'US' if int(ip.rsplit('.', 1)[1]) % 2 else 'DE',
            'malicious': malicious, 'suspicious': 1,
            'raw': {'data': {'attributes': {
                'network': '11.0.0.0/24', 'jarm': 'a' * 62,
                'last_analysis_stats': {'malicious': malicious, 'suspicious': 1},
            }}}}


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    assert 2 <= count <= 100
    incomplete = len(sys.argv) > 2 and sys.argv[2] == 'incomplete'
    handler = Handler({'ips': [f'11.0.0.{i}' for i in range(1, count + 1)],
                       'include_vt': True, 'vt_workers': 1, 'vt_budget': count,
                       'min_score': 1, 'pair_gate_enabled': False,
                       'candidate_limit': 1000 if incomplete else 500000,
                       'top_pairs': 5000, 'max_neighbors_per_ip': 200})
    with patch.object(rh, 'get_ip_report', report), \
         patch.object(rh, 'begin_cache_batch', None), \
         patch.object(rh, 'end_cache_batch', None), \
         patch.object(rh, '_load_geoip_reader', lambda path: None):
        rh.handle_ip_relationship_analysis(handler)
    assert handler.status == 200, handler.result
    assert isinstance(handler.result, dict)
    assert handler.result['pairs'] and handler.result['country_summary']
    print(json.dumps(handler.result))


if __name__ == '__main__':
    main()
