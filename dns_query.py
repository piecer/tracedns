#!/usr/bin/env python3
"""
DNS 쿼리 기능 모듈
"""
import sys

# dnspython 필요: pip install dnspython
try:
    import dns.resolver
except ImportError:
    print("ERROR: dnspython이 필요합니다. 설치: pip install dnspython", file=sys.stderr)
    sys.exit(1)


def query_dns(server, domain, rtype='A', timeout=2.0, with_meta=False):
    """
    DNS 쿼리를 수행합니다.
    
    Args:
        server (str): DNS 서버 IP 주소 (예: '8.8.8.8')
        domain (str): 조회할 도메인명
        rtype (str): 레코드 타입 ('A' 또는 'TXT')
        timeout (float): 타임아웃 시간(초)
    
    Returns:
        list | dict:
            - with_meta=False: 쿼리 결과 리스트(정상/무응답) 또는 None(오류)
            - with_meta=True: {"values": [...], "status": "..."} 형태
    """
    def _ret(values=None, status='ok'):
        vals = values if isinstance(values, list) else []
        if with_meta:
            return {'values': vals, 'status': status}
        if status in ('ok', 'nxdomain', 'nodata'):
            return vals
        return None

    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [server]
        r.timeout = timeout
        r.lifetime = timeout
        
        if rtype.upper() == 'TXT':
            try:
                answers = r.resolve(domain, 'TXT')
                vals = []
                for rr in answers:
                    # dnspython: rr.strings 또는 str(rr)
                    try:
                        if hasattr(rr, 'strings'):
                            parts = []
                            for s in rr.strings:
                                if isinstance(s, bytes):
                                    parts.append(s.decode('utf-8', errors='ignore'))
                                else:
                                    parts.append(str(s))
                            vals.append(''.join(parts))
                        else:
                            vals.append(str(rr))
                    except Exception:
                        vals.append(str(rr))
                return _ret(sorted(list({v for v in vals if v is not None})), 'ok')
            except dns.resolver.NXDOMAIN:
                return _ret([], 'nxdomain')
            except dns.resolver.NoAnswer:
                return _ret([], 'nodata')
        else:
            try:
                answers = r.resolve(domain, 'A')
                ips = sorted({str(a) for a in answers})
                return _ret(ips, 'ok')
            except dns.resolver.NXDOMAIN:
                return _ret([], 'nxdomain')
            except dns.resolver.NoAnswer:
                return _ret([], 'nodata')
    except Exception:
        return _ret([], 'error')
