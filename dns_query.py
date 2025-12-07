#!/usr/bin/env python3
"""
DNS 쿼리 기능 모듈
"""
import sys
import logging

# dnspython 필요: pip install dnspython
try:
    import dns.resolver
except ImportError:
    print("ERROR: dnspython이 필요합니다. 설치: pip install dnspython", file=sys.stderr)
    sys.exit(1)


def query_dns(server, domain, rtype='A', timeout=2.0):
    """
    DNS 쿼리를 수행합니다.
    
    Args:
        server (str): DNS 서버 IP 주소 (예: '8.8.8.8')
        domain (str): 조회할 도메인명
        rtype (str): 레코드 타입 ('A' 또는 'TXT')
        timeout (float): 타임아웃 시간(초)
    
    Returns:
        list: 쿼리 결과 리스트 (성공시) 또는 None (오류시)
    """
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [server]
        r.timeout = timeout
        r.lifetime = timeout
        
        if rtype.upper() == 'TXT':
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
            return sorted(list({v for v in vals if v is not None}))
        else:
            answers = r.resolve(domain, 'A')
            ips = sorted({str(a) for a in answers})
            return ips
    except Exception:
        return None
