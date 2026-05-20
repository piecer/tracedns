#!/usr/bin/env python3
"""SNS TXT proxy query helpers."""

from __future__ import annotations

import requests

DEFAULT_SOLAR_PROXY_HOSTS = [
    "https://sdk-proxy.sns.id",
    "https://sns-sdk-proxy.bonfida.workers.dev",
]


def normalize_sns_name(name: str) -> str:
    n = str(name or '').strip()
    if not n:
        raise ValueError('empty SNS name')
    if not n.endswith('.sol'):
        n += '.sol'
    return n


def fetch_sns_txt_record(proxy_host: str, name: str, timeout: int = 15, verify_tls: bool = True) -> str:
    base_url = str(proxy_host or '').strip().rstrip('/')
    if not base_url:
        raise ValueError('empty SNS proxy host')
    sns_name = normalize_sns_name(name)
    url = f"{base_url}/record-v2/{sns_name}/TXT"
    resp = requests.get(
        url,
        timeout=int(timeout),
        verify=bool(verify_tls),
        headers={
            "User-Agent": "tracedns-sns/1.0",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    resp.raise_for_status()
    return str(resp.text or '')
