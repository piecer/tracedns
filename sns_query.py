#!/usr/bin/env python3
"""SNS TXT proxy query helpers."""

from __future__ import annotations

import requests
from urllib.parse import quote

DEFAULT_SOLAR_PROXY_HOSTS = [
    "https://sdk-proxy.sns.id",
    "https://sns-sdk-proxy.bonfida.workers.dev",
]


def normalize_sns_name(name: str) -> str:
    n = str(name or '').strip().lower()
    if not n:
        raise ValueError('empty SNS name')
    if not n.endswith('.sol'):
        n += '.sol'
    if len(n) > 255:
        raise ValueError('SNS name too long')
    return n


def fetch_sns_record(
    proxy_host: str,
    name: str,
    record_key: str,
    timeout: int = 15,
    verify_tls: bool = True,
) -> str:
    base_url = str(proxy_host or '').strip().rstrip('/')
    if not base_url:
        raise ValueError('empty SNS proxy host')
    sns_name = normalize_sns_name(name)
    key = str(record_key or '').strip()
    if not key:
        raise ValueError('empty SNS record key')
    url = f"{base_url}/record-v2/{quote(sns_name, safe='')}/{quote(key, safe='')}"
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


def fetch_sns_txt_record(
    proxy_host: str,
    name: str,
    timeout: int = 15,
    verify_tls: bool = True,
) -> str:
    """Compatibility wrapper for callers that explicitly request TXT."""
    return fetch_sns_record(
        proxy_host,
        name,
        'TXT',
        timeout=timeout,
        verify_tls=verify_tls,
    )
