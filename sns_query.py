#!/usr/bin/env python3
"""SNS TXT proxy query helpers."""

from __future__ import annotations

import requests
import zlib
from urllib.parse import quote

from lookup_context import checkpoint, owned_lookup, transport_timeout

SNS_BODY_LIMIT = 1024 * 1024
SNS_CHUNK_SIZE = 8192

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


def _read_chunk(response, timeout):
    raw = response.raw
    remaining = transport_timeout(timeout)
    # Requests exposes no public live read-timeout setter. urllib3 retains the
    # socket either on its connection or on http.client's buffered response.
    sock = getattr(getattr(raw, '_connection', None), 'sock', None)
    if sock is None:
        fp = getattr(getattr(raw, '_fp', None), 'fp', None)
        sock = getattr(getattr(fp, 'raw', None), '_sock', None)
    if sock is not None:
        sock.settimeout(remaining)
    elif not raw.closed:
        raise RuntimeError('SNS response read timeout unavailable')
    checkpoint()
    chunk = raw.read1(SNS_CHUNK_SIZE, decode_content=False)
    checkpoint()
    if len(chunk) > SNS_CHUNK_SIZE:
        raise ValueError('SNS response chunk too large')
    return chunk


def _body_chunks(response, timeout):
    encoding = response.headers.get('Content-Encoding', '').strip().lower()
    if encoding not in ('', 'identity', 'gzip', 'deflate'):
        raise ValueError('SNS unsupported content encoding')
    window = 16 + zlib.MAX_WBITS if encoding == 'gzip' else zlib.MAX_WBITS
    decoder = zlib.decompressobj(window) if encoding in ('gzip', 'deflate') else None
    while True:
        pending = _read_chunk(response, timeout)
        if not pending:
            break
        if decoder is None:
            yield pending
            continue
        while pending:
            checkpoint()
            if decoder.eof:
                if encoding != 'gzip':
                    raise ValueError('SNS trailing compressed data')
                decoder = zlib.decompressobj(window)
            chunk = decoder.decompress(pending, SNS_CHUNK_SIZE)
            checkpoint()
            pending = decoder.unconsumed_tail or decoder.unused_data
            yield chunk
    if decoder is not None and not decoder.eof:
        raise ValueError('SNS truncated compressed body')


class _StreamingSession(requests.Session):
    def send(self, request, **kwargs):
        kwargs['timeout'] = transport_timeout(kwargs['timeout'])
        kwargs['stream'] = True
        kwargs['allow_redirects'] = False
        response = super().send(request, **kwargs)
        try:
            checkpoint()
            return response
        except BaseException:
            response.close()
            raise

    def resolve_redirects(self, *args, **kwargs):
        # Requests otherwise consumes a redirect body to prepare Response.next,
        # even with allow_redirects=False. Never let that bypass the body cap.
        return iter(())


def _owned_record(url, timeout, verify_tls, headers):
    with _StreamingSession() as session:
        response = session.get(url, timeout=transport_timeout(timeout),
                               verify=verify_tls, headers=headers,
                               stream=True, allow_redirects=False)
        try:
            checkpoint()
            response.raise_for_status()
            if not 200 <= response.status_code < 300:
                raise ValueError('SNS non-success response')
            body = bytearray()
            for chunk in _body_chunks(response, timeout):
                if len(body) + len(chunk) > SNS_BODY_LIMIT:
                    raise ValueError('SNS response body too large')
                body.extend(chunk)
            checkpoint()
            text = body.decode(response.encoding or 'utf-8', errors='replace')
            checkpoint()
            return text
        finally:
            response.close()


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
    if owned_lookup():
        return _owned_record(url, float(timeout), bool(verify_tls), {
            'User-Agent': 'tracedns-sns/1.0',
            'Accept': 'application/json,text/plain,*/*',
            'Accept-Encoding': 'gzip, deflate, identity',
        })
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
