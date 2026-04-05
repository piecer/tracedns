#!/usr/bin/env python3
"""ENS text-record query helpers."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlsplit, urlunsplit

from ens_decoder import decode_ens_hidden_ips

try:
    from web3 import Web3
    from web3.exceptions import ContractLogicError
except Exception:  # optional dependency
    Web3 = None

    class ContractLogicError(Exception):
        pass


ENS_REGISTRY_ADDRESS = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

ENS_REGISTRY_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "node", "type": "bytes32"}],
        "name": "resolver",
        "outputs": [{"name": "", "type": "address"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]

RESOLVER_ABI = [
    {
        "constant": True,
        "inputs": [
            {"name": "node", "type": "bytes32"},
            {"name": "key", "type": "string"},
        ],
        "name": "text",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]


class EnsQueryError(RuntimeError):
    """Structured ENS/Web3 query exception for operator-facing diagnostics."""

    def __init__(self, code: str, message: str, *, rpc_url: str = '', ens_name: str = '', key: str = '', cause: Exception | None = None):
        super().__init__(message)
        self.code = str(code or 'ens_query_error')
        self.rpc_url = _redact_rpc_url(rpc_url)
        self.ens_name = str(ens_name or '')
        self.key = str(key or '')
        self.cause = cause

    def to_dict(self) -> Dict[str, str]:
        out = {
            'code': self.code,
            'message': str(self),
        }
        if self.ens_name:
            out['ens_name'] = self.ens_name
        if self.key:
            out['key'] = self.key
        if self.rpc_url:
            out['rpc_url'] = self.rpc_url
        if self.cause:
            out['cause'] = f"{type(self.cause).__name__}: {self.cause}"
        return out

    def __str__(self) -> str:
        base = super().__str__()
        # Keep concise and avoid leaking sensitive RPC URL query params.
        parts = [base]
        if self.ens_name:
            parts.append(f"name={self.ens_name}")
        if self.key:
            parts.append(f"key={self.key}")
        if self.rpc_url:
            parts.append(f"rpc={self.rpc_url}")
        return " | ".join(parts)


def _redact_rpc_url(value: str) -> str:
    s = str(value or '').strip()
    if not s:
        return ''
    try:
        sp = urlsplit(s)
        if not sp.scheme or not sp.netloc:
            return s[:64]
        # Hide query/fragment/token-like information.
        return urlunsplit((sp.scheme, sp.netloc, sp.path[:64], '', ''))
    except Exception:
        return s[:64]


def format_ens_error(exc: Exception) -> str:
    if isinstance(exc, EnsQueryError):
        return f"{exc.code}: {exc}"
    return f"unexpected_error: {type(exc).__name__}: {exc}"


def namehash(name: str) -> bytes:
    if Web3 is None:
        raise EnsQueryError('dependency_missing', 'web3 package is required for ENS queries')
    node = b"\x00" * 32
    if not name:
        return node

    labels = name.lower().strip(".").split(".")
    for label in reversed(labels):
        label_hash = Web3.keccak(text=label)
        node = Web3.keccak(node + label_hash)
    return node


def decode_fake_ipv6_to_ipv4(value: str) -> str:
    prefix = "2001:db8:"
    suffix = "::1"

    if not value.startswith(prefix) or not value.endswith(suffix):
        raise ValueError(f"unexpected format: {value}")

    body = value[len(prefix): -len(suffix)]
    parts = body.split(":")
    if len(parts) != 2:
        raise ValueError(f"unexpected embedded body: {value}")

    left, right = parts
    if len(left) != 4 or len(right) != 4:
        raise ValueError(f"unexpected group width: {value}")

    hexpairs = [left[0:2], left[2:4], right[0:2], right[2:4]]
    octets = [str(int(pair, 16) ^ 0xA5) for pair in hexpairs]
    return ".".join(octets)


def parse_record(record: str) -> List[str]:
    """Backward-compatible helper using the default ENS decoder method."""
    return decode_ens_hidden_ips(record, method='ipv6_5to8_xor')


def fetch_ens_text_record(rpc_url: str, ens_name: str, key: str = 'ipv6', timeout_sec: int = 8) -> str:
    rpc = str(rpc_url or '').strip()
    name = str(ens_name or '').strip().rstrip('.')
    text_key = str(key or '').strip()
    if not rpc:
        raise EnsQueryError('invalid_rpc_url', 'rpc_url is required', rpc_url=rpc, ens_name=name, key=text_key)
    if not name:
        raise EnsQueryError('invalid_ens_name', 'ens_name is required', rpc_url=rpc, ens_name=name, key=text_key)
    if not text_key:
        raise EnsQueryError('invalid_text_key', 'text key is required', rpc_url=rpc, ens_name=name, key=text_key)

    if Web3 is None:
        raise EnsQueryError('dependency_missing', 'web3 package is required for ENS queries', rpc_url=rpc, ens_name=name, key=text_key)
    try:
        provider = Web3.HTTPProvider(rpc, request_kwargs={'timeout': max(2, int(timeout_sec or 8))})
        w3 = Web3(provider)
    except Exception as e:
        raise EnsQueryError('provider_init_failed', 'failed to initialize HTTP provider', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e
    try:
        connected = bool(w3.is_connected())
    except Exception as e:
        raise EnsQueryError('rpc_connect_check_failed', 'failed to check Ethereum RPC connectivity', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e
    if not connected:
        raise EnsQueryError('rpc_not_connected', 'failed to connect to Ethereum RPC', rpc_url=rpc, ens_name=name, key=text_key)

    try:
        node = namehash(name)
    except EnsQueryError:
        raise
    except Exception as e:
        raise EnsQueryError('namehash_failed', 'failed to calculate ENS namehash', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e

    try:
        registry = w3.eth.contract(
            address=Web3.to_checksum_address(ENS_REGISTRY_ADDRESS),
            abi=ENS_REGISTRY_ABI,
        )
    except Exception as e:
        raise EnsQueryError('registry_init_failed', 'failed to initialize ENS registry contract', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e

    try:
        resolver_addr = registry.functions.resolver(node).call()
    except Exception as e:
        code = 'resolver_lookup_reverted' if isinstance(e, ContractLogicError) else 'resolver_lookup_failed'
        raise EnsQueryError(code, 'failed to query resolver address from ENS registry', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e

    resolver_text = str(resolver_addr or '').strip()
    if not resolver_text:
        raise EnsQueryError('resolver_missing', f'no resolver set for {name}', rpc_url=rpc, ens_name=name, key=text_key)
    try:
        if int(resolver_text, 16) == 0:
            raise EnsQueryError('resolver_missing', f'no resolver set for {name}', rpc_url=rpc, ens_name=name, key=text_key)
    except EnsQueryError:
        raise
    except Exception as e:
        raise EnsQueryError('resolver_invalid', f'invalid resolver address: {resolver_text}', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e

    try:
        resolver = w3.eth.contract(
            address=Web3.to_checksum_address(resolver_text),
            abi=RESOLVER_ABI,
        )
    except Exception as e:
        raise EnsQueryError('resolver_contract_init_failed', 'failed to initialize resolver contract', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e
    try:
        value = resolver.functions.text(node, text_key).call()
    except Exception as e:
        code = 'resolver_text_reverted' if isinstance(e, ContractLogicError) else 'resolver_text_failed'
        raise EnsQueryError(code, 'failed to fetch ENS text record', rpc_url=rpc, ens_name=name, key=text_key, cause=e) from e

    out = str(value or '').strip()
    if not out:
        raise EnsQueryError('record_empty', f"text record '{text_key}' is empty for {name}", rpc_url=rpc, ens_name=name, key=text_key)
    return out
