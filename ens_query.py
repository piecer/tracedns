#!/usr/bin/env python3
"""ENS text-record query and fake-IPv6 decoder helpers."""

from __future__ import annotations

from typing import List

try:
    from web3 import Web3
except Exception:  # optional dependency
    Web3 = None


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


def namehash(name: str) -> bytes:
    if Web3 is None:
        raise RuntimeError("web3 package is required for ENS queries")
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
    results = []
    for item in (record or '').split("|"):
        item = item.strip()
        if not item:
            continue
        results.append(decode_fake_ipv6_to_ipv4(item))
    return results


def fetch_ens_text_record(rpc_url: str, ens_name: str, key: str = 'ipv6') -> str:
    if Web3 is None:
        raise RuntimeError("web3 package is required for ENS queries")
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError("failed to connect to Ethereum RPC")

    node = namehash(ens_name)

    registry = w3.eth.contract(
        address=Web3.to_checksum_address(ENS_REGISTRY_ADDRESS),
        abi=ENS_REGISTRY_ABI,
    )
    resolver_addr = registry.functions.resolver(node).call()
    if int(resolver_addr, 16) == 0:
        raise RuntimeError(f"no resolver set for {ens_name}")

    resolver = w3.eth.contract(
        address=Web3.to_checksum_address(resolver_addr),
        abi=RESOLVER_ABI,
    )
    value = resolver.functions.text(node, key).call()
    if not value:
        raise RuntimeError(f"text record '{key}' is empty for {ens_name}")
    return value
