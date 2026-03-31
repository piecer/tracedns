#!/usr/bin/env python3
"""Fetch an ENS text record and decode embedded IPv4 indicators.

This helper targets a specific obfuscation format where each IPv4 is encoded
inside a fake IPv6 literal with this pattern:

    2001:db8:XXXX:YYYY::1

and each byte is restored with:

    byte = hexpair ^ 0xA5
"""

import argparse
import sys
from typing import List

from web3 import Web3

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
    node = b"\x00" * 32
    if not name:
        return node

    labels = name.lower().strip(".").split(".")
    for label in reversed(labels):
        label_hash = Web3.keccak(text=label)
        node = Web3.keccak(node + label_hash)
    return node


def decode_fake_ipv6_to_ipv4(value: str) -> str:
    """Convert ``2001:db8:35ba:9ebe::1`` into ``144.31.59.27``."""
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

    octets = []
    for pair in hexpairs:
        octet = int(pair, 16) ^ 0xA5
        octets.append(str(octet))

    return ".".join(octets)


def parse_record(record: str) -> List[str]:
    results = []
    for item in record.split("|"):
        item = item.strip()
        if not item:
            continue
        results.append(decode_fake_ipv6_to_ipv4(item))
    return results


def fetch_ens_text_record(rpc_url: str, ens_name: str, key: str) -> str:
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch ENS text record and decode embedded C2 IPv4s."
    )
    parser.add_argument(
        "ens_name",
        nargs="?",
        default="ukranianhorseriding.eth",
        help="ENS name to query (default: ukranianhorseriding.eth)",
    )
    parser.add_argument("--rpc", required=True, help="Ethereum mainnet RPC URL")
    parser.add_argument(
        "--key",
        default="ipv6",
        help="ENS text record key to read (default: ipv6)",
    )
    parser.add_argument(
        "--raw-only",
        action="store_true",
        help="Only print the raw ENS text record",
    )

    args = parser.parse_args()

    try:
        raw_value = fetch_ens_text_record(args.rpc, args.ens_name, args.key)
        print(f"[+] ENS name      : {args.ens_name}")
        print(f"[+] Text key      : {args.key}")
        print(f"[+] Raw text value: {raw_value}")

        if args.raw_only:
            return 0

        print("[+] Decoded IPv4s :")
        for ip in parse_record(raw_value):
            print(ip)

        return 0

    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
