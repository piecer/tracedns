#!/usr/bin/env python3
"""Fetch an ENS text record and decode embedded IPv4 indicators."""

import argparse
import sys

from ens_query import fetch_ens_text_record, parse_record


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
