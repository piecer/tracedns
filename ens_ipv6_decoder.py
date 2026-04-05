#!/usr/bin/env python3
"""Fetch an ENS text record and decode embedded IPv4 indicators."""

import argparse
import json
import sys

from ens_decoder import decode_ens_hidden_ips, parse_ens_options
from ens_query import EnsQueryError, fetch_ens_text_record, format_ens_error


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
    parser.add_argument(
        "--decode-method",
        default="ipv6_5to8_xor",
        help="ENS decode method (default: ipv6_5to8_xor)",
    )
    parser.add_argument(
        "--xor-byte",
        default="0xA5",
        help="XOR byte for xor-based methods (default: 0xA5)",
    )
    parser.add_argument(
        "--ens-options",
        default="",
        help='JSON object for ENS decoder options (ex: {"xor_byte":"0xA5"})',
    )

    args = parser.parse_args()

    try:
        if args.ens_options:
            try:
                ens_options = parse_ens_options(args.ens_options, strict=True)
            except Exception as exc:
                raise ValueError(f"invalid --ens-options: {exc}") from exc
        else:
            ens_options = parse_ens_options(None, legacy_xor_byte=args.xor_byte, strict=False)

        raw_value = fetch_ens_text_record(args.rpc, args.ens_name, args.key)
        print(f"[+] ENS name      : {args.ens_name}")
        print(f"[+] Text key      : {args.key}")
        print(f"[+] Raw text value: {raw_value}")
        if ens_options:
            print(f"[+] Decode options: {json.dumps(ens_options, ensure_ascii=False, sort_keys=True)}")

        if args.raw_only:
            return 0

        print("[+] Decoded IPv4s :")
        for ip in decode_ens_hidden_ips(raw_value, method=args.decode_method, ens_options=ens_options):
            print(ip)

        return 0

    except EnsQueryError as exc:
        print(f"[!] ENS query error: {format_ens_error(exc)}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
