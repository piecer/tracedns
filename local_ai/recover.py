"""Offline operator attestation for an unsettled local-LLM reservation.

No inference, process inspection, service control, credentials or network access.
The operator must stop TraceDNS and have the runtime owner stop the prior
inference before using this command. Flags record human attestations, not proof.
"""
import argparse
import sqlite3
import sys

from security.store import SecurityError, SecurityStore


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--security-db', required=True, help='Existing private security database')
    parser.add_argument('--job-id', required=True, help='Exact outstanding provider job ID')
    parser.add_argument('--confirm-tracedns-stopped', action='store_true', required=True,
                        help='Attest that TraceDNS has been stopped')
    parser.add_argument('--confirm-provider-stopped', action='store_true', required=True,
                        help='Attest that the runtime owner stopped the prior inference')
    args = parser.parse_args(argv)
    try:
        store = SecurityStore(args.security_db)
        if not store.acknowledge_llm_provider_stopped(
                args.job_id, tracedns_stopped=args.confirm_tracedns_stopped,
                provider_stopped=args.confirm_provider_stopped):
            print('No matching outstanding provider job; no attestation recorded.', file=sys.stderr)
            return 1
        state = store.llm_provider_state()
        if state != {'blocked': False, 'job_id': args.job_id, 'outcome': 'operator_confirmed_stopped'}:
            print('Recovery state could not be confirmed; keep TraceDNS stopped.', file=sys.stderr)
            return 1
    except (SecurityError, sqlite3.Error, OSError):
        # Never print database/driver exception text or runtime-sensitive details.
        print('Recovery failed: security audit unavailable or invalid; keep TraceDNS stopped.', file=sys.stderr)
        return 1
    print('operator_confirmed_stopped recorded. Operator attestation only, not machine proof of completion.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
