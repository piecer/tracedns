"""Explicit local account bootstrap and recovery (no password arguments)."""
import argparse
import getpass
import sqlite3
import sys

from .store import SecurityError, SecurityStore


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default echoes unrecognized arguments, possibly secrets.
        self.print_usage(sys.stderr)
        self.exit(2, 'Invalid arguments; passwords must be entered interactively.\n')


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('command', choices=('bootstrap', 'reset-password'))
    parser.add_argument('username')
    args = parser.parse_args(argv)
    try:
        password = getpass.getpass('Password: ')
        confirmation = getpass.getpass('Confirm password: ')
        if password != confirmation:
            raise SecurityError('Passwords do not match')
        store = SecurityStore(args.db, create=args.command == 'bootstrap')
        if args.command == 'bootstrap':
            store.bootstrap(args.username, password)
        else:
            store.local_reset_password(args.username, password)
    except SecurityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (sqlite3.Error, OSError, EOFError, KeyboardInterrupt):
        print('Account operation failed; check local storage and input.', file=sys.stderr)
        return 1
    print('Account operation completed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
