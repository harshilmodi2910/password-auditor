"""Command line entry point.

Run with:  python -m auditor [options]
"""

import argparse
import getpass
import sys

from . import __version__
from .hash_check import ALGORITHMS, check_hash
from .report import format_hash_report, format_json, format_password_report
from .strength import check_password, load_wordlist

PASSWORD_ARG_WARNING = (
    "warning: a password given with --password can end up in your shell history "
    "and in the process list. Use --prompt or --stdin if that matters."
)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="auditor",
        description=(
            "Estimate password strength and flag weak hash algorithms. "
            "This is an estimator, not a cracking tool."
        ),
        epilog=(
            "With no options at all the tool asks for a password at a hidden prompt. "
            "With only --hash it checks the hash and does not ask for a password."
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--password", metavar="PW",
                        help="check this password (visible in shell history, see warning)")
    source.add_argument("--prompt", action="store_true",
                        help="read the password from a hidden prompt")
    source.add_argument("--stdin", action="store_true",
                        help="read the password from the first line of standard input")

    parser.add_argument("--hash", dest="hash_value", metavar="HASH",
                        help="check whether this hash's algorithm is weak")
    parser.add_argument("--algorithm", metavar="NAME",
                        help="algorithm of --hash, instead of detecting it. "
                             "One of: " + ", ".join(sorted(ALGORITHMS)))
    parser.add_argument("--wordlist", metavar="FILE",
                        help="common password list to use instead of the bundled one "
                             "(one password per line)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _get_password(args):
    """Return the password to check, or None if only a hash was asked for."""
    if args.password is not None:
        print(PASSWORD_ARG_WARNING, file=sys.stderr)
        return args.password
    if args.stdin:
        line = sys.stdin.readline()
        return line.rstrip("\r\n")
    if args.prompt or args.hash_value is None:
        return getpass.getpass("Password: ")
    return None


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.algorithm and not args.hash_value:
        parser.error("--algorithm only makes sense together with --hash")

    password_result = None
    hash_result = None

    try:
        password = _get_password(args)
        if password is not None:
            words = load_wordlist(args.wordlist)
            password_result = check_password(password, words)
        if args.hash_value is not None:
            hash_result = check_hash(args.hash_value, args.algorithm)
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("error: no input", file=sys.stderr)
        return 2

    if args.json:
        print(format_json(password_result, hash_result))
    else:
        parts = []
        if password_result is not None:
            parts.append(format_password_report(password_result))
        if hash_result is not None:
            parts.append(format_hash_report(hash_result))
        print("\n\n".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
