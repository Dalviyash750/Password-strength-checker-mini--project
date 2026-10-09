#!/usr/bin/env python3
"""Command-line interface for the Password Strength Checker.

Examples
--------
    python main.py                 # prompts for a password (input is hidden)
    python main.py --show          # prompts, but shows what you type
    python main.py --generate 16   # print a strong random password
    python main.py -p "MyP@ss123"  # check a password given as an argument
"""

from __future__ import annotations

import argparse
import getpass
import sys

from password_checker import check_password, generate_password

COLOURS = {
    "Very Weak": "\033[91m",  # red
    "Weak": "\033[31m",  # dark red
    "Moderate": "\033[93m",  # yellow
    "Strong": "\033[92m",  # green
    "Very Strong": "\033[32m",  # dark green
}
RESET = "\033[0m"


def render_bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def tick(flag: bool) -> str:
    return "yes" if flag else "no"


def print_report(password: str, use_colour: bool) -> None:
    result = check_password(password)
    colour = COLOURS.get(result.label, "") if use_colour else ""
    reset = RESET if use_colour else ""

    print()
    print("=" * 52)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 52)
    print(f" Strength   : {colour}{result.label}{reset}")
    print(f" Score      : {result.score}/100  {render_bar(result.score)}")
    print(f" Length     : {result.length} characters")
    print(f" Entropy    : ~{result.entropy_bits} bits")
    print(f" Crack time : {result.crack_time} (offline, fast hash)")
    print("-" * 52)
    print(
        f" Lowercase: {tick(result.has_lower)}   Uppercase: {tick(result.has_upper)}   "
        f"Digits: {tick(result.has_digit)}   Symbols: {tick(result.has_symbol)}"
    )

    if result.issues:
        print("-" * 52)
        print(" Problems found:")
        for issue in result.issues:
            print(f"   - {issue}")
    if result.suggestions:
        print("-" * 52)
        print(" Suggestions:")
        for tip in result.suggestions:
            print(f"   * {tip}")
    print("=" * 52)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check how strong a password is, or generate a strong one."
    )
    parser.add_argument(
        "-p",
        "--password",
        help="password to check (NOT recommended: it can end up in your shell history)",
    )
    parser.add_argument(
        "--show", action="store_true", help="show the password while typing it"
    )
    parser.add_argument(
        "-g",
        "--generate",
        nargs="?",
        const=16,
        type=int,
        metavar="LENGTH",
        help="generate a random password (default length 16) and check it",
    )
    parser.add_argument(
        "--no-symbols", action="store_true", help="leave symbols out of generated passwords"
    )
    parser.add_argument("--no-colour", action="store_true", help="disable coloured output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    use_colour = sys.stdout.isatty() and not args.no_colour

    if args.generate is not None:
        try:
            password = generate_password(args.generate, use_symbols=not args.no_symbols)
        except ValueError as error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        print(f"Generated password: {password}")
        print_report(password, use_colour)
        return 0

    if args.password is not None:
        password = args.password
    else:
        prompt = "Enter a password to check: "
        password = input(prompt) if args.show else getpass.getpass(prompt)

    print_report(password, use_colour)
    return 0


if __name__ == "__main__":
    sys.exit(main())
