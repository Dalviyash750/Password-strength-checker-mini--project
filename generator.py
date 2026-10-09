"""Secure random password generator (uses the ``secrets`` module)."""

from __future__ import annotations

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """Return a random password that contains every selected character type.

    ``secrets`` draws from the operating system's cryptographically secure
    random number generator, unlike ``random`` which must never be used for
    passwords.
    """
    if length < 8:
        raise ValueError("length must be at least 8")

    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        groups.append(SYMBOLS)
    alphabet = "".join(groups)

    # Guarantee one character from each group, fill the rest randomly.
    chars = [secrets.choice(group) for group in groups]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]

    # Fisher-Yates style shuffle with a secure RNG.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
