"""Core logic for the Password Strength Checker.

The checker looks at a password from several angles:

* length and character variety (lowercase, uppercase, digits, symbols)
* presence in a list of very common passwords (also with "leet speak"
  substitutions undone, e.g. ``p@ssw0rd`` -> ``password``)
* predictable patterns: repeated characters, simple sequences such as
  ``abcd`` / ``4321`` and keyboard walks such as ``qwerty``

From these it estimates the entropy (in bits), turns it into a 0-100 score,
a strength label, an estimated offline cracking time and a list of
suggestions for improvement.

Only the Python standard library is used.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Guesses per second for an attacker cracking a fast, unsalted hash offline
# with GPUs (a deliberately pessimistic assumption).
GUESSES_PER_SECOND = 10_000_000_000

KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)

# Common character substitutions used to disguise words ("leet speak").
LEET_MAP = str.maketrans(
    {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"}
)

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12

# Strength labels: (minimum score, label)
LEVELS = (
    (90, "Very Strong"),
    (70, "Strong"),
    (45, "Moderate"),
    (25, "Weak"),
    (0, "Very Weak"),
)

# Entropy (bits) that maps to a score of 100.
TARGET_ENTROPY_BITS = 80.0


@dataclass
class StrengthResult:
    """The outcome of analysing one password."""

    length: int
    score: int
    label: str
    entropy_bits: float
    crack_time: str
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    is_common: bool = False
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def load_common_passwords(path: Path = COMMON_PASSWORDS_FILE) -> set[str]:
    """Load the common-password list (one lowercase password per line)."""
    try:
        with open(path, encoding="utf-8") as handle:
            return {line.strip().lower() for line in handle if line.strip()}
    except FileNotFoundError:
        return set()


_COMMON = load_common_passwords()


def _pool_size(password: str) -> int:
    """Size of the character set the password appears to be drawn from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    # Anything else (spaces, accented letters, emoji...) is lumped together.
    if any(
        c not in string.ascii_letters + string.digits + string.punctuation for c in password
    ):
        pool += 20
    return pool


def _repeated_indices(password: str) -> set[int]:
    """Indices of characters that merely repeat the previous one (3+ in a row)."""
    indices: set[int] = set()
    run_start = 0
    for i in range(1, len(password) + 1):
        if i == len(password) or password[i] != password[run_start]:
            if i - run_start >= 3:
                indices.update(range(run_start + 1, i))
            run_start = i
    return indices


def _sequence_indices(password: str) -> set[int]:
    """Indices of characters that continue an ascending/descending run
    such as ``abcd``, ``9876`` (3 or more characters)."""
    indices: set[int] = set()
    lowered = password.lower()
    i = 0
    while i < len(lowered) - 1:
        step = ord(lowered[i + 1]) - ord(lowered[i])
        if step in (1, -1) and lowered[i].isalnum() and lowered[i + 1].isalnum():
            j = i + 1
            while (
                j + 1 < len(lowered)
                and ord(lowered[j + 1]) - ord(lowered[j]) == step
                and lowered[j + 1].isalnum()
            ):
                j += 1
            if j - i + 1 >= 3:
                indices.update(range(i + 1, j + 1))
            i = j
        else:
            i += 1
    return indices


def _keyboard_indices(password: str, min_run: int = 4) -> set[int]:
    """Indices of characters that are part of a keyboard walk like ``qwer``."""
    indices: set[int] = set()
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for candidate in (row, row[::-1]):
            for size in range(len(candidate), min_run - 1, -1):
                for start in range(len(candidate) - size + 1):
                    chunk = candidate[start : start + size]
                    pos = lowered.find(chunk)
                    while pos != -1:
                        indices.update(range(pos + 1, pos + size))
                        pos = lowered.find(chunk, pos + 1)
    return indices


def _common_word_indices(password: str) -> tuple[set[int], bool]:
    """Find common passwords/words hidden in the password.

    Returns the set of covered character indices (all but the first character
    of each hit) and whether the *whole* password is a common one.
    """
    lowered = password.lower()
    variants = {lowered, lowered.translate(LEET_MAP)}
    if any(v in _COMMON for v in variants):
        return set(range(1, len(password))), True

    indices: set[int] = set()
    for variant in variants:
        for word in _COMMON:
            if len(word) >= 5 and not word.isdigit() and word in variant:
                start = variant.find(word)
                indices.update(range(start + 1, start + len(word)))
    return indices, False


def format_crack_time(seconds: float) -> str:
    """Turn a number of seconds into a friendly string."""
    if seconds < 1:
        return "instantly"
    units = (
        ("year", 365 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    )
    if seconds >= 100 * 365 * 24 * 3600:
        centuries = seconds / (100 * 365 * 24 * 3600)
        if centuries >= 1_000_000:
            return "millions of centuries"
        return f"{centuries:,.0f} centuries"
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            value_text = f"{value:,.0f}" if value >= 10 else f"{value:.1f}"
            plural = "" if value_text in ("1", "1.0") else "s"
            return f"{value_text} {name}{plural}"
    return "instantly"  # pragma: no cover


def label_for_score(score: int) -> str:
    for minimum, label in LEVELS:
        if score >= minimum:
            return label
    return LEVELS[-1][1]  # pragma: no cover


def check_password(password: str) -> StrengthResult:
    """Analyse ``password`` and return a :class:`StrengthResult`."""
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    issues: list[str] = []
    suggestions: list[str] = []

    if length == 0:
        return StrengthResult(
            length=0,
            score=0,
            label="Very Weak",
            entropy_bits=0.0,
            crack_time="instantly",
            has_lower=False,
            has_upper=False,
            has_digit=False,
            has_symbol=False,
            issues=["Password is empty."],
            suggestions=["Enter a password to analyse."],
        )

    # --- pattern detection -------------------------------------------------
    repeated = _repeated_indices(password)
    sequences = _sequence_indices(password)
    keyboard = _keyboard_indices(password)
    common_idx, is_common = _common_word_indices(password)

    if repeated:
        issues.append("Contains repeated characters (e.g. 'aaa').")
        suggestions.append("Avoid repeating the same character several times in a row.")
    if sequences:
        issues.append("Contains a simple sequence (e.g. 'abc' or '1234').")
        suggestions.append("Avoid sequences of consecutive letters or numbers.")
    if keyboard:
        issues.append("Contains a keyboard pattern (e.g. 'qwerty').")
        suggestions.append("Avoid keyboard patterns - attackers try them first.")
    if is_common:
        issues.append("This is a very common password.")
        suggestions.append("Pick something unique; never use a well-known password.")
    elif common_idx:
        issues.append("Contains a commonly used password or word.")
        suggestions.append(
            "Don't build your password around common words, even with substitutions like '@' for 'a'."
        )

    predictable = repeated | sequences | keyboard | common_idx

    # --- entropy -----------------------------------------------------------
    pool = _pool_size(password)
    effective_length = max(length - len(predictable), 1)
    entropy = effective_length * math.log2(pool) if pool > 1 else 0.0

    # --- basic rules ---------------------------------------------------------
    if length < MIN_LENGTH:
        issues.append(f"Too short ({length} characters; minimum is {MIN_LENGTH}).")
        suggestions.append(f"Use at least {RECOMMENDED_LENGTH} characters.")
    elif length < RECOMMENDED_LENGTH:
        suggestions.append(f"Longer is better: aim for {RECOMMENDED_LENGTH}+ characters.")

    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_digit:
        suggestions.append("Add numbers.")
    if not has_symbol:
        suggestions.append("Add symbols such as ! @ # $ % ^ & *.")

    # --- score ---------------------------------------------------------------
    score = int(min(100, entropy / TARGET_ENTROPY_BITS * 100))
    if is_common:
        score = min(score, 5)
    if length < MIN_LENGTH:
        score = min(score, 24)  # always at most "Very Weak" when too short
    elif length < RECOMMENDED_LENGTH:
        # The entropy model assumes random characters, which short human-made
        # passwords (e.g. "Tr0ub4dor&3") usually are not, so don't call
        # anything under the recommended length "Very Strong".
        score = min(score, 89)

    crack_seconds = (2**entropy) / 2 / GUESSES_PER_SECOND
    if is_common:
        crack_seconds = 0
    elif length < MIN_LENGTH:
        crack_seconds = min(crack_seconds, 60)

    if not suggestions and score >= 90:
        suggestions.append("Great password! Store it in a password manager and don't reuse it.")

    return StrengthResult(
        length=length,
        score=score,
        label=label_for_score(score),
        entropy_bits=round(entropy, 1),
        crack_time=format_crack_time(crack_seconds),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        is_common=is_common,
        issues=issues,
        suggestions=suggestions,
    )
