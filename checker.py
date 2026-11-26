"""Core password strength evaluation engine.

Provides typed password strength analysis including length and character
diversity scoring, effective bit entropy calculation, multi-word passphrase
recognition, leet-speak common password normalization, horizontal/diagonal
keyboard walk detection, and optional privacy-safe Have I Been Pwned (HIBP)
k-anonymity breach checks.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Literal

Rating = Literal["Weak", "Fair", "Strong", "Very Strong"]

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
STRONG_LENGTH = 16
MAX_LENGTH = 128

SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
HIBP_RANGE_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
DEFAULT_HIBP_TIMEOUT = 3.0

COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "12345",
        "1234",
        "000000",
        "111111",
        "654321",
        "666666",
        "987654321",
        "password",
        "password1",
        "password123",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "abc123",
        "admin",
        "admin123",
        "administrator",
        "letmein",
        "letmein1",
        "welcome",
        "welcome1",
        "monkey",
        "dragon",
        "master",
        "football",
        "baseball",
        "iloveyou",
        "trustno1",
        "sunshine",
        "princess",
        "shadow",
        "superman",
        "michael",
        "charlie",
        "donald",
        "starwars",
        "batman",
        "freedom",
        "whatever",
        "qazwsx",
        "zaq12wsx",
        "root",
        "toor",
        "guest",
        "test",
        "testing",
        "changeme",
        "default",
        "login",
        "access",
        "secret",
        "pass",
        "temp123",
    }
)

_SEQUENTIAL_ALPHANUMERIC: tuple[str, ...] = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)

# Horizontal letter/symbol rows and diagonal QWERTY keyboard walks.
# Plain numeric runs ("1234") are handled by has_sequential_run to avoid double penalties.
_KEYBOARD_WALKS: tuple[str, ...] = (
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "~!@#$%^&*()_+",
    # Down-right diagonals
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/",
    "qazwsxedcrfvtgbyhnujmikolp",
    # Down-left diagonals
    "2qaz",
    "3wax",
    "4esz",
    "5rdx",
    "6tfc",
    "7ygv",
    "8uhb",
    "9ijn",
    "0okm",
    "-pl,",
    "=[;/",
)

_LEET_TRANS = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "0": "o",
        "$": "s",
        "5": "s",
        "3": "e",
        "!": "i",
        "7": "t",
    }
)

_TRAILING_STRIP_CHARS = "0123456789" + SPECIAL_CHARACTERS + " \t\r\n"
_PASSPHRASE_SEPARATOR_RE = re.compile(r"[\s\-_.]+")


@dataclass(frozen=True, slots=True)
class PasswordReport:
    """Structured result returned by :func:`evaluate_password`."""

    score: int
    rating: Rating
    entropy_bits: float
    is_breached: bool | None
    suggestions: list[str]
    is_passphrase: bool = False
    breach_count: int | None = None
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report into a JSON-compatible dictionary."""
        return {
            "score": self.score,
            "rating": self.rating,
            "entropy_bits": self.entropy_bits,
            "is_breached": self.is_breached,
            "breach_count": self.breach_count,
            "is_passphrase": self.is_passphrase,
            "suggestions": list(self.suggestions),
            "checks": dict(self.checks),
        }


def validate_password_input(password: str) -> str | None:
    """Validate raw password input before evaluation.

    Returns an error message string if invalid, or ``None`` if valid.
    Raises ``TypeError`` if *password* is not a ``str``.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if len(password) == 0:
        return "Password cannot be empty."
    if password.strip() == "":
        return "Password cannot contain only whitespace."
    if len(password) > MAX_LENGTH:
        return f"Password must not exceed {MAX_LENGTH} characters."
    return None


def has_lowercase(password: str) -> bool:
    """Return True if *password* contains at least one lowercase letter."""
    return any(ch.islower() for ch in password)


def has_uppercase(password: str) -> bool:
    """Return True if *password* contains at least one uppercase letter."""
    return any(ch.isupper() for ch in password)


def has_digit(password: str) -> bool:
    """Return True if *password* contains at least one digit."""
    return any(ch.isdigit() for ch in password)


def has_special_char(password: str) -> bool:
    """Return True if *password* contains at least one allowed special character."""
    return any(ch in SPECIAL_CHARACTERS for ch in password)


def has_edge_whitespace(password: str) -> bool:
    """Return True if *password* has leading or trailing whitespace."""
    return bool(password) and password != password.strip()


def normalize_leetspeak(password: str) -> set[str]:
    """Generate lowercase leet-speak normalized candidate strings for *password*.

    Normalizes common substitutions (``@``->``a``, ``0``->``o``, ``$``->``s``,
    ``1``->``i``/``l``, ``3``->``e``, ``!``->``i``, ``4``->``a``, ``5``->``s``,
    ``7``->``t``) and also evaluates variants with trailing digits/symbols stripped
    so mutations like ``P@ssw0rd!`` or ``P@ssw0rd123`` match ``password``.
    """
    base = password.strip().lower()
    if not base:
        return set()

    seeds: set[str] = {base}
    for strip_chars in (
        SPECIAL_CHARACTERS + " \t\r\n",
        "0123456789 \t\r\n",
        _TRAILING_STRIP_CHARS,
    ):
        stripped = base.rstrip(strip_chars)
        if len(stripped) >= 4:
            seeds.add(stripped)

    candidates: set[str] = set()
    for seed in seeds:
        candidates.add(seed)
        translated = seed.translate(_LEET_TRANS)
        candidates.add(translated)

        # Expand ambiguous '1' -> 'i' or 'l'
        one_positions = [idx for idx, ch in enumerate(translated) if ch == "1"]
        if one_positions:
            if len(one_positions) <= 6:
                chars = list(translated)
                for replacements in itertools.product(("i", "l"), repeat=len(one_positions)):
                    for pos, rep in zip(one_positions, replacements):
                        chars[pos] = rep
                    variant = "".join(chars)
                    candidates.add(variant)
            else:
                candidates.add(translated.replace("1", "i"))
                candidates.add(translated.replace("1", "l"))

    # Also check candidates with trailing symbols/digits trimmed after substitution
    extra: set[str] = set()
    for cand in candidates:
        trimmed = cand.rstrip(_TRAILING_STRIP_CHARS)
        if len(trimmed) >= 4:
            extra.add(trimmed)
    candidates.update(extra)

    return candidates


def is_common_password(password: str) -> bool:
    """Return True if *password* (or its leet-speak normalization) is a known weak password."""
    return any(candidate in COMMON_PASSWORDS for candidate in normalize_leetspeak(password))


def has_repeated_chars(password: str, min_run: int = 3) -> bool:
    """Return True if any character repeats consecutively at least *min_run* times."""
    if len(password) < min_run:
        return False

    run_length = 1
    for idx in range(1, len(password)):
        if password[idx] == password[idx - 1]:
            run_length += 1
            if run_length >= min_run:
                return True
        else:
            run_length = 1
    return False


def has_sequential_run(password: str, min_run: int = 4) -> bool:
    """Return True if *password* contains an ascending or descending alphanumeric run."""
    if len(password) < min_run:
        return False

    lowered = password.lower()
    for start in range(len(lowered) - min_run + 1):
        window = lowered[start : start + min_run]
        for source in _SEQUENTIAL_ALPHANUMERIC:
            if window in source or window in source[::-1]:
                return True
    return False


def has_keyboard_walk(password: str, min_run: int = 4) -> bool:
    """Return True if *password* contains a forward or reverse QWERTY keyboard walk.

    Detects both horizontal row sequences (e.g., ``qwerty``, ``asdfgh``, ``zxcvbn``)
    and diagonal walks (e.g., ``1qaz2wsx``, ``3edc``, ``4esz``).
    """
    if len(password) < min_run:
        return False

    lowered = password.lower()
    for start in range(len(lowered) - min_run + 1):
        window = lowered[start : start + min_run]
        for walk in _KEYBOARD_WALKS:
            if window in walk or window in walk[::-1]:
                return True
    return False


def is_passphrase(password: str) -> bool:
    """Return True if *password* qualifies as a multi-word passphrase.

    Requires at least ``STRONG_LENGTH`` (16) characters and at least 3 distinct
    word tokens (each >= 2 characters) separated by spaces, hyphens, underscores,
    or periods.
    """
    trimmed = password.strip()
    if len(trimmed) < STRONG_LENGTH:
        return False

    tokens = [tok for tok in _PASSPHRASE_SEPARATOR_RE.split(trimmed) if tok]
    if len(tokens) < 3:
        return False

    word_tokens = [tok.lower() for tok in tokens if len(tok) >= 2 and any(c.isalpha() for c in tok)]
    return len(word_tokens) >= 3 and len(set(word_tokens)) >= 3


def calculate_entropy(password: str) -> float:
    """Calculate effective password entropy in bits based on pool size and structure.

    Uses character-class pool size :math:`R` and an effective length adjusted for
    consecutive character repeats and predictable patterns.
    """
    if not password or password.strip() == "":
        return 0.0

    pool_size = 0
    if any(ch.isascii() and ch.islower() for ch in password):
        pool_size += 26
    if any(ch.isascii() and ch.isupper() for ch in password):
        pool_size += 26
    if any(ch.isascii() and ch.isdigit() for ch in password):
        pool_size += 10
    if any(ch in SPECIAL_CHARACTERS or (ch.isascii() and not ch.isalnum() and not ch.isspace()) for ch in password):
        pool_size += 32
    if any(ch.isspace() for ch in password):
        pool_size += 1
    if any(not ch.isascii() for ch in password):
        pool_size += 64

    if pool_size <= 1:
        return 0.0

    # Discount redundant consecutive repeats beyond 2 identical characters
    redundant = 0
    run_length = 1
    for idx in range(1, len(password)):
        if password[idx] == password[idx - 1]:
            run_length += 1
            if run_length > 2:
                redundant += 1
        else:
            run_length = 1

    effective_length = max(1, len(password) - redundant)
    bits = effective_length * math.log2(pool_size)

    # Apply realistic predictability discounts
    if has_sequential_run(password):
        bits *= 0.75
    if has_keyboard_walk(password):
        bits *= 0.70
    if is_common_password(password):
        bits = min(bits * 0.2, 10.0)

    return round(bits, 2)


def check_password_breach(
    password: str,
    timeout: float = DEFAULT_HIBP_TIMEOUT,
) -> tuple[bool | None, int | None]:
    """Query the HIBP k-anonymity API using only the first 5 SHA-1 hex characters.

    Args:
        password: The candidate password string.
        timeout: Network timeout in seconds (defaults to 3.0).

    Returns:
        A tuple ``(is_breached, count)``:
            - ``(True, count)`` if found in known breaches (``count > 0``).
            - ``(False, 0)`` if checked successfully and not found.
            - ``(None, None)`` if the API could not be reached or timed out.
    """
    sha1_hex = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hex[:5], sha1_hex[5:]

    url = HIBP_RANGE_API_URL.format(prefix=prefix)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PasswordStrengthChecker/2.0",
            "Add-Padding": "true",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return (None, None)

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        line_suffix, count_str = line.split(":", 1)
        if line_suffix.strip().upper() == suffix:
            try:
                count = int(count_str.strip())
            except ValueError:
                return (None, None)
            if count > 0:
                return (True, count)
            return (False, 0)

    return (False, 0)


def score_to_rating(score: int) -> Rating:
    """Map a numeric 0–100 score to a human-readable strength rating."""
    if score >= 90:
        return "Very Strong"
    if score >= 65:
        return "Strong"
    if score >= 40:
        return "Fair"
    return "Weak"


def evaluate_password(
    password: str,
    check_breach: bool = False,
    *,
    timeout: float = DEFAULT_HIBP_TIMEOUT,
) -> PasswordReport:
    """Evaluate password strength and return a typed :class:`PasswordReport`.

    Args:
        password: The candidate password string to evaluate.
        check_breach: If True, perform a privacy-safe HIBP k-anonymity lookup.
        timeout: Timeout in seconds for the optional HIBP lookup.

    Returns:
        A :class:`PasswordReport` instance containing score, rating, entropy,
        breach status, actionable suggestions, and per-rule checks.

    Raises:
        TypeError: If *password* is not a string.
    """
    validation_error = validate_password_input(password)
    if validation_error is not None:
        return PasswordReport(
            score=0,
            rating="Weak",
            entropy_bits=0.0,
            is_breached=None,
            breach_count=None,
            is_passphrase=False,
            suggestions=[validation_error],
            checks={
                "valid_input": False,
                "min_length": False,
                "recommended_length": False,
                "strong_length": False,
                "within_max_length": len(password) <= MAX_LENGTH,
                "has_lowercase": False,
                "has_uppercase": False,
                "has_digit": False,
                "has_special": False,
                "passphrase": False,
                "not_common": True,
                "no_repeated_chars": True,
                "no_sequential_runs": True,
                "no_keyboard_walks": True,
                "no_edge_whitespace": bool(password) and password == password.strip(),
            },
        )

    score = 0
    suggestions: list[str] = []

    # 1. Length rules (up to 40 points)
    length = len(password)
    meets_min_length = length >= MIN_LENGTH
    meets_recommended_length = length >= RECOMMENDED_LENGTH
    meets_strong_length = length >= STRONG_LENGTH

    if meets_strong_length:
        score += 40
    elif meets_recommended_length:
        score += 30
        suggestions.append(
            f"Consider using {STRONG_LENGTH} or more characters for maximum strength."
        )
    elif meets_min_length:
        score += 20
        suggestions.append(
            f"Increase length to at least {RECOMMENDED_LENGTH} characters for stronger security."
        )
    else:
        suggestions.append(
            f"Use at least {MIN_LENGTH} characters ({RECOMMENDED_LENGTH} or more recommended)."
        )

    # 2. Passphrase & character diversity rules (up to 60 points)
    passphrase_ok = is_passphrase(password)
    lower_ok = has_lowercase(password)
    upper_ok = has_uppercase(password)
    digit_ok = has_digit(password)
    special_ok = has_special_char(password)

    if lower_ok:
        score += 15
    else:
        suggestions.append("Add at least one lowercase letter (a–z).")

    if upper_ok:
        score += 15
    elif not passphrase_ok:
        suggestions.append("Add at least one uppercase letter (A–Z).")

    if digit_ok:
        score += 15
    elif not passphrase_ok:
        suggestions.append("Add at least one digit (0–9).")

    if special_ok:
        score += 15
    elif not passphrase_ok:
        suggestions.append(f"Add at least one special character ({SPECIAL_CHARACTERS}).")

    # Award passphrase credit so long multi-word passphrases score fairly without
    # forcing special characters.
    if passphrase_ok:
        tokens = [
            tok.lower()
            for tok in _PASSPHRASE_SEPARATOR_RE.split(password.strip())
            if len(tok) >= 2 and any(c.isalpha() for c in tok)
        ]
        distinct_words = len(set(tokens))
        passphrase_bonus = 30 if distinct_words >= 4 else 25
        score += passphrase_bonus
        if score < 90:
            suggestions.append(
                "Optionally capitalize a word or include a number to reach maximum strength."
            )

    # 3. Common password & leet-speak check
    common = is_common_password(password)
    if common:
        score -= 50
        suggestions.append(
            "Avoid commonly used passwords or predictable leet-speak variants (e.g., 'P@ssw0rd!')."
        )

    # 4. Pattern & keyboard walk penalties
    repeated = has_repeated_chars(password)
    if repeated:
        score -= 15
        suggestions.append(
            "Avoid repeating the same character consecutively (e.g., 'aaa', '1111')."
        )

    sequential = has_sequential_run(password)
    if sequential:
        score -= 15
        suggestions.append(
            "Avoid sequential letters or numbers (e.g., '1234', 'abcd', '9876')."
        )

    keyboard_walk = has_keyboard_walk(password)
    if keyboard_walk:
        score -= 15
        suggestions.append(
            "Avoid keyboard walk patterns (e.g., 'qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx')."
        )

    # 5. Whitespace check (leading/trailing spaces)
    edge_whitespace = has_edge_whitespace(password)
    if edge_whitespace:
        score -= 10
        suggestions.append(
            "Remove leading or trailing spaces, as they can cause login issues."
        )

    # 6. Entropy calculation
    entropy_bits = calculate_entropy(password)

    # 7. Optional privacy-safe HIBP breach check
    is_breached: bool | None = None
    breach_count: int | None = None
    if check_breach:
        is_breached, breach_count = check_password_breach(password, timeout=timeout)
        if is_breached is True:
            score = min(score, 10)
            if breach_count is not None:
                suggestions.append(
                    f"This password appeared in known data breaches ({breach_count:,} times). "
                    "Do not use it; choose a unique password."
                )
            else:
                suggestions.append(
                    "This password appeared in known data breaches. Do not use it."
                )

    # Enforce caps for critical failures and clamp to 0–100
    if not meets_min_length:
        score = min(score, 35)
    if common:
        score = min(score, 15)
    if is_breached is True:
        score = min(score, 10)

    score = max(0, min(100, score))

    checks: dict[str, bool] = {
        "valid_input": True,
        "min_length": meets_min_length,
        "recommended_length": meets_recommended_length,
        "strong_length": meets_strong_length,
        "within_max_length": True,
        "has_lowercase": lower_ok,
        "has_uppercase": upper_ok,
        "has_digit": digit_ok,
        "has_special": special_ok,
        "passphrase": passphrase_ok,
        "not_common": not common,
        "no_repeated_chars": not repeated,
        "no_sequential_runs": not sequential,
        "no_keyboard_walks": not keyboard_walk,
        "no_edge_whitespace": not edge_whitespace,
    }
    if is_breached is not None:
        checks["not_breached"] = not is_breached

    return PasswordReport(
        score=score,
        rating=score_to_rating(score),
        entropy_bits=entropy_bits,
        is_breached=is_breached,
        breach_count=breach_count,
        is_passphrase=passphrase_ok,
        suggestions=suggestions,
        checks=checks,
    )
