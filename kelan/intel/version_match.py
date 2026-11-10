from __future__ import annotations

import re
from typing import Any
from packaging.version import InvalidVersion, parse as parse_version


def _normalize_version_str(v: str) -> str:
    v = v.strip()
    if v.startswith(("v", "V")) and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    return v


def _tokenized_version(v: str) -> tuple[list[tuple[int, Any]], str]:
    """Fallback tokenized representation for non-PEP440 versions (e.g., Maven, custom SemVer tags)."""
    norm = _normalize_version_str(v)
    parts = re.split(r"([0-9]+)", norm)
    tokens: list[tuple[int, Any]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            tokens.append((0, int(part)))
        else:
            # Clean punctuation
            cleaned = part.strip(".-_+").lower()
            if cleaned:
                tokens.append((1, cleaned))
    return tokens, norm


def _fallback_compare(v1_str: str, v2_str: str) -> int:
    """Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
    t1, norm1 = _tokenized_version(v1_str)
    t2, norm2 = _tokenized_version(v2_str)

    max_len = max(len(t1), len(t2))
    for i in range(max_len):
        tok1 = t1[i] if i < len(t1) else (0, 0)
        tok2 = t2[i] if i < len(t2) else (0, 0)
        if tok1 == tok2:
            continue
        # Numbers compare with numbers, strings compare with strings
        if tok1[0] == tok2[0]:
            return -1 if tok1[1] < tok2[1] else 1
        # Numeric token vs string token: numeric token is typically considered newer/higher than pre-release tags
        return 1 if tok1[0] == 0 else -1

    return 0


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings across packaging ecosystems.
    Returns:
      -1 if v1 < v2
       0 if v1 == v2
       1 if v1 > v2
    """
    n1 = _normalize_version_str(v1)
    n2 = _normalize_version_str(v2)
    if n1 == n2:
        return 0

    try:
        p1 = parse_version(n1)
        p2 = parse_version(n2)
        if p1 < p2:
            return -1
        if p1 > p2:
            return 1
        return 0
    except (InvalidVersion, TypeError):
        return _fallback_compare(n1, n2)


def is_version_vulnerable(
    version: str,
    introduced: str = "0",
    fixed: str | None = None,
    specific_versions: list[str] | None = None,
) -> bool:
    """Check if a package version falls within a vulnerable range [introduced, fixed)
    or is explicitly listed in specific_versions.
    """
    clean_v = _normalize_version_str(version)
    if not clean_v:
        return False

    # Check explicit vulnerable versions list if available
    if specific_versions:
        match_specific = any(_normalize_version_str(sv) == clean_v for sv in specific_versions)
        if match_specific:
            return True
        # If specific_versions was provided and no range was specified, do not fall through to [0, None)
        if (introduced == "0" or not introduced) and (fixed is None or fixed == ""):
            return False

    # Check introduced bound
    intro = _normalize_version_str(introduced or "0")
    if intro and intro != "0":
        if compare_versions(clean_v, intro) < 0:
            return False

    # Check fixed bound
    if fixed:
        fix = _normalize_version_str(fixed)
        if fix and fix != "":
            if compare_versions(clean_v, fix) >= 0:
                return False

    return True
