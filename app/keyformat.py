from __future__ import annotations

import secrets

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
GROUPS = 4
GROUP_LEN = 4
PREFIX_TEXT = "RANK"
TIERS = {"1d": 1, "3d": 3, "7d": 7, "10d": 10, "30d": 30}


def normalize(raw: str) -> str:
    out = "".join(ch for ch in raw.upper() if ch not in " -_")
    if out.startswith(PREFIX_TEXT):
        out = out[len(PREFIX_TEXT):]
    return "".join(ch for ch in out if ch in ALPHABET)


def generate() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(GROUPS * GROUP_LEN))
    return PREFIX_TEXT + "-" + "-".join(body[i:i + GROUP_LEN] for i in range(0, len(body), GROUP_LEN))


def prefix_of(raw: str) -> str:
    """Lookup handle: RANK + first group, e.g. 'RANK-7Q4M'."""
    body = normalize(raw)
    if len(body) < GROUP_LEN:
        return ""
    return PREFIX_TEXT + "-" + body[:GROUP_LEN]


def is_well_formed(raw: str) -> bool:
    return len(normalize(raw)) == GROUPS * GROUP_LEN


def tier_days(tier: str) -> int:
    return TIERS.get(tier.lower(), 0)
