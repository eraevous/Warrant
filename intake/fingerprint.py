"""Public report fingerprint for Warrant's intake (DEC-260, amended by DEC-264 (5)).

The fingerprint is SHA-256 over a fresh random nonce followed by the report's
UTF-8 bytes: SHA-256(nonce || report). The nonce is 16 bytes (128 bits), so the
split between nonce and report is fixed and unambiguous. The submitter keeps
the nonce with the report; the fingerprint alone is published at intake and
attached to the fix. Without the nonce, a short or templated report can't be
recovered by hashing guesses. The scheme applies to every report kind.

Standard library only.
"""

import hashlib
import hmac
import secrets

SCHEME = "sha256(nonce16||utf8(report))"
NONCE_BYTES = 16
KINDS = ("security", "bug", "improvement")


def new_nonce() -> bytes:
    """A fresh 128-bit nonce from the operating system's CSPRNG."""
    return secrets.token_bytes(NONCE_BYTES)


def fingerprint(report: str, nonce: bytes) -> str:
    """Hex SHA-256 of nonce || report. Refuses a nonce of the wrong length."""
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be exactly {NONCE_BYTES} bytes")
    return hashlib.sha256(nonce + report.encode("utf-8")).hexdigest()


def verify(report: str, nonce: bytes, published: str) -> bool:
    """True when the published fingerprint matches this report and nonce."""
    return hmac.compare_digest(fingerprint(report, nonce), published.lower())


def receipt(report: str, kind: str) -> dict:
    """What intake returns: the public fingerprint and scheme, plus the nonce
    the submitter keeps. Only `kind`, `scheme` and `fingerprint` are published."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    nonce = new_nonce()
    return {
        "kind": kind,
        "scheme": SCHEME,
        "fingerprint": fingerprint(report, nonce),
        "nonce": nonce.hex(),
    }
