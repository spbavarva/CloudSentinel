"""Credential sanitization utilities.

Prevents AWS credential material from leaking into error messages,
logs, or SSE events sent to the frontend.
"""

from __future__ import annotations

import re


def mask_key(key: str) -> str:
    """Return a masked version of a credential string.

    Shows the first 4 characters followed by '****'.
    Short or empty strings are fully masked.
    """
    if not key or len(key) <= 4:
        return "****"
    return key[:4] + "****"


def sanitize_error(message: str, keys: list[str]) -> str:
    """Replace any occurrence of credential values in *message* with ***REDACTED***.

    *keys* should contain the raw credential strings (access key, secret key,
    session token) that must not appear in output.  ``None`` values and empty
    strings are silently skipped.
    """
    result = message
    for key in keys:
        if key:
            result = result.replace(key, "***REDACTED***")
    return result


def classify_aws_error(message: str) -> dict:
    """Classify an error message into a category with a user-friendly message.

    Returns ``{"category": ..., "message": ...}`` suitable for SSE error events.
    """
    msg_lower = message.lower()

    if any(tok in msg_lower for tok in ("accessdenied", "access denied", "invalidclienttokenid", "invalid client token")):
        return {
            "category": "auth",
            "message": "AWS credentials are invalid or lack required permissions.",
        }

    if "expiredtoken" in msg_lower or "expired token" in msg_lower:
        return {
            "category": "auth",
            "message": "Session token has expired. Please provide fresh credentials.",
        }

    if "timeout" in msg_lower or "timed out" in msg_lower:
        return {
            "category": "timeout",
            "message": "The operation timed out. Try scanning fewer services or a different region.",
        }

    return {
        "category": "unknown",
        "message": message,
    }
