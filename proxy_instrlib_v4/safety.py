"""
safety.py — Content safety classifier (v4, unchanged from v2)
Identical to proxy_instrlib_v2/safety.py. Kept here so v4 is fully
self-contained and v2 remains untouched.

Tool call safety lives in tool_parser.py, not here — the two concerns
(text content vs proposed actions) are kept cleanly separated.
"""

from typing import List

FORBIDDEN_WORDS: List[str] = ["password", "secret", "api_key", "token"]


def classify(text: str) -> bool:
    """
    Return True if the text is safe, False if it contains forbidden content.

    True  → safe (no forbidden words found)
    False → unsafe (at least one forbidden word found)
    """
    text_lower = text.lower()
    return all(word not in text_lower for word in FORBIDDEN_WORDS)
