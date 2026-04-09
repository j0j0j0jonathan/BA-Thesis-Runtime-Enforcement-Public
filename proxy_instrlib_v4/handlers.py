"""
handlers.py — η_e enforcement handlers (v4, tool call extension)

Extends v2's handlers with two new causation handlers for tool call
enforcement: BlockToolCall and WarnToolCall.

Handler Prioority: registration order in proxy_instrlib_v4.py PEP dict)

    1.  Block          — content policy: repeated unsafe response → full block
    2.  BlockToolCall  — tool policy: dangerous command proposed → full block
    3.  WarnToolCall   — tool policy: safe command after recent danger → warning
    4.  Disclaimer     — content policy: first unsafe response → prepend warning

Block always wins. If both content and tool policies fire simultaneously,
the most restrictive action is returned.

Handlers (unchanged from v2)

    handler(event_id: int, original_result: str) -> str | None
        Returns None    → full block (endpoint substitutes canned message)
        Returns str     → the string sent to the user (modified or original)
"""

from typing import Optional


# Content policy handlers (unchanged from v2)

_DISCLAIMER_PREFIX = (
    "⚠️ Policy notice: this response was flagged by the content enforcement layer.\n\n"
)


def cause_disclaimer(event_id: int, original_result: str) -> str:
    """Policy 1a: First unsafe content response → prepend disclaimer."""
    print(f"[v4] Disclaimer({event_id}): first unsafe content response.")
    return _DISCLAIMER_PREFIX + original_result


def cause_block(event_id: int, original_result: str) -> None:
    """Policy 1b/2: Repeated unsafe or rate limit → full block."""
    print(f"[v4] Block({event_id}): repeated unsafe content or rate limit.")
    return None


# Tool call policy handlers (new in v4)

_TOOL_BLOCK_PREFIX = (
    "🚫 Tool call blocked: the proposed command was classified as dangerous "
    "by the enforcement layer and has been suppressed.\n\n"
    "Original response (command redacted):\n\n"
)

_TOOL_WARN_PREFIX = (
    "⚠️ Tool call warning: a previous dangerous command was proposed recently. "
    "Proceed with caution.\n\n"
)


def cause_block_tool_call(event_id: int, original_result: str) -> None:
    """
    Policy 3: Dangerous tool call proposed → full block.

    Returns None so the endpoint substitutes its canned block message.
    The reason field in the response will include the specific command.
    """
    print(f"[v4] BlockToolCall({event_id}): dangerous command detected.")
    return None


def cause_warn_tool_call(event_id: int, original_result: str) -> str:
    """
    Policy 4: Safe tool call proposed after recent dangerous one → warning.

    Prepends a caution notice but still delivers the response.
    """
    print(f"[v4] WarnToolCall({event_id}): safe command after recent dangerous one.")
    return _TOOL_WARN_PREFIX + original_result
