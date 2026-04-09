"""
handlers.py — η_e enforcement action handlers for v5 (Anthropic API proxy)
These handlers modify the API response when enforcement fires.

In v4, handlers modified text strings. In v5, handlers modify the
structured Anthropic API response, specifically, they can remove or
replace tool_use content blocks.


BlockAction  → Remove the offending tool_use block(s), replace with a
               text block explaining what was blocked and why.
WarnAction   → Keep the tool_use block(s) but prepend a warning text
               block so the SDK (and thus the agent) sees the warning.
"""

from typing import Any, Dict, List, Optional


_BLOCK_TEMPLATE = (
    "[ENFORCEMENT] Action blocked by runtime policy. "
    "The agent attempted: {tool_name}({summary}). "
    "This was blocked because it matched a dangerous pattern. "
    "The agent should choose a safer alternative."
)

_WARN_TEMPLATE = (
    "[ENFORCEMENT WARNING] Elevated scrutiny active. "
    "A dangerous action was recently attempted. "
    "This action ({tool_name}) is allowed but monitored. "
    "Further dangerous actions will be blocked."
)


def cause_block_action(
    event_id: int,
    response_body: Dict[str, Any],
    blocked_tools: List[str],
) -> Dict[str, Any]:
    """
    Remove dangerous tool_use blocks from the response and replace
    them with a text explanation.

    Parameters
    event_id      : enforcement timestep
    response_body : the full Anthropic API response dict
    blocked_tools : list of tool names that triggered the block

    Returns
    Modified response body with tool_use blocks replaced by text.
    """
    content = response_body.get("content", [])
    new_content = []
    blocked_any = False

    for block in content:
        if block.get("type") == "tool_use" and block.get("name") in blocked_tools:
            # Replace with enforcement explanation
            tool_name = block.get("name", "unknown")
            tool_input = block.get("input", {})
            summary = _summarize_input(tool_name, tool_input)
            new_content.append({
                "type": "text",
                "text": _BLOCK_TEMPLATE.format(tool_name=tool_name, summary=summary),
            })
            blocked_any = True
        else:
            new_content.append(block)

    if blocked_any:
        response_body["content"] = new_content
        # Must also update stop_reason — if we removed all tool_use blocks
        # and only text remains, the stop_reason should be "end_turn"
        has_tool_use = any(b.get("type") == "tool_use" for b in new_content)
        if not has_tool_use:
            response_body["stop_reason"] = "end_turn"

    return response_body


def cause_warn_action(
    event_id: int,
    response_body: Dict[str, Any],
    warned_tools: List[str],
) -> Dict[str, Any]:
    """
    Keep tool_use blocks but prepend a warning text block.

    Parameters
    event_id      : enforcement timestep
    response_body : the full Anthropic API response dict
    warned_tools  : list of tool names that triggered the warning

    Returns
    Modified response body with warning prepended.
    """
    content = response_body.get("content", [])
    tool_names = ", ".join(warned_tools)
    warning_block = {
        "type": "text",
        "text": _WARN_TEMPLATE.format(tool_name=tool_names),
    }
    response_body["content"] = [warning_block] + content
    return response_body


def _summarize_input(tool_name: str, tool_input: dict) -> str:
    """Create a short summary of tool input for the block message."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if len(cmd) > 80:
            return cmd[:77] + "..."
        return cmd
    elif tool_name in ("Write", "Edit"):
        return tool_input.get("file_path", "unknown file")
    elif tool_name in ("WebSearch", "WebFetch"):
        return tool_input.get("url", tool_input.get("query", ""))
    else:
        return str(tool_input)[:80]
