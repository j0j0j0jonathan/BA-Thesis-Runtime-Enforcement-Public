"""
mappings.py — η_i instrumentation mappings for v5 (Anthropic API proxy)
Maps structured tool_use blocks from the Anthropic Messages API into
MFOTL events for EnfGuard enforcement.

Unlike v4 (which mapped raw LLM text → events), v5 maps STRUCTURED API
objects → events. This means:
  - No heuristic regex for tool call detection
  - The API explicitly tells us: tool name, tool ID, exact arguments
  - We get reliable classification with zero false positives

EVENT MODEL
Every API response with tool_use blocks produces:
    AgentTurn(id)         — always, marks a new enforcement timestep (= turn counter)
    BashExec(id)          — agent proposes a Bash command
    FileWrite(file_id)    — agent proposes a Write/Edit operation
                            NOTE: file_id is a PERSISTENT per-path ID from the
                            file registry, NOT the turn counter. This means two
                            writes to the same file share the same file_id, and
                            writes to different files get different file_ids.
                            This allows MFOTL's a <> b to correctly detect
                            distinct files, even within a single turn.
    FileRead(id)          — agent proposes a Read/Glob/Grep operation
    WebAccess(id)         — agent proposes WebSearch/WebFetch
    SafeCommand(id)       — proposed action passes safety checks
    DangerousCommand(id)  — proposed action fails safety checks
    TextOnly(id)          — response has no tool_use blocks (text only)

FILE REGISTRY
A global dict maps file paths → unique integer IDs that persist for the
lifetime of the proxy process. This lets the MFOTL formula distinguish
distinct files without encoding paths into the formula itself.

    /tmp/a.txt → 1
    /tmp/b.txt → 2
    /tmp/a.txt → 1  (same file, same ID on re-write)

The IDs are printed to the log whenever a new path is registered, so
the trace is always interpretable.
"""

import threading
from typing import List, Dict, Any
from instrlib.event import Event
from tool_classifier import classify_tool_use, FILE_WRITE_TOOLS


# File path registry
# IDs start at 1001 to avoid confusion with turn counters (which start at 1).

_file_registry: Dict[str, int] = {}
_file_id_counter: int = 1000
_file_registry_lock = threading.Lock()


def _get_or_create_file_id(file_path: str) -> int:
    """
    Return the persistent integer ID for a file path.
    Assigns a new ID if the path has not been seen before.
    """
    global _file_id_counter
    with _file_registry_lock:
        if file_path not in _file_registry:
            _file_id_counter += 1
            _file_registry[file_path] = _file_id_counter
            print(f"[FileRegistry] New path registered: {file_path!r} → id={_file_id_counter}")
        else:
            print(f"[FileRegistry] Known path: {file_path!r} → id={_file_registry[file_path]}")
        return _file_registry[file_path]


def reset_file_registry() -> None:
    """Clear the file registry — call at proxy startup for a clean slate."""
    global _file_id_counter
    with _file_registry_lock:
        _file_registry.clear()
        _file_id_counter = 1000
    print("[FileRegistry] Registry cleared.")


#  Main mapping function 

def map_api_response(event_id: int, content_blocks: List[Dict[str, Any]]) -> List[Event]:
    """
    η_i mapping for an Anthropic Messages API response.

    Parameters
    event_id       : monotonic turn counter (used as ID for all non-FileWrite events)
    content_blocks : the 'content' array from the API response, e.g.
                     [{"type": "text", "text": "..."}, {"type": "tool_use", ...}]

    Returns
    List[Event] to send to EnfGuard at this timestep.

    FileWrite events use file-path IDs (from _file_registry), not event_id.
    All other events use event_id. This allows the MFOTL rate-limit policy
    to distinguish writes to distinct files using integer inequality (a <> b).
    """
    events = [Event("AgentTurn", event_id)]

    tool_use_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]

    if not tool_use_blocks:
        events.append(Event("TextOnly", event_id))
        return events

    # Process each tool_use block.
    # FileWrite events get per-path IDs; all other events share event_id.
    # seen_non_file: deduplicate non-FileWrite events within a turn
    # (e.g. two bash calls → one BashExec event). FileWrite is NOT
    # deduplicated so every distinct file in a single response is counted.
    seen_non_file: set = set()

    for block in tool_use_blocks:
        tool_name = block.get("name", "")
        tool_input = block.get("input", {})

        event_names = classify_tool_use(tool_name, tool_input)

        for name in event_names:
            if name == "FileWrite":
                # Assign a persistent per-path ID
                file_path = tool_input.get("file_path",
                            tool_input.get("path",
                            f"<unknown>_{event_id}"))
                file_id = _get_or_create_file_id(file_path)
                events.append(Event("FileWrite", file_id))
                # Do NOT deduplicate — each distinct file gets its own event

            elif name not in seen_non_file:
                events.append(Event(name, event_id))
                seen_non_file.add(name)

    return events
