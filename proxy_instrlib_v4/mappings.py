"""
mappings.py — η_i instrumentation mappings (v4, tool call extension)

Extends v2's mapping with tool call detection.

At every request, the mapping function now performs TWO independent
classification tasks and encodes both as events in the trace:

    1.  Content safety  (unchanged from v2)
            Ask(id) + SafeResponse(id)    — if text content is safe
            Ask(id) + UnsafeResponse(id)  — if text contains forbidden words

    2.  Tool call detection  (new in v4)
            If the LLM response contains a proposed shell/tool command:
                ToolCallProposed(id) + SafeToolCall(id)     — if command is safe
                ToolCallProposed(id) + DangerousToolCall(id) — if command is dangerous
            If no command is detected: neither event is emitted.

These events are all sent at the same timestep (= event_id). EnfGuard
evaluates them simultaneously and applies whichever policy clauses fire.

Example traces: 
Safe response, no tool call:
    @5 Ask(5) SafeResponse(5)

Unsafe response, no tool call:
    @5 Ask(5) UnsafeResponse(5)

Safe response, dangerous tool call proposed:
    @5 Ask(5) SafeResponse(5) ToolCallProposed(5) DangerousToolCall(5)

Safe response, safe tool call proposed (e.g. "run `ls -la`"):
    @5 Ask(5) SafeResponse(5) ToolCallProposed(5) SafeToolCall(5)

separation:

    safety.py      — text content classification:   str → bool
    tool_parser.py — tool call detection:           str → Optional[str]
                   — tool call classification:      str → bool
    mappings.py    — event abstraction:             (id, text) → List[Event]
"""

from typing import List

from instrlib.event import Event
from safety import classify
from tool_parser import extract_tool_call, classify_tool_call


def ask_mapping(event_id: int, llm_response: str) -> List[Event]:

    events = [Event("Ask", event_id)]

    # Content safety (Policy 1 + 2) 
    if classify(llm_response):
        events.append(Event("SafeResponse", event_id))
    else:
        events.append(Event("UnsafeResponse", event_id))

    # Tool call detection (Policy 3 + 4) 
    command = extract_tool_call(llm_response)
    if command is not None:
        events.append(Event("ToolCallProposed", event_id))
        if classify_tool_call(command):
            events.append(Event("SafeToolCall", event_id))
        else:
            events.append(Event("DangerousToolCall", event_id))

    return events
