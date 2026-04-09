"""
instrlib.event — Event class
==============================
In the real InstrLib (Hublet et al., RV 2025), an Event is the unit of
communication between the application, η_i (mappings), and the PDP (EnfGuard).

The mapping function in the PEP produces Event objects from application action
arguments. These are serialised into the EnfGuard log format and later
parsed back from EnfGuard's output.

This implementation closely mirrors the real library's Event class.
"""

from typing import Any, Tuple


class Event:
    """
    A named, typed event with zero or more arguments.

    Examples:
        Event("Ask", 1)             → Ask(1)
        Event("Disclaimer", 3)      → Disclaimer(3)
        Event("UnsafeResponse", 2)  → UnsafeResponse(2)
    """

    def __init__(self, name: str, *args: Any) -> None:
        self.name: str             = name
        self.args: Tuple[Any, ...] = args

    # ── Serialisation ─────────────────────────────────────────────────────────
    # EnfGuard log format:  @<ts> EventName(arg1, arg2, ...)
    # Strings must be double-quoted; integers written bare.

    def _format_arg(self, v: Any) -> str:
        s = str(v)
        return s if s.lstrip("-").isnumeric() else f'"{s}"'

    def __str__(self) -> str:
        args_str = ", ".join(self._format_arg(a) for a in self.args)
        return f"{self.name}({args_str})"

    def __repr__(self) -> str:
        return self.__str__()

    def __hash__(self) -> int:
        return hash(repr(self))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Event) and hash(self) == hash(other)
