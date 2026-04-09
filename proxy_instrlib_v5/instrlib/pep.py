"""
instrlib.pep — Policy Enforcement Point (data structure)
==========================================================
In the real InstrLib (Hublet et al., RV 2025), the PEP is a plain data object
constructed upfront with three dictionaries:

    mapping              : (ClassName, methodName) → event-producing function
    causation_handlers   : event_name → handler function
    suppression_handlers : event_name → handler function

This is the key architectural difference from our v1 stub, which used Python
decorators (@action_mapping, @causation_handler) to build the same registries
at import time. Both approaches produce equivalent data structures, but the
real library's dict-based approach makes the PEP explicit and inspectable —
you can see the entire enforcement contract in one place.

The handler signature convention used here:
    causation_handler(event_id: int, original_result: str) -> str | None
        Returns None    → signal to fully block (replace with canned message)
        Returns str     → the enforced response to return to the caller

    suppression_handler(event_id: int, original_result: str) -> str
        Returns the replacement string for the suppressed response.
        (Not used in the test2 architecture — kept for completeness.)
"""

from typing import Any, Callable, Dict, Optional, Tuple


class PEP:
    """
    Policy Enforcement Point — ties η_i (mappings) and η_e (handlers) together.

    In the real library, the PEP supports the | operator to merge two PEPs
    (useful for composing multiple policies). We include that here as well.

    Attributes
    ----------
    mapping              : {(ClassName, methodName): Callable[..., List[Event]]}
    cau_event_map        : {event_name: handler_fn}
    sup_event_map        : {event_name: handler_fn}
    """

    def __init__(
        self,
        mapping:              Dict[Tuple[str, str], Callable] = None,
        causation_handlers:   Dict[str, Callable]            = None,
        suppression_handlers: Dict[str, Callable]            = None,
    ) -> None:
        self.mapping       : Dict[Tuple[str, str], Callable] = mapping              or {}
        self.cau_event_map : Dict[str, Callable]             = causation_handlers   or {}
        self.sup_event_map : Dict[str, Callable]             = suppression_handlers or {}

    def __or__(self, other: "PEP") -> "PEP":
        """Merge two PEPs — the real library uses this for policy composition."""
        return PEP(
            mapping              = {**self.mapping,       **other.mapping},
            causation_handlers   = {**self.cau_event_map, **other.cau_event_map},
            suppression_handlers = {**self.sup_event_map, **other.sup_event_map},
        )

    def __contains__(self, key: Tuple[str, str]) -> bool:
        return key in self.mapping

    def __getitem__(self, key: Tuple[str, str]) -> Callable:
        return self.mapping[key]

    def __repr__(self) -> str:
        return (
            f"PEP(\n"
            f"  mapping={list(self.mapping.keys())},\n"
            f"  causation_handlers={list(self.cau_event_map.keys())},\n"
            f"  suppression_handlers={list(self.sup_event_map.keys())}\n"
            f")"
        )
