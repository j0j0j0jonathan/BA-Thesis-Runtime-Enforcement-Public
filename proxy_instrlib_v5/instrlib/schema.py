"""
instrlib.schema — Schema (Python mirror of the .sig file)
===========================================================
The real InstrLib validates every event against a Schema before sending it to
EnfGuard. This mirrors the type information declared in the .sig file and
catches mismatches at the application layer rather than inside the PDP.

Usage:
    schema = Schema({
        "Ask":           [int],
        "Disclaimer":    [int],
        "Block":         [int],
        "UnsafeResponse":[int],
    })

The Schema is passed to the Logger, which calls validate() on every event
before logging it.
"""

from typing import Dict, List

from instrlib.event import Event


class Schema:
    """
    Maps event names to their expected argument types.

    In the real library, Schema also supports optional arguments and purpose
    annotations (for privacy enforcement). We implement the core subset needed
    for our LLM proxy use case.
    """

    def __init__(self, mapping: Dict[str, List[type]]) -> None:
        self.mapping = mapping

    def __contains__(self, event_name: str) -> bool:
        return event_name in self.mapping

    def get_types(self, event_name: str) -> List[type]:
        if event_name not in self.mapping:
            raise KeyError(f"Event '{event_name}' is not defined in the schema.")
        return self.mapping[event_name]

    def validate(self, event: Event) -> None:
        """
        Raise if the event's name is unknown or its arguments don't match
        the declared types.
        """
        if event.name not in self.mapping:
            raise ValueError(
                f"Event '{event.name}' is not in the schema. "
                f"Known events: {list(self.mapping)}"
            )
        expected = self.mapping[event.name]
        if len(event.args) != len(expected):
            raise ValueError(
                f"Event '{event.name}' expects {len(expected)} argument(s), "
                f"got {len(event.args)}."
            )
        for i, (arg, expected_type) in enumerate(zip(event.args, expected)):
            if not isinstance(arg, expected_type):
                raise TypeError(
                    f"Event '{event.name}' argument {i}: "
                    f"expected {expected_type.__name__}, got {type(arg).__name__}."
                )
