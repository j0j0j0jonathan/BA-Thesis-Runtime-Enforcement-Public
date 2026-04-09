"""
instrlib.pdp — EnfGuardPDP (batch mode with accumulated trace)
==============================================================
EnfGuard is a batch-only monitor: it reads a log file and exits.
It does NOT support interactive stdin/stdout streaming (that requires WhyEnf,
which is what the real InstrLib uses internally).

What this module does instead
------------------------------
  1.  Keep an in-memory list of all trace lines seen so far (_trace).
  2.  On every process_events() call, append the new line, write the full
      accumulated trace to a temp file, and run EnfGuard via subprocess.run().
  3.  Parse the text output for the current timestep's verdict.
  4.  Return the verdict in the same dict format that Logger.log() expects.

Why not streaming?
------------------
The '?' / ';' terminator protocol (send to stdin, read JSON from stdout) only
works with WhyEnf.  EnfGuard exits immediately after responding to '?'.
This was confirmed experimentally: timestep 2 always caused a BrokenPipeError.

Improvements over proxy_final (batch v1)
-----------------------------------------
  *  No '-func proxy_funcs.py': safety is expressed as SafeResponse(id) /
     UnsafeResponse(id) events in the trace — no external Python predicate.
  *  No RESPONSES_FILE: the mapping function produces events inline.
  *  Generic event parsing: _parse() extracts any (name, args) pair, not just
     specific hardcoded events.
  *  Thread-safe: a lock protects the shared _trace list and temp-file writes.

Interface (unchanged from the streaming version)
-------------------------------------------------
    pdp = EnfGuardPDP(binary, sig, formula)
    pdp.start()                                ← no-op in batch mode
    verdict = pdp.process_events(events, ts)   ← runs EnfGuard, returns dict
    pdp.log_events(events, ts)                 ← append to trace, no EnfGuard
    pdp.stop()                                 ← no-op in batch mode
    pdp.reset()                                ← clear the accumulated trace
"""

import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional

from instrlib.event import Event


class EnfGuardPDP:
    """
    Batch-mode PDP backed by a fresh EnfGuard subprocess per request.

    The accumulated trace grows monotonically across requests, so EnfGuard
    always sees the full history.  This is equivalent to the log-file approach
    used in proxy_final, but embedded in the v2 @Instrument architecture.
    """

    def __init__(
        self,
        binary:  str,
        sig:     str,
        formula: str,
        env:     Optional[Dict] = None,
    ) -> None:
        self._binary  = binary
        self._sig     = sig
        self._formula = formula
        self._env     = env

        self._trace: List[str]    = []   # accumulated "@ts Event(args)" lines
        self._lock                = threading.Lock()

    # ── Lifecycle (no-ops in batch mode) ──────────────────────────────────────

    def start(self) -> None:
        """No persistent process to start in batch mode."""
        print("[EnfGuardPDP] Batch mode — no process to start.")

    def stop(self) -> None:
        """Nothing to stop."""
        print("[EnfGuardPDP] Batch mode — nothing to stop.")

    def reset(self) -> None:
        """Clear the accumulated trace (call at server startup for clean slate)."""
        with self._lock:
            self._trace.clear()
        print("[EnfGuardPDP] Trace cleared.")

    # ── Public API ────────────────────────────────────────────────────────────

    def process_events(self, events: List[Event], timestep: int) -> dict:
        """
        Append events to trace, run EnfGuard on full trace, return verdict.

        Parameters
        ----------
        events   : List[Event] at this timestep (e.g. [Ask(3), UnsafeResponse(3)])
        timestep : logical timestamp (= request counter)

        Returns
        -------
        {
          "caused":     [{"name": str, "args": list}, ...],
          "suppressed": [{"name": str, "args": list}, ...],
        }
        """
        trace_line = f"@{timestep} {' '.join(str(e) for e in events)}"
        print(f"[PDP] trace ← {trace_line}")

        with self._lock:
            self._trace.append(trace_line)

            # Write full accumulated trace to a temporary log file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".log", delete=False, prefix="enfguard_"
            ) as f:
                tmpfile = f.name
                f.write("\n".join(self._trace) + "\n")

            try:
                result = subprocess.run(
                    [
                        self._binary,
                        "-sig",     self._sig,
                        "-formula", self._formula,
                        "-log",     tmpfile,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=self._env,
                )
                output = result.stdout
                print(f"[PDP] EnfGuard output:\n{output.strip()}")
                return self._parse(output, timestep)
            finally:
                Path(tmpfile).unlink(missing_ok=True)

    def log_events(self, events: List[Event], timestep: int) -> None:
        """
        Append events to trace WITHOUT running EnfGuard.

        Used for bookkeeping events that don't need a verdict — only their
        presence in the future trace matters for later evaluations.
        """
        trace_line = f"@{timestep} {' '.join(str(e) for e in events)}"
        with self._lock:
            self._trace.append(trace_line)
        print(f"[PDP] log_only ← {trace_line}")

    # ── Output parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse(output: str, timestep: int) -> dict:
        """
        Parse EnfGuard's text output for the current timestep's verdict.

        EnfGuard text output format:
            Cause:
              Block(3)

            Cause:
              Disclaimer(3)

            Suppress:
              SomeEvent(3)

        Since event arguments encode the request ID (= timestep), searching
        for EventName(timestep) unambiguously identifies the current verdict
        even when the output contains verdicts for all previous timesteps.

        Returns
        -------
        {"caused": [...], "suppressed": [...]}
        where each item is {"name": str, "args": [int, ...]}.
        """
        caused:     list = []
        suppressed: list = []

        # Match "Cause:\n  EventName(arg1, arg2, ...)" for the current timestep
        cau_pattern = re.compile(
            r'Cause:\s*\n\s*(\w+)\(([^)]*)\)'
        )
        sup_pattern = re.compile(
            r'Suppress:\s*\n\s*(\w+)\(([^)]*)\)'
        )

        for m in cau_pattern.finditer(output):
            name     = m.group(1)
            args_str = m.group(2)
            args     = _parse_args(args_str)
            # Filter to current timestep: first arg must equal timestep
            if args and args[0] == timestep:
                caused.append({"name": name, "args": args})
                print(f"[PDP] ✓ Cause: {name}({args})")

        for m in sup_pattern.finditer(output):
            name     = m.group(1)
            args_str = m.group(2)
            args     = _parse_args(args_str)
            if args and args[0] == timestep:
                suppressed.append({"name": name, "args": args})
                print(f"[PDP] ✓ Suppress: {name}({args})")

        return {"caused": caused, "suppressed": suppressed}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_args(args_str: str) -> list:
    """Parse a comma-separated argument string into a list of ints."""
    if not args_str.strip():
        return []
    result = []
    for part in args_str.split(","):
        part = part.strip()
        if part:
            try:
                result.append(int(part))
            except ValueError:
                result.append(part)   # keep as string if not numeric
    return result
