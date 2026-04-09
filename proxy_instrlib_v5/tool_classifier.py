"""
tool_classifier.py — Structured tool_use classifier for Anthropic Messages API
================================================================================
Unlike v4's heuristic regex approach on raw text, v5 receives STRUCTURED
tool_use blocks from the Anthropic API. Each block has:

    {"type": "tool_use", "id": "toolu_...", "name": "Bash", "input": {"command": "rm -rf /"}}

This means:
  - No guessing whether a command is proposed — the API explicitly marks it
  - The tool name tells us the category (Bash, Write, Edit, WebFetch, etc.)
  - The input gives us the exact arguments

This module classifies tool_use blocks into event categories for MFOTL enforcement.
"""

import re
from typing import List, Tuple

# ── Tool name → event category mapping ────────────────────────────────────────

BASH_TOOLS = {"Bash"}
FILE_WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}
FILE_READ_TOOLS = {"Read", "Glob", "Grep"}
WEB_TOOLS = {"WebSearch", "WebFetch"}

# ── Danger patterns for bash commands ─────────────────────────────────────────
# Same patterns as v4 but now applied to structured input, not regex-extracted text.

_DANGEROUS_PATTERNS = [
    # Destructive file operations
    r'\brm\b.*-[rRfF]',
    r'\brm\b.*--(?:recursive|force)',
    r'\bdd\b.*\bif=',
    r'>\s*/dev/(?:sd[a-z]|hd[a-z])',

    # Privilege escalation
    r'\bsudo\b',
    r'\bsu\b\s+-',

    # Remote code execution (pipe to shell)
    r'(?:curl|wget)\b.*\|\s*(?:ba)?sh',
    r'(?:curl|wget)\b.*\|\s*python',

    # Netcat reverse shell
    r'\bnc\b.*-[el]',
    r'\bncat\b.*-[el]',

    # Arbitrary code execution
    r'\beval\s*[\($]',
    r'\bexec\s*[\($]',
    r'\bpython[23]?\s+-c\b',
    r'\bnode\s+-e\b',
    r'\bperl\s+-e\b',
    r'\bruby\s+-e\b',
    r'\bbase64\b.*--decode\b',

    # World-writable permissions
    r'\bchmod\b.*(?:777|a\+w|o\+w)',

    # Sensitive file access
    r'/etc/(?:passwd|shadow|sudoers|hosts)',
    r'/root/\.',

    # Fork bomb
    r':\(\s*\)\s*\{',

    # Environment exfiltration
    r'\benv\b.*\|\s*curl',
    r'\bprintenv\b.*\|\s*curl',

    # Kill system processes
    r'\bkill\s+-9\s+1\b',
    r'\bkillall\b',

    # Disk formatting
    r'\bmkfs\b',
    r'\bfdisk\b',
]

_DANGER_RE = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


def classify_bash_command(command: str) -> bool:
    """Return True if safe, False if dangerous."""
    for pattern in _DANGER_RE:
        if pattern.search(command):
            return False
    return True


def classify_tool_use(tool_name: str, tool_input: dict) -> List[str]:
    """
    Classify a structured tool_use block into MFOTL event names.

    Parameters
    ----------
    tool_name  : e.g. "Bash", "Write", "Edit", "WebSearch"
    tool_input : the input dict from the API, e.g. {"command": "ls -la"}

    Returns
    -------
    List of event names to emit, e.g. ["BashExec", "DangerousCommand"]
    """
    events = []

    if tool_name in BASH_TOOLS:
        events.append("BashExec")
        command = tool_input.get("command", "")
        if classify_bash_command(command):
            events.append("SafeCommand")
        else:
            events.append("DangerousCommand")

    elif tool_name in FILE_WRITE_TOOLS:
        events.append("FileWrite")
        # Check if writing to sensitive paths
        file_path = tool_input.get("file_path", "")
        if _is_sensitive_path(file_path):
            events.append("DangerousCommand")
        else:
            events.append("SafeCommand")

    elif tool_name in FILE_READ_TOOLS:
        events.append("FileRead")
        # Reading is generally safe, but flag sensitive paths
        file_path = tool_input.get("file_path", tool_input.get("path", ""))
        pattern = tool_input.get("pattern", "")
        target = file_path or pattern
        if _is_sensitive_path(target):
            events.append("DangerousCommand")
        else:
            events.append("SafeCommand")

    elif tool_name in WEB_TOOLS:
        events.append("WebAccess")
        events.append("SafeCommand")

    else:
        # Unknown or non-dangerous tools (Task, TodoWrite, etc.)
        # Still track them but treat as safe
        events.append("SafeCommand")

    return events


def _is_sensitive_path(path: str) -> bool:
    """Check if a file path targets a sensitive location."""
    sensitive_patterns = [
        r'/etc/(?:passwd|shadow|sudoers|hosts)',
        r'/root/',
        r'\.env\b',
        r'\.ssh/',
        r'id_rsa',
        r'\.aws/credentials',
        r'\.kube/config',
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False
