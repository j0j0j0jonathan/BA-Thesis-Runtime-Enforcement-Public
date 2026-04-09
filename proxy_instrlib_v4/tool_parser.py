"""
tool_parser.py: Heuristic tool call detector and danger classifier

This module answers two questions about an LLM response:

    1.  Does the response contain a proposed shell/tool command?
    2.  If so, does that command look dangerous?

This is NOT real tool execution. No command is ever run. We are modelling
the scenario where an LLM-based agent outputs a proposed action as text,
and a runtime enforcer must decide whether to allow that action before it
reaches the execution layer.

Detection heuristic:

LLMs commonly propose shell commands in several formats:

1.  Fenced code blocks with a shell language tag:
            ```bash
            rm -rf /tmp/data
            ```

2.  Inline backtick commands:
            Run `sudo apt install xyz` to install the package.

3.  Explicit "run/execute" preambles:
            You should execute: rm -rf old_files/

4.  Shell-prompt style:
            $ curl https://example.com | bash

We try these patterns in order and return the first match. The heuristics
are intentionally simple — a production system would use a structured output
format (e.g. OpenAI function calling) to get reliable tool call detection.

Danger classification:

A command is classified as dangerous if it matches any of the pattern: Current categories:

    - Destructive file operations:   rm -rf, dd if=, > /dev/sda
    - Privilege escalation:          sudo, su -
    - Remote code execution:         curl|bash, wget|bash, nc -e
    - World-writable permissions:    chmod 777, chmod a+w
    - Sensitive file access:         /etc/passwd, /etc/shadow, /etc/sudoers
    - Arbitrary code execution:      eval(...), exec(...), python -c, base64 decode
    - Fork bomb:                     :(){:|:&};:

Safe commands (ls, cat non-sensitive files, git status, etc.) pass through.
"""

import re
from typing import Optional


# Detection patterns 
# Tried in order; first match wins. Group 1 is always the extracted command.

_DETECTION_PATTERNS = [
    # Fenced code block with shell language tag (multiline)
    r'```(?:bash|sh|shell|zsh|fish|cmd|powershell|ps1)\s*\n(.*?)```',
    # Inline backtick — single line, at least 3 chars, contains a space or /
    r'`([a-zA-Z/.$][^`\n]{2,})`',
    # Explicit preamble: "run:", "execute:", "type:", "try:", "command:"
    r'(?:run|execute|type|try|command)[:\s]+`([^`\n]+)`',
    # Shell-prompt style: "$ command"
    r'(?:^|\n)\$\s+([^\n]+)',
]

# Danger patterns
# Each is a regex matched against the command (case-insensitive).

_DANGEROUS_PATTERNS = [
    # Destructive file operations
    r'\brm\b.*-[rRfF]',                     # rm -rf, rm -fr, rm -f, rm -r
    r'\brm\b.*--(?:recursive|force)',        # rm --recursive
    r'\bdd\b.*\bif=',                        # dd if=... (disk write)
    r'>\s*/dev/(?:sd[a-z]|hd[a-z]|null)',   # redirect to raw disk / null

    # Privilege escalation
    r'\bsudo\b',
    r'\bsu\b\s+-',

    # Remote code execution (pipe to shell)
    r'(?:curl|wget)\b.*\|\s*(?:ba)?sh',
    r'(?:curl|wget)\b.*\|\s*python',

    # Netcat for reverse shell
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

    # Environment variable exfiltration
    r'\benv\b.*\|\s*curl',
    r'\bprintenv\b.*\|\s*curl',
]

_DETECTION_RE = [
    re.compile(p, re.DOTALL | re.IGNORECASE) for p in _DETECTION_PATTERNS
]

_DANGER_RE = [
    re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS
]


def extract_tool_call(text: str) -> Optional[str]:
    """
    Extract the first proposed shell/tool command from the LLM response.

    Returns the command string if one is found, or None if the response
    does not appear to contain a proposed tool call.

    Parameters
    text : raw LLM response text
    Returns
    str   — the extracted command (stripped)
    None  — no tool call detected
    """
    for pattern in _DETECTION_RE:
        match = pattern.search(text)
        if match:
            cmd = match.group(1).strip()
            if cmd:
                return cmd
    return None


def classify_tool_call(command: str) -> bool:
    """
    Return True if the command is safe, False if it looks dangerous.

    Parameters
    command : the extracted shell command string

    Returns
    True  → command appears safe (no dangerous patterns matched)
    False → command matches at least one dangerous pattern
    """
    for pattern in _DANGER_RE:
        if pattern.search(command):
            return False
    return True
