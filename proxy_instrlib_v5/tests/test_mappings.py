"""
tests/test_mappings.py — Unit tests for η_i API response mapping
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from mappings import map_api_response


class TestTextOnlyResponse:
    """Responses with no tool_use blocks → TextOnly event."""

    def test_text_only(self):
        content = [{"type": "text", "text": "The capital of France is Paris."}]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "AgentTurn" in names
        assert "TextOnly" in names
        assert len(events) == 2

    def test_empty_content(self):
        events = map_api_response(1, [])
        names = [e.name for e in events]
        assert "TextOnly" in names


class TestBashToolUse:
    """Responses with Bash tool_use blocks."""

    def test_safe_bash(self):
        content = [
            {"type": "text", "text": "Let me list the files."},
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "ls -la /workspace"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "AgentTurn" in names
        assert "BashExec" in names
        assert "SafeCommand" in names
        assert "TextOnly" not in names

    def test_dangerous_bash(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "rm -rf /workspace"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "BashExec" in names
        assert "DangerousCommand" in names
        assert "SafeCommand" not in names


class TestFileToolUse:
    """Responses with file operation tool_use blocks."""

    def test_safe_write(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Write",
             "input": {"file_path": "/workspace/out.txt", "content": "hello"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "FileWrite" in names
        assert "SafeCommand" in names

    def test_dangerous_write(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Write",
             "input": {"file_path": "/root/.bashrc", "content": "evil"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "FileWrite" in names
        assert "DangerousCommand" in names

    def test_safe_read(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Read",
             "input": {"file_path": "/workspace/README.md"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "FileRead" in names
        assert "SafeCommand" in names


class TestMultipleToolCalls:
    """Responses with multiple tool_use blocks in one turn."""

    def test_two_safe_tools(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "ls -la"}},
            {"type": "tool_use", "id": "toolu_2", "name": "Read",
             "input": {"file_path": "/workspace/config.json"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "BashExec" in names
        assert "FileRead" in names
        # SafeCommand should appear only once (deduplication)
        assert names.count("SafeCommand") == 1

    def test_mixed_safe_dangerous(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "ls -la"}},
            {"type": "tool_use", "id": "toolu_2", "name": "Bash",
             "input": {"command": "rm -rf /tmp"}},
        ]
        events = map_api_response(1, content)
        names = [e.name for e in events]
        assert "BashExec" in names
        assert "SafeCommand" in names
        assert "DangerousCommand" in names


class TestEventIdPropagation:
    """All events should share the same event_id."""

    def test_all_events_same_id(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "rm -rf /"}},
        ]
        events = map_api_response(42, content)
        for event in events:
            assert event.args[0] == 42

    def test_agent_turn_always_first(self):
        content = [
            {"type": "tool_use", "id": "toolu_1", "name": "WebSearch",
             "input": {"query": "test"}},
        ]
        events = map_api_response(7, content)
        assert events[0].name == "AgentTurn"
