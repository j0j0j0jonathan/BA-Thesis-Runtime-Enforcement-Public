"""
tests/test_handlers.py — Unit tests for enforcement action handlers
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from handlers import cause_block_action, cause_warn_action


class TestBlockAction:
    """Test that dangerous tool_use blocks are removed and replaced."""

    def _make_response(self, *tool_blocks):
        return {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": list(tool_blocks),
            "stop_reason": "tool_use",
            "model": "claude-sonnet-4-20250514",
        }

    def test_single_dangerous_tool_blocked(self):
        resp = self._make_response(
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "rm -rf /"}},
        )
        result = cause_block_action(1, resp, ["Bash"])
        # tool_use should be replaced with text
        assert all(b["type"] == "text" for b in result["content"])
        assert "[ENFORCEMENT]" in result["content"][0]["text"]
        # stop_reason should change since no tool_use remains
        assert result["stop_reason"] == "end_turn"

    def test_only_dangerous_tools_blocked(self):
        resp = self._make_response(
            {"type": "text", "text": "Let me do two things."},
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "rm -rf /"}},
            {"type": "tool_use", "id": "toolu_2", "name": "Read",
             "input": {"file_path": "/workspace/ok.txt"}},
        )
        result = cause_block_action(1, resp, ["Bash"])
        types = [b["type"] for b in result["content"]]
        # text + enforcement_text + tool_use(Read)
        assert "tool_use" in types  # Read survives
        assert result["stop_reason"] == "tool_use"  # still has tool_use

    def test_all_tools_blocked_changes_stop_reason(self):
        resp = self._make_response(
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "sudo reboot"}},
            {"type": "tool_use", "id": "toolu_2", "name": "Bash",
             "input": {"command": "rm -rf /tmp"}},
        )
        result = cause_block_action(1, resp, ["Bash"])
        assert result["stop_reason"] == "end_turn"

    def test_block_message_contains_command(self):
        resp = self._make_response(
            {"type": "tool_use", "id": "toolu_1", "name": "Bash",
             "input": {"command": "sudo rm -rf /"}},
        )
        result = cause_block_action(1, resp, ["Bash"])
        text = result["content"][0]["text"]
        assert "sudo rm -rf /" in text


class TestWarnAction:
    """Test that warning is prepended without removing tool_use blocks."""

    def test_warning_prepended(self):
        resp = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "Bash",
                 "input": {"command": "ls -la"}},
            ],
            "stop_reason": "tool_use",
        }
        result = cause_warn_action(1, resp, ["Bash"])
        # Warning text should be first
        assert result["content"][0]["type"] == "text"
        assert "[ENFORCEMENT WARNING]" in result["content"][0]["text"]
        # Original tool_use should still be there
        assert result["content"][1]["type"] == "tool_use"
        # stop_reason unchanged
        assert result["stop_reason"] == "tool_use"

    def test_warning_mentions_tool_name(self):
        resp = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "WebFetch",
                 "input": {"url": "https://example.com"}},
            ],
            "stop_reason": "tool_use",
        }
        result = cause_warn_action(1, resp, ["WebFetch"])
        assert "WebFetch" in result["content"][0]["text"]
