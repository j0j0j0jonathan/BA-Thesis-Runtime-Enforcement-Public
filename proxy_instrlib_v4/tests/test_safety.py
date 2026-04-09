"""
tests/test_safety.py — Unit tests for safety.py
================================================
Tests for classify() — content safety classification.

Run from proxy_instrlib_v4/:
    pytest tests/test_safety.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from safety import classify, FORBIDDEN_WORDS


class TestClassify:

    # ── Safe content ──────────────────────────────────────────────────────────

    def test_plain_safe_text(self):
        assert classify("The weather in Zurich is nice today.") is True

    def test_technical_safe_response(self):
        assert classify("You can use a list comprehension in Python: [x*2 for x in range(10)]") is True

    def test_empty_string_is_safe(self):
        assert classify("") is True

    def test_unrelated_word_similar_to_forbidden(self):
        # "passwords" contains "password" — should still be caught
        assert classify("Never reuse passwords across websites.") is False

    # ── Unsafe content — each forbidden word ─────────────────────────────────

    @pytest.mark.parametrize("word", FORBIDDEN_WORDS)
    def test_each_forbidden_word(self, word):
        text = f"Here is your {word}: abc123"
        assert classify(text) is False

    def test_password_in_sentence(self):
        assert classify("The password for the account is hunter2.") is False

    def test_secret_in_sentence(self):
        assert classify("Keep this secret between us.") is False

    def test_api_key_in_sentence(self):
        assert classify("Your api_key is sk-1234567890abcdef.") is False

    def test_token_in_sentence(self):
        assert classify("Use this token to authenticate: Bearer xyz789.") is False

    # ── Case insensitivity ────────────────────────────────────────────────────

    def test_uppercase_forbidden_word(self):
        assert classify("Enter your PASSWORD here.") is False

    def test_mixed_case_forbidden_word(self):
        assert classify("Your Api_Key expires in 30 days.") is False

    # ── Forbidden word not present ────────────────────────────────────────────

    def test_response_about_keys_but_not_api_keys(self):
        assert classify("Use a key to unlock the door.") is True

    def test_response_about_tokens_in_nlp_sense(self):
        # "token" IS in the forbidden list — this is a known limitation
        # of keyword-based classification
        assert classify("Each word is split into tokens by the tokenizer.") is False
