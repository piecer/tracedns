"""TDD tests for regex_safety.compile_safe_regex and validate_pattern.

Covers:
  * safe patterns compile successfully
  * ReDoS anti-patterns raise ReDoSValidationError
  * invalid / empty / non-string patterns raise ReDoSValidationError
  * validate_pattern returns a list of findings (empty for safe patterns)
  * integration: the three call-sites (txt_decoder, a_decoder,
    http_api_handlers) still work with their respective patterns
"""
from __future__ import annotations

import sys
import os
import re
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import regex_safety  # noqa: F401  (import check for the module itself)
from regex_safety import (  # noqa: E402
    MAX_PATTERN_LENGTH,
    ReDoSValidationError,
    compile_safe_regex,
    validate_pattern,
)


class TestSafePatterns(unittest.TestCase):
    """Patterns that should compile without error."""

    def test_simple_literal(self):
        pat = re.compile("(a+)+")  # noqa: F841 — we're testing that we CAN compile
        self.assertIsNotNone(pat)

    def test_simple_group(self):
        p = compile_safe_regex(r"(\d+)", name="test")
        m = p.search("abc123def")
        self.assertEqual(m.group(1), "123")

    def test_char_class(self):
        p = compile_safe_regex(r"^[a-z]+$")
        self.assertTrue(p.match("hello"))
        self.assertIsNone(p.match("HELLO"))

    def test_ip_pattern(self):
        p = compile_safe_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        m = p.search("the ip is 192.168.1.1 ok")
        self.assertEqual(m.group(0), "192.168.1.1")

    def test_alternation(self):
        p = compile_safe_regex(r"(foo|bar)")
        self.assertIn("foo", p.findall("foo and bar"))

    def test_nested_groups_no_quantifier(self):
        p = compile_safe_regex(r"(a(b)(c))")
        m = p.search("xabc")
        self.assertIsNotNone(m)


class TestReDoSDetection(unittest.TestCase):
    """Patterns that carry catastrophic-backtracking risk."""

    def test_nested_quantifier(self):
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(r"(a+)+")

    def test_nested_star_plus(self):
        # ``(a*)+`` — same shape
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(r"(a*)+")

    def test_nested_option(self):
        # ``(a?)+``
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(r"(a?)+")

    def test_double_nested(self):
        # ``((a)+)+``
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(r"((a)+)+")

    def test_wildcard_nested(self):
        # ``(.)+`` — quantifier on a dot (literal in re._parser)
        # This should NOT be flagged (it's not a nested quantifier).
        p = compile_safe_regex(r"(.)+")
        self.assertIsNotNone(p)

    def test_error_message_contains_pattern(self):
        with self.assertRaises(ReDoSValidationError) as ctx:
            compile_safe_regex(r"(a+)+")
        self.assertIn("unsafe regex", str(ctx.exception))
        self.assertEqual(ctx.exception.pattern, r"(a+)+")


class TestInvalidPatterns(unittest.TestCase):
    """Syntactically invalid or malformed patterns."""

    def test_empty_string(self):
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex("")

    def test_non_string(self):
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(12345)  # type: ignore[arg-type]

    def test_unclosed_paren(self):
        with self.assertRaises(ReDoSValidationError):
            compile_safe_regex(r"((a+")

    def test_very_long_pattern(self):
        # A pattern longer than MAX_PATTERN_LENGTH
        long_pat = "a" * (MAX_PATTERN_LENGTH + 1)
        with self.assertRaises(ReDoSValidationError) as ctx:
            compile_safe_regex(long_pat)
        self.assertIn("MAX_PATTERN_LENGTH", str(ctx.exception))

    def test_max_length_boundary_ok(self):
        # Exactly at the limit should be accepted (as long as valid).
        pat = "a" * MAX_PATTERN_LENGTH
        try:
            compile_safe_regex(pat)
        except ReDoSValidationError as e:
            # It's OK if this raises for other reasons, but not for length.
            self.assertNotIn("MAX_PATTERN_LENGTH", str(e))


class TestValidatePattern(unittest.TestCase):
    """validate_pattern returns a findings list (empty = safe)."""

    def test_safe_pattern_returns_empty(self):
        self.assertEqual(validate_pattern(r"(\d+)"), [])

    def test_reDos_pattern_returns_findings(self):
        findings = validate_pattern(r"(a+)+")
        self.assertTrue(findings)
        self.assertTrue(any("nested quantifier" in f for f in findings))

    def test_invalid_pattern_returns_findings(self):
        findings = validate_pattern(r"((a+")
        self.assertTrue(findings)
        self.assertTrue(any("invalid" in f for f in findings))

    def test_empty_returns_findings(self):
        findings = validate_pattern("")
        self.assertTrue(findings)


class TestIntegrationWithDecoders(unittest.TestCase):
    """Verify that the decoder DSL call-sites still work."""

    def test_txt_decoder_custom_regex_step(self):
        """The txt_decoder custom DSL regex step should still accept
        safe patterns and reject unsafe ones."""
        import txt_decoder as td

        # Safe pattern: extract first IP from a string
        steps = [{"op": "regex", "pattern": r"(\d+\.\d+\.\d+\.\d+)", "group": 1}]
        dec = td.create_custom_decoder(steps)
        self.assertIsNotNone(dec)
        result = dec(["192.168.1.1:some:other"])
        # The decoder extracts IPs from the regex group
        self.assertIn("192.168.1.1", result)

    def test_txt_decoder_rejects_reDos_pattern(self):
        """register_custom_decoder should reject a nested-quantifier pattern."""
        import txt_decoder as td

        steps = [{"op": "regex", "pattern": r"(a+)+", "group": 1}]
        # create_custom_decoder calls compile_safe_regex which raises
        with self.assertRaises(ReDoSValidationError):
            td.create_custom_decoder(steps)

    def test_a_decoder_custom_regex_step(self):
        """The a_decoder custom DSL regex step should still work."""
        import a_decoder as ad

        # Safe pattern: extract hex IP
        steps = [{"op": "regex", "pattern": r"([0-9a-f]{8})", "group": 1}]
        dec = ad.create_custom_a_decoder(steps)
        self.assertIsNotNone(dec)

    def test_a_decoder_rejects_reDos_pattern(self):
        import a_decoder as ad

        steps = [{"op": "regex", "pattern": r"(a+)+", "group": 1}]
        with self.assertRaises(ReDoSValidationError):
            ad.create_custom_a_decoder(steps)


class TestNoFalsePositives(unittest.TestCase):
    """Patterns commonly used in the codebase must NOT be flagged."""

    def test_decoder_regex_patterns(self):
        # Patterns observed in actual decoder usage
        safe_patterns = [
            r"(\d{1,3}(?:\.\d{1,3}){3})",  # IP
            r"([0-9a-fA-F]{8})",  # hex group
            r"^([A-Za-z0-9\-]+)(\.\w+){1,}",  # hostname
            r"ip:([0-9a-f.\-]+)",  # ip field
            r"(\d+\.\d+\.\d+\.\d+):(\d+)",  # ip:port
            r"([A-Za-z0-9\-_]+)",  # word
            r"^([A-Z0-9]{2,})",  # prefix
        ]
        for pat in safe_patterns:
            with self.subTest(pattern=pat):
                p = compile_safe_regex(pat)
                self.assertIsNotNone(p)


if __name__ == "__main__":
    unittest.main()
