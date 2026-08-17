"""ReDoS defense for user-supplied regex patterns in the decoder DSL.

Detection strategy
------------------
The pattern is parsed with ``re._parser.parse`` (CPython 3.9+) into a
``SubPattern`` AST.  A token is flagged when a quantifier (``MAX_REPEAT`` /
``MIN_REPEAT``) has a child ``SUBPATTERN`` whose child list itself contains
a quantifier wrapping a *literal or character class*.  Concretely:

Unsafe shapes (nested quantifier on a repeatable atom)::

    (a+)+     MAX_REPEAT  →  SUBPATTERN  →  MAX_REPEAT  →  LITERAL
    (a*)+     MAX_REPEAT  →  SUBPATTERN  →  MAX_REPEAT  →  LITERAL
    ((a)+)+   MAX_REPEAT  →  SUBPATTERN  →  MAX_REPEAT  →  SUBPATTERN → MAX_REPEAT → LITERAL

Safe shapes (quantifier directly on an atom — NOT nested)::

    (\\d+)     SUBPATTERN  →  MAX_REPEAT  →  IN (char class)
    (a|b)     SUBPATTERN  →  BRANCH  →  [LITERAL, LITERAL]
    (foo)     SUBPATTERN  →  LITERAL

The rule is simple: if we see ``MAX_REPEAT/MIN_REPEAT → SUBPATTERN →
MAX_REPEAT/MIN_REPEAT`` (i.e. a quantifier nested two levels deep inside a
group), the pattern is ReDoS-prone.
"""
from __future__ import annotations

import re
from typing import List

import re._parser as _rp

#: Hard cap on pattern length to stop ReDoS vectors built from sheer size.
MAX_PATTERN_LENGTH = 5000

_QUANTIFIER_OPS = frozenset((_rp.MAX_REPEAT, _rp.MIN_REPEAT))


class ReDoSValidationError(ValueError):
    """Raised when a user-supplied pattern fails safety validation.

    ``antipatterns`` lists specific shapes that were flagged.
    """

    def __init__(self, pattern: str, antipatterns: List[str]):
        self.pattern = pattern
        self.antipatterns = list(antipatterns)
        detail = "; ".join(antipatterns) if antipatterns else "unsafe structure"
        super().__init__(f"unsafe regex: {detail}")


def _is_pure_quantifier(node_children: list) -> bool:
    """Return True if *node_children* is exactly a single quantified atom.

    e.g. ``a+``, ``.+``, ``\\d*``  — the node children list is exactly
    ``[MAX_REPEAT/LITERAL]``.  This is the shape that causes catastrophic
    backtracking when wrapped in another quantifier.

    A shape like ``[LITERAL, MAX_REPEAT]`` (e.g. ``\\w+`` inside
    ``(\\..\\w+)*)`` is NOT pure — the group has other content alongside the
    quantifier, so the ReDoS risk is absent.
    """
    if len(node_children) != 1:
        return False
    ch = node_children[0]
    return isinstance(ch, tuple) and ch[0] in _QUANTIFIER_OPS


def _scan(node_children: list, findings: List[str]) -> None:
    """Walk a list of parsed AST children and flag ReDoS anti-patterns."""
    for ch in node_children:
        if not isinstance(ch, tuple):
            continue
        op = ch[0]

        # Case 1: MAX_REPEAT/MIN_REPEAT whose direct child is another
        # quantifier → the ``(?:a+)+`` shape (no SUBPATTERN wrapper).
        if op in _QUANTIFIER_OPS:
            # ch[1] = (min, max, [children])
            rep_children = ch[1][2]
            # Direct nested quantifier (non-capturing / flat shape)
            if _is_pure_quantifier(rep_children):
                findings.append("nested quantifier (direct)")
            else:
                # Case 2: MAX_REPEAT wrapping a SUBPATTERN that is itself a
                # pure quantifier → the ``(a+)+`` shape.
                for rc in rep_children:
                    if isinstance(rc, tuple) and rc[0] == _rp.SUBPATTERN:
                        inner_children = rc[1][3]
                        if _is_pure_quantifier(inner_children):
                            findings.append(
                                "nested quantifier inside group"
                            )
                            break
                        # Recurse to reach deeper nesting like ((a)+)+
                        _scan(inner_children, findings)
                    else:
                        # Also recurse into non-SUBPATTERN children to catch
                        # any embedded groups at deeper levels.
                        if (
                            isinstance(rc, tuple)
                            and rc[0] in (_rp.BRANCH, _rp.AT)
                        ):
                            pass  # BRANCH/AT don't nest quantifiers in dangerous ways
                        elif isinstance(rc, tuple) and rc[0] == _rp.IN:
                            pass  # char class — safe leaf

        # Case 3: SUBPATTERN that is not wrapped by a quantifier — recurse
        # to reach any nested quantifier shapes inside.
        elif op == _rp.SUBPATTERN:
            inner_children = ch[1][3]
            _scan(inner_children, findings)


def compile_safe_regex(pattern: str, name: str = "") -> re.Pattern:
    """Compile *pattern* after validating it against ReDoS heuristics.

    Parameters
    ----------
    pattern:
        A regular expression string.
    name:
        A human-readable label for error messages (e.g. the decoder name or
        endpoint that supplied the pattern).

    Returns
    -------
    re.Pattern
        The compiled regex, safe for use in ``re.search`` / ``re.sub``.

    Raises
    ------
    ReDoSValidationError
        If the pattern is syntactically invalid, too long, or flagged as
        unsafe by the ReDoS heuristic scan.
    """
    if not isinstance(pattern, str):
        raise ReDoSValidationError(str(pattern), ["pattern must be a string"])
    if not pattern:
        raise ReDoSValidationError(pattern, ["empty pattern"])
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ReDoSValidationError(
            pattern,
            [
                f"pattern length {len(pattern)} exceeds "
                f"MAX_PATTERN_LENGTH={MAX_PATTERN_LENGTH}"
            ],
        )

    # Syntactic validation first — a bad pattern is not safe anyway.
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ReDoSValidationError(pattern, [f"invalid regex: {exc}"]) from exc

    try:
        tree = _rp.parse(pattern, flags=0)
    except Exception:
        # re.compile already validated; parser failure is unexpected.
        raise ReDoSValidationError(pattern, ["unexpected parse failure"])

    findings: List[str] = []
    _scan(list(tree), findings)

    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: List[str] = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    if unique:
        raise ReDoSValidationError(pattern, unique)

    return compiled


def validate_pattern(pattern: str, name: str = "") -> List[str]:
    """Return a list of ReDoS findings for *pattern* (empty if safe).

    Convenience wrapper for dry-run validation in the API layer.
    """
    if not isinstance(pattern, str) or not pattern:
        return ["empty or non-string pattern"]
    if len(pattern) > MAX_PATTERN_LENGTH:
        return [
            f"pattern length {len(pattern)} exceeds "
            f"MAX_PATTERN_LENGTH={MAX_PATTERN_LENGTH}"
        ]
    try:
        re.compile(pattern)
    except re.error as exc:
        return [f"invalid regex: {exc}"]
    try:
        tree = _rp.parse(pattern, flags=0)
    except Exception:
        return ["unexpected parse failure"]
    findings: List[str] = []
    _scan(list(tree), findings)
    seen: set[str] = set()
    unique: List[str] = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique
