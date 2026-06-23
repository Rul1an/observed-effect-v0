#!/usr/bin/env python3
"""Canonicalization conformance for jcs-json-v1 (RFC 8785 JCS).

These pin the points where the reference canonicalizer must follow RFC 8785 and where a naive
``json.dumps(sort_keys=True, ensure_ascii=False)`` shortcut would have diverged. The observed-effect
v0 records live in a constrained value space (strings, integers, booleans, null, and containers of
those) where the two happen to agree byte-for-byte — which is why fixing the implementation moved no
published digest. But jcs-json-v1 is *defined* as RFC 8785, so the reference implementation must be
RFC 8785, not the shortcut. The same canonicalizer is duplicated by design in the drift-consumer and
below-harness worked examples; this file exercises the neutral-carriers copy.

Runs under pytest, or standalone: ``python3 test_canonicalization_rfc8785.py``.
"""
import json

from independent_recompute import _rfc8785, canon


def _old_shortcut(o):
    # The pre-fix shortcut, kept here only to show where it diverged from RFC 8785.
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_integer_valued_float_collapses_to_integer():
    # RFC 8785 (ES6 number serialization): 1.0 -> "1". The old shortcut emitted "1.0".
    assert _rfc8785({"n": 1.0}) == '{"n":1}'
    assert _old_shortcut({"n": 1.0}) == '{"n":1.0}'  # the divergence the fix closes


def test_object_keys_ordered_by_utf16_code_units():
    # RFC 8785 orders keys by UTF-16 code units. An astral key (U+1F600, whose surrogate pair
    # begins 0xD83D) sorts BEFORE U+FFFF by code unit, but AFTER it by code point — the shortcut
    # (Python sort_keys, i.e. code-point order) gets this backwards.
    obj = {"\U0001F600": 1, "￿": 2}
    assert _rfc8785(obj) == '{"\U0001F600":1,"￿":2}'
    assert _old_shortcut(obj) == '{"￿":2,"\U0001F600":1}'  # code-point order: the divergence


def test_nan_and_infinity_are_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            _rfc8785({"n": bad})
        except ValueError:
            pass
        else:
            raise AssertionError("RFC 8785 must reject NaN / Infinity")
    # The old shortcut emitted a non-conformant token instead of failing closed.
    assert _old_shortcut({"n": float("nan")}) == '{"n":NaN}'


def test_non_integer_float_fails_closed():
    # The jcs-json-v1 reference impl refuses non-integer numbers rather than risk non-RFC-8785 bytes.
    try:
        _rfc8785({"n": 0.1})
    except ValueError:
        pass
    else:
        raise AssertionError("non-integer float must fail closed")


def test_constrained_domain_matches_the_shortcut():
    # On the value space the v0 records actually use, the RFC 8785 implementation and the old
    # shortcut agree byte-for-byte — the reason fixing the implementation did not move any digest.
    for o in [{"b": [1, 2], "a": "x"}, {"k": ["é", "z", "a"]}, [True, False, None, 0, -7], {}]:
        assert canon(o).decode("utf-8") == _old_shortcut(o)


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok  " + fn.__name__)
    print("\n%d canonicalization conformance checks passed" % len(fns))


if __name__ == "__main__":
    _run()
