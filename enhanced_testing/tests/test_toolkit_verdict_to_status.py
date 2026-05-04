# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Unit tests for app.toolkit.verdict_to_status.

The function is the single source of truth that maps a probe's verdict
(validated / confidence / ok / error) to the four status strings the
findings table stores: validated, false_positive, inconclusive, errored.
The mapping is shared between the per-finding /challenge route and the
bulk-Challenge runner, so a regression here would silently mis-classify
every challenged finding in the product.

Round-9 fidelity hardening: the True branch now requires confidence
>= 0.7. These tests cover the 0.7 boundary in both directions plus
the regression case (the 0.2 verdict that started the audit).

Tests run without docker / network / DB; pure function under test.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# /app/toolkit.py is the runtime path inside the container; the source
# tree path is /data/pentest/app/toolkit.py. Try both so the suite runs
# in either environment without configuration.
for candidate in ("/app", "/data/pentest/app", str(Path(__file__).resolve().parents[2] / "app")):
    if Path(candidate, "toolkit.py").is_file() and candidate not in sys.path:
        sys.path.insert(0, candidate)

import toolkit  # noqa: E402


# ---- True branch (the round-9 floor) ----------------------------------------

def test_true_high_confidence_validates():
    """Classic positive: probe says yes, with strong evidence."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.95,
    }) == "validated"


def test_true_at_floor_validates():
    """Confidence exactly at the 0.7 floor still validates (boundary inclusive)."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.70,
    }) == "validated"


def test_true_just_below_floor_falls_to_inconclusive():
    """0.69 is below the floor: do not stamp validated."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.69,
    }) == "inconclusive"


def test_true_low_confidence_does_not_validate_regression():
    """The bug that started the round-9 audit: a probe returning
    `validated=True, confidence=0.2` used to silently mark the
    finding 'validated' (green badge). Now it falls into
    inconclusive, where the analyst can investigate."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.2,
    }) == "inconclusive"


def test_true_no_confidence_field_falls_to_inconclusive():
    """Missing confidence reads as 0 -> below floor -> inconclusive.
    Defensive: a malformed probe verdict should not silently validate."""
    assert toolkit.verdict_to_status({
        "validated": True,
    }) == "inconclusive"


def test_true_zero_confidence_falls_to_inconclusive():
    """Explicit 0 confidence -> inconclusive."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.0,
    }) == "inconclusive"


# ---- False branch (existing 0.8 floor — regression coverage) ----------------

def test_false_high_confidence_marks_false_positive():
    assert toolkit.verdict_to_status({
        "validated": False, "confidence": 0.9,
    }) == "false_positive"


def test_false_at_floor_marks_false_positive():
    """Confidence exactly at the 0.8 floor classes as false_positive."""
    assert toolkit.verdict_to_status({
        "validated": False, "confidence": 0.8,
    }) == "false_positive"


def test_false_below_floor_inconclusive():
    """Tentative refutation -> inconclusive, not false_positive."""
    assert toolkit.verdict_to_status({
        "validated": False, "confidence": 0.5,
    }) == "inconclusive"


# ---- Null / soft-refusal branch ---------------------------------------------

def test_validated_null_inconclusive():
    """Probe declined to take a position -> inconclusive."""
    assert toolkit.verdict_to_status({
        "validated": None, "confidence": 0.95,
    }) == "inconclusive"


def test_ok_false_no_error_inconclusive():
    """Soft refusal (ok=False with no `error`) -> inconclusive,
    not errored. This was the 'red badge on a clean run' fix."""
    assert toolkit.verdict_to_status({
        "ok": False, "validated": None,
    }) == "inconclusive"


# ---- Error branch -----------------------------------------------------------

def test_error_field_marks_errored():
    """Subprocess crash / safety violation -> errored."""
    assert toolkit.verdict_to_status({
        "error": "subprocess died",
    }) == "errored"


def test_error_field_takes_priority_over_validated():
    """If error is set, the validated field is irrelevant."""
    assert toolkit.verdict_to_status({
        "validated": True, "confidence": 0.95,
        "error": "safety_violation: out of scope",
    }) == "errored"


# ---- Pretty-print smoke (helps diagnose CI failures) ------------------------

@pytest.mark.parametrize(
    "verdict,expected",
    [
        ({"validated": True,  "confidence": 0.95}, "validated"),
        ({"validated": True,  "confidence": 0.70}, "validated"),
        ({"validated": True,  "confidence": 0.20}, "inconclusive"),
        ({"validated": False, "confidence": 0.95}, "false_positive"),
        ({"validated": False, "confidence": 0.50}, "inconclusive"),
        ({"validated": None,                    }, "inconclusive"),
        ({"error": "boom"},                       "errored"),
    ],
)
def test_table(verdict, expected):
    assert toolkit.verdict_to_status(verdict) == expected
