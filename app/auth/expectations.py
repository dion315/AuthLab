"""Asserting what a sign-in should have produced.

Without this, the result of a Conditional Access test is a person looking at a
claim dump and deciding whether it looks right. That works once. It does not
work as a regression check you run after every policy change, and it does not
produce anything you can attach to a change record.

An expectation is the same vocabulary as a role-mapping rule — a claim, an
operator, a value — evaluated against the claims a sign-in actually produced.
Attach a few to a connection ("amr contains mfa", "tid equals <our tenant>")
and every sign-in through it reports pass or fail, on the dashboard and in the
activity log.

Pure, like `rolemap`, and for the same reason: the awkward cases are cheap to
test and the UI can show its work.
"""

from __future__ import annotations

from typing import Any

from app.auth.rolemap import extract_claim, matches
from app.models import IdpConnection

OPERATORS = ("equals", "contains", "starts_with", "regex", "present", "absent")


def evaluate_one(expectation: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single expectation and explain the outcome."""
    claim_name = str(expectation.get("claim", "")).strip()
    operator = str(expectation.get("operator", "equals"))
    expected = str(expectation.get("value", ""))
    description = str(expectation.get("description", ""))

    values = extract_claim(claims, claim_name) if claim_name else []

    if operator == "present":
        passed = bool(values)
        actual = ", ".join(values) if values else None
    elif operator == "absent":
        passed = not values
        actual = ", ".join(values) if values else None
    else:
        matched = next((v for v in values if matches(operator, expected, v)), None)
        passed = matched is not None
        actual = matched if matched is not None else (", ".join(values) or None)

    return {
        "claim": claim_name,
        "operator": operator,
        "value": expected,
        "description": description,
        "passed": passed,
        "actual": actual,
        "claim_present": bool(values),
    }


def evaluate(
    connection: IdpConnection, claims: dict[str, Any], role: str
) -> dict[str, Any]:
    """Evaluate every expectation on a connection, plus the expected role.

    Returns a result carrying `configured` so callers can distinguish "nothing
    was asserted" from "everything passed" — reporting a green tick for a
    connection nobody set expectations on would be actively misleading.
    """
    checks = [evaluate_one(item, claims) for item in (connection.expectations or [])]

    expected_role = (connection.expected_role or "").strip()
    if expected_role:
        checks.insert(
            0,
            {
                "claim": "(resolved role)",
                "operator": "equals",
                "value": expected_role,
                "description": "The role the mapping rules should have assigned.",
                "passed": role == expected_role,
                "actual": role,
                "claim_present": True,
            },
        )

    return {
        "configured": bool(checks),
        "checks": checks,
        "passed": all(check["passed"] for check in checks) if checks else None,
        "failed_count": sum(1 for check in checks if not check["passed"]),
    }


def summarise(result: dict[str, Any]) -> str:
    """One line for the activity log."""
    if not result.get("configured"):
        return ""
    total = len(result["checks"])
    if result["passed"]:
        return f"expectations: {total}/{total} passed"
    return f"expectations: {total - result['failed_count']}/{total} passed"
