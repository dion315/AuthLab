"""Role sourcing, expectations, and token lifetimes.

These are the pure functions, so they are tested without a browser or an IdP.
"""

from __future__ import annotations

import time

import pytest

from app.auth import expectations, lifetimes
from app.auth.rolemap import describe_claim_lookup, resolve_role
from app.models import IdpConnection


def make_connection(**kwargs) -> IdpConnection:
    defaults = dict(
        slug="c",
        name="C",
        protocol="oidc",
        role_claim="groups",
        role_source="claims",
        default_role="user",
        role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}],
        expectations=[],
        expected_role="",
        stepup_claim="amr",
        stepup_operator="contains",
        stepup_value="",
        config={},
    )
    defaults.update(kwargs)
    return IdpConnection(**defaults)


# --- role sources -------------------------------------------------------------


def test_claims_source_ignores_scim_groups():
    connection = make_connection(role_source="claims")
    role, trace = resolve_role(connection, {"groups": ["Everyone"]}, ["SEC-Admins"])
    assert role == "user"
    assert all(step["source"] == "claims" for step in trace)


def test_scim_source_ignores_claims():
    """A SCIM-sourced connection must not be satisfied by a token claim.

    The whole point of choosing this source is to authorise on provisioned
    state; silently falling back to the token would make the setting a lie.
    """
    connection = make_connection(role_source="scim")
    role, trace = resolve_role(connection, {"groups": ["SEC-Admins"]}, [])
    assert role == "user"
    assert all(step["source"] == "scim" for step in trace)


def test_scim_source_matches_provisioned_group():
    connection = make_connection(role_source="scim")
    role, _ = resolve_role(connection, {}, ["SEC-Admins"])
    assert role == "admin"


def test_claims_then_scim_prefers_claims():
    connection = make_connection(
        role_source="claims_then_scim",
        role_rules=[
            {"operator": "equals", "value": "SEC-Admins", "role": "admin"},
            {"operator": "equals", "value": "SEC-Power", "role": "power"},
        ],
    )
    role, trace = resolve_role(connection, {"groups": ["SEC-Admins"]}, ["SEC-Power"])
    assert role == "admin"
    assert trace[0]["source"] == "claims"


def test_claims_then_scim_falls_back_to_scim():
    connection = make_connection(role_source="claims_then_scim")
    role, trace = resolve_role(connection, {"groups": ["Nothing"]}, ["SEC-Admins"])
    assert role == "admin"
    # Claims were exhausted first, then SCIM matched.
    assert trace[0]["source"] == "claims"
    assert trace[-1]["source"] == "scim"
    assert trace[-1]["matched"] is True


def test_claim_lookup_reports_both_sources():
    connection = make_connection(role_source="claims_then_scim")
    lookup = describe_claim_lookup(connection, {"groups": ["A"]}, ["B"])
    assert lookup["by_source"] == {"claims": ["A"], "scim": ["B"]}
    assert lookup["role_source"] == "claims_then_scim"


# --- expectations -------------------------------------------------------------


def test_no_expectations_is_not_a_pass():
    """`passed` must be None, not True, when nothing was asserted.

    A green tick on a connection nobody configured expectations for would be
    actively misleading — it would read as evidence that a policy applied.
    """
    result = expectations.evaluate(make_connection(), {"amr": ["pwd"]}, "user")
    assert result["configured"] is False
    assert result["passed"] is None


def test_amr_contains_mfa_passes():
    connection = make_connection(
        expectations=[{"claim": "amr", "operator": "contains", "value": "mfa"}]
    )
    result = expectations.evaluate(connection, {"amr": ["pwd", "mfa"]}, "user")
    assert result["passed"] is True
    assert result["checks"][0]["actual"] == "mfa"


def test_amr_without_mfa_fails_and_reports_actual():
    connection = make_connection(
        expectations=[{"claim": "amr", "operator": "contains", "value": "mfa"}]
    )
    result = expectations.evaluate(connection, {"amr": ["pwd"]}, "user")
    assert result["passed"] is False
    assert result["failed_count"] == 1
    assert result["checks"][0]["actual"] == "pwd"


def test_expected_role_is_checked_first():
    connection = make_connection(expected_role="admin")
    result = expectations.evaluate(connection, {}, "user")
    assert result["checks"][0]["claim"] == "(resolved role)"
    assert result["checks"][0]["passed"] is False
    assert result["checks"][0]["actual"] == "user"


def test_present_and_absent_operators():
    connection = make_connection(
        expectations=[
            {"claim": "deviceid", "operator": "present", "value": ""},
            {"claim": "unexpected", "operator": "absent", "value": ""},
        ]
    )
    result = expectations.evaluate(connection, {"deviceid": "abc"}, "user")
    assert result["passed"] is True


def test_absent_fails_when_claim_is_there():
    connection = make_connection(
        expectations=[{"claim": "amr", "operator": "absent", "value": ""}]
    )
    result = expectations.evaluate(connection, {"amr": ["pwd"]}, "user")
    assert result["passed"] is False


def test_summarise_counts_passes():
    connection = make_connection(
        expectations=[
            {"claim": "amr", "operator": "contains", "value": "mfa"},
            {"claim": "tid", "operator": "present", "value": ""},
        ]
    )
    result = expectations.evaluate(connection, {"amr": ["pwd"], "tid": "x"}, "user")
    assert expectations.summarise(result) == "expectations: 1/2 passed"


# --- lifetimes ----------------------------------------------------------------


class _FakeSession:
    def __init__(self, created_at, expires_at):
        self.created_at = created_at
        self.expires_at = expires_at


def test_describe_decodes_time_claims():
    now = int(time.time())
    rows = lifetimes.describe({"iat": now, "exp": now + 3600})
    names = [row["name"] for row in rows]
    assert names == ["iat", "exp"]
    assert all(row["source"] == "token" for row in rows)


def test_describe_marks_an_expired_token():
    now = int(time.time())
    rows = lifetimes.describe({"exp": now - 60})
    assert rows[0]["expired"] is True
    assert "ago" in rows[0]["relative"]


def test_describe_ignores_unparseable_values():
    assert lifetimes.describe({"exp": "not-a-timestamp"}) == []


def test_outlives_token_detects_the_gap():
    """The configuration where token expiry does not end access."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    token_expiry = int((now + timedelta(minutes=5)).timestamp())
    session = _FakeSession(now, now + timedelta(minutes=60))
    assert lifetimes.outlives_token({"exp": token_expiry}, session) is True


def test_outlives_token_false_when_session_is_shorter():
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    token_expiry = int((now + timedelta(hours=8)).timestamp())
    session = _FakeSession(now, now + timedelta(minutes=60))
    assert lifetimes.outlives_token({"exp": token_expiry}, session) is False


@pytest.mark.parametrize(
    ("claims", "expected"),
    [({}, False), ({"exp": "x"}, False)],
)
def test_outlives_token_handles_missing_data(claims, expected):
    from datetime import UTC, datetime

    session = _FakeSession(datetime.now(UTC), datetime.now(UTC))
    assert lifetimes.outlives_token(claims, session) is expected
