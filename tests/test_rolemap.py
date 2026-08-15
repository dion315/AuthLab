"""Claim-to-role mapping.

Pure functions with no database or request involved, which is what makes the
tricky cases cheap to cover: scalar-versus-list claims, ordering, and the
providers that put groups somewhere unusual.
"""

from __future__ import annotations

from app.auth.rolemap import extract_claim, resolve_role
from app.models import IdpConnection


def connection(**overrides) -> IdpConnection:
    defaults = {
        "slug": "test",
        "name": "Test",
        "protocol": "oidc",
        "role_claim": "groups",
        "default_role": "user",
        "role_rules": [],
        "config": {},
    }
    defaults.update(overrides)
    return IdpConnection(**defaults)


# --- claim extraction --------------------------------------------------------


def test_extract_list_claim():
    assert extract_claim({"groups": ["a", "b"]}, "groups") == ["a", "b"]


def test_extract_scalar_claim_is_wrapped():
    """A single-valued claim must behave like a one-element list."""
    assert extract_claim({"groups": "a"}, "groups") == ["a"]


def test_extract_missing_claim():
    assert extract_claim({}, "groups") == []


def test_extract_nested_dotted_path():
    claims = {"resource_access": {"account": {"roles": ["admin"]}}}
    assert extract_claim(claims, "resource_access.account.roles") == ["admin"]


def test_extract_literal_key_containing_dots():
    """SAML attribute names are URNs full of dots and colons."""
    claims = {"http://schemas.xmlsoap.org/claims/Group": ["staff"]}
    assert extract_claim(claims, "http://schemas.xmlsoap.org/claims/Group") == ["staff"]


def test_extract_coerces_non_strings():
    assert extract_claim({"groups": [1, 2]}, "groups") == ["1", "2"]


# --- rule evaluation ---------------------------------------------------------


def test_equals_rule_matches():
    conn = connection(role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}])
    role, trace = resolve_role(conn, {"groups": ["SEC-Admins"]})
    assert role == "admin"
    assert trace[0]["matched"] is True
    assert trace[0]["matched_on"] == "SEC-Admins"


def test_falls_back_to_default_role():
    conn = connection(role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}])
    role, _ = resolve_role(conn, {"groups": ["Everyone"]})
    assert role == "user"


def test_first_matching_rule_wins():
    conn = connection(
        role_rules=[
            {"operator": "equals", "value": "SEC-Power", "role": "power"},
            {"operator": "equals", "value": "SEC-Admins", "role": "admin"},
        ]
    )
    role, _ = resolve_role(conn, {"groups": ["SEC-Admins", "SEC-Power"]})
    assert role == "power"


def test_starts_with_operator():
    conn = connection(role_rules=[{"operator": "starts_with", "value": "SEC-", "role": "power"}])
    assert resolve_role(conn, {"groups": ["SEC-Anything"]})[0] == "power"


def test_contains_operator():
    conn = connection(role_rules=[{"operator": "contains", "value": "Admin", "role": "admin"}])
    assert resolve_role(conn, {"groups": ["Global Administrators"]})[0] == "admin"


def test_regex_operator():
    conn = connection(role_rules=[{"operator": "regex", "value": r"^SEC-.*-Admins$", "role": "admin"}])
    assert resolve_role(conn, {"groups": ["SEC-DLP-Admins"]})[0] == "admin"


def test_invalid_regex_does_not_raise():
    """A malformed pattern must not break a sign-in — it just fails to match."""
    conn = connection(role_rules=[{"operator": "regex", "value": "[unclosed", "role": "admin"}])
    role, trace = resolve_role(conn, {"groups": ["anything"]})
    assert role == "user"
    assert trace[0]["matched"] is False


def test_missing_claim_yields_default_and_full_trace():
    conn = connection(role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}])
    role, trace = resolve_role(conn, {"sub": "abc"})
    assert role == "user"
    assert len(trace) == 1 and trace[0]["matched"] is False


def test_scalar_claim_still_matches():
    """Providers that emit a single group as a string, not a list."""
    conn = connection(role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}])
    assert resolve_role(conn, {"groups": "SEC-Admins"})[0] == "admin"


def test_entra_app_roles_claim():
    conn = connection(
        role_claim="roles",
        role_rules=[{"operator": "equals", "value": "Lab.Admin", "role": "admin"}],
    )
    assert resolve_role(conn, {"roles": ["Lab.Admin"]})[0] == "admin"


def test_saml_group_attribute():
    conn = connection(
        protocol="saml",
        role_claim="http://schemas.xmlsoap.org/claims/Group",
        role_rules=[{"operator": "equals", "value": "staff", "role": "power"}],
    )
    claims = {"http://schemas.xmlsoap.org/claims/Group": ["staff", "students"]}
    assert resolve_role(conn, claims)[0] == "power"
