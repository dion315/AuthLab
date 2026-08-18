"""Turning IdP claims into an application role.

Kept separate and pure — no database, no request — because this is the piece
people most often get wrong and most want to test in isolation. Every IdP
expresses group membership differently:

    Entra ID    "roles": ["Admin"]  or  "groups": ["<guid>"]
    Okta        "groups": ["Everyone", "SEC-Admins"]
    Shibboleth  "urn:oid:1.3.6.1.4.1.5923.1.5.1.1": ["staff"]
    Generic     a single scalar string rather than a list

So the claim name, the match operator, and the resulting role are all
configuration rather than code.
"""

from __future__ import annotations

import re
from typing import Any

from app.models import DEFAULT_ROLE, IdpConnection


def extract_claim(claims: dict[str, Any], path: str) -> list[str]:
    """Read a claim as a list of strings.

    Supports dotted paths for nested claims, which SAML attribute names and
    some OIDC extension claims need. Scalars are wrapped so callers never have
    to care whether the IdP sent one value or several — the single most common
    source of role-mapping bugs.
    """
    if not path:
        return []

    value: Any = claims
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            # Not a nested path after all — try the whole string as one key.
            value = claims.get(path)
            break

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _matches(operator: str, rule_value: str, claim_value: str) -> bool:
    if operator == "equals":
        return claim_value == rule_value
    if operator == "contains":
        return rule_value in claim_value
    if operator == "starts_with":
        return claim_value.startswith(rule_value)
    if operator == "regex":
        try:
            return re.search(rule_value, claim_value) is not None
        except re.error:
            # A malformed pattern should not take down a sign-in. It simply
            # fails to match, and the trace below records why.
            return False
    return False


def resolve_role(
    connection: IdpConnection, claims: dict[str, Any]
) -> tuple[str, list[dict[str, Any]]]:
    """Map claims to a role.

    Returns the role plus a trace of every rule evaluated. The trace is shown
    in the dashboard so that "why am I only a 'user'?" is answerable by looking
    at the screen instead of by adding logging and redeploying.
    """
    claim_values = extract_claim(claims, connection.role_claim)
    trace: list[dict[str, Any]] = []

    for index, rule in enumerate(connection.role_rules or []):
        operator = rule.get("operator", "equals")
        rule_value = rule.get("value", "")
        role = rule.get("role", DEFAULT_ROLE)

        matched_on = next(
            (cv for cv in claim_values if _matches(operator, rule_value, cv)), None
        )
        trace.append(
            {
                "rule": index + 1,
                "operator": operator,
                "value": rule_value,
                "role": role,
                "matched": matched_on is not None,
                "matched_on": matched_on,
            }
        )
        if matched_on is not None:
            return role, trace

    return connection.default_role or DEFAULT_ROLE, trace


def describe_claim_lookup(
    connection: IdpConnection, claims: dict[str, Any]
) -> dict[str, Any]:
    """Diagnostics for the dashboard: what we looked for and what we found.

    The values key is deliberately not called "values": Jinja resolves
    `mapping.values` to the dict's own method before it looks for a key of that
    name, so a template rendering it gets a bound builtin and fails at the
    filter rather than at the lookup.
    """
    found_values = extract_claim(claims, connection.role_claim)
    return {
        "claim": connection.role_claim,
        "found": bool(found_values),
        "found_values": found_values,
        "available_claims": sorted(claims.keys()),
    }
