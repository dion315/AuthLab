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

There is a second place group membership can come from: SCIM. A great many
real applications authorise against the groups a provisioning connector pushed
them rather than against anything in the token — the token says who you are,
the directory sync says what you can do. `role_source` selects between the two,
and SCIM group names are passed *in* by the caller so this module keeps having
no idea a database exists.
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


def matches(operator: str, rule_value: str, claim_value: str) -> bool:
    """Apply one operator. Public because expectations reuse the vocabulary."""
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


def candidate_sources(
    connection: IdpConnection,
    claims: dict[str, Any],
    scim_groups: list[str] | None = None,
) -> list[tuple[str, list[str]]]:
    """The value lists the rules run against, in the order they are tried.

    Source-major rather than rule-major: "claims_then_scim" means *exhaust the
    rules against the token first*, and only fall back to provisioned group
    membership if nothing there matched. That ordering is the one people
    expect, because the token is the fresher signal.
    """
    role_source = connection.role_source or "claims"
    sources: list[tuple[str, list[str]]] = []

    if role_source in ("claims", "claims_then_scim"):
        sources.append(("claims", extract_claim(claims, connection.role_claim)))
    if role_source in ("scim", "claims_then_scim"):
        sources.append(("scim", list(scim_groups or [])))

    return sources


def resolve_role(
    connection: IdpConnection,
    claims: dict[str, Any],
    scim_groups: list[str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Map claims and/or SCIM group membership to a role.

    Returns the role plus a trace of every rule evaluated. The trace is shown
    in the dashboard so that "why am I only a 'user'?" is answerable by looking
    at the screen instead of by adding logging and redeploying.
    """
    trace: list[dict[str, Any]] = []

    for source_name, values in candidate_sources(connection, claims, scim_groups):
        for index, rule in enumerate(connection.role_rules or []):
            operator = rule.get("operator", "equals")
            rule_value = rule.get("value", "")
            role = rule.get("role", DEFAULT_ROLE)

            matched_on = next(
                (value for value in values if matches(operator, rule_value, value)), None
            )
            trace.append(
                {
                    "rule": index + 1,
                    "source": source_name,
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
    connection: IdpConnection,
    claims: dict[str, Any],
    scim_groups: list[str] | None = None,
) -> dict[str, Any]:
    """Diagnostics for the dashboard: what we looked for and what we found."""
    sources = candidate_sources(connection, claims, scim_groups)
    values = [value for _, source_values in sources for value in source_values]
    # Deliberately not called "values": Jinja resolves \{\{ mapping.values \}\} to
    # the dict *method*, so a key by that name renders as a bound method and
    # any filter applied to it fails at request time.
    return {
        "claim": connection.role_claim,
        "role_source": connection.role_source or "claims",
        "found": bool(values),
        "matched_values": values,
        "by_source": {name: source_values for name, source_values in sources},
        "available_claims": sorted(claims.keys()),
    }
