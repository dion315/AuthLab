"""Reading how the user authenticated out of what the provider asserted.

The three-valued verdict is the point of these tests: a provider that says
nothing must produce "unknown", not "no". Reporting an absent claim as a
negative result would turn a missing configuration into a false conclusion
about a policy.
"""

from __future__ import annotations

from app.auth import authn_methods


def test_password_only_is_not_certificate_based():
    result = authn_methods.analyse({"amr": ["pwd"]}, protocol="oidc")

    assert result["certificate_based"] is False
    assert result["multi_factor"] is False


def test_x509_in_amr_is_certificate_based():
    result = authn_methods.analyse({"amr": ["x509"]}, protocol="oidc")

    assert result["certificate_based"] is True
    assert result["phishing_resistant"] is True


def test_entra_emits_rsa_for_certificate_authentication():
    result = authn_methods.analyse({"amr": ["rsa", "mfa"]}, protocol="oidc")

    assert result["certificate_based"] is True
    assert result["multi_factor"] is True
    # The caveat matters: `rsa` means something narrower at other providers.
    note = next(m["note"] for m in result["methods"] if m["value"] == "rsa")
    assert "Entra" in note


def test_a_scalar_amr_claim_is_handled():
    """Some providers send a string where the spec says array."""
    result = authn_methods.analyse({"amr": "sc"}, protocol="oidc")

    assert result["certificate_based"] is True


def test_no_amr_and_no_context_is_unknown_not_negative():
    result = authn_methods.analyse({"sub": "abc", "email": "a@b.test"}, protocol="oidc")

    assert result["certificate_based"] is None
    assert "did not say" in " ".join(result["evidence"])


def test_saml_x509_context_is_certificate_based():
    claims = {"authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"}

    result = authn_methods.analyse(claims, protocol="saml")

    assert result["certificate_based"] is True
    assert result["methods"][0]["label"] == "X.509 certificate"


def test_saml_previous_session_is_flagged():
    """ForceAuthn was asked for and the IdP reused a session anyway."""
    claims = {"authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"}

    result = authn_methods.analyse(claims, protocol="saml")

    assert result["certificate_based"] is False
    assert "did not authenticate the user again" in result["methods"][0]["note"]


def test_unrecognised_values_are_shown_rather_than_dropped():
    result = authn_methods.analyse({"amr": ["vendor-specific-thing"]}, protocol="oidc")

    assert result["methods"][0]["recognised"] is False
    assert result["methods"][0]["value"] == "vendor-specific-thing"
    assert result["certificate_based"] is False


def test_mtls_sign_in_is_certificate_based_by_construction():
    result = authn_methods.analyse({"amr": ["x509"]}, protocol="mtls")

    assert result["certificate_based"] is True
    assert "no provider was involved" in " ".join(result["evidence"])


def test_local_sign_in_is_never_certificate_based():
    result = authn_methods.analyse({"email": "admin@authlab.local"}, protocol="local")

    assert result["certificate_based"] is False


def test_multiple_distinct_factors_count_as_multi_factor():
    result = authn_methods.analyse({"amr": ["pwd", "otp"]}, protocol="oidc")

    assert result["multi_factor"] is True


def test_policy_signals_only_lists_claims_that_are_present():
    signals = authn_methods.policy_signals({"amr": ["pwd"], "ipaddr": "203.0.113.9", "x": 1})

    names = [signal["name"] for signal in signals]
    assert names == ["amr", "ipaddr"]
    assert all(signal["description"] for signal in signals)
