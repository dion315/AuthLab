"""Reading what a provider asserted about *how* the user authenticated.

An access policy — Entra Conditional Access, an Okta authentication policy, a
Ping or Duo policy — is evaluated at the provider. This app never sees the
policy. What it does see is the token that comes back, and the token says which
authentication methods were actually used. That is the evidence: if a policy
was supposed to require multi-factor or a certificate and the token says
`pwd`, the policy did not apply to this sign-in.

Everything here is pure lookup over a claims dictionary. It is deliberately
descriptive rather than prescriptive — the app reports what the values mean and
lets the operator draw the conclusion, because "certificate-based" means
subtly different things across providers and guessing wrong is worse than
saying so.
"""

from __future__ import annotations

from typing import Any

# RFC 8176 authentication method reference values, plus the extensions the
# major providers actually emit. `certificate` marks a method that proves
# possession of an X.509 private key.
AMR_VALUES: dict[str, dict[str, Any]] = {
    "pwd": {"label": "Password", "factor": "something you know", "certificate": False},
    "mfa": {
        "label": "Multiple factors",
        "factor": "two or more",
        "certificate": False,
        "note": "The provider is asserting that more than one factor was used.",
    },
    "otp": {"label": "One-time password", "factor": "something you have", "certificate": False},
    "sms": {"label": "SMS code", "factor": "something you have", "certificate": False},
    "tel": {"label": "Telephone call", "factor": "something you have", "certificate": False},
    "kba": {"label": "Knowledge-based answers", "factor": "something you know", "certificate": False},
    "pin": {"label": "PIN", "factor": "something you know", "certificate": False},
    "hwk": {
        "label": "Hardware-held key",
        "factor": "something you have",
        "certificate": False,
        "phishing_resistant": True,
    },
    "swk": {"label": "Software-held key", "factor": "something you have", "certificate": False},
    "fpt": {"label": "Fingerprint", "factor": "something you are", "certificate": False},
    "face": {"label": "Facial recognition", "factor": "something you are", "certificate": False},
    "iris": {"label": "Iris scan", "factor": "something you are", "certificate": False},
    "geo": {"label": "Geolocation", "factor": "context", "certificate": False},
    "user": {"label": "User presence confirmed", "factor": "context", "certificate": False},
    "pop": {"label": "Proof of possession", "factor": "something you have", "certificate": False},
    # --- certificate-based ---
    "x509": {
        "label": "X.509 certificate",
        "factor": "something you have",
        "certificate": True,
        "phishing_resistant": True,
        "note": "The user proved possession of a private key whose certificate the provider trusts.",
    },
    "sc": {
        "label": "Smart card",
        "factor": "something you have",
        "certificate": True,
        "phishing_resistant": True,
    },
    "smartcard": {
        "label": "Smart card",
        "factor": "something you have",
        "certificate": True,
        "phishing_resistant": True,
    },
    "rsa": {
        "label": "RSA key proof of possession",
        "factor": "something you have",
        "certificate": True,
        "phishing_resistant": True,
        "note": (
            "Entra ID emits this for certificate-based authentication. Other providers "
            "use it for any RSA key proof, so treat it as certificate-based only if the "
            "provider is Entra."
        ),
    },
    "certauth": {"label": "Certificate authentication", "factor": "something you have", "certificate": True},
    # --- phishing-resistant, not certificate ---
    "fido": {
        "label": "FIDO2 / passkey",
        "factor": "something you have",
        "certificate": False,
        "phishing_resistant": True,
    },
    "phr": {
        "label": "Phishing-resistant method",
        "factor": "context",
        "certificate": False,
        "phishing_resistant": True,
    },
    "phh": {"label": "Phishing-hardened method", "factor": "context", "certificate": False},
    "wia": {"label": "Windows integrated authentication", "factor": "context", "certificate": False},
    "ngcmfa": {
        "label": "Fresh multi-factor (Entra)",
        "factor": "two or more",
        "certificate": False,
        "note": "Entra emits this when MFA was performed recently enough to satisfy a step-up.",
    },
    "mfa_required": {"label": "Multi-factor required", "factor": "two or more", "certificate": False},
}

# SAML equivalents. The AuthnContextClassRef is what a SAML IdP returns in
# place of `amr`, and it is the value a RequestedAuthnContext asks for.
SAML_CONTEXTS: dict[str, dict[str, Any]] = {
    "urn:oasis:names:tc:SAML:2.0:ac:classes:X509": {
        "label": "X.509 certificate",
        "certificate": True,
        "phishing_resistant": True,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI": {
        "label": "Smart card with PKI",
        "certificate": True,
        "phishing_resistant": True,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard": {
        "label": "Smart card",
        "certificate": True,
        "phishing_resistant": True,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient": {
        "label": "Mutual TLS client certificate",
        "certificate": True,
        "phishing_resistant": True,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password": {
        "label": "Password",
        "certificate": False,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport": {
        "label": "Password over TLS",
        "certificate": False,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos": {"label": "Kerberos", "certificate": False},
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract": {
        "label": "Mobile two-factor",
        "certificate": False,
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession": {
        "label": "Existing session reused — no fresh authentication",
        "certificate": False,
        "note": "The IdP did not authenticate the user again; ForceAuthn was not honoured.",
    },
    "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified": {
        "label": "Unspecified",
        "certificate": False,
        "note": "The IdP declined to say how the user authenticated.",
    },
    "http://schemas.microsoft.com/claims/multipleauthn": {
        "label": "Multi-factor (Entra ID)",
        "certificate": False,
    },
    "urn:federation:authentication:windows": {
        "label": "Windows integrated authentication (ADFS)",
        "certificate": False,
    },
}

# Claims worth calling out when working out why a policy did or did not apply.
# Anything not listed still appears in the full claim dump.
POLICY_SIGNAL_CLAIMS: dict[str, str] = {
    "amr": "Authentication methods actually used. The claim a multi-factor or certificate policy changes.",
    "acr": "Authentication context class the provider asserted. '1' typically means single-factor.",
    "acrs": "Authentication contexts this token satisfies (Entra: authentication context / step-up).",
    "authnContextClassRef": "SAML equivalent of amr — the authentication context the IdP asserted.",
    "auth_time": "When the user actually authenticated, as opposed to when this token was issued.",
    "ipaddr": "Source IP as the provider saw it. Compare with the address this app recorded.",
    "tid": "Tenant/directory the user signed in from.",
    "oid": "Immutable object id for the user in the directory.",
    "sub": "Subject identifier — unique per user per application.",
    "groups": "Group memberships, when the provider is configured to emit them.",
    "roles": "Application roles assigned at the provider.",
    "wids": "Directory role template ids (Entra).",
    "deviceid": "Device identifier — present when the device is registered or compliant.",
    "xms_cc": "Client capabilities, including whether this client can handle a claims challenge.",
    "sid": "Session identifier at the provider, used for federated sign-out.",
    "auth_method": "How this app authenticated the user when no provider was involved.",
    "identity_source": "Which certificate field the username was taken from.",
    "thumbprint_sha256": "SHA-256 thumbprint of the presented client certificate.",
    "trust_anchor": "The CA this certificate chained to.",
}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def describe_methods(claims: dict[str, Any]) -> list[dict[str, Any]]:
    """One entry per authentication method the provider named."""
    described: list[dict[str, Any]] = []

    for value in _as_list(claims.get("amr")):
        known = AMR_VALUES.get(value.lower(), {})
        described.append(
            {
                "value": value,
                "source": "amr",
                "label": known.get("label", value),
                "factor": known.get("factor", "unknown"),
                "certificate": bool(known.get("certificate")),
                "phishing_resistant": bool(known.get("phishing_resistant")),
                "note": known.get("note", ""),
                "recognised": bool(known),
            }
        )

    for value in _as_list(claims.get("authnContextClassRef")):
        known = SAML_CONTEXTS.get(value, {})
        described.append(
            {
                "value": value,
                "source": "AuthnContextClassRef",
                "label": known.get("label", value.rsplit(":", 1)[-1]),
                "factor": known.get("factor", "unknown"),
                "certificate": bool(known.get("certificate")),
                "phishing_resistant": bool(known.get("phishing_resistant")),
                "note": known.get("note", ""),
                "recognised": bool(known),
            }
        )

    return described


def analyse(claims: dict[str, Any], *, protocol: str = "") -> dict[str, Any]:
    """A verdict on how the user authenticated, with the evidence behind it.

    `certificate_based` is deliberately three-valued: True, False, or None for
    "the provider did not say". A provider that emits no `amr` and no
    AuthnContextClassRef has told you nothing, and reporting that as "not
    certificate-based" would be a made-up answer.
    """
    methods = describe_methods(claims)
    multi_factor = any(m["value"].lower() in ("mfa", "ngcmfa") for m in methods) or len(
        {m["value"].lower() for m in methods if m["factor"] not in ("context", "unknown")}
    ) > 1

    if protocol == "mtls":
        certificate_based: bool | None = True
    elif protocol == "local":
        certificate_based = False
    elif methods:
        certificate_based = any(m["certificate"] for m in methods)
    else:
        certificate_based = None

    evidence: list[str] = []
    if protocol == "mtls":
        evidence.append(
            "The certificate was presented to this app directly and validated here; "
            "no provider was involved."
        )
    elif protocol == "local":
        evidence.append(
            "Local account: a password checked against this app's own database. No "
            "identity provider was involved, so no access policy applied to this "
            "sign-in — which is exactly why the local account still works when one "
            "blocks you."
        )
    for method in methods:
        evidence.append(f"{method['source']} = {method['value']} ({method['label']})")
    if not methods and protocol not in ("mtls", "local"):
        evidence.append(
            "The token carried neither an amr claim nor an AuthnContextClassRef, so the "
            "provider did not say how the user authenticated. Many providers only emit "
            "amr when asked to."
        )

    return {
        "methods": methods,
        "certificate_based": certificate_based,
        "multi_factor": multi_factor,
        "phishing_resistant": any(m["phishing_resistant"] for m in methods),
        "evidence": evidence,
        "acr": claims.get("acr", ""),
        "auth_time": claims.get("auth_time", ""),
    }


def policy_signals(claims: dict[str, Any]) -> list[dict[str, Any]]:
    """The claims worth showing on their own, with what each one tells you."""
    return [
        {"name": name, "value": claims[name], "description": description}
        for name, description in POLICY_SIGNAL_CLAIMS.items()
        if name in claims
    ]
