"""Certificate-based authentication with no identity provider in the path.

The user's browser presents an X.509 client certificate during the TLS
handshake; something in front of this app terminates that TLS and passes the
certificate along in a header. This module turns that header back into a
certificate, decides whether to accept it, and produces the same shape of
claims dictionary that an OIDC or SAML sign-in produces — so role mapping, the
dashboard, and the audit trail all work unchanged.

Why a header rather than the socket: every platform this deploys to (Container
Apps, App Runner behind an ALB, Cloud Run behind a load balancer, nginx in
front of a container) terminates TLS before the request reaches the app, and
ASGI has no standard way to surface a peer certificate anyway. Reading a header
is not a workaround, it is the only thing that works — but it does mean the
header must be one the proxy sets and strips, never one a client can forge.
That warning is in the admin UI next to the field, not just here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from fastapi import Request

from app.auth import certs
from app.auth.connections import load_settings
from app.auth.schemas import MtlsSettings
from app.models import IdpConnection

# Envoy's XFCC header is a comma-separated list of `key=value;key="value"`
# elements, one per hop. The leaf certificate is the `Cert` key of the first.
_XFCC_PAIR_RE = re.compile(r'(?P<key>[A-Za-z]+)=(?P<quoted>"(?:[^"\\]|\\.)*"|[^;,]*)')

# Header names that carry a client certificate on the platforms this runs on.
# Used for the "what did the proxy actually send?" diagnostic, which is the
# fastest way to find out that a proxy is not forwarding anything at all.
KNOWN_HEADERS = (
    "x-forwarded-client-cert",
    "x-amzn-mtls-clientcert",
    "x-amzn-mtls-clientcert-leaf",
    "ssl-client-cert",
    "x-ssl-client-cert",
    "x-client-cert",
    "x-arr-clientcert",
    "x-forwarded-tls-client-cert",
)


class MtlsError(Exception):
    def __init__(self, message: str, *, detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


# --- getting the certificate out of the request ------------------------------


def parse_xfcc(value: str) -> str:
    """The leaf certificate PEM out of an Envoy XFCC header.

    Envoy percent-encodes the PEM and wraps it in quotes. Azure Container Apps
    uses this format, so it is the default.
    """
    first_element = value.split(",")[0]
    for match in _XFCC_PAIR_RE.finditer(first_element):
        if match.group("key").lower() != "cert":
            continue
        raw = match.group("quoted").strip()
        if raw.startswith('"') and raw.endswith('"'):
            raw = raw[1:-1]
        return unquote(raw.replace('\\"', '"'))
    return ""


def decode_header_value(value: str, header_format: str = "auto") -> str:
    """Normalise whatever the proxy sent into PEM text."""
    raw = (value or "").strip()
    if not raw:
        return ""

    if header_format == "xfcc" or (
        header_format == "auto" and ("Cert=" in raw or raw.startswith("Hash="))
    ):
        raw = parse_xfcc(raw)
        if not raw:
            return ""

    return certs.normalise_pem(raw)


def certificate_from_request(
    request: Request, settings: MtlsSettings
) -> tuple[str, str]:
    """Return (pem, header_name). Empty pem means no certificate was presented."""
    header_name = settings.header_name
    value = request.headers.get(header_name, "")
    if value:
        return decode_header_value(value, settings.header_format), header_name

    # Nothing under the configured name. Rather than reporting "no certificate"
    # when the proxy is in fact sending one under a different name, look at the
    # others we know about and say so.
    for candidate in KNOWN_HEADERS:
        if candidate == header_name:
            continue
        other = request.headers.get(candidate, "")
        if other:
            return decode_header_value(other, "auto"), candidate

    return "", header_name


def headers_present(request: Request) -> dict[str, int]:
    """Which known certificate headers arrived, and how long each was."""
    return {
        name: len(request.headers[name])
        for name in KNOWN_HEADERS
        if request.headers.get(name)
    }


# --- deciding whether to accept it -------------------------------------------


@dataclass
class CertificateAuthResult:
    """The full outcome of evaluating one certificate.

    Carries the failures as well as the verdict: the inspector page renders
    exactly this, and a refusal you cannot explain is not a useful test result.
    """

    accepted: bool
    reason: str = ""
    identity: str = ""
    identity_source: str = ""
    certificate: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)
    anchor: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    pem: str = ""

    def as_detail(self) -> dict[str, Any]:
        """A compact form for the audit trail — no full certificate bodies."""
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "identity": self.identity,
            "identity_source": self.identity_source,
            "subject": self.certificate.get("subject", ""),
            "issuer": self.certificate.get("issuer", ""),
            "serial_number": self.certificate.get("serial_number", ""),
            "thumbprint_sha256": self.certificate.get("thumbprint_sha256", ""),
            "failed_checks": [c["name"] for c in self.checks if not c["passed"]],
        }


def _first_value(described: dict[str, Any], source: str) -> str:
    value = described.get(
        {
            "san_upn": "san_upn",
            "san_email": "san_email",
            "san_dns": "san_dns",
            "subject_cn": "subject_cn",
            "subject_email": "subject_email",
            "subject_dn": "subject",
            "serial_number": "serial_number",
            "thumbprint_sha256": "thumbprint_sha256",
        }.get(source, source)
    )
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def resolve_identity(described: dict[str, Any], identity_sources: str) -> tuple[str, str]:
    """First configured field that actually has a value. Returns (identity, source)."""
    for source in [s.strip() for s in identity_sources.split(",") if s.strip()]:
        value = _first_value(described, source)
        if value:
            return value, source
    return "", ""


def build_claims(described: dict[str, Any], *, identity: str, identity_source: str,
                 anchor: str, chain: list[str]) -> dict[str, Any]:
    """The claims dictionary a certificate sign-in produces.

    `amr` is synthesised rather than asserted — no provider said this — so that
    the dashboard's authentication-method analysis, the role mapper, and any
    rule written against `amr` behave the same way they do for a federated
    sign-in. The note says plainly where it came from.
    """
    claims: dict[str, Any] = {
        "note": (
            "Certificate-based authentication directly to this app. No identity "
            "provider was involved; every value below was read from the client "
            "certificate presented during the TLS handshake."
        ),
        "auth_method": "mtls",
        "amr": ["x509"],
        "identity": identity,
        "identity_source": identity_source,
        "subject_dn": described.get("subject", ""),
        "subject_cn": described.get("subject_cn", ""),
        "subject_o": described.get("subject_o", ""),
        "subject_ou": described.get("subject_ou", ""),
        "subject_email": described.get("subject_email", ""),
        "issuer_dn": described.get("issuer", ""),
        "issuer_cn": described.get("issuer_cn", ""),
        "serial_number": described.get("serial_number", ""),
        "not_before": described.get("not_before", ""),
        "not_after": described.get("not_after", ""),
        "days_remaining": described.get("days_remaining"),
        "san_upn": described.get("san_upn", []),
        "san_email": described.get("san_email", []),
        "san_dns": described.get("san_dns", []),
        "key_usage": described.get("key_usage", []),
        "extended_key_usage": described.get("extended_key_usage", []),
        "public_key": described.get("public_key", ""),
        "thumbprint_sha1": described.get("thumbprint_sha1", ""),
        "thumbprint_sha256": described.get("thumbprint_sha256", ""),
        "chain": chain,
        "trust_anchor": anchor,
    }
    return claims


def evaluate(connection: IdpConnection, pem: str) -> CertificateAuthResult:
    """Validate a presented certificate against a connection's rules.

    Never raises for a bad certificate — an unparseable or rejected one is a
    result to display, not an exception. Only a broken *configuration* (an
    unreadable trust store) raises, because that is the operator's problem
    rather than the caller's.
    """
    settings = load_settings(connection)
    if not isinstance(settings, MtlsSettings):  # pragma: no cover — guarded by callers
        raise MtlsError("This connection is not a client-certificate connection.")

    if not pem:
        return CertificateAuthResult(
            accepted=False,
            reason=(
                "No client certificate was presented. The TLS terminator in front of "
                "this app has to request one and forward it — see the connection "
                "settings for the header it should use."
            ),
        )

    try:
        certificate = certs.load_certificate(pem)
    except certs.CertificateError as exc:
        return CertificateAuthResult(accepted=False, reason=exc.message, pem=pem)

    described = certs.describe(certificate)

    try:
        anchors = certs.load_certificates(settings.trusted_ca_pem)
    except certs.CertificateError as exc:
        raise MtlsError(
            f"The trust store on connection '{connection.name}' cannot be read: {exc.message}"
        ) from exc

    try:
        crls = certs.load_crls(settings.crl_pem)
    except certs.CertificateError as exc:
        raise MtlsError(
            f"The CRL on connection '{connection.name}' cannot be read: {exc.message}"
        ) from exc

    checks: list[dict[str, Any]] = []
    chain: list[str] = [described["subject"]]
    anchor = ""

    if settings.require_chain:
        result = certs.validate_chain(
            certificate,
            anchors,
            crls=crls,
            require_client_auth_eku=settings.require_client_auth_eku,
            check_validity=settings.check_validity,
        )
        checks.extend(result.as_dict()["checks"])
        chain = result.chain
        anchor = result.anchor
    else:
        # Trust anchoring off: still report the individual checks, because
        # "accepted anything" is a state an operator should be able to see.
        checks.append(
            {
                "name": "Chain to a trusted CA",
                "passed": True,
                "detail": "not required by this connection — any certificate is accepted",
            }
        )
        if settings.check_validity:
            checks.append(
                {
                    "name": "Validity period",
                    "passed": not described["expired"] and not described["not_yet_valid"],
                    "detail": f"{described['not_before']} to {described['not_after']}",
                }
            )
        if settings.require_client_auth_eku:
            usages = described["extended_key_usage"]
            checks.append(
                {
                    "name": "Extended key usage",
                    "passed": (not usages) or "clientAuth" in usages,
                    "detail": ", ".join(usages) or "no EKU extension (unconstrained)",
                }
            )
        if crls:
            revoked = certs.revocation_entry(certificate, crls)
            checks.append(
                {
                    "name": "Revocation (CRL)",
                    "passed": revoked is None,
                    "detail": "not listed on the supplied CRL" if revoked is None else "revoked",
                }
            )

    allowed_issuers = [i.strip() for i in settings.allowed_issuer_cns.split(",") if i.strip()]
    if allowed_issuers:
        checks.append(
            {
                "name": "Issuer allow-list",
                "passed": described["issuer_cn"] in allowed_issuers,
                "detail": f"issuer CN '{described['issuer_cn']}'; allowed: {', '.join(allowed_issuers)}",
            }
        )

    identity, identity_source = resolve_identity(described, settings.identity_sources)
    checks.append(
        {
            "name": "Identity binding",
            "passed": bool(identity),
            "detail": (
                f"{identity_source} = {identity}"
                if identity
                else f"none of {settings.identity_sources} carried a value"
            ),
        }
    )

    failed = [c for c in checks if not c["passed"]]
    accepted = not failed

    return CertificateAuthResult(
        accepted=accepted,
        reason="" if accepted else "; ".join(f"{c['name']}: {c['detail']}" for c in failed),
        identity=identity,
        identity_source=identity_source,
        certificate=described,
        checks=checks,
        chain=chain,
        anchor=anchor,
        claims=build_claims(
            described, identity=identity, identity_source=identity_source, anchor=anchor, chain=chain
        ),
        pem=certs.normalise_pem(pem),
    )
