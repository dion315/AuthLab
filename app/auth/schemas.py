"""Validated shapes for the protocol settings stored on IdpConnection.config.

The database column is JSON, so these Pydantic models are what stop the admin
UI writing a connection that cannot possibly work. Validating on write means a
misconfiguration surfaces as a form error next to the field, rather than as an
exception in the middle of a redirect to the IdP.

Three protocols are modelled. OIDC and SAML federate to a provider; `mtls`
authenticates a client certificate presented directly to this app, with no
provider in the path at all.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

# Fields encrypted before they touch the database. Keyed by protocol so the
# admin layer never has to guess which values are sensitive.
SECRET_FIELDS: dict[str, set[str]] = {
    "oidc": {"client_secret", "client_private_key"},
    "saml": {"sp_private_key"},
    "mtls": {"ca_private_key"},
}

# How a client certificate can be bound to a user. Ordered per connection; the
# first source that yields a value names the user.
IDENTITY_SOURCES = (
    "san_upn",  # Microsoft otherName UPN — what smart cards and Entra CBA carry
    "san_email",
    "san_dns",
    "subject_cn",
    "subject_email",
    "subject_dn",
    "serial_number",
    "thumbprint_sha256",
)

CLIENT_AUTH_METHODS = (
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
    "none",
)


class OidcSettings(BaseModel):
    """OIDC / OAuth 2.0 via discovery.

    Everything here comes from the provider's discovery document, so any
    compliant IdP works with no vendor-specific code: Entra ID, Okta, Auth0,
    Ping, Keycloak, Google, Duo. The only value you must find by hand is the
    issuer URL.
    """

    issuer: str = Field(default="", description="Issuer URL; /.well-known/openid-configuration is appended")
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email"
    use_pkce: bool = True

    # --- how this app authenticates itself to the token endpoint ---
    # A shared secret is the default because it is what most consoles hand you
    # first. private_key_jwt is certificate-based authentication for the
    # *client*: the app proves possession of a private key whose certificate
    # was uploaded to the provider, and no shared secret exists to leak.
    client_auth_method: str = "client_secret_post"
    client_certificate: str = ""
    client_private_key: str = ""
    # Providers disagree about the client assertion's audience: the spec allows
    # the issuer, Entra and Okta want the token endpoint. Blank uses the token
    # endpoint, which every provider tested here accepts.
    assertion_audience: str = ""

    # --- what this connection asks the provider's policy engine for ---
    # These are *requests*. The policy that decides whether to honour them
    # lives at the provider, not here.
    prompt: str = ""
    # Request a specific authentication context — this is how you ask for MFA
    # or a certificate explicitly and watch whether the IdP honours it,
    # challenges for it, or ignores the request.
    acr_values: str = ""
    # Reject an IdP session older than N seconds. Another re-auth lever.
    max_age: int | None = None
    # Raw OIDC "claims" request parameter, used for step-up challenges.
    claims_request: str = ""

    # Federated sign-out. Without it, "log out" only clears the local session
    # and the next sign-in is silent, which makes repeat testing painful.
    federated_logout: bool = True

    # Only for a local test IdP over plain http.
    allow_insecure_http: bool = False

    @field_validator("issuer")
    @classmethod
    def _strip_wellknown(cls, v: str) -> str:
        # People paste the discovery URL rather than the issuer constantly.
        v = v.strip().rstrip("/")
        suffix = "/.well-known/openid-configuration"
        if v.endswith(suffix):
            v = v[: -len(suffix)]
        return v

    @field_validator("prompt")
    @classmethod
    def _valid_prompt(cls, v: str) -> str:
        allowed = {"", "login", "consent", "select_account", "none"}
        if v not in allowed:
            raise ValueError(f"prompt must be one of {sorted(allowed)}")
        return v

    @field_validator("client_auth_method")
    @classmethod
    def _valid_client_auth(cls, v: str) -> str:
        if v not in CLIENT_AUTH_METHODS:
            raise ValueError(f"client_auth_method must be one of {sorted(CLIENT_AUTH_METHODS)}")
        return v


class SamlSettings(BaseModel):
    """SAML 2.0 service provider settings.

    Covers Entra ID, Okta, Shibboleth, ADFS, Ping, and Duo. Certificates are
    accepted as PEM or bare base64 — every IdP exports them differently and
    normalising here saves a support round-trip.
    """

    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_slo_url: str = ""
    idp_x509_cert: str = ""

    sp_entity_id: str = ""
    # Optional SP keypair: needed for signed AuthnRequests and for decrypting
    # encrypted assertions. The admin console can generate one.
    sp_x509_cert: str = ""
    sp_private_key: str = ""

    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    want_assertions_signed: bool = True
    want_response_signed: bool = False
    want_assertions_encrypted: bool = False
    sign_authn_requests: bool = False

    # Accept IdP-initiated SAML (no matching AuthnRequest on our side).
    # Off by default: leaving it on disables replay protection, which is a real
    # weakness and should be a decision rather than a default.
    allow_unsolicited: bool = False

    # --- what this connection asks the IdP's policy engine for ---
    force_authn: bool = False
    requested_authn_context: str = ""
    requested_authn_context_comparison: str = "exact"

    @field_validator("idp_x509_cert", "sp_x509_cert")
    @classmethod
    def _normalise_cert(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return v
        if "BEGIN CERTIFICATE" in v:
            body = "".join(
                line.strip()
                for line in v.splitlines()
                if line.strip() and "BEGIN CERT" not in line and "END CERT" not in line
            )
            return body
        return "".join(v.split())

    @field_validator("requested_authn_context_comparison")
    @classmethod
    def _valid_comparison(cls, v: str) -> str:
        allowed = {"exact", "minimum", "maximum", "better"}
        if v not in allowed:
            raise ValueError(f"comparison must be one of {sorted(allowed)}")
        return v


class MtlsSettings(BaseModel):
    """Certificate-based authentication straight to this app (mutual TLS).

    No identity provider is involved: the browser presents an X.509 client
    certificate during the TLS handshake, the terminating proxy passes it
    through in a header, and this app validates it and maps it to a user. That
    is the same credential a smart card or PIV card holds, so it is the
    cheapest way to see what a certificate actually carries before pointing a
    provider's own certificate-based authentication at it.

    The app never sees the handshake itself — TLS is terminated in front of it
    on every platform this deploys to — so the certificate arrives in a header
    whose name and encoding differ per proxy. Both are configurable, and
    `auto` covers the four shapes seen in practice.
    """

    # Header the terminating proxy puts the certificate in.
    #   Envoy / Azure Container Apps        x-forwarded-client-cert
    #   AWS Application Load Balancer       x-amzn-mtls-clientcert
    #   nginx ($ssl_client_escaped_cert)    ssl-client-cert / x-client-cert
    #   Azure App Service                   x-arr-clientcert
    header_name: str = "x-forwarded-client-cert"
    header_format: str = "auto"  # auto | xfcc | pem | base64_der

    # Trust anchors. A certificate must chain to one of these to be accepted.
    trusted_ca_pem: str = ""
    # Set only when the admin console generated a test CA here, so the same
    # page can go on to issue client certificates. Encrypted at rest.
    ca_private_key: str = ""
    # Optional CRL. Supply one to test that a revoked certificate is refused;
    # nothing is fetched over the network, so revocation is only ever checked
    # against what is pasted here.
    crl_pem: str = ""

    require_chain: bool = True
    require_client_auth_eku: bool = True
    check_validity: bool = True
    # Comma-separated issuer common names to additionally require. Empty means
    # any issuer that chains to a trust anchor is acceptable.
    allowed_issuer_cns: str = ""

    # Ordered list of certificate fields to take the username from.
    identity_sources: str = "san_upn,san_email,subject_cn"

    # The inspector accepts a pasted certificate and runs the full validation
    # pipeline against it. That is what makes this testable with no proxy in
    # front, so it defaults on — but it does let an admin exercise the
    # validator with an arbitrary certificate, so it can be turned off.
    allow_pasted_certificate: bool = True

    @field_validator("header_name")
    @classmethod
    def _normalise_header(cls, v: str) -> str:
        return (v or "").strip().lower() or "x-forwarded-client-cert"

    @field_validator("header_format")
    @classmethod
    def _valid_format(cls, v: str) -> str:
        allowed = {"auto", "xfcc", "pem", "base64_der"}
        if v not in allowed:
            raise ValueError(f"header_format must be one of {sorted(allowed)}")
        return v

    @field_validator("identity_sources")
    @classmethod
    def _valid_sources(cls, v: str) -> str:
        parts = [p.strip() for p in (v or "").split(",") if p.strip()]
        if not parts:
            return "san_upn,san_email,subject_cn"
        unknown = [p for p in parts if p not in IDENTITY_SOURCES]
        if unknown:
            raise ValueError(
                f"unknown identity source(s) {unknown}; choose from {sorted(IDENTITY_SOURCES)}"
            )
        return ",".join(parts)


SETTINGS_MODELS: dict[str, type[BaseModel]] = {
    "oidc": OidcSettings,
    "saml": SamlSettings,
    "mtls": MtlsSettings,
}

PROTOCOL_LABELS = {
    "oidc": "OIDC / OAuth 2.0",
    "saml": "SAML 2.0",
    "mtls": "Client certificate (mTLS)",
}


class RoleRule(BaseModel):
    """One claim-to-role rule. Evaluated in order, first match wins."""

    operator: str = "equals"  # equals | contains | starts_with | regex
    value: str = ""
    role: str = "user"

    @field_validator("operator")
    @classmethod
    def _valid_operator(cls, v: str) -> str:
        allowed = {"equals", "contains", "starts_with", "regex"}
        if v not in allowed:
            raise ValueError(f"operator must be one of {sorted(allowed)}")
        return v

    @field_validator("role")
    @classmethod
    def _valid_role(cls, v: str) -> str:
        from app.models import ROLES

        if v not in ROLES:
            raise ValueError(f"role must be one of {sorted(ROLES)}")
        return v
