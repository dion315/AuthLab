"""SAML 2.0 service provider.

Works with Entra ID, Okta, Shibboleth, ADFS, Ping, and Duo. Signature and
assertion validation is delegated to python3-saml (which uses xmlsec) — SAML
signature verification has too many sharp edges to reimplement.

On replay protection: the AuthnRequest ID is kept in a signed, short-lived
cookie and handed back to `process_response(request_id=...)`, so InResponseTo
is genuinely validated for SP-initiated flows. Accepting unsolicited
(IdP-initiated) responses disables that check and is therefore opt-in per
connection rather than the default.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from app.auth import certs
from app.auth.connections import acs_url, load_settings, sls_url
from app.auth.schemas import SamlSettings
from app.config import get_settings
from app.models import IdpConnection

REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


class SamlError(Exception):
    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


def build_saml_settings(connection: IdpConnection) -> dict[str, Any]:
    settings = load_settings(connection)
    assert isinstance(settings, SamlSettings)
    base_url = get_settings().base_url.rstrip("/")

    sp_entity_id = settings.sp_entity_id or f"{base_url}/auth/saml/{connection.slug}/metadata"

    requested_context: bool | list[str] = False
    if settings.requested_authn_context:
        requested_context = [
            value.strip()
            for value in settings.requested_authn_context.split(",")
            if value.strip()
        ]

    # Decrypting an assertion needs the SP private key. Asking for encryption
    # without one produces a failure at the ACS endpoint that reads like an IdP
    # problem, so refuse it here where the message can be specific.
    if settings.want_assertions_encrypted and not settings.sp_private_key:
        raise SamlError(
            "This connection requires encrypted assertions but has no SP private key. "
            "Generate or paste an SP keypair, or turn encryption off."
        )

    return {
        # "strict" enforces signature, destination, and timing checks. Turning
        # it off is the usual bad advice for making SAML "work"; it makes the
        # assertion meaningless, so it stays on.
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url(connection.slug),
                "binding": POST_BINDING,
            },
            "singleLogoutService": {
                "url": sls_url(connection.slug),
                "binding": REDIRECT_BINDING,
            },
            "NameIDFormat": settings.name_id_format,
            "x509cert": settings.sp_x509_cert,
            "privateKey": settings.sp_private_key,
        },
        "idp": {
            "entityId": settings.idp_entity_id,
            "singleSignOnService": {
                "url": settings.idp_sso_url,
                "binding": REDIRECT_BINDING,
            },
            "singleLogoutService": {
                "url": settings.idp_slo_url,
                "binding": REDIRECT_BINDING,
            },
            "x509cert": settings.idp_x509_cert,
        },
        "security": {
            "authnRequestsSigned": settings.sign_authn_requests,
            "wantAssertionsSigned": settings.want_assertions_signed,
            "wantMessagesSigned": settings.want_response_signed,
            "wantAssertionsEncrypted": settings.want_assertions_encrypted,
            "wantNameId": True,
            "requestedAuthnContext": requested_context,
            "requestedAuthnContextComparison": settings.requested_authn_context_comparison,
            "rejectUnsolicitedResponsesWithInResponseTo": not settings.allow_unsolicited,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def build_request_dict(
    *, url: str, query_params: dict[str, str], form_data: dict[str, str]
) -> dict[str, Any]:
    """Adapt a Starlette request into the shape python3-saml expects.

    Host and scheme are taken from the configured BASE_URL rather than from
    request headers. Behind a load balancer the inbound request is plain HTTP
    on some internal port, and SAML Destination validation compares against the
    externally visible URL — using headers here is the usual cause of
    "Destination mismatch" errors that look like an IdP problem.
    """
    base = urlparse(get_settings().base_url)
    is_https = base.scheme == "https"
    port = base.port or (443 if is_https else 80)

    return {
        "https": "on" if is_https else "off",
        "http_host": base.hostname or "localhost",
        "server_port": str(port),
        "script_name": urlparse(url).path,
        "get_data": query_params,
        "post_data": form_data,
        "query_string": urlparse(url).query,
    }


def _auth(
    connection: IdpConnection,
    request_data: dict[str, Any],
    *,
    security_overrides: dict[str, Any] | None = None,
) -> OneLogin_Saml2_Auth:
    settings_dict = build_saml_settings(connection)
    if security_overrides:
        # Per-attempt only: the saved connection is untouched, which is what
        # lets the dashboard ask for a stronger authentication context once
        # without committing to it.
        settings_dict["security"].update(security_overrides)
    try:
        return OneLogin_Saml2_Auth(request_data, settings_dict)
    except Exception as exc:
        raise SamlError(
            f"SAML settings for '{connection.name}' are not usable: {exc}",
            detail={"reason": str(exc)},
        ) from exc


def build_login_url(
    connection: IdpConnection,
    request_data: dict[str, Any],
    *,
    force_authn: bool | None = None,
    authn_context: str = "",
) -> tuple[str, str]:
    """Return (redirect_url, request_id).

    request_id must be stored and presented back at the ACS endpoint so that
    InResponseTo can be validated.

    `authn_context` overrides the saved RequestedAuthnContext for this one
    attempt — that is how the dashboard asks for a certificate or multi-factor
    context without editing the connection.
    """
    settings = load_settings(connection)
    assert isinstance(settings, SamlSettings)

    if not settings.idp_sso_url:
        raise SamlError("This connection has no IdP sign-on URL configured.")
    if not settings.idp_x509_cert:
        raise SamlError(
            "This connection has no IdP signing certificate. Without it, no "
            "assertion can be verified."
        )

    overrides: dict[str, Any] = {}
    if authn_context:
        overrides["requestedAuthnContext"] = [
            value.strip() for value in authn_context.split(",") if value.strip()
        ]

    auth = _auth(connection, request_data, security_overrides=overrides)
    url = auth.login(
        force_authn=settings.force_authn if force_authn is None else force_authn,
        set_nameid_policy=bool(settings.name_id_format),
    )
    return url, auth.get_last_request_id()


def process_response(
    connection: IdpConnection, request_data: dict[str, Any], *, request_id: str | None
) -> dict[str, Any]:
    """Validate a SAML Response and return the asserted attributes.

    Raises SamlError carrying the underlying reason — when you are testing an
    access policy, the specific validation failure is the result you came for.
    """
    settings = load_settings(connection)
    assert isinstance(settings, SamlSettings)

    auth = _auth(connection, request_data)
    try:
        auth.process_response(request_id=request_id if not settings.allow_unsolicited else None)
    except Exception as exc:
        raise SamlError(
            f"Could not parse the SAML response: {exc}", detail={"reason": str(exc)}
        ) from exc

    errors = auth.get_errors()
    if errors:
        raise SamlError(
            "SAML response rejected: " + ", ".join(errors),
            detail={
                "errors": errors,
                "reason": auth.get_last_error_reason() or "",
            },
        )

    if not auth.is_authenticated():
        raise SamlError(
            "SAML response parsed but did not authenticate the user.",
            detail={"reason": auth.get_last_error_reason() or ""},
        )

    # Flatten single-valued attributes so role mapping and templates do not
    # have to special-case "list of one", which is how SAML expresses scalars.
    attributes: dict[str, Any] = {}
    for name, values in (auth.get_attributes() or {}).items():
        attributes[name] = values[0] if isinstance(values, list) and len(values) == 1 else values

    claims: dict[str, Any] = dict(attributes)
    claims["nameId"] = auth.get_nameid()
    claims["nameIdFormat"] = auth.get_nameid_format()
    if auth.get_session_index():
        claims["sessionIndex"] = auth.get_session_index()
    # Which authentication method the IdP actually performed — the SAML
    # equivalent of the OIDC "amr" claim, and the thing an MFA policy changes.
    contexts = auth.get_last_authn_contexts() or []
    if contexts:
        claims["authnContextClassRef"] = contexts[0] if len(contexts) == 1 else contexts

    return claims


def build_metadata(connection: IdpConnection) -> str:
    """SP metadata XML.

    Most IdP consoles can import this and fill in entity ID, ACS URL, and
    NameID format automatically, which removes the most error-prone part of
    SAML setup.
    """
    settings_dict = build_saml_settings(connection)
    try:
        saml_settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    except Exception as exc:
        # python3-saml raises its own error type for an unusable SP block — most
        # often because BASE_URL is not a URL it will accept, which makes the ACS
        # and SLS URLs invalid. Converted here so the caller renders a page
        # naming the cause instead of a 500 that names nothing.
        raise SamlError(
            f"SP settings are not usable: {exc}. Check that BASE_URL is the "
            f"externally visible URL of this app; it is currently "
            f"'{get_settings().base_url}'.",
            detail={"reason": str(exc), "acs_url": acs_url(connection.slug)},
        ) from exc

    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise SamlError("Generated SP metadata is invalid: " + ", ".join(errors))
    return metadata.decode("utf-8") if isinstance(metadata, bytes) else metadata


def certificate_diagnostics(connection: IdpConnection) -> dict[str, Any]:
    """Describe the certificates on a SAML connection.

    An expired IdP signing certificate is one of the most common causes of a
    sign-in that worked yesterday and does not today, and the error a provider
    returns for it rarely says so. Showing the dates next to the field turns a
    half-hour of confusion into a glance.
    """
    settings = load_settings(connection)
    assert isinstance(settings, SamlSettings)
    diagnostics: dict[str, Any] = {}
    if settings.idp_x509_cert:
        diagnostics["idp_signing_certificate"] = certs.describe_pem(settings.idp_x509_cert)
    if settings.sp_x509_cert:
        diagnostics["sp_certificate"] = certs.describe_pem(settings.sp_x509_cert)
    return diagnostics


def logout_request_nameid(request_data: dict[str, Any]) -> str:
    """NameID out of an inbound LogoutRequest, or "" if it cannot be read.

    Used to end the right user's sessions on IdP-initiated logout. Best effort:
    the request has already been validated by process_logout at this point, so
    failing to read the NameID costs us a nicety, not a security property.
    """
    encoded = request_data.get("get_data", {}).get("SAMLRequest") or request_data.get(
        "post_data", {}
    ).get("SAMLRequest")
    if not encoded:
        return ""
    try:
        return OneLogin_Saml2_Logout_Request.get_nameid(encoded) or ""
    except Exception:  # noqa: BLE001 — any parse failure just means "unknown"
        return ""


def process_logout(
    connection: IdpConnection, request_data: dict[str, Any], *, request_id: str | None = None
) -> str:
    """Handle a message at the SLS endpoint.

    Two different messages arrive here and both have to work:

      * a LogoutResponse, closing out a sign-out this app started. Returns "".
      * a LogoutRequest, because the user signed out at the provider and it is
        telling every service provider to do the same. Returns the URL to
        redirect to, carrying our LogoutResponse.

    Advertising an SLS endpoint in SP metadata and then not implementing it
    leaves the user on a 404 at the end of a federated sign-out, which looks
    exactly like a broken logout.
    """
    auth = _auth(connection, request_data)
    try:
        url = auth.process_slo(keep_local_session=True, request_id=request_id)
    except Exception as exc:
        raise SamlError(
            f"Could not process the SAML logout message: {exc}", detail={"reason": str(exc)}
        ) from exc

    errors = auth.get_errors()
    if errors:
        raise SamlError(
            "SAML logout message rejected: " + ", ".join(errors),
            detail={"errors": errors, "reason": auth.get_last_error_reason() or ""},
        )
    return url or ""


def build_logout_url(
    connection: IdpConnection,
    request_data: dict[str, Any],
    *,
    name_id: str = "",
    session_index: str = "",
) -> str:
    settings = load_settings(connection)
    assert isinstance(settings, SamlSettings)
    if not settings.idp_slo_url:
        return ""
    auth = _auth(connection, request_data)
    return auth.logout(
        name_id=name_id or None,
        session_index=session_index or None,
        return_to=get_settings().base_url.rstrip("/") + "/",
    )
