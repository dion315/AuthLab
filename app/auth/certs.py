"""X.509 handling: parsing, inspection, chain validation, and test issuance.

Certificates turn up in four different places in this app and every one of them
is a place people get stuck, so the work is done once here:

  * a SAML IdP signing certificate, pasted from a provider console
  * an SP keypair, for signed AuthnRequests or encrypted assertions
  * a client credential (certificate + key) used to authenticate *this app* to
    an OIDC token endpoint with private_key_jwt
  * a client certificate presented by a *user* over mutual TLS

Two deliberate choices:

**Every check is reported, not just the verdict.** `validate_chain` returns the
list of checks it ran with a pass/fail and a reason for each, because "the
certificate was rejected" is not a useful answer when you are trying to work
out why a smart card sign-in fails.

**Chain building is explicit rather than delegated.** `cryptography`'s
`PolicyBuilder` verifier exists, but it is all-or-nothing and its availability
moves between releases. Walking the chain here costs about forty lines and
makes each step inspectable. It is deliberately not a general-purpose PKI
validator: there is no name-constraint or certificate-policy processing, and
revocation is checked only against a CRL you supply. That is the right scope
for a harness, and the UI says so rather than implying more.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_PEM_HEADER = "-----BEGIN CERTIFICATE-----"
CERT_PEM_FOOTER = "-----END CERTIFICATE-----"

# Microsoft's otherName OID for a User Principal Name. This is what a smart
# card or Entra certificate-based authentication credential actually carries,
# and it is the field almost every CBA username-binding rule reads.
UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)

_EKU_NAMES = {
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"): "smartcardLogon",
}


class CertificateError(Exception):
    """A certificate could not be read or did not pass a check."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


# --- normalisation -----------------------------------------------------------


def normalise_pem(value: str) -> str:
    """Turn any of the shapes a certificate arrives in into canonical PEM.

    Providers and proxies mangle certificates in predictable ways: a console
    exports bare base64 with no header, Envoy percent-encodes the PEM into a
    header, nginx does the same and also replaces newlines with tabs, and
    copy-paste through a JSON field turns newlines into a literal ``\\n``. All
    of those are accepted here so nobody has to work out which one they have.
    """
    text = (value or "").strip()
    if not text:
        return ""

    text = _unescape(text)
    # nginx's $ssl_client_escaped_cert unescapes to a tab-separated PEM.
    text = text.replace("\\n", "\n").replace("\t", "\n").replace("\r\n", "\n")

    blocks = _PEM_BLOCK_RE.findall(text)
    if blocks:
        return "\n\n".join(_rewrap(block) for block in blocks)

    body = "".join(text.split())
    if not body:
        return ""
    return _wrap_base64(body)


def _unescape(text: str) -> str:
    """Percent-decode, if that is what this is.

    The test is for the complete unencoded PEM header rather than a prefix of
    it: nginx and AWS leave the dashes alone and encode only the spaces and
    newlines, so a value can contain a literal `-----BEGIN` and still be
    percent-encoded. Checking for the prefix alone silently skips decoding
    exactly the values the common proxies send.
    """
    if "%" in text and CERT_PEM_HEADER not in text:
        return unquote(text)
    return text


def _rewrap(block: str) -> str:
    body = "".join(
        line.strip()
        for line in block.splitlines()
        if line.strip() and "-----" not in line
    )
    return _wrap_base64(body)


def _wrap_base64(body: str) -> str:
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "\n".join([CERT_PEM_HEADER, *lines, CERT_PEM_FOOTER])


def decode_der_or_pem(value: str) -> bytes:
    """Raw DER bytes from PEM text, base64 DER, or percent-encoded PEM."""
    pem = normalise_pem(value)
    if not pem:
        raise CertificateError("No certificate data was supplied.")
    body = "".join(
        line for line in pem.splitlines() if line and "-----" not in line
    )
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertificateError(f"Certificate data is not valid base64: {exc}") from exc


# --- loading -----------------------------------------------------------------


def load_certificate(value: str) -> x509.Certificate:
    pem = normalise_pem(value)
    if not pem:
        raise CertificateError("No certificate was supplied.")
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise CertificateError(f"Could not parse the certificate: {exc}") from exc


def load_certificates(value: str) -> list[x509.Certificate]:
    """Every certificate in a bundle. Used for CA bundles and chains."""
    text = (value or "").strip()
    if not text:
        return []
    text = _unescape(text).replace("\\n", "\n").replace("\t", "\n")

    blocks = _PEM_BLOCK_RE.findall(text)
    if not blocks:
        return [load_certificate(text)]

    certificates: list[x509.Certificate] = []
    for index, block in enumerate(blocks, start=1):
        try:
            certificates.append(load_certificate(block))
        except CertificateError as exc:
            raise CertificateError(
                f"Certificate {index} in the bundle could not be parsed: {exc.message}"
            ) from exc
    return certificates


def load_private_key(value: str, password: str | None = None):
    """Load a PEM private key. PKCS#1, PKCS#8, and encrypted PKCS#8 all work."""
    text = (value or "").strip().replace("\\n", "\n")
    if not text:
        raise CertificateError("No private key was supplied.")
    try:
        return serialization.load_pem_private_key(
            text.encode("utf-8"),
            password=password.encode("utf-8") if password else None,
        )
    except (ValueError, TypeError) as exc:
        raise CertificateError(
            "Could not read the private key. It must be PEM-encoded "
            f"(PKCS#1 or PKCS#8): {exc}"
        ) from exc


# --- inspection --------------------------------------------------------------


def thumbprint(certificate: x509.Certificate, algorithm: str = "sha256") -> str:
    digest = hashes.SHA1() if algorithm == "sha1" else hashes.SHA256()  # noqa: S303
    return certificate.fingerprint(digest).hex().upper()


def x5t_s256(certificate: x509.Certificate) -> str:
    """base64url SHA-256 thumbprint, for the `x5t#S256` JWT header."""
    return (
        base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256()))
        .decode("ascii")
        .rstrip("=")
    )


def _name_component(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def _decode_other_name(other: x509.OtherName) -> str:
    """Best-effort text out of an otherName value.

    The value is a DER-encoded string — UTF8String for a UPN. Decoding the tag
    and length by hand avoids pulling in an ASN.1 library for two bytes.
    """
    raw = other.value
    if len(raw) >= 2 and raw[0] in (0x0C, 0x16, 0x13, 0x1E):
        length = raw[1]
        if length & 0x80:  # long form length
            count = length & 0x7F
            offset = 2 + count
        else:
            offset = 2
        try:
            return raw[offset:].decode("utf-8", errors="replace")
        except UnicodeDecodeError:  # pragma: no cover — errors="replace" covers it
            return raw[offset:].hex()
    return raw.decode("utf-8", errors="replace")


def subject_alt_names(certificate: x509.Certificate) -> dict[str, list[str]]:
    names: dict[str, list[str]] = {"dns": [], "email": [], "upn": [], "uri": [], "ip": [], "other": []}
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return names

    for entry in extension.value:
        if isinstance(entry, x509.DNSName):
            names["dns"].append(entry.value)
        elif isinstance(entry, x509.RFC822Name):
            names["email"].append(entry.value)
        elif isinstance(entry, x509.UniformResourceIdentifier):
            names["uri"].append(entry.value)
        elif isinstance(entry, x509.IPAddress):
            names["ip"].append(str(entry.value))
        elif isinstance(entry, x509.OtherName):
            text = _decode_other_name(entry)
            if entry.type_id == UPN_OID:
                names["upn"].append(text)
            else:
                names["other"].append(f"{entry.type_id.dotted_string}={text}")
    return names


def extended_key_usages(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return []
    return [_EKU_NAMES.get(oid, oid.dotted_string) for oid in extension.value]


def key_usages(certificate: x509.Certificate) -> list[str]:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    flags = {
        "digitalSignature": usage.digital_signature,
        "contentCommitment": usage.content_commitment,
        "keyEncipherment": usage.key_encipherment,
        "dataEncipherment": usage.data_encipherment,
        "keyAgreement": usage.key_agreement,
        "keyCertSign": usage.key_cert_sign,
        "cRLSign": usage.crl_sign,
    }
    return [name for name, present in flags.items() if present]


def _public_key_description(certificate: x509.Certificate) -> str:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return key.__class__.__name__


def _signature_algorithm(certificate: x509.Certificate) -> str:
    """Human-readable signature algorithm.

    `signature_algorithm_oid._name` is what everyone reaches for and it is a
    private attribute; the dotted string is the stable fallback so a change in
    `cryptography` degrades the label rather than breaking every page that
    shows a certificate.
    """
    oid = certificate.signature_algorithm_oid
    return getattr(oid, "_name", None) or oid.dotted_string


def is_certificate_authority(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)


def describe(certificate: x509.Certificate, *, now: datetime | None = None) -> dict[str, Any]:
    """Everything worth showing about a certificate, as plain data.

    Templates render this directly, so nothing here is an object with methods —
    it survives being put in a session, an event record, or a JSON dump.
    """
    now = now or datetime.now(UTC)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    sans = subject_alt_names(certificate)

    return {
        "subject": certificate.subject.rfc4514_string(),
        "subject_cn": _name_component(certificate.subject, NameOID.COMMON_NAME),
        "subject_o": _name_component(certificate.subject, NameOID.ORGANIZATION_NAME),
        "subject_ou": _name_component(certificate.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "subject_email": _name_component(certificate.subject, NameOID.EMAIL_ADDRESS),
        "issuer": certificate.issuer.rfc4514_string(),
        "issuer_cn": _name_component(certificate.issuer, NameOID.COMMON_NAME),
        "serial_number": format(certificate.serial_number, "X"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "self_signed": certificate.subject == certificate.issuer,
        "is_ca": is_certificate_authority(certificate),
        "public_key": _public_key_description(certificate),
        "signature_algorithm": _signature_algorithm(certificate),
        "key_usage": key_usages(certificate),
        "extended_key_usage": extended_key_usages(certificate),
        "san_dns": sans["dns"],
        "san_email": sans["email"],
        "san_upn": sans["upn"],
        "san_uri": sans["uri"],
        "san_ip": sans["ip"],
        "san_other": sans["other"],
        "thumbprint_sha1": thumbprint(certificate, "sha1"),
        "thumbprint_sha256": thumbprint(certificate, "sha256"),
        "x5t_s256": x5t_s256(certificate),
    }


def describe_pem(value: str, *, now: datetime | None = None) -> dict[str, Any]:
    """`describe` for a pasted certificate, returning the error instead of raising.

    Used wherever a certificate is displayed next to a form field: a bad paste
    should annotate the field, not blow up the page.
    """
    try:
        return {"ok": True, **describe(load_certificate(value), now=now)}
    except CertificateError as exc:
        return {"ok": False, "error": exc.message}


# --- revocation --------------------------------------------------------------


def load_crls(value: str) -> list[x509.CertificateRevocationList]:
    text = (value or "").strip()
    if not text:
        return []
    blocks = re.findall(r"-----BEGIN X509 CRL-----.*?-----END X509 CRL-----", text, re.DOTALL)
    if not blocks:
        blocks = [text]
    crls = []
    for block in blocks:
        try:
            crls.append(x509.load_pem_x509_crl(block.encode("ascii")))
        except (ValueError, TypeError) as exc:
            raise CertificateError(f"Could not parse the CRL: {exc}") from exc
    return crls


def revocation_entry(
    certificate: x509.Certificate, crls: list[x509.CertificateRevocationList]
) -> x509.RevokedCertificate | None:
    for crl in crls:
        revoked = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
        if revoked is not None:
            return revoked
    return None


# --- chain validation --------------------------------------------------------


@dataclass
class Check:
    """One validation step, with enough context to act on a failure."""

    name: str
    passed: bool
    detail: str = ""


@dataclass
class ChainResult:
    valid: bool
    checks: list[Check] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)
    anchor: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "anchor": self.anchor,
            "chain": self.chain,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks
            ],
        }

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]


def validate_chain(
    leaf: x509.Certificate,
    trust_anchors: list[x509.Certificate],
    *,
    intermediates: list[x509.Certificate] | None = None,
    crls: list[x509.CertificateRevocationList] | None = None,
    require_client_auth_eku: bool = True,
    check_validity: bool = True,
    now: datetime | None = None,
    max_depth: int = 8,
) -> ChainResult:
    """Verify a client certificate against a set of trust anchors.

    Returns every check that ran rather than a bare boolean — when a smart card
    sign-in is refused, which check failed *is* the answer.
    """
    now = now or datetime.now(UTC)
    intermediates = list(intermediates or [])
    checks: list[Check] = []
    chain_names = [leaf.subject.rfc4514_string()]

    if check_validity:
        checks.append(
            Check(
                "Validity period",
                leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc,
                f"valid {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} to "
                f"{leaf.not_valid_after_utc:%Y-%m-%d %H:%M} UTC",
            )
        )

    if require_client_auth_eku:
        usages = extended_key_usages(leaf)
        checks.append(
            Check(
                "Extended key usage",
                (not usages) or "clientAuth" in usages,
                ", ".join(usages) or "no EKU extension (unconstrained)",
            )
        )

    if crls:
        revoked = revocation_entry(leaf, crls)
        checks.append(
            Check(
                "Revocation (CRL)",
                revoked is None,
                "not listed on the supplied CRL"
                if revoked is None
                else f"revoked at {revoked.revocation_date_utc:%Y-%m-%d %H:%M} UTC",
            )
        )

    anchor_subjects = {anchor.subject.rfc4514_string() for anchor in trust_anchors}
    anchor_used = ""

    if not trust_anchors:
        checks.append(Check("Chain to a trusted CA", False, "no trust anchors are configured"))
        return ChainResult(valid=False, checks=checks, chain=chain_names)

    current = leaf
    depth = 0
    pool = intermediates + trust_anchors

    while depth < max_depth:
        if current.subject.rfc4514_string() in anchor_subjects and depth > 0:
            anchor_used = current.subject.rfc4514_string()
            break

        issuer = _find_issuer(current, pool)
        if issuer is None:
            checks.append(
                Check(
                    "Chain to a trusted CA",
                    False,
                    f"no certificate in the trust store issued '{current.subject.rfc4514_string()}' "
                    f"(issuer is '{current.issuer.rfc4514_string()}')",
                )
            )
            return ChainResult(valid=False, checks=checks, chain=chain_names)

        if check_validity and not (issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc):
            checks.append(
                Check(
                    "CA validity period",
                    False,
                    f"'{issuer.subject.rfc4514_string()}' expired "
                    f"{issuer.not_valid_after_utc:%Y-%m-%d}",
                )
            )
            return ChainResult(valid=False, checks=checks, chain=chain_names)

        if not is_certificate_authority(issuer):
            checks.append(
                Check(
                    "Issuer is a CA",
                    False,
                    f"'{issuer.subject.rfc4514_string()}' has no basicConstraints CA:TRUE",
                )
            )
            return ChainResult(valid=False, checks=checks, chain=chain_names)

        chain_names.append(issuer.subject.rfc4514_string())
        if issuer.subject.rfc4514_string() in anchor_subjects:
            anchor_used = issuer.subject.rfc4514_string()
            break

        current = issuer
        depth += 1
    else:
        checks.append(Check("Chain to a trusted CA", False, f"chain longer than {max_depth}"))
        return ChainResult(valid=False, checks=checks, chain=chain_names)

    checks.append(
        Check("Chain to a trusted CA", True, f"anchored at '{anchor_used}' ({len(chain_names)} certificates)")
    )
    return ChainResult(
        valid=all(check.passed for check in checks),
        checks=checks,
        chain=chain_names,
        anchor=anchor_used,
    )


def _find_issuer(
    certificate: x509.Certificate, candidates: list[x509.Certificate]
) -> x509.Certificate | None:
    """The certificate that actually signed this one.

    Name matching alone is not enough — two CAs can share a subject across a
    key rollover — so the signature is verified before a candidate is accepted.
    """
    for candidate in candidates:
        if candidate.subject != certificate.issuer:
            continue
        if candidate.fingerprint(hashes.SHA256()) == certificate.fingerprint(hashes.SHA256()):
            continue  # self-signed leaf; not its own issuer for chain purposes
        try:
            certificate.verify_directly_issued_by(candidate)
        except (ValueError, TypeError):
            continue
        return candidate
    return None


# --- test issuance -----------------------------------------------------------
#
# The app can mint its own certificates. That is not a general-purpose CA — it
# exists so that testing certificate-based authentication does not first
# require standing up a PKI, and so the app can hand a browser a PKCS#12 to
# import. Everything it issues is clearly labelled as test material.


def _rsa_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_key_pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def generate_ca(common_name: str = "AuthLab Test CA", *, days: int = 1825) -> tuple[str, str]:
    """Create a self-signed CA. Returns (certificate_pem, private_key_pem)."""
    key = _rsa_key(3072)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AuthLab"),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate_pem(certificate), private_key_pem(key)


def issue_client_certificate(
    *,
    ca_cert_pem: str,
    ca_key_pem: str,
    common_name: str,
    upn: str = "",
    email: str = "",
    days: int = 365,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[str, str]:
    """Issue a client-auth certificate from a CA. Returns (cert_pem, key_pem).

    `not_before`/`not_after` are overridable so an already-expired or
    not-yet-valid certificate can be issued on purpose — testing that the
    validity check actually rejects one is the point of having the check.
    """
    ca_certificate = load_certificate(ca_cert_pem)
    ca_key = load_private_key(ca_key_pem)
    key = _rsa_key()
    now = datetime.now(UTC)

    sans: list[x509.GeneralName] = []
    if upn:
        sans.append(
            x509.OtherName(UPN_OID, b"\x0c" + bytes([len(upn.encode("utf-8"))]) + upn.encode("utf-8"))
        )
    if email:
        sans.append(x509.RFC822Name(email))

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - timedelta(minutes=5)))
        .not_valid_after(not_after or (now + timedelta(days=days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    certificate = builder.sign(ca_key, hashes.SHA256())
    return certificate_pem(certificate), private_key_pem(key)


def generate_self_signed(
    common_name: str, *, days: int = 730, client_auth: bool = False
) -> tuple[str, str]:
    """A self-signed keypair for SAML SP signing or an OIDC client credential.

    Both of those upload the public certificate to the provider, which then
    trusts it directly — there is no chain to build, so self-signed is the
    normal and correct shape.
    """
    key = _rsa_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    return certificate_pem(builder.sign(key, hashes.SHA256())), private_key_pem(key)


def to_pkcs12(
    *, cert_pem: str, key_pem: str, ca_pem: str = "", friendly_name: str = "authlab", password: str
) -> bytes:
    """Bundle a certificate and key as PKCS#12 for import into a browser.

    A password is required, not optional: some operating systems refuse to
    import an unprotected .p12 at all, and a file that silently fails to import
    is worse than one that asks for a password.
    """
    extra = [load_certificate(ca_pem)] if ca_pem else None
    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8"),
        key=load_private_key(key_pem),
        cert=load_certificate(cert_pem),
        cas=extra,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def sha256_fingerprint_of_pem(value: str) -> str:
    """Fingerprint without a full parse — for comparing two pasted blobs."""
    return hashlib.sha256(decode_der_or_pem(value)).hexdigest().upper()
