"""Encrypted ID tokens — the JWE half of OIDC.

An ID token is normally a JWS: signed, readable by anyone who intercepts it.
Some deployments require it to arrive as a JWE instead — signed, then encrypted
to a key only the client holds — so that claims like group membership or a
directory object id are not exposed to anything sitting between the provider
and the application.

For that to work the provider needs a public key from us, which means the app
has to publish a JWKS. That is the piece people find surprising: the *client*
serves a key set, at `/auth/oidc/{slug}/jwks.json`, and registers that URL at
the provider.

A caution worth reading before enabling it: support for encrypted ID tokens is
uneven. Okta and Ping offer it, Entra ID does not for OIDC, and several
providers accept the configuration and then quietly send an unencrypted token
anyway. Because of that last case the app *accepts* a plain signed token even
when encryption is configured, and reports which one it actually received —
telling you the provider ignored the request is more useful than failing with a
parse error.
"""

from __future__ import annotations

import json
from typing import Any

from authlib.jose import JsonWebEncryption, JsonWebKey

# RSA-OAEP with AES-256-GCM: the pairing every implementation supports, and the
# one a provider is most likely to offer in its dropdown.
KEY_ALGORITHM = "RSA-OAEP"
CONTENT_ENCRYPTION = "A256GCM"
KEY_SIZE = 2048


class TokenCryptoError(Exception):
    """The token could not be decrypted, and the operator needs to know why."""


def generate_key() -> str:
    """A new RSA private key, serialised as a JWK JSON string for storage."""
    key = JsonWebKey.generate_key("RSA", KEY_SIZE, is_private=True)
    data = key.as_dict(is_private=True)
    # A stable kid lets a provider cache the key set and lets you tell two
    # generations apart if you ever rotate.
    data.setdefault("kid", key.thumbprint())
    return json.dumps(data)


def load_key(serialised: str) -> Any:
    if not serialised:
        raise TokenCryptoError("No decryption key is configured for this connection.")
    try:
        return JsonWebKey.import_key(json.loads(serialised))
    except (ValueError, TypeError, KeyError) as exc:
        raise TokenCryptoError(f"The stored decryption key could not be read: {exc}") from exc


def public_jwks(serialised: str) -> dict[str, Any]:
    """The key set to publish, in the shape a provider expects to fetch.

    `use` and `alg` are included because some providers will not select a key
    without them, and silently fall back to sending an unencrypted token.
    """
    key = load_key(serialised)
    public = dict(key.as_dict(is_private=False))
    public.setdefault("kid", key.thumbprint())
    public["use"] = "enc"
    public["alg"] = KEY_ALGORITHM
    return {"keys": [public]}


def looks_encrypted(token: str) -> bool:
    """A JWE has five dot-separated parts; a JWS has three."""
    return token.count(".") == 4


def decrypt_id_token(token: str, serialised_key: str) -> tuple[str, dict[str, Any]]:
    """Unwrap a JWE-wrapped ID token.

    Returns (inner_token, report). The inner value is the signed JWS that
    normal validation then runs against — decryption proves who the token was
    *for*, never who issued it, so the signature check still has to happen
    afterwards and is not skipped here.
    """
    key = load_key(serialised_key)
    jwe = JsonWebEncryption()

    try:
        decrypted = jwe.deserialize_compact(token.encode("ascii"), key)
    except Exception as exc:  # noqa: BLE001 — every failure mode is a result to report
        raise TokenCryptoError(
            f"The ID token is encrypted but could not be decrypted: {exc}. "
            "The provider is probably encrypting to a different key than the one "
            "published at this connection's jwks.json."
        ) from exc

    header = dict(decrypted.get("header") or {})
    inner = decrypted.get("payload", b"").decode("utf-8")

    return inner, {
        "encrypted": True,
        "alg": header.get("alg", ""),
        "enc": header.get("enc", ""),
        "kid": header.get("kid", ""),
    }


def unwrap(token: str, settings: Any) -> tuple[str, dict[str, Any]]:
    """Decrypt if it arrived encrypted; pass it through if it did not.

    The report says which happened, so "I configured encryption and the
    provider ignored it" is visible rather than invisible.
    """
    if not looks_encrypted(token):
        return token, {
            "encrypted": False,
            "expected_encrypted": bool(getattr(settings, "accept_encrypted_id_token", False)),
        }

    if not getattr(settings, "accept_encrypted_id_token", False):
        raise TokenCryptoError(
            "The provider sent an encrypted ID token, but encryption is not "
            "enabled on this connection so there is no key to decrypt it with. "
            "Turn on 'Accept encrypted ID tokens' and register this connection's "
            "jwks.json at the provider."
        )

    inner, report = decrypt_id_token(token, settings.jwe_private_key)
    report["expected_encrypted"] = True
    return inner, report
