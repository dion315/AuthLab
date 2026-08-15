"""Encryption for IdP secrets held in the database.

Moving IdP configuration out of environment variables and into a runtime-
editable admin UI means client secrets now sit in a database row. Storing them
in plaintext there would be strictly worse than the environment variables we
replaced, so they are encrypted with a key derived from APP_SECRET_KEY.

This protects against database-at-rest exposure (a leaked backup, a snapshot,
a curious operator with read access to the table). It does NOT protect against
someone who already has both the database and the app's environment — that is
the same trust boundary the process itself runs inside, and no amount of
application-level crypto changes it.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings

# Domain separation: the same APP_SECRET_KEY also signs session cookies, and a
# key should never be reused across two purposes.
_HKDF_INFO = b"authlab.secret-storage.v1"

_PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    settings = get_settings()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(settings.app_secret_key.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt a secret for storage. Empty/None passes through unchanged."""
    if not plaintext:
        return plaintext
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt(stored: str | None) -> str | None:
    """Decrypt a stored secret.

    Values without the version prefix are returned as-is so that a database
    written before encryption was enabled still loads. Values that carry the
    prefix but fail to decrypt return None rather than raising — that happens
    when APP_SECRET_KEY was rotated, and the right response is to prompt for
    re-entry in the admin UI, not to crash every request that touches config.
    """
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        return stored
    try:
        return _fernet().decrypt(stored[len(_PREFIX) :].encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None


def is_encrypted(stored: str | None) -> bool:
    return bool(stored) and stored.startswith(_PREFIX)
