"""Decoding the time claims on a token, and comparing them to our own session.

The thing that surprises people testing revocation is that there are two clocks
and they are unrelated. The IdP issued a token with its own lifetime; this app
issued a session with `SESSION_TTL_MINUTES`. Whichever is longer is how long
access really lasts, and if the app's session outlives the token then "the
token expired" does not mean the user lost access.

Reading that off a raw claim dump means converting Unix timestamps in your head.
This does it instead, and puts the app's own session expiry next to them so the
comparison is visible rather than inferred.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Time-bearing claims, in the order they make sense to read.
TIME_CLAIMS: dict[str, str] = {
    "auth_time": (
        "When the user actually authenticated. A policy requiring recent "
        "authentication compares against this, not iat."
    ),
    "iat": "When this token was issued.",
    "nbf": "Not valid before. Usually equal to iat.",
    "exp": "When the token stops being accepted by the provider.",
    "xms_st": "Session start (Entra), when present.",
}


def _as_datetime(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _relative(moment: datetime, now: datetime) -> str:
    seconds = int((moment - now).total_seconds())
    past = seconds < 0
    seconds = abs(seconds)

    if seconds < 90:
        text = f"{seconds}s"
    elif seconds < 5400:
        text = f"{seconds // 60}m"
    elif seconds < 172800:
        text = f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    else:
        text = f"{seconds // 86400}d"

    return f"{text} ago" if past else f"in {text}"


def describe(claims: dict[str, Any], session: Any = None) -> list[dict[str, Any]]:
    """Rows for the dashboard: each time claim, decoded, plus our session.

    `session` is a UserSession; passing None omits the app-side rows, which is
    what the local account wants — there is no token to compare against.
    """
    now = datetime.now(UTC)
    rows: list[dict[str, Any]] = []

    for name, description in TIME_CLAIMS.items():
        if name not in claims:
            continue
        moment = _as_datetime(claims[name])
        if moment is None:
            continue
        rows.append(
            {
                "name": name,
                "source": "token",
                "utc": moment.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "relative": _relative(moment, now),
                "description": description,
                "expired": name == "exp" and moment < now,
            }
        )

    if session is not None:
        for name, moment, description in (
            (
                "session created",
                _normalise(session.created_at),
                "When this app issued its own session, independent of the token.",
            ),
            (
                "session expires",
                _normalise(session.expires_at),
                "When this app stops accepting the session. Set by "
                "SESSION_TTL_MINUTES, not by the provider.",
            ),
        ):
            if moment is None:
                continue
            rows.append(
                {
                    "name": name,
                    "source": "app",
                    "utc": moment.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "relative": _relative(moment, now),
                    "description": description,
                    "expired": name == "session expires" and moment < now,
                }
            )

    return rows


def _normalise(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; the comparison below needs tz-aware."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def outlives_token(claims: dict[str, Any], session: Any) -> bool:
    """True when the app session is still valid after the token expires.

    That is the configuration where "revoke the token" does not revoke access,
    which is the point worth making on screen.
    """
    token_expiry = _as_datetime(claims.get("exp"))
    session_expiry = _normalise(getattr(session, "expires_at", None))
    if token_expiry is None or session_expiry is None:
        return False
    return session_expiry > token_expiry
