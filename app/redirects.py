"""Safe handling of caller-supplied return paths.

The step-up flow needs to send someone to the IdP and bring them back to the
page they were trying to reach, which means carrying a target across a redirect
the user controls. That is exactly the shape of an open redirect, and an open
redirect on a *sign-in* endpoint is worth more to an attacker than most, because
the link genuinely comes from your domain and genuinely completes a login.

So the rule here is deliberately strict: a return target is a path on this app
or it is discarded. Not "a URL whose host matches" — a path. Anything with a
scheme, an authority, or a backslash is rejected outright rather than parsed and
normalised, because every open-redirect bug of the last decade lives in the gap
between one parser's idea of a URL and another's.
"""

from __future__ import annotations

DEFAULT_TARGET = "/dashboard"


def safe_path(candidate: str | None, *, default: str = DEFAULT_TARGET) -> str:
    """Return `candidate` if it is a local path on this app, else `default`.

    Accepts "/dashboard", "/step-up?x=1". Rejects "https://evil.example",
    "//evil.example", "/\\evil.example", "javascript:...", and anything that
    does not begin with a single forward slash.
    """
    if not candidate:
        return default

    value = candidate.strip()
    if not value.startswith("/"):
        # Includes every absolute URL and every scheme-relative trick.
        return default
    if value.startswith("//"):
        # Protocol-relative: "//evil.example" is a different origin.
        return default
    if "\\" in value:
        # Browsers have historically normalised backslashes to slashes, which
        # turns "/\evil.example" into a protocol-relative URL after we have
        # already approved it.
        return default
    if "\n" in value or "\r" in value:
        # Header injection into Location.
        return default
    return value
