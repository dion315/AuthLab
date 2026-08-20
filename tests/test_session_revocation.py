"""Session revocation matching.

The regression these cover: revocation used to match only `UserSession.subject`
against SCIM's `userName`. For a federated session `subject` is whatever
`subject_claim` produced, which defaults to `sub` — and Entra ID's `sub` is a
pairwise pseudonymous identifier that is never equal to a UPN. Deprovisioning a
real federated user therefore revoked nothing and logged "revoked 0 session(s)"
without complaint.

The original test passed because it used the *local* admin session, where
subject happens to equal the email. These use identifiers that differ, which is
the case that was broken.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models import UserSession
from app.security import revoke_sessions_for_user

FEDERATED_SUB = "AAAAAAAAAAAAAAAAAAAAAHTHJ2fJ3vFmQxYQ1Wt9pQk"
UPN = "alice@contoso.com"


def _session(db, *, subject: str, email: str, revoked: bool = False) -> UserSession:
    now = datetime.now(UTC)
    record = UserSession(
        subject=subject,
        email=email,
        display_name=email,
        role="user",
        source="entra",
        protocol="oidc",
        raw_claims={"sub": subject},
        created_at=now,
        expires_at=now + timedelta(hours=1),
        revoked_at=now if revoked else None,
    )
    db.add(record)
    db.commit()
    return record


def test_revokes_a_federated_session_by_email(db):
    """The exact case that used to silently do nothing."""
    record = _session(db, subject=FEDERATED_SUB, email=UPN)

    revoked = revoke_sessions_for_user(db, UPN)

    assert revoked == 1
    db.refresh(record)
    assert record.revoked_at is not None


def test_subject_alone_no_longer_has_to_match(db):
    record = _session(db, subject=FEDERATED_SUB, email=UPN)
    assert revoke_sessions_for_user(db, FEDERATED_SUB) == 1
    db.refresh(record)
    assert record.revoked_at is not None


def test_matching_is_case_insensitive(db):
    """Providers are inconsistent about the casing they assert."""
    record = _session(db, subject=FEDERATED_SUB, email="Alice@Contoso.com")
    assert revoke_sessions_for_user(db, "alice@CONTOSO.com") == 1
    db.refresh(record)
    assert record.revoked_at is not None


def test_several_identifiers_are_tried(db):
    record = _session(db, subject=FEDERATED_SUB, email=UPN)
    # externalId first, then userName — only the second matches.
    assert revoke_sessions_for_user(db, "5f3e-object-id", UPN) == 1
    db.refresh(record)
    assert record.revoked_at is not None


def test_unrelated_sessions_are_untouched(db):
    keep = _session(db, subject="other-sub", email="bob@contoso.com")
    _session(db, subject=FEDERATED_SUB, email=UPN)

    assert revoke_sessions_for_user(db, UPN) == 1

    db.refresh(keep)
    assert keep.revoked_at is None


def test_already_revoked_sessions_are_not_counted_twice(db):
    _session(db, subject=FEDERATED_SUB, email=UPN, revoked=True)
    assert revoke_sessions_for_user(db, UPN) == 0


def test_blank_identifiers_revoke_nothing(db):
    """A user with no email must not become a wildcard that ends every session."""
    _session(db, subject=FEDERATED_SUB, email="")
    _session(db, subject="another", email="")

    assert revoke_sessions_for_user(db, "", None, "   ") == 0
    assert (
        db.execute(
            select(UserSession).where(UserSession.revoked_at.is_(None))
        ).scalars().all()
    )


# --- through the SCIM endpoints ----------------------------------------------


def test_scim_deactivation_revokes_a_federated_session(admin_client, db, scim_headers):
    """End to end: provision a user, sign them in federated, deactivate."""
    record = _session(db, subject=FEDERATED_SUB, email=UPN)

    created = admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": UPN,
            "emails": [{"value": UPN, "primary": True}],
        },
        headers=scim_headers,
    )
    assert created.status_code == 201

    response = admin_client.patch(
        f"/scim/v2/Users/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        },
        headers=scim_headers,
    )
    assert response.status_code == 200

    db.refresh(record)
    assert record.revoked_at is not None, (
        "Deactivating a provisioned user must end the federated session whose "
        "subject is a pairwise identifier, not just one keyed on the UPN."
    )


def test_scim_delete_revokes_a_federated_session(admin_client, db, scim_headers):
    record = _session(db, subject=FEDERATED_SUB, email=UPN)

    created = admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": UPN,
            "emails": [{"value": UPN, "primary": True}],
        },
        headers=scim_headers,
    )
    user_id = created.json()["id"]

    assert admin_client.delete(f"/scim/v2/Users/{user_id}", headers=scim_headers).status_code == 204

    db.refresh(record)
    assert record.revoked_at is not None
