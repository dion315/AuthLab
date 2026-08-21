"""SCIM is independent of OIDC and SAML.

Worth asserting rather than assuming, because it is a natural thing to get
wrong: SCIM looks like part of an SSO integration and is configured next to one
in every provider's console, so people reasonably ask whether it is "SAML SCIM"
or "OIDC SCIM". It is neither. SSO answers "who is signing in right now"; SCIM
answers "which accounts should exist". They share no machinery here — the
provisioning endpoints authenticate on their own bearer token and have no
reference to a connection at all.

These cover the four shapes anyone might deploy: SCIM with an OIDC connection,
with a SAML connection, with several of each at once, and with no connection
configured whatsoever.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.auth import connections as conn
from app.models import IdpConnection, ScimGroup, ScimUser, UserSession
from app.security import _serializer

# The Entra ID SAML claim carrying the immutable directory object id.
OBJECTID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"


def make_connection(slug: str, protocol: str, **kwargs) -> IdpConnection:
    defaults = dict(
        slug=slug,
        name=slug.replace("-", " ").title(),
        protocol=protocol,
        enabled=True,
        role_claim="groups",
        role_source="scim",
        default_role="user",
        role_rules=[{"operator": "equals", "value": "SEC-Admins", "role": "admin"}],
        subject_claim="sub" if protocol == "oidc" else "nameId",
        config={},
    )
    defaults.update(kwargs)
    return IdpConnection(**defaults)


def provision(db, user_name: str, *groups: str, external_id: str | None = None) -> ScimUser:
    user = ScimUser(user_name=user_name, email=user_name, external_id=external_id)
    for name in groups:
        group = db.execute(
            select(ScimGroup).where(ScimGroup.display_name == name)
        ).scalar_one_or_none()
        if group is None:
            group = ScimGroup(display_name=name)
            db.add(group)
        user.groups.append(group)
    db.add(user)
    db.commit()
    return user


def sign_in(db, *, source: str, protocol: str, subject: str, email: str, claims: dict):
    now = datetime.now(UTC)
    row = UserSession(
        subject=subject,
        email=email,
        display_name=email or subject,
        role="user",
        source=source,
        protocol=protocol,
        raw_claims=claims,
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    return row


def adopt(client, row: UserSession) -> None:
    client.cookies.set("authlab_session", _serializer().dumps(row.id))


# --- the provisioning endpoints stand alone ------------------------------------


def test_scim_works_with_no_connections_configured_at_all(client, db, scim_headers):
    """Provisioning must not require an SSO connection to exist first.

    The realistic order of work is to stand up provisioning, watch the payloads
    arrive, and configure sign-in afterwards — or never, if provisioning is all
    you are testing.
    """
    assert conn.list_all(db) == []

    created = client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "standalone@contoso.com",
        },
        headers=scim_headers,
    )
    assert created.status_code == 201

    listed = client.get("/scim/v2/Users", headers=scim_headers)
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1


def test_service_provider_config_needs_no_connection(client, db, scim_headers):
    assert conn.list_all(db) == []
    response = client.get("/scim/v2/ServiceProviderConfig", headers=scim_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/scim+json")


def test_a_scim_token_is_not_bound_to_a_connection(client, db, scim_headers):
    """Deleting every connection must not break provisioning."""
    db.add(make_connection("entra", "oidc"))
    db.add(make_connection("okta-saml", "saml"))
    db.commit()

    assert client.get("/scim/v2/Users", headers=scim_headers).status_code == 200

    for connection in conn.list_all(db):
        db.delete(connection)
    db.commit()

    assert client.get("/scim/v2/Users", headers=scim_headers).status_code == 200


def test_the_scim_tenant_url_comes_from_base_url_not_a_connection(db):
    assert conn.scim_base_url() == "http://testserver/scim/v2"
    db.add(make_connection("entra", "oidc"))
    db.commit()
    assert conn.scim_base_url() == "http://testserver/scim/v2"


# --- provisioned groups grant roles on either protocol -------------------------


@pytest.mark.parametrize("protocol", ["oidc", "saml"])
def test_scim_groups_grant_a_role_on_either_protocol(admin_client, db, protocol):
    """The end-to-end case: provision into a group, sign in, gain the role."""
    connection = make_connection(f"idp-{protocol}", protocol)
    db.add(connection)
    db.commit()

    provision(db, "alice@contoso.com", "SEC-Admins")

    subject_claim = "sub" if protocol == "oidc" else "nameId"
    row = sign_in(
        db,
        source=f"idp-{protocol}",
        protocol=protocol,
        subject="alice@contoso.com",
        email="alice@contoso.com",
        claims={subject_claim: "alice@contoso.com"},
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert 'matched on "SEC-Admins"' in response.text
    # The session was stored as `user`; the SCIM group promotes it to `admin`.
    assert "would assign" in response.text
    assert "Provisioned identity" in response.text


@pytest.mark.parametrize("protocol", ["oidc", "saml"])
def test_a_provisioned_user_in_no_group_gets_the_default_role(admin_client, db, protocol):
    connection = make_connection(f"idp-{protocol}", protocol)
    db.add(connection)
    db.commit()

    provision(db, "bob@contoso.com")

    row = sign_in(
        db,
        source=f"idp-{protocol}",
        protocol=protocol,
        subject="bob@contoso.com",
        email="bob@contoso.com",
        claims={},
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "in no groups, so no SCIM rule can match" in response.text


# --- several connections at once ------------------------------------------------


def test_several_connections_of_each_protocol_share_one_scim_store(
    admin_client, db, scim_headers
):
    """Two tenants and two protocols, one directory of provisioned users."""
    for slug, protocol in (
        ("contoso-oidc", "oidc"),
        ("fabrikam-oidc", "oidc"),
        ("contoso-saml", "saml"),
        ("fabrikam-saml", "saml"),
    ):
        db.add(make_connection(slug, protocol))
    db.commit()

    assert len(conn.list_enabled(db)) == 4

    provision(db, "carol@contoso.com", "SEC-Admins")

    # The same provisioned user resolves through every connection.
    for slug, protocol in (
        ("contoso-oidc", "oidc"),
        ("fabrikam-oidc", "oidc"),
        ("contoso-saml", "saml"),
        ("fabrikam-saml", "saml"),
    ):
        row = sign_in(
            db,
            source=slug,
            protocol=protocol,
            subject="carol@contoso.com",
            email="carol@contoso.com",
            claims={},
        )
        adopt(admin_client, row)
        response = admin_client.get("/dashboard")
        assert response.status_code == 200, slug
        assert 'matched on "SEC-Admins"' in response.text, slug


def test_the_login_page_offers_every_enabled_connection(client, db):
    for slug, protocol in (("entra", "oidc"), ("okta", "saml"), ("duo", "saml")):
        db.add(make_connection(slug, protocol))
    db.commit()

    response = client.get("/login")
    assert response.status_code == 200
    for slug in ("entra", "okta", "duo"):
        assert f"/auth/{'oidc' if slug == 'entra' else 'saml'}/{slug}/login" in response.text


def test_separate_scim_tokens_are_attributed_separately(client, db):
    """One token per provisioning source, so the log says which system called."""
    from app.models import ScimClient
    from app.security import generate_token, hash_token

    tokens = {}
    for name in ("entra-provisioning", "okta-provisioning"):
        token = generate_token()
        db.add(ScimClient(name=name, token_hash=hash_token(token), token_hint=token[:6]))
        tokens[name] = token
    db.commit()

    for name, token in tokens.items():
        response = client.get(
            "/scim/v2/Users", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, name

    from app.models import ScimClient as SC

    used = db.execute(select(SC).where(SC.last_used_at.isnot(None))).scalars().all()
    assert {client_row.name for client_row in used} == set(tokens)


# --- Entra: an unstable NameID, and the fix ------------------------------------


def test_a_upn_keyed_saml_session_breaks_when_the_upn_changes(admin_client, db):
    """Why NameID stability matters: rename the user, lose the link.

    Entra's default SAML NameID is the UPN, which changes when someone is
    renamed or a domain is rebranded. The provisioned record follows the change;
    a session keyed on the old value does not.
    """
    connection = make_connection("entra-saml", "saml", subject_claim="nameId")
    db.add(connection)
    db.commit()

    provision(db, "alice.new@contoso.com", "SEC-Admins", external_id="obj-guid-1234")

    # The session was established before the rename, under the old UPN.
    row = sign_in(
        db,
        source="entra-saml",
        protocol="saml",
        subject="alice.old@contoso.com",
        email="alice.old@contoso.com",
        claims={"nameId": "alice.old@contoso.com"},
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert "No provisioned user matches this session" in response.text


def test_an_objectid_keyed_saml_session_survives_a_upn_change(admin_client, db):
    """The fix: key on the immutable object id at both ends.

    Point `subject_claim` at Entra's objectidentifier claim and map SCIM
    `externalId` to the same objectId. The identifiers then match on a value
    that never changes, and a rename is invisible to the app.
    """
    connection = make_connection("entra-saml", "saml", subject_claim=OBJECTID_CLAIM)
    db.add(connection)
    db.commit()

    provision(db, "alice.new@contoso.com", "SEC-Admins", external_id="obj-guid-1234")

    row = sign_in(
        db,
        source="entra-saml",
        protocol="saml",
        # Renamed since the account was provisioned; the object id has not moved.
        subject="obj-guid-1234",
        email="alice.old@contoso.com",
        claims={OBJECTID_CLAIM: "obj-guid-1234", "nameId": "alice.old@contoso.com"},
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert response.status_code == 200
    assert 'matched on "SEC-Admins"' in response.text


def test_an_oid_keyed_oidc_session_matches_external_id(admin_client, db):
    """The OIDC equivalent: `oid` is immutable where `sub` is pairwise."""
    connection = make_connection("entra-oidc", "oidc", subject_claim="oid")
    db.add(connection)
    db.commit()

    provision(db, "alice@contoso.com", "SEC-Admins", external_id="obj-guid-5678")

    row = sign_in(
        db,
        source="entra-oidc",
        protocol="oidc",
        subject="obj-guid-5678",
        email="alice@contoso.com",
        claims={"oid": "obj-guid-5678", "sub": "pairwise-and-useless-for-matching"},
    )
    adopt(admin_client, row)

    response = admin_client.get("/dashboard")
    assert 'matched on "SEC-Admins"' in response.text


# --- deprovisioning reaches both protocols --------------------------------------


@pytest.mark.parametrize("protocol", ["oidc", "saml"])
def test_deactivation_revokes_sessions_on_either_protocol(
    admin_client, db, scim_headers, protocol
):
    db.add(make_connection(f"idp-{protocol}", protocol))
    db.commit()

    created = admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "dave@contoso.com",
            "externalId": "obj-guid-9999",
        },
        headers=scim_headers,
    )
    assert created.status_code == 201

    row = sign_in(
        db,
        source=f"idp-{protocol}",
        protocol=protocol,
        # A pairwise subject that matches nothing SCIM knows — the email and
        # externalId are what make this work.
        subject="pairwise-subject-value",
        email="dave@contoso.com",
        claims={},
    )

    response = admin_client.patch(
        f"/scim/v2/Users/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        },
        headers=scim_headers,
    )
    assert response.status_code == 200

    db.refresh(row)
    assert row.revoked_at is not None


def test_deactivation_matches_on_external_id_alone(admin_client, db, scim_headers):
    """The objectid-keyed configuration must still be revocable."""
    db.add(make_connection("entra-saml", "saml", subject_claim=OBJECTID_CLAIM))
    db.commit()

    created = admin_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "erin@contoso.com",
            "externalId": "obj-guid-4321",
        },
        headers=scim_headers,
    )
    user_id = created.json()["id"]

    row = sign_in(
        db,
        source="entra-saml",
        protocol="saml",
        subject="obj-guid-4321",
        email="",
        claims={},
    )

    admin_client.patch(
        f"/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=scim_headers,
    )

    db.refresh(row)
    assert row.revoked_at is not None
