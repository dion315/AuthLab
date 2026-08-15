"""SCIM user provisioning, written against the request shapes real connectors send."""

from __future__ import annotations

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def make_user(client, headers, user_name="alice@contoso.com", **overrides):
    payload = {
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "name": {"givenName": "Alice", "familyName": "Adams"},
        "emails": [{"value": user_name, "primary": True}],
        "active": True,
    }
    payload.update(overrides)
    response = client.post("/scim/v2/Users", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


# --- authentication ----------------------------------------------------------


def test_requires_bearer_token(client):
    response = client.get("/scim/v2/Users")
    assert response.status_code == 401
    assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_rejects_wrong_token(client):
    response = client.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401


def test_discovery_endpoints_are_unauthenticated(client):
    # Some connectors fetch these before credentials are configured.
    for path in ("/ServiceProviderConfig", "/ResourceTypes", "/Schemas"):
        response = client.get(f"/scim/v2{path}")
        assert response.status_code == 200, path


def test_responses_use_scim_media_type(client):
    response = client.get("/scim/v2/ServiceProviderConfig")
    assert response.headers["content-type"].startswith("application/scim+json")


# --- create / read -----------------------------------------------------------


def test_create_user_accepts_scim_json_content_type(client, scim_headers):
    # Entra ID sends application/scim+json rather than application/json.
    assert scim_headers["Content-Type"] == "application/scim+json"
    user = make_user(client, scim_headers)
    assert user["userName"] == "alice@contoso.com"
    assert user["active"] is True
    assert user["meta"]["resourceType"] == "User"


def test_create_sets_location_header(client, scim_headers):
    response = client.post(
        "/scim/v2/Users",
        json={"schemas": [USER_SCHEMA], "userName": "bob@contoso.com"},
        headers=scim_headers,
    )
    assert response.status_code == 201
    assert response.headers["location"].endswith(f"/Users/{response.json()['id']}")


def test_duplicate_user_returns_409(client, scim_headers):
    make_user(client, scim_headers)
    response = client.post(
        "/scim/v2/Users",
        json={"schemas": [USER_SCHEMA], "userName": "alice@contoso.com"},
        headers=scim_headers,
    )
    assert response.status_code == 409
    assert response.json()["scimType"] == "uniqueness"


def test_missing_username_is_a_400_not_a_500(client, scim_headers):
    response = client.post(
        "/scim/v2/Users", json={"schemas": [USER_SCHEMA]}, headers=scim_headers
    )
    assert response.status_code == 400


def test_get_unknown_user_returns_404(client, scim_headers):
    response = client.get("/scim/v2/Users/does-not-exist", headers=scim_headers)
    assert response.status_code == 404


# --- the deactivation bug ----------------------------------------------------
#
# Entra ID sends `active` as the *string* "False" in the deactivation PATCH.
# Treating that as truthy leaves deprovisioned users enabled, which is the most
# consequential bug a hand-rolled SCIM server can have.


def test_patch_deactivates_with_string_false(client, scim_headers):
    user = make_user(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        },
        headers=scim_headers,
    )
    assert response.status_code == 200
    assert response.json()["active"] is False


def test_patch_deactivates_with_boolean_false(client, scim_headers):
    user = make_user(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=scim_headers,
    )
    assert response.json()["active"] is False


def test_patch_deactivates_with_pathless_value_object(client, scim_headers):
    """The other shape Entra sends: no path, value is an attribute object."""
    user = make_user(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "Replace", "value": {"active": False}}],
        },
        headers=scim_headers,
    )
    assert response.json()["active"] is False


def test_patch_reactivates_with_string_true(client, scim_headers):
    user = make_user(client, scim_headers, active=False)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": "True"}],
        },
        headers=scim_headers,
    )
    assert response.json()["active"] is True


def test_patch_updates_nested_name_path(client, scim_headers):
    """Okta sends dotted paths like name.givenName."""
    user = make_user(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "name.givenName", "value": "Alicia"}],
        },
        headers=scim_headers,
    )
    assert response.json()["name"]["givenName"] == "Alicia"


def test_patch_handles_multivalue_email_path(client, scim_headers):
    """Some connectors send emails[type eq "work"].value."""
    user = make_user(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": 'emails[type eq "work"].value', "value": "new@contoso.com"}
            ],
        },
        headers=scim_headers,
    )
    assert response.json()["emails"][0]["value"] == "new@contoso.com"


# --- replace / delete --------------------------------------------------------


def test_put_replaces_user(client, scim_headers):
    user = make_user(client, scim_headers)
    response = client.put(
        f"/scim/v2/Users/{user['id']}",
        json={
            "schemas": [USER_SCHEMA],
            "userName": "alice@contoso.com",
            "displayName": "Alice A.",
            "active": False,
        },
        headers=scim_headers,
    )
    assert response.status_code == 200
    assert response.json()["displayName"] == "Alice A."
    assert response.json()["active"] is False


def test_delete_user(client, scim_headers):
    user = make_user(client, scim_headers)
    assert client.delete(f"/scim/v2/Users/{user['id']}", headers=scim_headers).status_code == 204
    assert client.get(f"/scim/v2/Users/{user['id']}", headers=scim_headers).status_code == 404


# --- listing, filtering, pagination -----------------------------------------


def test_filter_by_username(client, scim_headers):
    make_user(client, scim_headers, "alice@contoso.com")
    make_user(client, scim_headers, "bob@contoso.com")
    response = client.get(
        '/scim/v2/Users?filter=userName eq "alice@contoso.com"', headers=scim_headers
    )
    body = response.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "alice@contoso.com"


def test_filter_is_case_insensitive_on_value(client, scim_headers):
    make_user(client, scim_headers, "alice@contoso.com")
    response = client.get(
        '/scim/v2/Users?filter=userName eq "ALICE@CONTOSO.COM"', headers=scim_headers
    )
    assert response.json()["totalResults"] == 1


def test_compound_filter(client, scim_headers):
    make_user(client, scim_headers, "alice@contoso.com")
    make_user(client, scim_headers, "bob@contoso.com", active=False)
    response = client.get(
        '/scim/v2/Users?filter=userName sw "bob" and active eq false', headers=scim_headers
    )
    assert response.json()["totalResults"] == 1


def test_unsupported_filter_returns_400_not_wrong_results(client, scim_headers):
    make_user(client, scim_headers)
    response = client.get(
        '/scim/v2/Users?filter=emails[type eq "work"].value eq "x"', headers=scim_headers
    )
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidFilter"


def test_unknown_filter_attribute_is_rejected(client, scim_headers):
    response = client.get('/scim/v2/Users?filter=nickname eq "x"', headers=scim_headers)
    assert response.status_code == 400


def test_pagination(client, scim_headers):
    for index in range(5):
        make_user(client, scim_headers, f"user{index}@contoso.com")
    response = client.get("/scim/v2/Users?startIndex=2&count=2", headers=scim_headers)
    body = response.json()
    assert body["totalResults"] == 5
    assert body["itemsPerPage"] == 2
    assert body["startIndex"] == 2
