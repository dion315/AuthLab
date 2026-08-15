"""SCIM group provisioning and membership PATCH shapes."""

from __future__ import annotations

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def make_user(client, headers, user_name):
    response = client.post(
        "/scim/v2/Users",
        json={"schemas": [USER_SCHEMA], "userName": user_name},
        headers=headers,
    )
    assert response.status_code == 201
    return response.json()


def make_group(client, headers, display_name="SEC-Admins", members=None):
    response = client.post(
        "/scim/v2/Groups",
        json={
            "schemas": [GROUP_SCHEMA],
            "displayName": display_name,
            "members": members or [],
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_group(client, scim_headers):
    group = make_group(client, scim_headers)
    assert group["displayName"] == "SEC-Admins"
    assert group["meta"]["resourceType"] == "Group"


def test_create_group_with_members(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers, members=[{"value": user["id"]}])
    assert [m["value"] for m in group["members"]] == [user["id"]]


def test_duplicate_group_returns_409(client, scim_headers):
    make_group(client, scim_headers)
    response = client.post(
        "/scim/v2/Groups",
        json={"schemas": [GROUP_SCHEMA], "displayName": "SEC-Admins"},
        headers=scim_headers,
    )
    assert response.status_code == 409


def test_patch_add_members(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}],
        },
        headers=scim_headers,
    )
    assert [m["value"] for m in response.json()["members"]] == [user["id"]]


def test_patch_add_is_idempotent(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers, members=[{"value": user["id"]}])
    response = client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}],
        },
        headers=scim_headers,
    )
    assert len(response.json()["members"]) == 1


def test_patch_remove_member_by_value_list(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers, members=[{"value": user["id"]}])
    response = client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": "members", "value": [{"value": user["id"]}]}],
        },
        headers=scim_headers,
    )
    assert response.json()["members"] == []


def test_patch_remove_member_by_path_filter(client, scim_headers):
    """Entra removes members with members[value eq "<id>"] and no value body."""
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers, members=[{"value": user["id"]}])
    response = client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{user["id"]}"]'}],
        },
        headers=scim_headers,
    )
    assert response.json()["members"] == []


def test_patch_rename_group(client, scim_headers):
    group = make_group(client, scim_headers)
    response = client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "displayName", "value": "SEC-Admins-Renamed"}],
        },
        headers=scim_headers,
    )
    assert response.json()["displayName"] == "SEC-Admins-Renamed"


def test_group_membership_appears_on_user(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    make_group(client, scim_headers, members=[{"value": user["id"]}])
    response = client.get(f"/scim/v2/Users/{user['id']}", headers=scim_headers)
    assert [g["display"] for g in response.json()["groups"]] == ["SEC-Admins"]


def test_filter_groups_by_display_name(client, scim_headers):
    make_group(client, scim_headers, "SEC-Admins")
    make_group(client, scim_headers, "SEC-Users")
    response = client.get(
        '/scim/v2/Groups?filter=displayName eq "SEC-Users"', headers=scim_headers
    )
    assert response.json()["totalResults"] == 1


def test_delete_group_leaves_users_intact(client, scim_headers):
    user = make_user(client, scim_headers, "alice@contoso.com")
    group = make_group(client, scim_headers, members=[{"value": user["id"]}])
    assert client.delete(f"/scim/v2/Groups/{group['id']}", headers=scim_headers).status_code == 204
    assert client.get(f"/scim/v2/Users/{user['id']}", headers=scim_headers).status_code == 200
