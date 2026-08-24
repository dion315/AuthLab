"""Setup guides and the per-field terminology hints.

The point of both is that somebody configuring a provider should not have to
translate between two vocabularies in their head. Which means the content has to
be internally consistent — a hint that named a field the walkthrough two clicks
away contradicted would be worse than no hint — so most of these assert the
shape of the data rather than the prose.
"""

from __future__ import annotations

import pytest

from app import providers
from app.auth import connections as conn
from app.models import IdpConnection

ALL_PROTOCOLS = ("oidc", "saml", "scim")

# Field names the connection form renders a hint slot for. A term keyed on
# anything else would render nowhere.
FORM_FIELDS = {
    "issuer", "client_id", "client_secret", "scopes",
    "idp_entity_id", "idp_sso_url", "idp_slo_url", "idp_x509_cert",
    "sp_entity_id", "name_id_format",
    "role_claim", "subject_claim", "email_claim",
    # Rendered on the guides rather than the form, but still legitimate keys.
    "redirect_uri", "acs_url", "scim_tenant_url", "scim_token",
}


# --- the data itself ------------------------------------------------------------


def test_every_requested_provider_is_present():
    assert set(providers.PROVIDERS) == {"entra", "okta", "auth0", "cognito", "duo", "generic"}


@pytest.mark.parametrize("provider_key", sorted(providers.PROVIDERS))
def test_every_provider_covers_every_protocol(provider_key):
    """Silence is not an answer. Either there is a guide or there is a reason."""
    provider = providers.PROVIDERS[provider_key]
    for protocol in ALL_PROTOCOLS:
        guide = provider.guide(protocol)
        assert guide is not None, f"{provider_key} says nothing about {protocol}"
        if not guide.supported:
            assert guide.unsupported_reason, (
                f"{provider_key}/{protocol} is unsupported without saying why"
            )


@pytest.mark.parametrize("provider_key", sorted(providers.PROVIDERS))
def test_supported_guides_have_steps(provider_key):
    provider = providers.PROVIDERS[provider_key]
    for protocol in ALL_PROTOCOLS:
        guide = provider.guide(protocol)
        if guide and guide.supported:
            assert guide.steps, f"{provider_key}/{protocol} claims support but has no steps"


def test_unsupported_guides_carry_no_steps():
    """An unsupported protocol must not also ship instructions for itself."""
    for provider in providers.PROVIDERS.values():
        for guide in provider.guides.values():
            if not guide.supported:
                assert not guide.steps
                assert not guide.terms


@pytest.mark.parametrize(
    ("provider_key", "protocol"),
    [
        ("auth0", "scim"),
        ("cognito", "saml"),
        ("cognito", "scim"),
        ("duo", "scim"),
    ],
)
def test_the_known_gaps_are_recorded_as_gaps(provider_key, protocol):
    """These four are the ones people waste an afternoon looking for."""
    guide = providers.PROVIDERS[provider_key].guide(protocol)
    assert guide is not None and guide.supported is False


def test_term_keys_match_form_field_names():
    """A hint keyed on a name the form does not use would render nowhere."""
    unknown = {
        (provider.key, term.key)
        for provider in providers.PROVIDERS.values()
        for guide in provider.guides.values()
        for term in guide.terms
        if term.key not in FORM_FIELDS
    }
    assert not unknown, f"terms keyed on unknown fields: {sorted(unknown)}"


def test_step_placeholders_are_all_resolvable():
    """A step promising a value we cannot substitute would render a literal brace."""
    known = {p.strip("{}") for p in providers.PLACEHOLDERS}
    unknown = {
        (provider.key, guide.protocol, step.paste)
        for provider in providers.PROVIDERS.values()
        for guide in provider.guides.values()
        for step in guide.steps
        if step.paste and step.paste not in known
    }
    assert not unknown, f"unresolvable paste keys: {sorted(unknown)}"


def test_resolve_substitutes_every_placeholder():
    urls = {name.strip("{}"): f"https://x/{name.strip('{}')}" for name in providers.PLACEHOLDERS}
    text = " ".join(providers.PLACEHOLDERS)
    resolved = providers.resolve(text, urls)
    assert "{" not in resolved


def test_resolve_leaves_unknown_placeholders_readable():
    """Without a connection the guides still have to make sense."""
    assert providers.resolve("go to {acs_url}", {}) == "go to {acs_url}"


# --- the vocabulary lookup ------------------------------------------------------


def test_vocabulary_is_field_major_for_the_form():
    vocab = providers.vocabulary("oidc")
    assert "issuer" in vocab
    assert "entra" in vocab["issuer"]
    assert vocab["issuer"]["entra"]["provider"] == "Microsoft Entra ID"
    assert vocab["issuer"]["entra"]["name"]


def test_vocabulary_translates_the_field_people_ask_about():
    """"Issuer" here is "Directory (tenant) ID" there — the canonical example."""
    entry = providers.vocabulary("oidc")["issuer"]["entra"]
    assert "tenant" in entry["name"].lower()


def test_vocabulary_excludes_unsupported_providers():
    """Cognito cannot be a SAML IdP, so it must not offer SAML wording."""
    saml = providers.vocabulary("saml")
    for field_terms in saml.values():
        assert "cognito" not in field_terms


def test_vocabulary_covers_the_core_saml_fields():
    saml = providers.vocabulary("saml")
    for field_name in ("idp_entity_id", "idp_sso_url", "idp_x509_cert"):
        assert "entra" in saml[field_name]
        assert "okta" in saml[field_name]


def test_capability_matrix_shape():
    matrix = providers.capability_matrix()
    assert len(matrix) == len(providers.PROVIDERS)
    entra = next(row for row in matrix if row["key"] == "entra")
    assert all(entra["protocols"][p]["supported"] for p in ALL_PROTOCOLS)
    cognito = next(row for row in matrix if row["key"] == "cognito")
    assert cognito["protocols"]["oidc"]["supported"] is True
    assert cognito["protocols"]["saml"]["supported"] is False
    assert cognito["protocols"]["saml"]["reason"]


# --- the pages ------------------------------------------------------------------


def test_help_index_renders(admin_client):
    response = admin_client.get("/help")
    assert response.status_code == 200
    for name in ("Microsoft Entra ID", "Okta", "Auth0", "AWS Cognito", "Duo"):
        assert name in response.text


def test_help_requires_a_session(client):
    response = client.get("/help", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("provider_key", sorted(providers.PROVIDERS))
@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_every_guide_page_renders(admin_client, provider_key, protocol):
    response = admin_client.get(f"/help/{provider_key}?protocol={protocol}")
    assert response.status_code == 200, response.text[:400]


def test_an_unknown_provider_redirects_to_the_index(admin_client):
    response = admin_client.get("/help/nonesuch", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/help"


def test_a_guide_defaults_to_a_protocol_the_provider_supports(admin_client):
    """Landing on an 'unavailable' explanation by default would be a poor welcome.

    Cognito supports only OIDC, so a bare /help/cognito must open the OIDC
    guide rather than the first protocol in the list.
    """
    response = admin_client.get("/help/cognito")
    assert response.status_code == 200
    # The steps of the OIDC guide, not the refusal body for SAML.
    assert "Hosted UI domain" in response.text
    assert providers.PROVIDERS["cognito"].guides["saml"].unsupported_reason not in response.text


def test_an_unsupported_protocol_explains_itself(admin_client):
    response = admin_client.get("/help/cognito?protocol=saml")
    assert response.status_code == 200
    assert "service provider" in response.text
    assert "Use OIDC / OAuth 2.0 instead" in response.text


def test_guides_show_patterns_without_a_connection(admin_client):
    response = admin_client.get("/help/entra?protocol=saml")
    assert "/auth/saml/%7Bslug%7D/acs" in response.text or "/auth/saml/{slug}/acs" in response.text


def test_guides_substitute_real_urls_for_a_connection(admin_client, db):
    connection = IdpConnection(slug="contoso", name="Contoso", protocol="saml", config={})
    conn.store_settings(connection, {"idp_sso_url": "https://idp.example/sso"})
    db.add(connection)
    db.commit()

    response = admin_client.get("/help/entra?protocol=saml&slug=contoso")
    assert response.status_code == 200
    assert "http://testserver/auth/saml/contoso/acs" in response.text
    assert "http://testserver/auth/saml/contoso/sls" in response.text


def test_scim_guides_offer_the_tenant_url(admin_client):
    response = admin_client.get("/help/okta?protocol=scim")
    assert "http://testserver/scim/v2" in response.text


# --- the connection form --------------------------------------------------------


def test_the_form_offers_a_provider_picker(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=oidc")
    assert response.status_code == 200
    assert 'name="provider"' in response.text
    assert "Microsoft Entra ID" in response.text


def test_the_form_renders_hints_for_every_provider(admin_client):
    """All of them are rendered up front; the browser reveals one set."""
    response = admin_client.get("/admin/connections/new?protocol=oidc")
    assert 'data-vocab-for="entra"' in response.text
    assert 'data-vocab-for="okta"' in response.text
    assert "calls this:" in response.text


def test_saml_form_renders_saml_vocabulary(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=saml")
    assert "Microsoft Entra Identifier" in response.text
    assert "Identity Provider Issuer" in response.text  # Okta's name for it


def test_arriving_from_a_guide_preselects_the_provider(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=oidc&provider=okta")
    assert 'value="okta" selected' in response.text


def test_an_unknown_provider_in_the_query_is_ignored(admin_client):
    response = admin_client.get("/admin/connections/new?protocol=oidc&provider=nonesuch")
    assert response.status_code == 200
    assert "selected" not in response.text.split('name="provider"')[1].split("</select>")[0]


def test_the_provider_choice_is_saved_and_shown_again(admin_client, db):
    admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "Contoso Entra",
            "slug": "contoso-entra",
            "provider": "entra",
            "issuer": "https://login.microsoftonline.com/tid/v2.0",
            "default_role": "user",
        },
        follow_redirects=False,
    )
    created = conn.get_by_slug(db, "contoso-entra")
    assert created is not None
    assert created.provider == "entra"

    response = admin_client.get(f"/admin/connections/{created.id}")
    assert 'value="entra" selected' in response.text


def test_an_unknown_provider_is_stored_as_empty(admin_client, db):
    """Advisory data must never be able to break saving a connection."""
    admin_client.post(
        "/admin/connections",
        data={
            "protocol": "oidc",
            "name": "Odd",
            "slug": "odd",
            "provider": "not-a-real-provider",
            "issuer": "https://idp.example/",
            "default_role": "user",
        },
        follow_redirects=False,
    )
    created = conn.get_by_slug(db, "odd")
    assert created is not None
    assert created.provider == ""


def test_the_provider_choice_is_not_exported():
    """It is a UI aid, not connection configuration."""
    assert "provider" not in conn._PORTABLE_COLUMNS
