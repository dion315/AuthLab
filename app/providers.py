"""What each identity provider calls the things this app asks for.

Every console names the same handful of values differently, and the gap between
"Issuer" here and "Directory (tenant) ID" over there is where most of the time
in a first integration actually goes. Nothing is conceptually hard; you are
translating.

This module is the single source for that translation, and it feeds two places:

  * the connection form, which shows the provider's own wording beside each
    field once you say which provider you are using;
  * the in-app guides at /help, which are the same steps in order.

Keeping both off one structure is the point. A terminology hint that disagreed
with the walkthrough two clicks away would be worse than having neither.

Console navigation drifts, so the wording here describes **what the value is
called** rather than a click path that will be wrong in six months. Where a
provider simply cannot do something — Cognito is not a SAML identity provider,
Auth0 does not push SCIM — that is recorded as plainly as the things it can.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- structure ----------------------------------------------------------------

# Placeholders a step body may contain. They are substituted with the real URLs
# for a connection when one is in context, and left as readable patterns when
# not, so the guides are useful before anything has been created.
PLACEHOLDERS = (
    "{redirect_uri}",
    "{acs_url}",
    "{sls_url}",
    "{metadata_url}",
    "{sp_entity_id}",
    "{scim_tenant_url}",
    "{login_url}",
    "{base_url}",
)


@dataclass(frozen=True)
class Term:
    """One of our field names, in the provider's vocabulary."""

    # Matches the form input name, so the template can look it up directly.
    key: str
    their_name: str
    where: str = ""
    note: str = ""


@dataclass(frozen=True)
class Step:
    title: str
    body: str
    # A value of ours to copy in this step, if any. Rendered as a copy box.
    paste: str = ""


@dataclass(frozen=True)
class Guide:
    protocol: str
    supported: bool = True
    # Why not, when supported is False. This is the useful half for Cognito,
    # Auth0, and Duo, where people otherwise hunt for a menu that is not there.
    unsupported_reason: str = ""
    summary: str = ""
    steps: tuple[Step, ...] = ()
    terms: tuple[Term, ...] = ()
    gotchas: tuple[str, ...] = ()


@dataclass(frozen=True)
class Provider:
    key: str
    name: str
    blurb: str = ""
    guides: dict[str, Guide] = field(default_factory=dict)

    def guide(self, protocol: str) -> Guide | None:
        return self.guides.get(protocol)

    def supports(self, protocol: str) -> bool:
        guide = self.guides.get(protocol)
        return bool(guide and guide.supported)


# --- Microsoft Entra ID --------------------------------------------------------

ENTRA = Provider(
    key="entra",
    name="Microsoft Entra ID",
    blurb="Formerly Azure AD. Does all three protocols; SCIM needs Entra ID P1 or above.",
    guides={
        "oidc": Guide(
            protocol="oidc",
            summary="An App registration provides the client; the issuer is built from your tenant id.",
            terms=(
                Term(
                    key="issuer",
                    their_name="Built from the Directory (tenant) ID",
                    where="App registration → Overview",
                    note="https://login.microsoftonline.com/<tenant-id>/v2.0 — the v2.0 suffix matters.",
                ),
                Term(
                    key="client_id",
                    their_name="Application (client) ID",
                    where="App registration → Overview",
                ),
                Term(
                    key="client_secret",
                    their_name="Client secret → Value",
                    where="App registration → Certificates & secrets",
                    note="Copy the Value column, not Secret ID. It is shown only once.",
                ),
                Term(
                    key="scopes",
                    their_name="Delegated permissions",
                    where="App registration → API permissions",
                    note="openid, profile, and email are enough for sign-in.",
                ),
                Term(
                    key="role_claim",
                    their_name="App roles, or the groups claim",
                    where="App registration → App roles / Token configuration",
                    note="'roles' carries app roles as readable values; 'groups' carries object GUIDs.",
                ),
                Term(
                    key="subject_claim",
                    their_name="oid — the immutable object id",
                    note=(
                        "Prefer oid over sub. Entra's sub is pairwise per application and matches nothing "
                        "else."
                    ),
                ),
                Term(
                    key="email_claim",
                    their_name="email, or preferred_username",
                    where="App registration → Token configuration → optional claims",
                ),
            ),
            steps=(
                Step(
                    title="Create an App registration",
                    body=(
                        "In Entra ID, register a new application. A single-tenant account type is fine for "
                        "testing."
                    ),
                ),
                Step(
                    title="Add the redirect URI",
                    body=(
                        "Add a platform of type **Web** and register this exact URI. It must match including "
                        "scheme and path."
                    ),
                    paste="redirect_uri",
                ),
                Step(
                    title="Copy the client id",
                    body="From Overview, copy **Application (client) ID** into the Client ID field here.",
                ),
                Step(
                    title="Create a client secret",
                    body=(
                        "Under Certificates & secrets, create a client secret and copy its **Value** into "
                        "Client secret here. Copy it immediately — Entra hides it after you leave the page."
                    ),
                ),
                Step(
                    title="Build the issuer URL",
                    body=(
                        "Take the **Directory (tenant) ID** from Overview and paste "
                        "`https://login.microsoftonline.com/<tenant-id>/v2.0` into Issuer."
                    ),
                ),
                Step(
                    title="Emit groups or roles",
                    body=(
                        "Entra sends neither by default. Either define **App roles** and assign users (they "
                        "arrive in `roles` as readable values), or use **Token configuration → Add groups "
                        "claim** (they arrive in `groups` as object GUIDs)."
                    ),
                ),
                Step(
                    title="Optional — refresh tokens",
                    body=(
                        "Add `offline_access` to the app registration's API permissions, then tick "
                        "**Request a refresh token** here. Entra does not support encrypted ID "
                        "tokens or DPoP for OIDC clients, so those two options will have no effect "
                        "against Entra — the dashboard will report the token as unbound and "
                        "unencrypted, which in this case is the provider and not your setup."
                    ),
                ),
                Step(
                    title="Check it before signing in",
                    body=(
                        "Save the connection and press **Test configuration**. It fetches the discovery "
                        "document and lists the endpoints Entra advertises, which catches a wrong tenant id "
                        "without a browser round trip."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Set the subject claim to `oid`, not `sub`. Entra's `sub` is pairwise per application, "
                    "so "
                    "it will never equal anything SCIM or another system knows about the same person."
                ),
                (
                    "Past roughly 200 groups in a JWT, Entra drops the groups claim entirely and sends "
                    "`_claim_names`/`_claim_sources` pointing at Microsoft Graph instead. This app does not "
                    "follow that link, so groups will simply appear absent. Use app roles or a group filter "
                    "for anyone likely to hit it."
                ),
                (
                    "A client secret is required unless you configure the app registration as a public "
                    "client. If you leave it blank here, enable PKCE and allow public client flows at Entra."
                ),
            ),
        ),
        "saml": Guide(
            protocol="saml",
            summary=(
                "An Enterprise application with SAML sign-on. Entra will import the SP "
                "metadata URL for you."
            ),
            terms=(
                Term(
                    key="idp_entity_id",
                    their_name="Microsoft Entra Identifier",
                    where="Single sign-on → section 4, Set up <app>",
                    note="Looks like https://sts.windows.net/<tenant-id>/",
                ),
                Term(
                    key="idp_sso_url",
                    their_name="Login URL",
                    where="Single sign-on → section 4",
                ),
                Term(
                    key="idp_slo_url",
                    their_name="Logout URL",
                    where="Single sign-on → section 4",
                ),
                Term(
                    key="idp_x509_cert",
                    their_name="Certificate (Base64)",
                    where="Single sign-on → section 3, SAML Certificates",
                    note="Download the Base64 file, not the Raw or Federation Metadata XML one.",
                ),
                Term(
                    key="sp_entity_id",
                    their_name="Identifier (Entity ID)",
                    where="Single sign-on → section 1, Basic SAML Configuration",
                ),
                Term(
                    key="name_id_format",
                    their_name="Unique User Identifier (Name ID)",
                    where="Single sign-on → section 2, Attributes & Claims",
                ),
                Term(
                    key="role_claim",
                    their_name="A group or role claim",
                    where="Single sign-on → section 2, Attributes & Claims",
                    note=(
                        "Group claims arrive under the full URN "
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
                    ),
                ),
                Term(
                    key="subject_claim",
                    their_name="The objectidentifier claim",
                    note=(
                        "http://schemas.microsoft.com/identity/claims/objectidentifier — sent by default and "
                        "immutable."
                    ),
                ),
            ),
            steps=(
                Step(
                    title="Create an Enterprise application",
                    body=(
                        "Add a **Non-gallery** application, then open **Single sign-on** and "
                        "choose **SAML**."
                    ),
                ),
                Step(
                    title="Import the SP metadata",
                    body=(
                        "In Basic SAML Configuration, use **Upload metadata file** with this URL, or paste "
                        "the values by hand from the steps below. Importing fills in the identifier, reply "
                        "URL, and logout URL for you."
                    ),
                    paste="metadata_url",
                ),
                Step(
                    title="Identifier (Entity ID)",
                    body="If you are not importing metadata, set the Identifier to this value.",
                    paste="sp_entity_id",
                ),
                Step(
                    title="Reply URL (Assertion Consumer Service URL)",
                    body="Where Entra POSTs the assertion.",
                    paste="acs_url",
                ),
                Step(
                    title="Logout URL",
                    body=(
                        "Where Entra sends its LogoutResponse, and any LogoutRequest when the user signs out "
                        "elsewhere. Register it or single logout ends at a 404."
                    ),
                    paste="sls_url",
                ),
                Step(
                    title="Make the Name ID stable",
                    body=(
                        "In Attributes & Claims, edit the **Unique User Identifier (Name ID)** and set the "
                        "source attribute to `user.objectid`. See the warnings below for why the default is "
                        "a "
                        "problem."
                    ),
                ),
                Step(
                    title="Copy Entra's own values back",
                    body=(
                        "From section 4, copy **Microsoft Entra Identifier**, **Login URL**, and **Logout "
                        "URL** into the IdP fields here, and download **Certificate (Base64)** from section "
                        "3 "
                        "into the signing certificate box."
                    ),
                ),
                Step(
                    title="Optional — encrypt the assertion",
                    body=(
                        "Entra can encrypt the SAML assertion. Generate an SP keypair, paste the "
                        "certificate and private key into this connection, upload the same "
                        "certificate under **Token encryption** on the enterprise application and "
                        "activate it, then tick **Require the assertion to be encrypted** here. "
                        "Both sides must be configured — enabling only one gives you a rejected "
                        "assertion rather than a silent downgrade, which is the intended outcome."
                    ),
                ),
                Step(
                    title="Assign someone",
                    body=(
                        "Under Users and groups, assign at least one user. Entra refuses sign-in for "
                        "unassigned users with AADSTS50105, which reads like a configuration error but is "
                        "not."
                    ),
                ),
            ),
            gotchas=(
                (
                    "**The default Name ID is not stable.** Entra uses the user principal name, which "
                    "changes "
                    "on rename or a domain rebrand. When it changes the user looks like a brand new person, "
                    "stops matching their provisioned SCIM record, and may not be caught by deprovisioning. "
                    "Set the Name ID source to `user.objectid`, or point this app's subject claim at "
                    "http://schemas.microsoft.com/identity/claims/objectidentifier — which Entra sends "
                    "regardless, so it needs no change on their side."
                ),
                (
                    "Setting the Name ID **format** to Persistent without changing the source attribute "
                    "gives "
                    "you an identifier that is stable for that enterprise application and is regenerated if "
                    "the application is deleted and recreated. Rebuilding your test app then silently "
                    "orphans "
                    "every provisioned record."
                ),
                (
                    "http://schemas.microsoft.com/claims/authnmethodsreferences is the SAML equivalent of "
                    "`amr`. Point an expectation at it to assert that multi-factor actually happened."
                ),
            ),
        ),
        "scim": Guide(
            protocol="scim",
            summary="Automatic provisioning on the same Enterprise application. Needs Entra ID P1 or above.",
            terms=(
                Term(
                    key="scim_tenant_url",
                    their_name="Tenant URL",
                    where="Enterprise application → Provisioning → Admin Credentials",
                ),
                Term(
                    key="scim_token",
                    their_name="Secret Token",
                    where="Enterprise application → Provisioning → Admin Credentials",
                ),
            ),
            steps=(
                Step(
                    title="Generate a token here first",
                    body="Under **Admin → SCIM**, create a provisioning client. The token is shown once.",
                ),
                Step(
                    title="Set the Tenant URL",
                    body=(
                        "In the Enterprise application, open **Provisioning**, set the mode to "
                        "**Automatic**, "
                        "and paste this as the Tenant URL. Appending `?aadOptscim062020` opts into Entra's "
                        "stricter, more standards-compliant behaviour, which is what you want when testing a "
                        "real implementation."
                    ),
                    paste="scim_tenant_url",
                ),
                Step(
                    title="Set the Secret Token",
                    body=(
                        "Paste the token from step 1 into **Secret Token**, then press **Test Connection**. "
                        "Entra probes the endpoint and will say plainly if it cannot reach it."
                    ),
                ),
                Step(
                    title="Fix the externalId mapping",
                    body=(
                        "Under Mappings → Provision Microsoft Entra ID Users, change **externalId** to map "
                        "from `objectId`. The default is often `mailNickname`, which is mutable and will not "
                        "match a session keyed on the object id."
                    ),
                ),
                Step(
                    title="Start provisioning and watch",
                    body=(
                        "Turn provisioning on. Every request Entra sends is recorded with its full payload "
                        "under **Admin → SCIM** here, which is the fastest way to see what your attribute "
                        "mappings actually produce."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Provisioning is a direct call from Microsoft's servers to yours. It cannot reach "
                    "localhost or a private endpoint — sign-in will keep working while provisioning silently "
                    "does not. Deploy the app, or put a tunnel in front of it."
                ),
                (
                    "Entra sends `Content-Type: application/scim+json` and sends `active` as the string "
                    "\"False\" when deactivating. Both are handled here and covered by tests, but they break "
                    "many hand-rolled SCIM servers."
                ),
            ),
        ),
    },
)


# --- Okta ----------------------------------------------------------------------

OKTA = Provider(
    key="okta",
    name="Okta",
    blurb="Does all three protocols. SCIM needs Lifecycle Management and a provisioning-capable app.",
    guides={
        "oidc": Guide(
            protocol="oidc",
            summary="An OIDC Web Application, plus a groups claim on the authorization server.",
            terms=(
                Term(
                    key="issuer",
                    their_name="Issuer",
                    where="Security → API → Authorization Servers",
                    note="Usually https://<org>.okta.com/oauth2/default",
                ),
                Term(key="client_id", their_name="Client ID", where="Applications → your app → General"),
                Term(
                    key="client_secret",
                    their_name="CLIENT SECRETS → Secret",
                    where="Applications → your app → General → Client Credentials",
                    note=(
                        "Only exists on a **Web Application**. If the General tab shows \"Client "
                        "authentication: None\" and there is no CLIENT SECRETS section, the app was "
                        "created as a SPA or Native integration and no secret can be produced for it. "
                        "Unlike Entra, Okta lets you view the secret again later."
                    ),
                ),
                Term(
                    key="scopes",
                    their_name="Grant type / scopes",
                    note="openid profile email groups — 'groups' only works once the claim below exists.",
                ),
                Term(
                    key="role_claim",
                    their_name="A claim named groups",
                    where="Security → API → Authorization Servers → Claims",
                    note="Okta sends group names rather than ids, so mapping rules read nicely.",
                ),
                Term(key="subject_claim", their_name="sub", note="Stable in Okta and a reasonable choice."),
            ),
            steps=(
                Step(
                    title="Create the app integration — choose Web Application",
                    body=(
                        "Applications → Create App Integration → **OIDC - OpenID Connect**, then pick "
                        "**Web Application** as the application type. Get this right first: it decides "
                        "whether the app can hold a client secret, and Okta will not let you change it "
                        "afterwards. If you have already made a Single-Page Application, see the "
                        "warnings below."
                    ),
                ),
                Step(
                    title="Add the sign-in redirect URI",
                    body="Set **Sign-in redirect URIs** to this value.",
                    paste="redirect_uri",
                ),
                Step(
                    title="Add the sign-out redirect URI",
                    body=(
                        "Set **Sign-out redirect URIs** to the app root so federated sign-out returns "
                        "cleanly."
                    ),
                    paste="base_url",
                ),
                Step(
                    title="Copy the client credentials",
                    body="From the app's General tab, copy the Client ID and Secret into the fields here.",
                ),
                Step(
                    title="Set the issuer",
                    body=(
                        "Security → API → Authorization Servers. Copy the **Issuer** URI of the server you "
                        "are using — `default` unless you have made another — into Issuer here."
                    ),
                ),
                Step(
                    title="Add a groups claim",
                    body=(
                        "On that same authorization server, open **Claims** → Add Claim. Name it `groups`, "
                        "include it in the **ID Token**, set the value type to **Groups**, and filter "
                        "**Matches regex** `.*`. Narrow that filter for anything real."
                    ),
                ),
                Step(
                    title="Assign people",
                    body="Under Assignments, assign the users or groups who should be able to sign in.",
                ),
                Step(
                    title="Optional — refresh tokens",
                    body=(
                        "To exercise refresh, tick **Refresh Token** under Grant type on the app, "
                        "make sure the `offline_access` scope is available on the authorization "
                        "server, then enable **Request a refresh token** here. Okta's refresh token "
                        "rotation setting is on the app's General tab; with rotation on, each "
                        "refresh returns a replacement and invalidates the previous one."
                    ),
                ),
                Step(
                    title="Optional — DPoP",
                    body=(
                        "Okta supports sender-constrained tokens. Enable **Proof of possession: "
                        "Require Demonstrating Proof of Possession (DPoP) header** on the "
                        "application's General tab, then tick **Use DPoP** here. Sign in and the "
                        "dashboard will show whether the access token came back carrying a "
                        "`cnf.jkt` matching this connection's key."
                    ),
                ),
                Step(
                    title="Optional — encrypted ID tokens",
                    body=(
                        "Tick **Accept encrypted ID tokens** here, copy the JWKS URL it then "
                        "shows, and register it as the client's JWKS on the Okta app. Okta "
                        "encrypts to the key it finds there. If tokens keep arriving "
                        "unencrypted, the dashboard says so — it usually means the JWKS URL is "
                        "not registered or is unreachable from Okta."
                    ),
                ),
                Step(
                    title="Optional — custom claims",
                    body=(
                        "Any claim you add on the authorization server (Security → API → your "
                        "server → Claims) arrives in the token and is listed in full on the "
                        "dashboard. To *demand* one rather than hope for it, put a claims request "
                        "in the connection's `claims` field, and add an expectation so each "
                        "sign-in reports pass or fail on it."
                    ),
                ),
            ),
            gotchas=(
                (
                    "**Choose Web Application, not Single-Page Application.** This is the one that "
                    "catches people: SPA sounds like the modern default and the wizard offers it "
                    "prominently. A SPA is a *public* client, so Okta shows \"Client authentication: "
                    "None\" on the General tab, there is no CLIENT SECRETS section, and no secret "
                    "exists to copy. Web Application is a confidential client and is what these steps "
                    "assume. The type cannot be changed after creation — delete the integration and "
                    "create a new one."
                ),
                (
                    "If you would rather keep a SPA integration, it can still work: leave Client "
                    "secret blank here and keep **Use PKCE** ticked, which is a legitimate "
                    "public-client flow. You lose the client-credentials grant, so that connection "
                    "cannot be used on the Service access page."
                ),
                (
                    "The groups claim lives on the **authorization server**, not on the application. Adding "
                    "a "
                    "groups attribute to the app profile does nothing for the token, and the dashboard will "
                    "show no groups while listing the claims that are present — which is the giveaway."
                ),
                (
                    "If you use a custom authorization server, its issuer differs from the org URL. Paste "
                    "the "
                    "issuer exactly as the Authorization Servers list shows it."
                ),
            ),
        ),
        "saml": Guide(
            protocol="saml",
            summary="A SAML 2.0 app integration, plus a group attribute statement.",
            terms=(
                Term(
                    key="idp_entity_id",
                    their_name="Identity Provider Issuer",
                    where="Sign On → View SAML setup instructions",
                ),
                Term(
                    key="idp_sso_url",
                    their_name="Identity Provider Single Sign-On URL",
                    where="Sign On → View SAML setup instructions",
                ),
                Term(
                    key="idp_slo_url",
                    their_name="Identity Provider Single Logout URL",
                    where="Sign On → View SAML setup instructions",
                    note="Only present once Single Logout is enabled in the app's SAML settings.",
                ),
                Term(
                    key="idp_x509_cert",
                    their_name="X.509 Certificate",
                    where="Sign On → View SAML setup instructions",
                ),
                Term(
                    key="sp_entity_id",
                    their_name="Audience URI (SP Entity ID)",
                    where="General → SAML Settings",
                ),
                Term(
                    key="name_id_format",
                    their_name="Name ID format",
                    where="General → SAML Settings",
                ),
                Term(
                    key="role_claim",
                    their_name="Group Attribute Statements → Name",
                    where="General → SAML Settings",
                ),
            ),
            steps=(
                Step(
                    title="Create the app integration",
                    body="Applications → Create App Integration → **SAML 2.0**.",
                ),
                Step(
                    title="Single sign-on URL",
                    body="This is Okta's name for the ACS URL.",
                    paste="acs_url",
                ),
                Step(
                    title="Audience URI (SP Entity ID)",
                    body="Set the audience to this value.",
                    paste="sp_entity_id",
                ),
                Step(
                    title="Add a group attribute statement",
                    body=(
                        "Still in SAML Settings, add a **Group Attribute Statement**: name it `groups`, "
                        "filter **Matches regex** `.*`. Without this no groups are asserted at all."
                    ),
                ),
                Step(
                    title="Enable Single Logout",
                    body=(
                        "Under Advanced Settings, tick **Allow application to initiate Single Logout** and "
                        "set the Single Logout URL to this value. Upload the app's signature certificate if "
                        "Okta asks for one."
                    ),
                    paste="sls_url",
                ),
                Step(
                    title="Copy Okta's values back",
                    body=(
                        "From the Sign On tab, open **View SAML setup instructions** and copy the Identity "
                        "Provider Issuer, Single Sign-On URL, and X.509 Certificate into the IdP fields here."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Group attribute statements are separate from attribute statements. Adding a `groups` "
                    "attribute statement instead does not produce group membership."
                ),
            ),
        ),
        "scim": Guide(
            protocol="scim",
            summary="Provisioning on a SCIM-capable app integration. Needs Lifecycle Management.",
            terms=(
                Term(
                    key="scim_tenant_url",
                    their_name="SCIM connector base URL",
                    where="Provisioning → Integration → Configure API Integration",
                ),
                Term(
                    key="scim_token",
                    their_name="Authorization — as an HTTP Header",
                    where="Provisioning → Integration",
                    note='Authentication Mode "HTTP Header", value "Bearer <token>".',
                ),
            ),
            steps=(
                Step(
                    title="Generate a token here first",
                    body="Under **Admin → SCIM**, create a provisioning client. The token is shown once.",
                ),
                Step(
                    title="Enable SCIM on the app",
                    body=(
                        "General → App Settings → **Provisioning**, set it to **SCIM**. The app integration "
                        "must have been created as SCIM-capable; not every template offers this."
                    ),
                ),
                Step(
                    title="Configure the API integration",
                    body=(
                        "Provisioning → Integration → Configure API Integration. Set the SCIM connector base "
                        "URL to this value, the unique identifier field to `userName`, and enable Push New "
                        "Users, Push Profile Updates, and Push Groups."
                    ),
                    paste="scim_tenant_url",
                ),
                Step(
                    title="Set the credentials",
                    body=(
                        "Set Authentication Mode to **HTTP Header** and Authorization to `Bearer <your "
                        "token>`, then press **Test API Credentials**."
                    ),
                ),
                Step(
                    title="Enable the actions you want",
                    body=(
                        "Under Provisioning → To App, enable Create Users, Update User Attributes, and "
                        "Deactivate Users. Deactivation is the interesting one: it should end live sessions "
                        "here immediately."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Provisioning is a direct call from Okta's servers to yours, so it cannot reach "
                    "localhost "
                    "or a private endpoint."
                ),
                (
                    "Okta uses PUT for updates in some configurations rather than PATCH. Both are "
                    "implemented "
                    "here."
                ),
            ),
        ),
    },
)


# --- Auth0 ---------------------------------------------------------------------

AUTH0 = Provider(
    key="auth0",
    name="Auth0",
    blurb="Sign-in only. Auth0 receives SCIM provisioning rather than sending it.",
    guides={
        "oidc": Guide(
            protocol="oidc",
            summary="A Regular Web Application. Watch the trailing slash on the issuer.",
            terms=(
                Term(
                    key="issuer",
                    their_name="Domain",
                    where="Applications → your app → Settings",
                    note=(
                        "Prefix with https:// and keep the trailing slash: "
                        "https://<tenant>.<region>.auth0.com/"
                    ),
                ),
                Term(key="client_id", their_name="Client ID", where="Applications → Settings"),
                Term(key="client_secret", their_name="Client Secret", where="Applications → Settings"),
                Term(
                    key="role_claim",
                    their_name="A namespaced custom claim",
                    where="Actions → Library → your post-login Action",
                    note="Auth0 silently drops custom claims that are not namespaced URIs.",
                ),
            ),
            steps=(
                Step(
                    title="Create the application",
                    body="Applications → Create Application → **Regular Web Application**.",
                ),
                Step(
                    title="Allowed Callback URLs",
                    body="Add this to **Allowed Callback URLs** in the application settings.",
                    paste="redirect_uri",
                ),
                Step(
                    title="Allowed Logout URLs",
                    body="Add the app root so federated sign-out returns cleanly.",
                    paste="base_url",
                ),
                Step(
                    title="Set the issuer",
                    body=(
                        "Take the **Domain** from settings and enter it here as `https://<domain>/` — with "
                        "the scheme and the trailing slash. Auth0's `iss` claim includes both, and the "
                        "issuer "
                        "is validated exactly."
                    ),
                ),
                Step(
                    title="Add roles to the token",
                    body=(
                        "Auth0 puts neither roles nor groups in the token by default. Add a post-login "
                        "Action "
                        "that sets a namespaced claim, then point the role claim field at that full URI."
                    ),
                ),
            ),
            gotchas=(
                (
                    "The trailing slash on the issuer is not cosmetic. Without it the issuer will not match "
                    "the discovery document and every sign-in fails validation."
                ),
                (
                    "Custom claims must be namespaced URIs, e.g. `https://authlab.example/roles`. Auth0 "
                    "drops "
                    "anything else without complaint, which looks exactly like the claim not being "
                    "configured."
                ),
            ),
        ),
        "saml": Guide(
            protocol="saml",
            summary="The SAML2 Web App addon turns an Auth0 application into a SAML identity provider.",
            terms=(
                Term(
                    key="idp_entity_id",
                    their_name="Issuer",
                    where="Addons → SAML2 Web App → Usage",
                    note="Usually urn:<tenant>.auth0.com",
                ),
                Term(
                    key="idp_sso_url",
                    their_name="Identity Provider Login URL",
                    where="Addons → SAML2 Web App → Usage",
                    note="https://<tenant>.auth0.com/samlp/<client-id>",
                ),
                Term(
                    key="idp_x509_cert",
                    their_name="Signing Certificate",
                    where="Settings → Advanced → Certificates, or the Usage tab of the addon",
                ),
                Term(
                    key="acs_url",
                    their_name="Application Callback URL",
                    where="Addons → SAML2 Web App → Settings",
                ),
            ),
            steps=(
                Step(
                    title="Enable the SAML2 addon",
                    body="Open the application, go to **Addons**, and enable **SAML2 Web App**.",
                ),
                Step(
                    title="Application Callback URL",
                    body=(
                        "On the addon's Settings tab, set this as the callback — it is Auth0's name for the "
                        "ACS URL."
                    ),
                    paste="acs_url",
                ),
                Step(
                    title="Copy Auth0's values back",
                    body=(
                        "The addon's **Usage** tab lists the Issuer, Identity Provider Login URL, and a "
                        "downloadable certificate. Paste them into the IdP fields here."
                    ),
                ),
            ),
        ),
        "scim": Guide(
            protocol="scim",
            supported=False,
            unsupported_reason=(
                "Auth0 does not push SCIM to downstream applications. Its SCIM support is "
                "for *receiving* provisioning into Auth0 from a directory, which is the "
                "opposite direction. Use Auth0 for sign-in and provision from whichever "
                "directory owns the users — this app matches provisioned records to "
                "sessions by identifier, so they do not have to be the same system."
            ),
        ),
    },
)


# --- AWS Cognito ---------------------------------------------------------------

COGNITO = Provider(
    key="cognito",
    name="AWS Cognito",
    blurb="OIDC sign-in only. Cognito is a SAML service provider, not an identity provider.",
    guides={
        "oidc": Guide(
            protocol="oidc",
            summary=(
                "A user pool app client. A Hosted UI domain is required or there is "
                "nowhere to redirect to."
            ),
            terms=(
                Term(
                    key="issuer",
                    their_name="Built from the User pool ID",
                    where="User pool → Overview",
                    note="https://cognito-idp.<region>.amazonaws.com/<user-pool-id>",
                ),
                Term(
                    key="client_id",
                    their_name="Client ID",
                    where="User pool → App integration → App client",
                ),
                Term(
                    key="client_secret",
                    their_name="Client secret",
                    where="User pool → App integration → App client",
                    note="Only exists if you ticked 'Generate a client secret' when creating the client.",
                ),
                Term(
                    key="redirect_uri",
                    their_name="Allowed callback URLs",
                    where="App client → Hosted UI settings",
                ),
                Term(
                    key="role_claim",
                    their_name="cognito:groups",
                    note="Group names, emitted automatically for users in a group.",
                ),
                Term(key="subject_claim", their_name="sub", note="A pool-scoped UUID; stable."),
            ),
            steps=(
                Step(
                    title="Create or choose a user pool",
                    body="Any user pool works. Note its **User pool ID** from the Overview page.",
                ),
                Step(
                    title="Set a Hosted UI domain",
                    body=(
                        "Under App integration, configure a **Domain** — either a Cognito prefix domain or "
                        "your own. Without it there is no authorization endpoint and the flow has nowhere to "
                        "send the browser."
                    ),
                ),
                Step(
                    title="Create an app client",
                    body=(
                        "Create an app client **with** a client secret, and enable the **Authorization code "
                        "grant** with the `openid`, `profile`, and `email` scopes."
                    ),
                ),
                Step(
                    title="Allowed callback URLs",
                    body="Add this to the app client's allowed callback URLs.",
                    paste="redirect_uri",
                ),
                Step(
                    title="Build the issuer",
                    body="Enter `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` as the Issuer.",
                ),
                Step(
                    title="Verify before you sign in",
                    body=(
                        "Press **Test configuration**. It prints the endpoints Cognito advertises — a "
                        "missing "
                        "or unexpected authorization endpoint means the Hosted UI domain is not set, and you "
                        "have found that out without a browser round trip."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Cognito's `sub` is scoped to the user pool, so it matches nothing an external directory "
                    "knows. If you are provisioning from elsewhere, match on email."
                ),
                "Groups arrive as `cognito:groups`, not `groups`. Set the role claim accordingly.",
            ),
        ),
        "saml": Guide(
            protocol="saml",
            supported=False,
            unsupported_reason=(
                "Cognito is a SAML **service provider** — it federates outward to external "
                "SAML identity providers so that users can sign in to Cognito. It cannot "
                "act as the SAML identity provider for another application. Use the OIDC "
                "guide instead, which is Cognito's native role here."
            ),
        ),
        "scim": Guide(
            protocol="scim",
            supported=False,
            unsupported_reason=(
                "Cognito has no outbound SCIM provisioning. If you need provisioning tested "
                "alongside Cognito sign-in, provision from a directory that can send SCIM — "
                "Entra ID or Okta — since this app matches provisioned records to sessions "
                "by identifier rather than by connection."
            ),
        ),
    },
)


# --- Duo -----------------------------------------------------------------------

DUO = Provider(
    key="duo",
    name="Duo",
    blurb="Duo Single Sign-On as a SAML or OIDC provider. No outbound SCIM.",
    guides={
        "saml": Guide(
            protocol="saml",
            summary="A Generic SAML Service Provider application in the Duo Admin Panel.",
            terms=(
                Term(
                    key="idp_entity_id",
                    their_name="Entity ID",
                    where="Duo SSO application → Metadata",
                ),
                Term(
                    key="idp_sso_url",
                    their_name="Single Sign-On URL",
                    where="Duo SSO application → Metadata",
                ),
                Term(
                    key="idp_slo_url",
                    their_name="Single Log-Out URL",
                    where="Duo SSO application → Metadata",
                ),
                Term(
                    key="idp_x509_cert",
                    their_name="Certificate",
                    where="Duo SSO application → Metadata → Download certificate",
                ),
                Term(
                    key="sp_entity_id",
                    their_name="Entity ID",
                    where="Service Provider section of the Duo application",
                ),
                Term(
                    key="acs_url",
                    their_name="Assertion Consumer Service (ACS) URL",
                    where="Service Provider section",
                ),
                Term(
                    key="role_claim",
                    their_name="A mapped attribute",
                    where="SAML Response → Map attributes",
                    note="Duo asserts whatever you map; name it `groups` to keep the rules readable.",
                ),
            ),
            steps=(
                Step(
                    title="Add the application",
                    body=(
                        "In the Duo Admin Panel, Applications → Protect an Application → **Generic SAML "
                        "Service Provider**."
                    ),
                ),
                Step(
                    title="Entity ID",
                    body="Set the Service Provider Entity ID to this value.",
                    paste="sp_entity_id",
                ),
                Step(
                    title="Assertion Consumer Service URL",
                    body="Where Duo POSTs the assertion.",
                    paste="acs_url",
                ),
                Step(
                    title="Single Logout URL",
                    body="Set this so single logout completes rather than ending at a 404.",
                    paste="sls_url",
                ),
                Step(
                    title="Map attributes",
                    body=(
                        "Under **Map attributes**, assert at least an email address and a group attribute. "
                        "Give the group attribute a name you will recognise and set the role claim here to "
                        "match."
                    ),
                ),
                Step(
                    title="Copy Duo's values back",
                    body=(
                        "From the application's metadata section, copy the Entity ID, Single Sign-On URL, "
                        "and "
                        "certificate into the IdP fields here. Duo also accepts the SP metadata URL if you "
                        "prefer to import."
                    ),
                ),
            ),
            gotchas=(
                (
                    "Duo is often an MFA layer in front of another identity provider rather than the "
                    "provider "
                    "itself. In that arrangement you connect to the upstream provider normally, and Duo "
                    "shows "
                    "up in the authentication context rather than in these settings."
                ),
                (
                    "To assert that Duo actually challenged, add an expectation on `authnContextClassRef` "
                    "containing `MultiFactor`. That turns the interesting question into a pass or fail "
                    "instead of a claim dump to interpret."
                ),
            ),
        ),
        "oidc": Guide(
            protocol="oidc",
            summary="A Generic OIDC Relying Party in Duo Single Sign-On.",
            terms=(
                Term(
                    key="issuer",
                    their_name="Discovery / Issuer URL",
                    where="Duo SSO application → OIDC details",
                    note=(
                        "Paste whichever Duo shows — a full .well-known/openid-configuration URL is accepted "
                        "and the suffix is stripped."
                    ),
                ),
                Term(key="client_id", their_name="Client ID", where="Duo SSO application"),
                Term(key="client_secret", their_name="Client Secret", where="Duo SSO application"),
                Term(
                    key="redirect_uri",
                    their_name="Redirect URI",
                    where="Duo SSO application",
                ),
            ),
            steps=(
                Step(
                    title="Add the application",
                    body="Applications → Protect an Application → **Generic OIDC Relying Party**.",
                ),
                Step(title="Redirect URI", body="Register this exact URI.", paste="redirect_uri"),
                Step(
                    title="Copy the credentials and issuer",
                    body=(
                        "Copy the Client ID and Client Secret into the fields here, and paste the discovery "
                        "or issuer URL Duo shows into Issuer."
                    ),
                ),
                Step(
                    title="Verify",
                    body=(
                        "Press **Test configuration** to confirm what Duo advertises before attempting a "
                        "sign-in."
                    ),
                ),
            ),
        ),
        "scim": Guide(
            protocol="scim",
            supported=False,
            unsupported_reason=(
                "Duo synchronises users *from* a directory — Active Directory, Entra ID, "
                "Okta — rather than provisioning them onward to applications. There is no "
                "outbound SCIM to configure. Provision from the directory that owns the "
                "users instead."
            ),
        ),
    },
)


# --- Generic -------------------------------------------------------------------

GENERIC = Provider(
    key="generic",
    name="Any other provider",
    blurb="The specification's own vocabulary, for anything not listed.",
    guides={
        "oidc": Guide(
            protocol="oidc",
            summary="Find the issuer. Discovery supplies everything else.",
            terms=(
                Term(
                    key="issuer",
                    their_name="Issuer, or Discovery endpoint",
                    note=(
                        "Everything else comes from {issuer}/.well-known/openid-configuration. Pasting the "
                        "full discovery URL works — the suffix is stripped."
                    ),
                ),
                Term(key="client_id", their_name="Client ID, or Application ID"),
                Term(key="client_secret", their_name="Client Secret, or Application Secret"),
                Term(
                    key="redirect_uri",
                    their_name="Redirect URI, Callback URL, or Reply URL",
                ),
                Term(
                    key="role_claim",
                    their_name="Whichever claim carries groups or roles",
                    note="Dotted paths work for nested claims, e.g. realm_access.roles on Keycloak.",
                ),
            ),
            steps=(
                Step(
                    title="Register a confidential client",
                    body=(
                        "Create an application or client of the web/server-side kind, capable of holding a "
                        "secret."
                    ),
                ),
                Step(
                    title="Register the redirect URI",
                    body="Exactly as shown, including scheme and path.",
                    paste="redirect_uri",
                ),
                Step(
                    title="Enter the issuer",
                    body=(
                        "Paste the issuer URL, or the full discovery URL. Then press **Test configuration** "
                        "— "
                        "if that succeeds, the flow will work, and if it fails the error names what could "
                        "not "
                        "be reached."
                    ),
                ),
                Step(
                    title="Point the role claim at group membership",
                    body=(
                        "Sign in once and read the claim dump on the dashboard. It lists every claim the "
                        "provider actually sent, which is the quickest way to find the right name."
                    ),
                ),
            ),
        ),
        "saml": Guide(
            protocol="saml",
            summary="Three values in, one metadata URL out.",
            terms=(
                Term(key="idp_entity_id", their_name="Entity ID, Issuer, or IdP Identifier"),
                Term(key="idp_sso_url", their_name="SSO URL, Login URL, or SAML endpoint"),
                Term(key="idp_slo_url", their_name="SLO URL, or Logout URL"),
                Term(
                    key="idp_x509_cert",
                    their_name="Signing certificate, or Token-signing certificate",
                    note="PEM or bare base64 — both are accepted and normalised.",
                ),
                Term(key="sp_entity_id", their_name="Audience, Entity ID, or SP Identifier"),
                Term(
                    key="acs_url",
                    their_name="ACS URL, Reply URL, Single sign-on URL, or Consumer URL",
                ),
            ),
            steps=(
                Step(
                    title="Give the provider the SP metadata",
                    body=(
                        "Most consoles will import this and fill in the entity ID, ACS URL, logout URL, and "
                        "NameID format themselves — which removes the most error-prone part of SAML setup."
                    ),
                    paste="metadata_url",
                ),
                Step(
                    title="Or enter the values by hand",
                    body="Entity ID and ACS URL are the two the provider must have.",
                    paste="acs_url",
                ),
                Step(
                    title="Copy the provider's values back",
                    body=(
                        "You need its entity ID, its sign-on URL, and its signing certificate. Without the "
                        "certificate no assertion can be verified."
                    ),
                ),
            ),
        ),
        "scim": Guide(
            protocol="scim",
            summary="A tenant URL and a bearer token.",
            terms=(
                Term(
                    key="scim_tenant_url",
                    their_name="Tenant URL, Base URL, or SCIM endpoint",
                ),
                Term(
                    key="scim_token",
                    their_name="Secret Token, API Token, or Bearer token",
                ),
            ),
            steps=(
                Step(
                    title="Generate a token",
                    body="Under **Admin → SCIM**, create a provisioning client. The token is shown once.",
                ),
                Step(
                    title="Give the provider the tenant URL",
                    body="Along with the token as a bearer credential.",
                    paste="scim_tenant_url",
                ),
                Step(
                    title="Let it discover the rest",
                    body=(
                        "`/ServiceProviderConfig`, `/ResourceTypes`, and `/Schemas` are implemented, so a "
                        "compliant connector can discover what is supported rather than being told."
                    ),
                ),
            ),
        ),
    },
)


PROVIDERS: dict[str, Provider] = {
    p.key: p for p in (ENTRA, OKTA, AUTH0, COGNITO, DUO, GENERIC)
}

PROTOCOL_NAMES = {"oidc": "OIDC / OAuth 2.0", "saml": "SAML 2.0", "scim": "SCIM 2.0"}


# --- lookups -------------------------------------------------------------------


def get(provider_key: str) -> Provider | None:
    return PROVIDERS.get(provider_key)


def choices() -> list[tuple[str, str]]:
    """(key, name) pairs for a select, in the order defined above."""
    return [(p.key, p.name) for p in PROVIDERS.values()]


def vocabulary(protocol: str) -> dict[str, dict[str, dict[str, str]]]:
    """Terminology for one protocol, as {field key: {provider key: {...}}}.

    Shaped for the connection form: it renders one hint element per field and
    the browser picks the provider, so the lookup has to be field-major.
    """
    result: dict[str, dict[str, dict[str, str]]] = {}
    for provider in PROVIDERS.values():
        guide = provider.guide(protocol)
        if guide is None or not guide.supported:
            continue
        for term in guide.terms:
            result.setdefault(term.key, {})[provider.key] = {
                "provider": provider.name,
                "name": term.their_name,
                "where": term.where,
                "note": term.note,
            }
    return result


def capability_matrix() -> list[dict[str, Any]]:
    """One row per provider, for the help index."""
    return [
        {
            "key": provider.key,
            "name": provider.name,
            "blurb": provider.blurb,
            "protocols": {
                protocol: {
                    "supported": provider.supports(protocol),
                    "reason": (
                        provider.guides[protocol].unsupported_reason
                        if protocol in provider.guides
                        else "Not documented for this provider."
                    ),
                }
                for protocol in ("oidc", "saml", "scim")
            },
        }
        for provider in PROVIDERS.values()
    ]


def resolve(text: str, urls: dict[str, str]) -> str:
    """Substitute {redirect_uri} and friends into a step body."""
    for placeholder in PLACEHOLDERS:
        key = placeholder.strip("{}")
        if placeholder in text:
            text = text.replace(placeholder, urls.get(key, placeholder))
    return text
