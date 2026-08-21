# Connecting providers

Per-provider setup for OIDC, SAML, and SCIM. The app is written against the
specifications rather than against any vendor, so most of this is "which value
goes in which box" rather than special cases.

Console navigation changes constantly, so this describes **what each value is**
rather than pretending to give click-by-click paths. Where something is genuinely
uncertain, the answer is to use **Admin → connection → Test configuration**,
which fetches the provider's own discovery document and shows you what it
actually advertises.

> Reading `AuthZ` in the request as **Auth0** — the identity provider. If you
> meant something else, say so and I will add it.

---

## Contents

- [What each provider can actually do](#what-each-provider-can-actually-do)
- [Before you start: where the app must be reachable from](#before-you-start-where-the-app-must-be-reachable-from)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Okta](#okta)
- [Auth0](#auth0)
- [AWS Cognito](#aws-cognito)
- [Duo](#duo)
- [Any other provider](#any-other-provider)
- [Running several connections at once](#running-several-connections-at-once)

---

## What each provider can actually do

SCIM is not part of OIDC or SAML. It is a separate protocol with its own
bearer-token authentication, and in this app the provisioning endpoints have no
reference to a connection at all — you can run SCIM alongside an OIDC
connection, a SAML connection, several of each, or none.

What varies is whether a given product can *send* SCIM to a downstream
application. Several of these are excellent identity providers that simply do
not do outbound provisioning:

| Provider | OIDC sign-in | SAML sign-in | Outbound SCIM |
|---|---|---|---|
| Microsoft Entra ID | Yes | Yes | Yes — needs Entra ID P1 or above |
| Okta | Yes | Yes | Yes — needs Lifecycle Management |
| Auth0 | Yes | Yes | **No** — Auth0 receives SCIM, it does not send it |
| AWS Cognito | Yes | **No** — Cognito is a SAML *service provider*, not an IdP | **No** |
| Duo SSO | Yes | Yes | **No** — Duo syncs *from* a directory, it does not provision outward |
| Generic | If OIDC-compliant | If SAML 2.0 | If it can send SCIM 2.0 |

If your directory is Entra ID or Okta and your sign-in is Auth0, Cognito, or
Duo, that is a perfectly normal arrangement: provision from the directory that
owns the users, and federate sign-in through whatever sits in front of it. The
app does not care that they are different systems — it matches provisioned
users to sessions by identifier, not by connection.

---

## Before you start: where the app must be reachable from

This trips people up because OIDC and SAML behave differently from SCIM.

**Sign-in is carried by the browser.** Every message in an OIDC or SAML flow is
a redirect or a form POST that *your browser* performs. The provider never
connects to the app directly. That is why `http://localhost:8000` works
perfectly for testing sign-in — your browser can reach both ends.

**SCIM is a direct server-to-server call.** The provider's own infrastructure
opens a connection to the tenant URL you give it. `localhost` is meaningless to
Microsoft's or Okta's servers, and a private VNet address is unreachable. SCIM
provisioning therefore **cannot** be tested against a purely local deployment.

To provision against a local instance, put a tunnel in front of it and set
`BASE_URL` to the tunnel's URL:

```bash
# any of these work; the app only cares that BASE_URL matches
cloudflared tunnel --url http://localhost:8000
ngrok http 8000
devtunnel host -p 8000 --allow-anonymous
```

Then restart with `BASE_URL=https://<your-tunnel-host>`, because redirect URIs,
ACS URLs, and the SCIM tenant URL are all derived from it.

[deployment-urls.md](deployment-urls.md) covers this properly, including what
the URLs look like on each cloud and what to do about the chicken-and-egg
problem of needing a URL that only exists after deployment.

---

## Microsoft Entra ID

### OIDC

Create an **App registration**.

| Field in AuthLab | Value |
|---|---|
| Issuer | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Client ID | Application (client) ID |
| Client secret | Certificates & secrets → New client secret |
| Scopes | `openid profile email` |

Register the redirect URI shown on the connection page as a **Web** platform
redirect URI. It must match exactly, including scheme and path.

**Groups and roles.** Entra emits neither by default.

- *App roles* — define them on the app registration, assign users in the
  enterprise app, and they arrive in the `roles` claim. Set `role_claim` to
  `roles`. Values are the role's **Value** field, so they are readable.
- *Groups* — Token configuration → Add groups claim. They arrive in `groups`
  as **object GUIDs**, not names, unless you select group names for
  synchronised groups. Set `role_claim` to `groups` and write rules against the
  GUIDs.

> **The groups overage.** If a user is in more than roughly 150 groups (SAML) or
> 200 (JWT), Entra drops the `groups` claim entirely and sends `_claim_names`
> and `_claim_sources` pointing at Microsoft Graph instead. This app does not
> follow that link — the dashboard will show no groups and your rules will not
> match. Use app roles, or a group filter, for anyone likely to hit that.

**Which claim identifies the user.** This matters, and the default is not the
best choice:

| Claim | Stable? | Use it for |
|---|---|---|
| `oid` | **Yes** — immutable directory object id | `subject_claim` |
| `sub` | Stable, but pairwise per application | Nothing that must match another system |
| `preferred_username` / `upn` | **No** — changes on rename | `email_claim`, display |

Set `subject_claim` to `oid`. `sub` is scoped to the application, so it will
never equal anything SCIM knows about the same person.

### SAML

Create an **Enterprise application** → Single sign-on → SAML.

| Entra field | Paste from the AuthLab connection page |
|---|---|
| Identifier (Entity ID) | SP entity ID — the metadata URL, unless you set your own |
| Reply URL (ACS) | `.../auth/saml/<slug>/acs` |
| Logout URL | `.../auth/saml/<slug>/sls` |

Then back into AuthLab:

| Field in AuthLab | Value |
|---|---|
| IdP entity ID | `https://sts.windows.net/<tenant-id>/` (Entra shows it as *Microsoft Entra Identifier*) |
| IdP sign-on URL | `https://login.microsoftonline.com/<tenant-id>/saml2` |
| IdP single logout URL | `https://login.microsoftonline.com/<tenant-id>/saml2` |
| IdP signing certificate | SAML Signing Certificate → **Certificate (Base64)** |

Entra will also import the SP metadata URL directly, which fills in the entity
ID, ACS, and logout URL for you.

Useful claim URNs for role mapping and expectations:

```
http://schemas.microsoft.com/identity/claims/objectidentifier   immutable object id
http://schemas.microsoft.com/identity/claims/tenantid           tenant
http://schemas.microsoft.com/ws/2008/06/identity/claims/groups  groups
http://schemas.microsoft.com/claims/authnmethodsreferences      the SAML equivalent of amr
```

That last one is what to point an expectation at when asserting that MFA
actually happened over SAML.

### NameID stability — the thing that quietly breaks

**Entra's default SAML NameID is the user principal name.** A UPN is not
immutable. It changes when somebody is renamed, when a domain is rebranded, or
when a mailbox is migrated. When it changes:

- the user comes back looking like a brand new person;
- their session no longer matches their provisioned SCIM record;
- role mapping via SCIM groups stops working;
- deprovisioning may not revoke the session you expect.

There is a second failure mode. If you set the NameID **format** to `Persistent`
without changing the source attribute, Entra emits a pairwise identifier that is
stable *for that enterprise application* — and is regenerated if the application
is deleted and recreated. Rebuilding your test app silently orphans every
provisioned record.

**The fix, at both ends:**

1. **In Entra**, edit the NameID claim: set the source attribute to
   `user.objectid`. The object id is a GUID that never changes for the lifetime
   of the account, survives renames, and survives recreating the application.

2. **In AuthLab**, set `subject_claim` to the object id claim rather than
   leaving it on `nameId`:

   ```
   http://schemas.microsoft.com/identity/claims/objectidentifier
   ```

   Use this even if you did not change the NameID — Entra sends the object id
   as an additional claim regardless, so you can key on it without touching the
   Entra configuration at all. This is the lower-risk option if the enterprise
   application is shared with anything else.

3. **In the SCIM mapping**, map `externalId` to `objectId`. Entra's default for
   `externalId` varies by template and is often `mailNickname`, which is
   mutable. Aligning it on `objectId` means the session's subject and the
   provisioned record's `externalId` are the same immutable GUID.

With all three aligned, a rename is invisible to the app: sign-in, role
mapping via SCIM groups, and deprovisioning all keep working. There are tests
covering exactly this in
[tests/test_scim_protocol_independence.py](../tests/test_scim_protocol_independence.py)
— one showing a UPN-keyed session losing its link after a rename, and one
showing an object-id-keyed session surviving it.

Keep `email_claim` pointed at the email or UPN claim. It is still the right
thing to *display*, and it gives identifier matching a second route.

### SCIM

Enterprise application → **Provisioning** → Automatic. Requires Entra ID P1 or
above.

| Entra field | Value |
|---|---|
| Tenant URL | `<BASE_URL>/scim/v2` — shown under Admin → SCIM |
| Secret Token | Generated under Admin → SCIM, shown once |

Press **Test Connection** before saving. Entra probes the endpoint and will
tell you plainly if it cannot reach it — which, if you are running locally
without a tunnel, it cannot.

Two things worth doing:

- Append `?aadOptscim062020` to the tenant URL. This opts into Entra's stricter,
  more standards-compliant SCIM behaviour, and is generally what you want when
  testing a real SCIM implementation rather than working around old quirks.
- Change the `externalId` mapping to `objectId`, per the NameID section above.

Every request Entra sends is recorded with its payload under **Admin → SCIM**,
which is the fastest way to see what your attribute mappings actually produce.

Entra's two well-known quirks are already handled and covered by tests: it sends
`Content-Type: application/scim+json` rather than `application/json`, and it
sends `active` as the **string** `"False"` when deactivating.

---

## Okta

### OIDC

Applications → Create App Integration → **OIDC** → Web Application.

| Field in AuthLab | Value |
|---|---|
| Issuer | `https://<org>.okta.com/oauth2/default`, or your custom authorization server |
| Client ID / secret | From the app's General tab |
| Scopes | `openid profile email groups` |

Set the Sign-in redirect URI to the callback shown on the connection page.

**Groups need to be added to the authorization server**, not just the app.
Security → API → your authorization server → Claims → Add Claim:

- Name `groups`, include in **ID Token**, value type **Groups**,
  filter **Matches regex** `.*` (narrow this in anything real).

Without that claim the token carries no groups and your rules will not match —
the dashboard will list the claims that *are* present, which is the giveaway.

Set `role_claim` to `groups`. Okta sends group **names**, so rules read nicely.

For identity, `sub` is stable in Okta and is a reasonable `subject_claim`;
`preferred_username` is the login and can change.

### SAML

Applications → Create App Integration → **SAML 2.0**.

| Okta field | Paste from the connection page |
|---|---|
| Single sign-on URL | `.../auth/saml/<slug>/acs` |
| Audience URI (SP Entity ID) | SP entity ID |
| Name ID format | EmailAddress |

Add a **Group Attribute Statement** — name it `groups`, filter Matches regex
`.*` — or groups will not be asserted at all.

Then, from Okta's Sign On tab → View SAML setup instructions:

| Field in AuthLab | Value |
|---|---|
| IdP entity ID | Identity Provider Issuer |
| IdP sign-on URL | Identity Provider Single Sign-On URL |
| IdP signing certificate | X.509 Certificate |

For single logout, enable it in Okta's SAML settings and give it
`.../auth/saml/<slug>/sls` plus Okta's signature certificate.

### SCIM

Requires Okta Lifecycle Management, and the app integration must have SCIM
provisioning enabled — create it as a SCIM-capable app, or enable
**Provisioning** on a custom app.

General → App Settings → Provisioning → SCIM, then Configure API Integration:

| Okta field | Value |
|---|---|
| SCIM connector base URL | `<BASE_URL>/scim/v2` |
| Unique identifier field for users | `userName` |
| Authentication Mode | HTTP Header |
| Authorization | `Bearer <token from Admin → SCIM>` |

Enable Push New Users, Push Profile Updates, Push Groups, and Deactivate Users
as needed. **Test API Credentials** verifies reachability.

Okta uses `PUT` for updates rather than `PATCH` in some configurations; both
are implemented.

---

## Auth0

Auth0 is an SSO provider here. It does **not** do outbound SCIM provisioning to
downstream applications — its SCIM support is for *receiving* provisioning into
Auth0 from a directory. If you need provisioning tested alongside Auth0
sign-in, provision from Entra ID or Okta directly.

### OIDC

Applications → Create Application → **Regular Web Application**.

| Field in AuthLab | Value |
|---|---|
| Issuer | `https://<tenant>.<region>.auth0.com/` — **keep the trailing slash** |
| Client ID / secret | Application settings |
| Scopes | `openid profile email` |

Add the callback URL to **Allowed Callback URLs**, and your `BASE_URL` to
**Allowed Logout URLs** so federated sign-out returns cleanly.

The trailing slash matters: Auth0's `iss` claim includes it, and the app
validates the issuer against the discovery document exactly.

**Groups and roles are not in the token by default.** Auth0 requires an Action
(or Rule, on older tenants) to add them, under a namespaced claim:

```js
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim("https://authlab.example/roles", event.authorization?.roles ?? []);
};
```

Set `role_claim` to the full namespaced URI. Auth0 silently drops non-namespaced
custom claims, which is a common source of "the claim just is not there".

### SAML

Auth0 acts as the IdP through the **SAML2 Web App** addon on an application.

| Field in AuthLab | Value |
|---|---|
| IdP entity ID | `urn:<tenant>.auth0.com` |
| IdP sign-on URL | `https://<tenant>.auth0.com/samlp/<client-id>` |
| IdP signing certificate | Tenant Settings → Advanced → download the signing certificate |

In the addon settings, set the callback to the ACS URL from the connection page.

---

## AWS Cognito

Cognito is an OIDC provider. It is a SAML **service provider** — it federates
*to* external SAML IdPs — so it cannot act as the SAML IdP for this app. It also
has no outbound SCIM provisioning. Use it for OIDC sign-in.

### OIDC

| Field in AuthLab | Value |
|---|---|
| Issuer | `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` |
| Client ID / secret | App client — enable "Generate a client secret" when creating it |
| Scopes | `openid profile email` |

You must configure a **Hosted UI domain** on the user pool. Without one there is
no authorization endpoint to redirect to. Run **Test configuration** after
saving the connection: it prints the endpoints Cognito advertises, and a missing
or unexpected `authorization_endpoint` there tells you the domain is the problem
before you burn a browser round trip on it.

Add the callback URL to the app client's **Allowed callback URLs**, and enable
the Authorization code grant.

**Groups** arrive in the `cognito:groups` claim, as group names. Set
`role_claim` to `cognito:groups`.

Note that Cognito's `sub` is a pool-scoped UUID and is stable — a good
`subject_claim`. It will not match anything an external directory knows, so if
you are also provisioning from elsewhere, match on email.

---

## Duo

Duo Single Sign-On acts as a SAML or OIDC identity provider, typically in front
of another directory. It does not do outbound SCIM provisioning — Duo
synchronises users *from* a directory rather than pushing them onward.

Duo is also frequently deployed as an MFA layer in front of another IdP rather
than as the IdP itself. In that arrangement you connect to the upstream provider
normally, and Duo shows up in the authentication context rather than in the
connection settings.

### SAML

In the Duo Admin Panel, add a **Generic SAML Service Provider** application.

| Duo field | Paste from the connection page |
|---|---|
| Entity ID | SP entity ID |
| Assertion Consumer Service | `.../auth/saml/<slug>/acs` |
| Single Logout URL | `.../auth/saml/<slug>/sls` |

Duo then gives you the entity ID, SSO URL, and certificate to paste back. Duo
can also produce SP metadata import, and will accept the metadata URL from the
connection page.

Configure the attribute map so that at minimum an email address and a groups
attribute are asserted, then set `email_claim` and `role_claim` to the names Duo
uses.

### OIDC

Duo SSO supports OIDC relying parties. Add a **Generic OIDC Relying Party** and
paste the discovery or issuer URL Duo shows into the Issuer field — the app
accepts a full `.../.well-known/openid-configuration` URL and strips the suffix,
so you can paste whichever the console gives you. Then **Test configuration** to
confirm what it advertises.

### Asserting that Duo actually challenged

This is the interesting part for Conditional Access work. Whatever sits in front
of Duo, the outcome you care about is whether a second factor really happened.
Add an expectation to the connection:

- SAML: claim `authnContextClassRef`, operator `contains`, value `MultiFactor`
- OIDC: claim `amr`, operator `contains`, value `mfa`

Then every sign-in through that connection reports pass or fail instead of
leaving you to interpret a claim dump.

---

## Any other provider

**OIDC.** Find the issuer URL. Everything else — endpoints, JWKS, supported
scopes, the logout endpoint — comes from
`{issuer}/.well-known/openid-configuration`. Paste the issuer (or the full
discovery URL) and press Test configuration. If that succeeds, the flow will
work; if it fails, the error names what could not be reached.

**SAML.** You need three values: the IdP entity ID, the sign-on URL, and the
signing certificate (PEM or bare base64, both accepted). Give the provider the
SP metadata URL from the connection page and most consoles will fill in the rest
themselves.

**SCIM.** You need two: the tenant URL `<BASE_URL>/scim/v2` and a bearer token
from Admin → SCIM. The endpoints implement `/Users`, `/Groups`,
`/ServiceProviderConfig`, `/ResourceTypes`, and `/Schemas`, so a compliant
connector can discover what is supported rather than being told.

---

## Running several connections at once

Every connection is independent. Enable as many as you like and the sign-in page
shows a button for each — which is how you compare two providers, or the same
provider across two tenants, without tearing anything down.

They share one SCIM store. That is deliberate: a person exists once, however
many ways they can sign in. Matching is by `userName`, email, and `externalId`
against the session's subject and email, so the same provisioned record resolves
through every connection that asserts one of those values.

Mint **one SCIM token per provisioning source** under Admin → SCIM. Each request
is then attributed to the system that made it in the activity log, and you can
revoke one without disturbing the others.

For sign-in, the practical advice for a multi-connection setup is:

- Give every connection a `subject_claim` that is stable and, ideally, the same
  identifier your provisioning source uses as `externalId`.
- Use **Admin → Compare sessions** to diff two sign-ins claim by claim when a
  policy applies to one and not the other.
