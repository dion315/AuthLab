# AuthLab

A small weather app wrapped around a complete authentication stack — OIDC/OAuth 2.0,
SAML 2.0, SCIM 2.0 provisioning, and role-based access control — built so you can
point a real identity provider at it and watch exactly what happens.

Three things make it useful rather than just another sample:

**Nothing about your identity provider is baked in at deploy time.** Issuers,
client secrets, signing certificates, claim-to-role rules, and provisioning
tokens all live in the database and are edited from an admin console while the
app is running. Changing a role mapping and retrying a sign-in takes seconds.

**There is always a local account.** It authenticates against the app directly,
with no identity provider involved. When a Conditional Access policy blocks your
federated sign-in — frequently the outcome you were testing for — you can still
get in and change the configuration that locked you out.

**A test produces a result, not an impression.** Attach expectations to a
connection ("`amr` must contain `mfa`", "the role must come out as admin") and
every sign-in reports pass or fail. Export the activity log as JSON or CSV and
attach it to a change record. Run the whole thing from a pipeline.

```bash
docker compose up --build
```

That is the whole local setup. No database service, no cloud account, no
identity provider needed to start. The app comes up at http://localhost:8000
and prints a generated administrator password to the log on first run.

---

## Contents

- [Quick start](#quick-start)
- [How the code is organised](#how-the-code-is-organised)
- [Connecting an identity provider](#connecting-an-identity-provider)
- [Deciding who gets which role](#deciding-who-gets-which-role)
- [SCIM provisioning](#scim-provisioning)
- [Testing Conditional Access](#testing-conditional-access)
- [Step-up and authentication contexts](#step-up-and-authentication-contexts)
- [Service and API access](#service-and-api-access)
- [The automation API](#the-automation-api)
- [Deploying](#deploying)
- [API reference](#api-reference)
- [Running the tests](#running-the-tests)
- [Security notes](#security-notes)
- [Known limitations](#known-limitations)

Two longer guides live in [docs/](docs/):
[connecting providers](docs/providers.md) (Entra ID, Okta, Auth0, Cognito, Duo —
for OIDC, SAML, and SCIM) and
[URLs and reachability](docs/deployment-urls.md) (`BASE_URL`, what works on
localhost and what cannot, and running a test across an organisation).

---

## Quick start

```bash
docker compose up --build
```

Watch the log for the administrator password:

```
====================================================================
  Local administrator created
    email:    admin@authlab.local
    password: xY3k...
  Sign in at http://localhost:8000/login
====================================================================
```

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into APP_SECRET_KEY
```

### The administrator password

This is the account that still works when a Conditional Access policy blocks
federated sign-in, so it is deliberately easy to recover. There are three
states, reconciled on every start:

| `BOOTSTRAP_ADMIN_PASSWORD` | What happens |
|---|---|
| Set | That is the password. Reapplied every start, so editing `.env` and restarting is a supported way back in. Never written to the log — it is already in a file you control. |
| Blank | The app generates one, and **reissues and prints it on every start**. Missing the banner in a wall of container output costs a restart, not the account. |
| Blank, but you changed the password in the console | Left alone. Startup will not overwrite a password somebody chose, and cannot display it — it is an Argon2 hash. |

A generated password is therefore in your container log, and in anything
collecting it. That is a fair trade for a harness you take apart and rebuild,
and it is the reason to set `BOOTSTRAP_ADMIN_PASSWORD` for anything that lives
longer than an afternoon.

To take an account back after someone has changed its password, put a value in
`BOOTSTRAP_ADMIN_PASSWORD` and restart. That also re-enables the account if it
had been disabled, since a recovery password is no use if the account it opens
is switched off.

Admin → Local accounts shows which state each account is in, and can require a
password change at next sign-in when you reset one for somebody else.

To run against Postgres instead of the default SQLite:

```bash
docker compose --profile postgres up --build
```

### Without Docker

```bash
# SAML needs the xmlsec1 system library
sudo apt-get install pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl
# macOS: brew install libxmlsec1 pkg-config

python -m venv .venv && source .venv/bin/activate
pip install --no-binary lxml,xmlsec lxml xmlsec
pip install -e ".[dev]"

export APP_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
python -m app.main
```

The `--no-binary` step matters on Linux and macOS: `lxml` and `xmlsec` must be
compiled against the same `libxml2`, and mixing prebuilt wheels produces a
version-mismatch error at import time that is hard to diagnose from the message
alone. On Windows the published wheels are self-contained and a plain
`pip install -e ".[dev]"` works.

---

## How the code is organised

Worth a read if you are using this as a reference for your own work — the layout
is meant to keep each protocol concern in one obvious place.

```
app/
  main.py             FastAPI app, middleware, error handlers, routing
  config.py           Bootstrap settings only (everything else is runtime config)
  db.py               SQLAlchemy engine and session management
  schema_sync.py      Additive column reconciliation for an existing database
  models.py           All persistence: connections, SCIM users, sessions, events
  crypto.py           Fernet encryption for IdP secrets held in the database
  security.py         Password hashing, bearer tokens, sessions, client IP
  redirects.py        Safe handling of caller-supplied return paths
  deps.py             FastAPI dependencies: require_login, require_role
  ratelimit.py        Throttle for local password sign-in
  events.py           The authentication/provisioning audit trail
  templating.py       Jinja2 setup; autoescaping asserted on at import

  auth/
    schemas.py        Pydantic models validating per-protocol settings
    connections.py    Loading/saving connections, encryption, import/export
    rolemap.py        Claims or SCIM groups -> application role (pure functions)
    scimlink.py       Linking a session to the SCIM user provisioned for it
    expectations.py   Asserting what a sign-in should have produced (pure)
    lifetimes.py      Decoding token time claims against our own session
    oidc.py           Discovery, PKCE, token exchange, ID token validation
    apitoken.py       Access token validation — the resource-server side
    saml.py           SP metadata, AuthnRequest, assertions, single logout
    flowstate.py      Signed short-lived cookies carrying in-flight login state
    router.py         Sign-in, sign-out, callbacks, SLS

  scim/
    schemas.py        SCIM 2.0 resource shapes
    filters.py        A real SCIM filter parser (tokeniser + recursive descent)
    router.py         Users, Groups, ServiceProviderConfig, ResourceTypes, Schemas

  providers.py        Per-provider vocabulary and setup steps (one source for
                      the form hints and the in-app guides)

  routes/
    pages.py          Landing page, dashboard, weather proxy, health checks
    account.py        Self-service password change, step-up challenge page
    help.py           The in-app setup guides
    admin.py          The admin console
    api.py            The automation API

  templates/          Jinja2, autoescaping on
  static/             CSS and JS as real files, so the CSP needs no 'unsafe-inline'

docs/                 Per-provider setup, and URLs/reachability
terraform/            Azure, AWS, and GCP modules
tests/                348 tests
```

A few decisions your developers may find worth copying:

**Session state is server-side, not a self-contained JWT.** A signed cookie
carries only an opaque session id. This is what makes revocation possible — when
SCIM deactivates a user, their live sessions end immediately instead of staying
valid until a token expires. It also means the full claim set can be kept and
displayed, which routinely exceeds the 4KB cookie limit.

**Role mapping is a pure function.** `app/auth/rolemap.py` takes a connection,
a claims dictionary, and an optional list of SCIM group names, and returns a
role plus a trace of every rule it evaluated. No database, no request object, so
the awkward cases — scalar-versus-list claims, rule ordering, providers that put
groups somewhere unusual — are cheap to test and the dashboard can show its
work. The SCIM lookup happens in the caller precisely to keep it that way.

**Errors from the identity provider are preserved verbatim.** `OidcError` and
`SamlError` carry the provider's own code and description through to a page that
displays them. For Conditional Access work that string *is* the test result.

**Nothing that can fail at request time takes the process down.** Every handler
that talks to an IdP catches its own errors, and `main.py` has a catch-all. A
typo in an issuer URL produces a 502 page, not a crash loop.

---

## Connecting an identity provider

Sign in with the local account, then **Admin → Add OIDC connection** (or SAML).
Several connections can be enabled at once; the sign-in page shows a button for
each, which makes comparing two providers or two tenants straightforward.

### OIDC — any compliant provider

The only value you must find by hand is the issuer URL. Everything else comes
from `{issuer}/.well-known/openid-configuration`.

| Provider | Issuer URL |
|---|---|
| Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Okta | `https://<org>.okta.com/oauth2/default` |
| Auth0 | `https://<tenant>.auth0.com/` |
| Google | `https://accounts.google.com` |
| Keycloak | `https://<host>/realms/<realm>` |
| Ping | `https://auth.pingone.com/<env-id>/as` |

Pasting the full discovery URL works too — the suffix is stripped.

**The app has the setup guides built in.** Tell a connection which product is
at the other end and every field shows that product's own wording beside it —
"Issuer" here is "Directory (tenant) ID" at Entra, "Audience URI" at Okta — and
**Help** carries step-by-step instructions with your own redirect URI and ACS
URL already substituted in and copyable. Covers Entra ID, Okta, Auth0, AWS
Cognito, Duo, and generic providers, for OIDC, SAML, and SCIM, and says plainly
which of them cannot send SCIM at all.

[docs/providers.md](docs/providers.md) is the same material as prose, for
reading outside the app.

The connection page shows the exact redirect URI to register at the provider.
It is derived from `BASE_URL`, so if that is wrong you will get a redirect-URI
mismatch — that is the first thing to check when a flow fails.

**Test configuration** fetches the discovery document and lists the endpoints
the provider advertises, without starting a browser flow. Catching a typo there
saves a lot of round trips. The same check is available headlessly — see
[the automation API](#the-automation-api).

### SAML

Provide the IdP entity ID, sign-on URL, and signing certificate (PEM or bare
base64, both accepted). The connection page exposes an **SP metadata URL** that
most IdP consoles will import, filling in entity ID, ACS URL, SLS URL, and
NameID format for you.

`InResponseTo` is genuinely validated for SP-initiated flows — the AuthnRequest
ID is kept in a signed, short-lived cookie and checked when the assertion comes
back. Accepting IdP-initiated sign-in disables that replay protection, so it is
an explicit per-connection opt-in rather than a default.

**Single logout works in both directions.** `/auth/saml/{slug}/sls` receives the
provider's `LogoutResponse` after an SP-initiated sign-out, with the same
`InResponseTo` validation the sign-in flow uses; and it handles an unsolicited
`LogoutRequest` when the user signs out at the IdP or at another application,
terminating the session here and returning a signed `LogoutResponse`. Register
the SLS URL at the provider — it is on the connection page — or single logout
will end at a 404 on the provider's side.

---

## Deciding who gets which role

Point `role_claim` at whatever carries group or role information, then add
ordered rules. First match wins.

| Provider | Typical claim |
|---|---|
| Entra ID | `roles` (app roles) or `groups` (object IDs) |
| Okta | `groups` |
| Shibboleth | the full attribute URN, e.g. `urn:oid:1.3.6.1.4.1.5923.1.5.1.1` |
| Keycloak | `realm_access.roles` (dotted paths work) |

Operators are `equals`, `contains`, `starts_with`, and `regex`. The dashboard
shows which rule matched and why — and if the claim was not in the token at all,
it lists the claims that *were*, which is usually the answer.

### Claims, SCIM groups, or both

`role_source` chooses what those rules are evaluated against:

| Value | Behaviour |
|---|---|
| `claims` | The token or assertion only. |
| `scim` | SCIM-provisioned group membership only. |
| `claims_then_scim` | Exhaust the rules against the token, then fall back to SCIM groups. |

The SCIM sources exist because a great many real applications authorise against
the groups a provisioning connector pushed them rather than against anything in
the token: the token says who you are, the directory sync says what you can do.
Choosing one lets you test that whole loop — provision a user into a group, sign
in, gain the role, remove them from the group, lose it.

The join between a session and its SCIM user is by identifier, because there is
no point at which the two systems agree on one: `userName`, email, and
`externalId` are all tried, case-insensitively. **If your `subject_claim` is
`sub` this will not match**, because Entra ID's `sub` is a pairwise pseudonymous
identifier scoped to the application and is never equal to a UPN. Point it at
`preferred_username` or `email`. The dashboard says so explicitly when it fails
to find a link, and lists the identifiers it looked for.

### Asserting the outcome

A connection can carry an expected role and any number of claim expectations —
the same operator vocabulary as role rules, plus `present` and `absent`:

```
amr  contains  mfa      "multi-factor actually happened"
tid  equals    <guid>   "the user came from our directory"
```

Every sign-in through that connection is checked against them and reported as
pass or fail, on the dashboard and in the activity log — where a failed
expectation is recorded with outcome `denied`, so it shows up red and can be
filtered for. That is what turns "sign in and read the claims" into a
regression test you re-run after a policy change, and into a result you can hand
to someone who was not watching your screen.

A connection with no expectations reports nothing rather than reporting success,
because a green tick nobody configured would read as evidence that a policy
applied.

---

## SCIM provisioning

**SCIM is independent of OIDC and SAML.** It is a separate protocol with its own
bearer-token authentication, and the provisioning endpoints hold no reference to
a connection at all. Run it alongside an OIDC connection, a SAML connection,
several of each at once, or with nothing configured for sign-in — provisioning
works standalone, which is often the order you want to work in anyway.

What varies is whether a given product can *send* SCIM: Entra ID and Okta can,
Auth0, Cognito, and Duo cannot. [docs/providers.md](docs/providers.md) has the
matrix and the setup for each.

**Admin → SCIM** generates a bearer token (shown once) and displays the tenant
URL to paste into your provider's provisioning configuration.

> Provisioning is the one feature that cannot be tested against a purely local
> deployment. Sign-in is carried by your browser, so `localhost` is fine; SCIM
> is a direct call from the provider's servers to yours, so it needs a publicly
> reachable URL — a tunnel, or a real deployment. See
> [docs/deployment-urls.md](docs/deployment-urls.md).

Implemented: `/Users` and `/Groups` with full CRUD and PATCH,
`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, filtering, and pagination.

The filter support is a real parser rather than a regex — `eq ne co sw ew pr`,
`and`, `or`, `not`, and grouping all work. Anything it cannot evaluate faithfully
returns a `400` naming the unsupported construct, because a filter that silently
matches the wrong set is far worse than one that errors.

Two details that trip up hand-rolled SCIM servers, both covered by tests:

- Entra ID sends `Content-Type: application/scim+json`, not `application/json`.
- Entra ID sends `active` as the **string** `"False"` in the deactivation PATCH.
  Treating that as truthy leaves deprovisioned users enabled.

Deactivating or deleting a user through SCIM revokes their live sessions
immediately. Revocation matches on `userName`, email, and `externalId` against
both the session's subject and its email, case-insensitively — all of them,
because a federated session's subject is usually a pairwise identifier that
matches none of the values SCIM knows the user by. Matching on subject alone
revoked nothing and reported "revoked 0 sessions" without complaint.

Every provisioning request is recorded with its payload under **Admin → SCIM**,
which is the fastest way to see the exact shapes your provider sends.

---

## Testing Conditional Access

This is what the app is really for.

**See what the provider asserted.** The dashboard shows the complete claim set,
and calls out the ones that matter for policy evaluation — `amr` (which
authentication methods were actually used), `acr`, `auth_time`, `ipaddr`,
`deviceid`, `tid`. If `amr` does not contain `mfa`, the policy did not apply.

**Read denials properly.** When a policy blocks a sign-in, the provider redirects
back with an error rather than a code. That lands on a page showing the error and
description as sent — `AADSTS53003`, `access_denied`, and so on — and the same
detail is kept under **Activity**.

**Force re-authentication.** The dashboard has per-attempt buttons that add
`prompt=login`, `acr_values=mfa`, `max_age=0`, or SAML `ForceAuthn` without
changing the saved connection. Use these to check that a policy actually
challenges instead of silently passing.

**Sign out for real.** Local sign-out leaves the provider session intact, so the
next sign-in completes silently and you cannot retest anything. **Sign out
everywhere** ends the session at the provider too.

**Check the source IP.** Source IP is a policy condition, and behind a load
balancer it is easy to get wrong. The dashboard shows the address the app
recorded next to the `ipaddr` claim the provider saw. If they disagree,
`TRUST_PROXY_HEADERS` or your proxy configuration needs attention.

**Watch both clocks.** The dashboard decodes `iat`, `nbf`, `exp`, and
`auth_time` to real times and puts the app's own session expiry beside them. If
the session outlives the token — which it does by default — it says so, because
that gap is the reason revocation has to be server-side rather than left to
token expiry.

**Diff two attempts.** **Admin → Compare sessions** puts two sign-ins
side by side and marks every claim added, removed, or changed. When one attempt
satisfied a policy and another did not, the difference is usually two or three
claims, and this finds them instead of you reading two JSON dumps.

---

## Step-up and authentication contexts

`/step-up` is a protected action that demands a stronger authentication context
than an ordinary sign-in provides, and issues a challenge when the session does
not have one. It is the shape of an Entra ID authentication context or a step-up
ACR request: the user is already signed in, but *this particular action* requires
more.

Configure the condition on the connection — a claim, an operator, and a required
value (`amr contains mfa`) — plus what to ask for when it is not met:

- **`acr_values`** for most providers.
- **A claims challenge** for Entra ID authentication contexts: the raw `claims`
  request parameter, carrying the context id (`c1`, `c2`, …) you assigned to a
  Conditional Access policy.

The challenge always includes `prompt=login`. Without it a provider with a live
session will frequently return the existing authentication context unchanged,
and the test passes without anything having been challenged — which looks
exactly like success.

The return path is carried through the round trip as a `return_to` parameter,
validated as a local path before it goes anywhere near a cookie. An open
redirect on a sign-in endpoint is worth more to an attacker than almost
anywhere else, so anything with a scheme, an authority, or a backslash is
discarded rather than parsed and normalised.

---

## Service and API access

**Admin → Service access** is the resource-server half of OAuth — the part no
browser flow exercises. Most application-to-application access in an enterprise
is a service principal getting a token and presenting it to an API, and none of
the interactive flow tells you anything about it.

**Inspect an access token.** Paste one from anywhere and every check is reported
separately: signature against the issuer's published keys, `iss`, `aud`,
`exp`, `nbf`. A rejection names which check failed rather than saying "invalid".
The `scp`, `roles`, `appid`, and `idtyp` claims are pulled out on their own,
since those are what an API actually authorises on — `scp` is delegated scope,
`roles` is application permission with no user involved.

**Run a client_credentials grant.** Mints a token as the application itself
using the connection's client ID and secret, then inspects it. A public client
(PKCE, no secret) is refused, which is itself worth demonstrating.

Only asymmetric algorithms are accepted. Allowing an HMAC alongside RSA is the
classic JWT confusion attack, where an attacker signs a token using the public
key as an HMAC secret.

One provider-specific trap worth knowing, because it costs people a day: an
Entra ID access token issued for **Microsoft Graph** cannot be validated by
anyone but Graph — its signature covers a nonce only Microsoft holds, so the
check fails no matter what you do. Tokens issued for an API you expose on your
own app registration validate normally.

---

## The automation API

The console is the right interface for the first hour with a new provider and
the wrong one afterwards. **Admin → Automation** mints scoped bearer tokens for
everything below. An administrator session cookie is accepted anywhere a token
is, which is what lets the console's own download links work with no separate
credential.

| Method | Path | Scope |
|---|---|---|
| GET | `/api/admin/events` | `events:read` |
| GET | `/api/admin/sessions` | `sessions:read` |
| GET | `/api/admin/connections` | `connections:read` |
| POST | `/api/admin/connections` | `connections:write` |
| POST | `/api/admin/connections/{slug}/test` | `connections:read` |

**Evidence.** The activity log as JSON or CSV, filterable by kind, outcome, and
time. CSV keeps `detail` as a JSON string in its own column rather than dropping
it, because that is where the provider's error code lives.

```bash
curl -H "Authorization: Bearer $AUTHLAB_TOKEN" \
  "$BASE_URL/api/admin/events?format=csv&kind=login_failure&since_minutes=1440" \
  -o evidence.csv
```

**Portable connections.** Export a working connection as JSON and import it
somewhere else — a colleague's instance, a fresh deployment, a pipeline that
stands up a known state before it asserts anything. Matching is by `slug`, so an
import updates rather than duplicates.

Secrets are never exported. They are also never *cleared* by an import: a
definition with no `client_secret` leaves whatever is already stored alone, so
re-importing a config over a working one does not break it. The import response
names which secrets still need entering at the destination.

```bash
curl -H "Authorization: Bearer $AUTHLAB_TOKEN" \
  "$BASE_URL/api/admin/connections?slug=entra" > entra.json

curl -H "Authorization: Bearer $AUTHLAB_TOKEN" -H "Content-Type: application/json" \
  -X POST --data-binary @entra.json "$BASE_URL/api/admin/connections"
```

**Configuration checks in CI.** `POST /api/admin/connections/{slug}/test` runs
the discovery or metadata check and returns `200` with `ok: true|false`. Branch
on `ok`, not on the status code — a misconfigured *provider* is a verdict the
check successfully produced, and non-2xx is reserved for the check not running
at all.

API tokens are deliberately separate from SCIM provisioning tokens. A
provisioning connector should not be able to rewrite your identity provider
configuration.

---

## Deploying

Terraform modules for all three clouds, each deploying the same image with the
same environment contract:

| Cloud | Compute | Database | Secrets |
|---|---|---|---|
| Azure | Container Apps (scale-to-zero) | Postgres Flexible Server | Key Vault |
| AWS | App Runner | RDS Postgres | Secrets Manager |
| GCP | Cloud Run (scale-to-zero) | Cloud SQL Postgres | Secret Manager |

```bash
cd terraform/examples/azure     # or aws, or gcp
cp terraform.tfvars.example terraform.tfvars
terraform init && terraform apply
```

[docs/deployment-urls.md](docs/deployment-urls.md) covers what `BASE_URL`
produces, what each platform's assigned hostname looks like, which features need
the app to be reachable *from the provider* rather than from your browser, and a
symptom-to-cause table for when a flow fails for reasons the error does not
explain.

### Getting a predictable URL

The app derives its redirect URIs, SAML ACS URLs, and SCIM tenant URL from
`BASE_URL`, which must equal its own public URL — and that URL wants to be
stable, so it can be registered at a provider once and circulated to whoever is
testing.

| Cloud | URL known before deploy? | Passes |
|---|---|---|
| Azure Container Apps | Yes — composed from the environment's domain, created first | **One** |
| GCP Cloud Run | Yes — deterministic, no random component | **One** |
| AWS App Runner | No — random subdomain minted at creation | Two, or a custom domain |

Azure and GCP come up correct on the first `apply`. App Runner needs a second
one: read `generated_url`, set `base_url_override`, apply again. Every module
has a `next_step` output that says exactly what to do, and `url_is_predictable`
confirming the computed URL matched what the platform assigned.

Rather than copying URLs out of the admin console, read them from Terraform:

```bash
terraform output login_url          # the link to hand to testers
terraform output idp_configuration  # every URL to register at the provider
```

Set `custom_domain` for anything beyond an afternoon. It survives the service
being recreated, keeps registered redirect URIs valid, and is a link colleagues
will actually click — a random cloud hostname asking for corporate credentials
reads as phishing. Terraform does not create the DNS records; `custom_domain_dns`
lists them.

`terraform/README.md` has the details, including what to fix before using any of
this for something real — chiefly that Terraform state holds secrets in
plaintext and the databases default to public endpoints.

### Upgrading over an existing database

`create_all` builds missing tables but never alters an existing one, so a
release that adds a column would otherwise leave a populated database unreadable.
On startup the app reconciles that additively: it adds columns present in the
models but missing from the table, and backfills existing rows with the model's
default. It logs what it added. Nothing is ever dropped, renamed, or retyped.

That covers the only case a harness actually hits. Anything beyond it — dropping
a column, changing a type, backfilling from another table — is a real migration
and wants Alembic; the models are ordinary SQLAlchemy so that is a drop-in
addition.

### CI

`azure-pipelines.yml` lints, runs the tests, validates all three Terraform
configurations, then builds and pushes the image. Deployment is a separate stage
gated on an ADO environment approval, and fails the build if the new revision
does not pass its health check.

---

## API reference

A running instance serves the generated OpenAPI reference at **`/docs`**. It is
the browsable spec for the SCIM and automation endpoints — request shapes,
parameters, and response schemas — without anyone having to write one.

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests -q
ruff check app tests
```

348 tests, covering the SCIM request shapes real connectors send (including the
two Entra quirks above), the filter parser, role mapping from both claims and
SCIM groups, expectation evaluation, session revocation across mismatched
identifiers, access token validation, the automation API and its scopes, schema
reconciliation, the open-redirect guard, authorisation guards, output escaping,
secret encryption, administrator password reconciliation across restarts,
SCIM's independence from both SSO protocols, Entra NameID stability, the
consistency of the provider guides, and that every page renders.

---

## Security notes

What is deliberate, in case you are adapting this:

- **Templates autoescape.** IdP display names and SCIM attributes are
  attacker-influenced — anyone holding a provisioning token can set
  `displayName` to anything. There is a test asserting they are escaped.
- **The CSP is strict**: `default-src 'self'` with no `unsafe-inline` and no
  nonce. That is only possible because all CSS and JS are real files and the
  weather call is proxied server-side. A policy you have to loosen to make the
  app work is not doing much. Note that `style-src 'self'` blocks inline
  `style=` attributes as well as `<style>` blocks, so the templates use utility
  classes instead — an inline style here is silently dropped by the browser and
  the layout quietly goes wrong.
- **Return paths are validated as local paths**, not as URLs whose host happens
  to match. Every open-redirect bug of the last decade lives in the gap between
  one parser's idea of a URL and another's.
- **IdP client secrets are encrypted at rest** with a key derived from
  `APP_SECRET_KEY` via HKDF, and never rendered back to the browser or included
  in an export.
- **Passwords use Argon2**; SCIM and API bearer tokens are stored as keyed
  hashes and compared in constant time.
- **Changing your own password requires the current one**, even though the
  session already proves identity — that is what stops an unattended browser
  becoming a permanent account takeover. Doing so also takes ownership of the
  password, so startup stops reissuing it.
- **A configured `BOOTSTRAP_ADMIN_PASSWORD` is never logged.** Only a password
  the app generated is printed, because only then is the log the sole place it
  exists.
- **Sign-in failures are indistinguishable** whether the account exists or not,
  and local sign-in is throttled per IP and account.
- **Secrets never travel in URLs.** SCIM and API tokens are rendered directly
  into the page that creates them rather than passed through a redirect, because
  URLs end up in access logs, browser history, and referrer headers.
- **Inspected access tokens are never stored.** Only the verdict and the
  individual check results reach the activity log.

`APP_SECRET_KEY` is the one thing to protect. It signs sessions and derives the
IdP-secret encryption key. Rotating it signs everyone out and makes stored IdP
secrets unreadable — the admin console will prompt for re-entry.

---

## Known limitations

Honest scope, so nobody is surprised:

- **Additive schema sync, not migrations.** New columns are added and backfilled
  automatically (see above), but nothing else is. Dropping a column, changing a
  type, or moving data across tables needs Alembic.
- **Rate limiting is in-process.** With multiple replicas each keeps its own
  counters. Fine for one local account on one replica; use platform rate
  limiting for anything else.
- **The discovery/JWKS cache is in-process too**, with a one-hour TTL. Editing a
  connection clears it on the replica that served the edit; other replicas keep
  serving the previous document until it expires. If a configuration change
  seems not to have taken effect on a scaled-out deployment, that is why.
- **SCIM complex value filters are not supported** (`emails[type eq "work"]`).
  The data model stores one email per user, so there is nothing for the inner
  filter to select over. These return a 400 rather than a wrong answer.
- **Access token validation needs a JWT.** Providers that issue opaque access
  tokens expose them only through their own introspection endpoint; the
  inspector says so rather than failing obscurely.
- **Expectations are evaluated at sign-in**, against the claims that sign-in
  produced. They are not a continuous policy monitor.
- **Terraform state contains secrets** in plaintext, and the databases are
  created with public endpoints so a first deployment needs no VPC work. Both
  need addressing before this holds anything you care about.
- **This is a test harness.** It is not built to hold production data, and the
  weather is the only real feature.
