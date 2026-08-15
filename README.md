# AuthLab

A small weather app wrapped around a complete authentication stack — OIDC/OAuth 2.0,
SAML 2.0, SCIM 2.0 provisioning, and role-based access control — built so you can
point a real identity provider at it and watch exactly what happens.

Two things make it useful rather than just another sample:

**Nothing about your identity provider is baked in at deploy time.** Issuers,
client secrets, signing certificates, claim-to-role rules, and provisioning
tokens all live in the database and are edited from an admin console while the
app is running. Changing a role mapping and retrying a sign-in takes seconds.

**There is always a local account.** It authenticates against the app directly,
with no identity provider involved. When a Conditional Access policy blocks your
federated sign-in — frequently the outcome you were testing for — you can still
get in and change the configuration that locked you out.

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
- [SCIM provisioning](#scim-provisioning)
- [Testing Conditional Access](#testing-conditional-access)
- [Deploying](#deploying)
- [Running the tests](#running-the-tests)
- [Security notes](#security-notes)
- [Known limitations](#known-limitations)

---

## Quick start

```bash
docker compose up --build
```

Watch the log for the first-run credentials:

```
====================================================================
  First-run local administrator created
    email:    admin@authlab.local
    password: xY3k...
  Sign in at http://localhost:8000/login and change it.
====================================================================
```

Set `BOOTSTRAP_ADMIN_PASSWORD` if you would rather choose it yourself, and
`APP_SECRET_KEY` so sessions survive a restart:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into APP_SECRET_KEY
```

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

The `--no-binary` step matters: `lxml` and `xmlsec` must be compiled against the
same `libxml2`, and mixing prebuilt wheels produces a version-mismatch error at
import time that is hard to diagnose from the message alone.

---

## How the code is organised

Worth a read if you are using this as a reference for your own work — the layout
is meant to keep each protocol concern in one obvious place.

```
app/
  main.py             FastAPI app, middleware, error handlers, routing
  config.py           Bootstrap settings only (everything else is runtime config)
  db.py               SQLAlchemy engine and session management
  models.py           All persistence: connections, SCIM users, sessions, events
  crypto.py           Fernet encryption for IdP secrets held in the database
  security.py         Password hashing, bearer tokens, sessions, client IP
  deps.py             FastAPI dependencies: require_login, require_role
  ratelimit.py        Throttle for local password sign-in
  events.py           The authentication/provisioning audit trail

  auth/
    schemas.py        Pydantic models validating per-protocol settings
    connections.py    Loading/saving connections, applying encryption
    rolemap.py        Claims -> application role (pure functions, heavily tested)
    oidc.py           Discovery, PKCE, token exchange, ID token validation
    saml.py           SP metadata, AuthnRequest, assertion validation
    flowstate.py      Signed short-lived cookies carrying in-flight login state
    router.py         Sign-in, sign-out, and callback routes

  scim/
    schemas.py        SCIM 2.0 resource shapes
    filters.py        A real SCIM filter parser (tokeniser + recursive descent)
    router.py         Users, Groups, ServiceProviderConfig, ResourceTypes, Schemas

  routes/
    pages.py          Landing page, dashboard, weather proxy, health checks
    admin.py          The admin console

  templates/          Jinja2, autoescaping on
  static/             CSS and JS as real files, so the CSP needs no 'unsafe-inline'

terraform/            Azure, AWS, and GCP modules
tests/                115 tests
```

A few decisions your developers may find worth copying:

**Session state is server-side, not a self-contained JWT.** A signed cookie
carries only an opaque session id. This is what makes revocation possible — when
SCIM deactivates a user, their live sessions end immediately instead of staying
valid until a token expires. It also means the full claim set can be kept and
displayed, which routinely exceeds the 4KB cookie limit.

**Role mapping is a pure function.** `app/auth/rolemap.py` takes a connection and
a claims dictionary and returns a role plus a trace of every rule it evaluated.
No database, no request object, so the awkward cases — scalar-versus-list claims,
rule ordering, providers that put groups somewhere unusual — are cheap to test
and the dashboard can show its work.

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

The connection page shows the exact redirect URI to register at the provider.
It is derived from `BASE_URL`, so if that is wrong you will get a redirect-URI
mismatch — that is the first thing to check when a flow fails.

**Test configuration** fetches the discovery document and lists the endpoints
the provider advertises, without starting a browser flow. Catching a typo there
saves a lot of round trips.

### SAML

Provide the IdP entity ID, sign-on URL, and signing certificate (PEM or bare
base64, both accepted). The connection page exposes an **SP metadata URL** that
most IdP consoles will import, filling in entity ID, ACS URL, and NameID format
for you.

`InResponseTo` is genuinely validated for SP-initiated flows — the AuthnRequest
ID is kept in a signed, short-lived cookie and checked when the assertion comes
back. Accepting IdP-initiated sign-in disables that replay protection, so it is
an explicit per-connection opt-in rather than a default.

### Role mapping

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

---

## SCIM provisioning

**Admin → SCIM** generates a bearer token (shown once) and displays the tenant
URL to paste into your provider's provisioning configuration.

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

Deactivating a user through SCIM revokes their live sessions immediately. That
is the behaviour most people actually want to verify when they test
deprovisioning, and it is only possible because sessions are server-side.

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
`prompt=login`, `acr_values=mfa`, or SAML `ForceAuthn` without changing the saved
connection. Use these to check that a policy actually challenges instead of
silently passing.

**Sign out for real.** Local sign-out leaves the provider session intact, so the
next sign-in completes silently and you cannot retest anything. **Sign out
everywhere** ends the session at the provider too.

**Check the source IP.** Source IP is a policy condition, and behind a load
balancer it is easy to get wrong. The dashboard shows the address the app
recorded next to the `ipaddr` claim the provider saw. If they disagree,
`TRUST_PROXY_HEADERS` or your proxy configuration needs attention.

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

### The two-pass deploy

The app derives its redirect URIs, SAML ACS URLs, and SCIM tenant URL from
`BASE_URL`, which must equal its own public URL. On all three platforms that URL
only exists after the service is created.

So: apply, read the `app_url` output, set `base_url_override` to it, apply again.
Each module has a `next_step` output that tells you exactly what to do. Setting
`custom_domain` avoids the second pass entirely and is the better answer for
anything long-lived.

`terraform/README.md` has the details, including what to fix before using any of
this for something real — chiefly that Terraform state holds secrets in
plaintext and the databases default to public endpoints.

### CI

`azure-pipelines.yml` lints, runs the tests, validates all three Terraform
configurations, then builds and pushes the image. Deployment is a separate stage
gated on an ADO environment approval, and fails the build if the new revision
does not pass its health check.

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests -q
ruff check app tests
```

115 tests, covering the SCIM request shapes real connectors send (including the
two Entra quirks above), the filter parser, role mapping, session revocation,
authorisation guards, output escaping, and secret encryption.

---

## Security notes

What is deliberate, in case you are adapting this:

- **Templates autoescape.** IdP display names and SCIM attributes are
  attacker-influenced — anyone holding a provisioning token can set
  `displayName` to anything. There is a test asserting they are escaped.
- **The CSP is strict**: `default-src 'self'` with no `unsafe-inline` and no
  nonce. That is only possible because all CSS and JS are real files and the
  weather call is proxied server-side. A policy you have to loosen to make the
  app work is not doing much.
- **IdP client secrets are encrypted at rest** with a key derived from
  `APP_SECRET_KEY` via HKDF, and never rendered back to the browser.
- **Passwords use Argon2**; SCIM bearer tokens are stored as keyed hashes and
  compared in constant time.
- **Sign-in failures are indistinguishable** whether the account exists or not,
  and local sign-in is throttled per IP and account.
- **Secrets never travel in URLs.** The SCIM token is rendered directly into the
  page that creates it rather than passed through a redirect, because URLs end
  up in access logs, browser history, and referrer headers.

`APP_SECRET_KEY` is the one thing to protect. It signs sessions and derives the
IdP-secret encryption key. Rotating it signs everyone out and makes stored IdP
secrets unreadable — the admin console will prompt for re-entry.

---

## Known limitations

Honest scope, so nobody is surprised:

- **`create_all`, not migrations.** The schema is created at startup, which is
  right for a harness whose schema only changes with the code. Anything carrying
  data across versions wants Alembic; the models are ordinary SQLAlchemy, so
  that is a drop-in addition.
- **Rate limiting is in-process.** With multiple replicas each keeps its own
  counters. Fine for one local account on one replica; use platform rate
  limiting for anything else.
- **SCIM complex value filters are not supported** (`emails[type eq "work"]`).
  The data model stores one email per user, so there is nothing for the inner
  filter to select over. These return a 400 rather than a wrong answer.
- **No SAML Single Logout endpoint for IdP-initiated logout.** SP-initiated SLO
  works; an unsolicited `LogoutRequest` from the IdP is not handled.
- **Terraform state contains secrets** in plaintext, and the databases are
  created with public endpoints so a first deployment needs no VPC work. Both
  need addressing before this holds anything you care about.
- **This is a test harness.** It is not built to hold production data, and the
  weather is the only real feature.
