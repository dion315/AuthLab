# AuthLab

A small weather app wrapped around a complete authentication stack — OIDC/OAuth 2.0,
SAML 2.0, certificate-based sign-in, SCIM 2.0 provisioning, and role-based access
control — built so you can point a real identity provider at it and watch exactly
what happens.

Three things make it useful rather than just another sample:

**Nothing about your identity provider is baked in at deploy time.** Issuers,
client secrets, signing certificates, trusted CAs, claim-to-role rules, and
provisioning tokens all live in the database and are edited from an admin
console while the app is running. Changing a role mapping and retrying a
sign-in takes seconds.

**Certificates are first-class, not an afterthought.** A user can authenticate
with a client certificate over mutual TLS, the app can authenticate *itself* to
a token endpoint with a certificate credential instead of a shared secret, and
every certificate check — chain, validity, extended key usage, revocation,
identity binding — is reported individually rather than as a single pass or
fail. It will even issue you a test CA and client certificate, because
otherwise testing any of this starts with building a PKI.

**There is always a local account.** It authenticates against the app directly,
with no identity provider involved. When a policy blocks your federated
sign-in — frequently the outcome you were testing for — you can still get in and
change the configuration that locked you out.

```bash
docker compose up --build
```

That is the whole local setup. No database service, no cloud account, no
identity provider needed to start. The app comes up at http://localhost:8000
and prints a generated administrator password to the log on first run.

---

## Where policy actually lives

Worth stating plainly, because the name of this section used to be "Testing
Conditional Access" and that read as though policies were configured here.

Access policies are evaluated **at your identity provider** — Conditional Access
in Entra ID, authentication policies in Okta, sign-on policies in Ping, and the
equivalents elsewhere. Neither this app nor the cloud hosting it can change
them, and nothing in the admin console does.

What this app does is play the part of the application those policies protect:

- it **asks** for things (`prompt=login`, `acr_values`, a claims challenge, SAML
  `ForceAuthn` and `RequestedAuthnContext`) and shows you whether the provider
  honoured, challenged, or quietly ignored each request;
- it **shows what came back** — the full claim set, the `amr` values, the
  authentication context — which is the evidence that a policy did or did not
  apply;
- it **preserves denials verbatim**, with the provider's own error code, because
  when you are testing a policy the denial *is* the result.

The one place authentication decisions are genuinely made here is certificate
sign-in, where there is no provider in the path at all — and every check that
produces the decision is shown on screen.

---

## Contents

- [Quick start](#quick-start)
- [How the code is organised](#how-the-code-is-organised)
- [Connecting an identity provider](#connecting-an-identity-provider)
- [Certificate-based authentication](#certificate-based-authentication)
- [SCIM provisioning](#scim-provisioning)
- [Testing access policies](#testing-access-policies)
- [The interface](#the-interface)
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

To test client certificates, which need a TLS terminator that asks the browser
for one:

```bash
docker compose up nginx-mtls --build      # https://localhost:8443
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
    authn_methods.py  Reading amr/AuthnContextClassRef: how did they authenticate?
    certs.py          X.509 parsing, chain validation, and test issuance
    oidc.py           Discovery, PKCE, client authentication, token exchange
    saml.py           SP metadata, AuthnRequest, assertion validation, SLO
    mtls.py           Client certificates presented directly to this app
    flowstate.py      Signed short-lived cookies carrying in-flight login state
    router.py         Sign-in, sign-out, and callback routes

  scim/
    schemas.py        SCIM 2.0 resource shapes
    filters.py        A real SCIM filter parser (tokeniser + recursive descent)
    router.py         Users, Groups, ServiceProviderConfig, ResourceTypes, Schemas

  routes/
    pages.py          Landing page, dashboard, weather proxy, health checks
    admin.py          The admin console, including certificate tooling

  templates/          Jinja2, autoescaping on
  static/             CSS and JS as real files, so the CSP needs no 'unsafe-inline'
                      (theme.js loads in <head>: the theme has to resolve before paint)

mtls/                 nginx config for local client-certificate testing
terraform/            Azure, AWS, and GCP modules
tests/                192 tests
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

**Certificate validation reports every check.** `app/auth/certs.py` returns the
list of checks it ran with a pass/fail and a reason for each, rather than a
boolean. "The certificate was rejected" is not a useful answer when you are
trying to work out why a smart card sign-in fails.

**Errors from the identity provider are preserved verbatim.** `OidcError` and
`SamlError` carry the provider's own code and description through to a page that
displays them. When you are testing a policy, that string *is* the result.

**Nothing that can fail at request time takes the process down.** Every handler
that talks to an IdP catches its own errors, and `main.py` has a catch-all. A
typo in an issuer URL produces a 502 page, not a crash loop.

---

## Connecting an identity provider

Sign in with the local account, then **Connections → Add OIDC** (or SAML, or
client certificate). Several connections can be enabled at once; the sign-in
page shows a button for each, which makes comparing two providers or two tenants
straightforward.

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
the provider advertises, without starting a browser flow. It also checks that
the client authentication method you chose is one the provider actually
supports, and — for `private_key_jwt` — that the assertion can be built and
signed. Catching any of that there saves a lot of round trips.

### SAML

Provide the IdP entity ID, sign-on URL, and signing certificate (PEM or bare
base64, both accepted). The connection page exposes an **SP metadata URL** that
most IdP consoles will import, filling in entity ID, ACS URL, and NameID format
for you. Certificate dates are shown next to the field, because an expired
signing certificate is the usual cause of a SAML flow that worked yesterday.

`InResponseTo` is genuinely validated for SP-initiated flows — the AuthnRequest
ID is kept in a signed, short-lived cookie and checked when the assertion comes
back. Accepting IdP-initiated sign-in disables that replay protection, so it is
an explicit per-connection opt-in rather than a default.

Signed AuthnRequests and encrypted assertions both need an SP keypair; the
connection page will generate one.

### Role mapping

Point `role_claim` at whatever carries group or role information, then add
ordered rules. First match wins.

| Provider | Typical claim |
|---|---|
| Entra ID | `roles` (app roles) or `groups` (object IDs) |
| Okta | `groups` |
| Shibboleth | the full attribute URN, e.g. `urn:oid:1.3.6.1.4.1.5923.1.5.1.1` |
| Keycloak | `realm_access.roles` (dotted paths work) |
| Client certificate | `issuer_cn`, `subject_ou`, `san_upn` — any certificate field |

Operators are `equals`, `contains`, `starts_with`, and `regex`. The dashboard
shows which rule matched and why — and if the claim was not in the token at all,
it lists the claims that *were*, which is usually the answer.

---

## Certificate-based authentication

Three different things get called "certificate-based authentication". All three
are supported, and the app is explicit about which one you are exercising.

### 1. A user's certificate, presented to this app (mutual TLS)

**Connections → Add client certificate.** The browser presents an X.509 client
certificate during the TLS handshake, the terminator in front of the app
forwards it in a header, and the app validates it: chain to a configured trust
anchor, validity period, `clientAuth` extended key usage, revocation against a
CRL you supply, an optional issuer allow-list, and identity binding. No identity
provider is involved at any point.

Identity comes from the certificate, in an order you configure — `san_upn` first
by default, because that is what a smart card, a PIV card, and an Entra
certificate credential carry.

**The app never sees the handshake.** TLS is terminated in front of it on every
platform it deploys to, so the certificate arrives in a header whose name and
encoding differ per proxy. `auto` detection covers all four shapes seen in
practice:

| Terminator | Header | Encoding |
|---|---|---|
| Envoy, Azure Container Apps | `x-forwarded-client-cert` | XFCC, percent-encoded PEM inside `Cert="..."` |
| AWS Application Load Balancer | `x-amzn-mtls-clientcert` | percent-encoded PEM |
| nginx (`$ssl_client_escaped_cert`) | your choice | percent-encoded PEM |
| Azure App Service | `x-arr-clientcert` | base64 DER |

That header must be one the proxy *replaces*, never one it appends to.
Anything that lets a caller supply its own value makes certificate
authentication worthless.

Three things make this testable rather than theoretical:

- **`docker compose up nginx-mtls`** runs an nginx in front that asks for a
  client certificate and forwards it, at https://localhost:8443. It uses
  `optional_no_ca`, so a certificate that would be rejected still reaches the
  app and you see *which check* rejected it, rather than an nginx error page.
- **The connection page issues test certificates.** Generate a test CA, then
  issue client certificates from it — including deliberately expired or
  not-yet-valid ones — and download a PKCS#12 to import into the browser.
  Private keys the app generates are encrypted at rest; issued certificates are
  shown once and never stored.
- **`/auth/mtls/{slug}/inspect`** shows what the proxy actually forwarded and
  every check that ran, without signing in. When nothing arrives it lists the
  certificate headers that *did*, which is usually a proxy that was never asked
  to request a certificate. The admin console can run the same pipeline against
  a pasted certificate, with no proxy at all.

### 2. This app's own certificate, presented to a token endpoint

Set client authentication to **`private_key_jwt`** on an OIDC connection. Instead
of a shared secret, the app signs a JWT assertion with a private key whose
certificate is registered at the provider — an Entra app registration with a
certificate credential, an Okta service app, or anything else implementing
RFC 7523. There is no shared secret in existence to leak.

The connection page will generate the keypair, store the private key encrypted,
and show you the certificate to upload along with both thumbprint forms. The
assertion carries `x5t` and `x5t#S256`, is valid for five minutes, and uses a
fresh `jti` every time so a replayed one is refused.

`client_secret_post`, `client_secret_basic`, and `none` (public client with
PKCE) are the other three options — some providers accept only one of them, and
the configuration test will tell you which they advertise.

### 3. A user's certificate, presented to the identity provider

This is Entra certificate-based authentication, Okta's Smart Card IdP, and the
equivalents. The provider does the work; the app reads the result.

The dashboard states plainly whether the session was certificate-based, and
shows the evidence: `amr` values (`x509`, `sc`, and Entra's `rsa`) or the SAML
`AuthnContextClassRef` (`X509`, `SmartcardPKI`, `TLSClient`), each with what it
means. If the provider said nothing at all, that is reported as unknown rather
than as a negative — a missing claim is not evidence of a missing certificate.

The re-test buttons ask for a certificate context explicitly: an OIDC claims
request for an X.509 authentication context, an Entra authentication-context
step-up, or a SAML `RequestedAuthnContext`. Whether the provider honours the
request is the test.

---

## SCIM provisioning

**Provisioning** generates a bearer token (shown once) and displays the tenant
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

Every provisioning request is recorded with its payload, which is the fastest
way to see the exact shapes your provider sends.

---

## Testing access policies

The policy is at your provider. This is how you find out what it did.

**See what the provider asserted.** The dashboard shows the complete claim set
and calls out the ones policies are written against — `amr`, `acr`, `acrs`,
`auth_time`, `ipaddr`, `deviceid`, `tid`, `xms_cc` — with what each one tells
you. If `amr` does not contain `mfa`, the policy did not apply.

**Read denials properly.** When a policy blocks a sign-in, the provider
redirects back with an error rather than a code. That lands on a page showing
the error and description as sent — `AADSTS53003`, `access_denied`, and so on —
and the same detail is kept under **Activity**.

**Ask for more, one attempt at a time.** The dashboard has per-attempt buttons
that add `prompt=login`, `max_age=0`, `acr_values=mfa`, `acr_values=phr`, an
X.509 claims request, an Entra authentication-context challenge, or SAML
`ForceAuthn` and `RequestedAuthnContext` — without changing the saved
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

## The interface

Deliberately plain and deliberately conventional: a centred sign-in card with
one button per configured provider, and an application shell behind it.

- **Responsive.** Usable at phone width, where tables become labelled rows
  rather than something to scroll sideways. Touch targets are sized for a
  thumb, and the navigation collapses behind a menu button.
- **Light, dark, or system.** The control in the header has three states, not
  two: "system" follows the operating system live, which a boolean toggle
  cannot express. The choice is remembered per browser and applied before the
  first paint, so there is no flash of the wrong palette.
- **Strict CSP, still.** `default-src 'self'` with no `unsafe-inline` and no
  nonce, which is why theme resolution is a real file in `<head>` rather than
  an inline script, and why there is not a single `style` attribute in the
  templates — under this policy the browser would ignore it.

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

### Client certificates in the cloud

Certificate sign-in needs the platform's TLS terminator to request a client
certificate. On Azure that is one variable — `client_certificate_mode =
"accept"` — and it is already wired through the module. App Runner cannot do
mutual TLS at all and needs an ALB in front; Cloud Run needs a global external
load balancer. `terraform/README.md` has the details and the header each one
sends.

`terraform/README.md` also covers what to fix before using any of this for
something real — chiefly that Terraform state holds secrets in plaintext and the
databases default to public endpoints.

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

192 tests, covering the SCIM request shapes real connectors send (including the
two Entra quirks above), the filter parser, role mapping, session revocation,
authorisation guards, output escaping, secret encryption, certificate parsing
and chain validation, the four client-certificate header encodings, client
assertion construction, authentication-method analysis, and that every page
renders for every kind of session.

---

## Security notes

What is deliberate, in case you are adapting this:

- **Templates autoescape.** IdP display names, SCIM attributes, and certificate
  subjects are all attacker-influenced — anyone holding a provisioning token can
  set `displayName` to anything, and a certificate subject is whatever the CA
  put there. There is a test asserting they are escaped.
- **The CSP is strict**: `default-src 'self'` with no `unsafe-inline` and no
  nonce. That is only possible because all CSS and JS are real files and the
  weather call is proxied server-side. A policy you have to loosen to make the
  app work is not doing much.
- **IdP client secrets and private keys are encrypted at rest** with a key
  derived from `APP_SECRET_KEY` via HKDF, and never rendered back to the
  browser.
- **Passwords use Argon2**; SCIM bearer tokens are stored as keyed hashes and
  compared in constant time.
- **Sign-in failures are indistinguishable** whether the account exists or not,
  and local sign-in is throttled per IP and account.
- **Secrets never travel in URLs.** The SCIM token is rendered directly into the
  page that creates it rather than passed through a redirect, because URLs end
  up in access logs, browser history, and referrer headers.
- **Certificate trust is explicit.** A client certificate is accepted only if it
  chains to a CA configured on that connection. The checks can each be turned
  off — seeing an expired certificate accepted proves which check was rejecting
  it — but they are on by default and the console says what turning one off
  means.

`APP_SECRET_KEY` is the one thing to protect. It signs sessions and derives the
key that encrypts stored IdP secrets. Rotating it signs everyone out and makes
those secrets unreadable — the admin console will prompt for re-entry.

---

## Known limitations

Honest scope, so nobody is surprised:

- **`create_all`, not migrations.** The schema is created at startup, which is
  right for a harness whose schema only changes with the code. Anything carrying
  data across versions wants Alembic; the models are ordinary SQLAlchemy, so
  that is a drop-in addition.
- **Certificate revocation is CRL-only, and only what you paste in.** Nothing is
  fetched over the network and OCSP is not consulted. Certificate path
  validation is deliberately simple: no name constraints, no policy processing.
  It is enough to answer "would this certificate be accepted, and if not, which
  check said no", which is what a harness is for.
- **Rate limiting is in-process.** With multiple replicas each keeps its own
  counters. Fine for one local account on one replica; use platform rate
  limiting for anything else.
- **SCIM complex value filters are not supported** (`emails[type eq "work"]`).
  The data model stores one email per user, so there is nothing for the inner
  filter to select over. These return a 400 rather than a wrong answer.
- **A stored secret cannot be blanked from the form.** An empty field means
  "leave what is stored", which is what stops the console wiping a secret it
  never renders back. Replace it with a new value, or delete the connection.
- **Terraform state contains secrets** in plaintext, and the databases are
  created with public endpoints so a first deployment needs no VPC work. Both
  need addressing before this holds anything you care about.
- **This is a test harness.** It is not built to hold production data, and the
  weather is the only real feature.
