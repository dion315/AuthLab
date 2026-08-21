# URLs, reachability, and `BASE_URL`

Every address the app hands to an identity provider is derived from one setting.
Getting it wrong is the single most common cause of a flow that fails for
reasons the error message does not explain, so this covers what the value has to
be, what it produces, and what changes when the app moves off your laptop.

---

## Contents

- [One setting, four URLs](#one-setting-four-urls)
- [The distinction that matters: who connects to whom](#the-distinction-that-matters-who-connects-to-whom)
- [Running locally](#running-locally)
- [Provisioning against a local instance](#provisioning-against-a-local-instance)
- [Deploying to a cloud](#deploying-to-a-cloud)
- [The chicken-and-egg problem](#the-chicken-and-egg-problem)
- [Testing with people across the organisation](#testing-with-people-across-the-organisation)
- [Behind a load balancer](#behind-a-load-balancer)
- [Network restrictions and allowlisting](#network-restrictions-and-allowlisting)
- [Symptoms and what they mean](#symptoms-and-what-they-mean)

---

## One setting, four URLs

`BASE_URL` must equal the app's own externally visible URL. From it the app
derives, in [app/auth/connections.py](../app/auth/connections.py):

| Derived URL | Used by |
|---|---|
| `<BASE_URL>/auth/oidc/<slug>/callback` | OIDC redirect URI, registered at the provider |
| `<BASE_URL>/auth/saml/<slug>/acs` | SAML Assertion Consumer Service |
| `<BASE_URL>/auth/saml/<slug>/sls` | SAML Single Logout Service |
| `<BASE_URL>/scim/v2` | SCIM tenant URL, pasted into the provisioning config |

They are computed rather than stored so they cannot drift out of sync with where
the app is actually running. Each connection page displays its own set with copy
buttons, and the SCIM tenant URL is on Admin → SCIM.

`BASE_URL` also decides one thing that is easy to miss: the session cookie's
`Secure` flag is set when it starts with `https://`. A production deployment
served over HTTPS but configured with an `http://` `BASE_URL` will issue
non-secure cookies.

---

## The distinction that matters: who connects to whom

This is the thing to internalise, because it explains why `localhost` is fine
for one half of the app and useless for the other.

**Sign-in never involves the provider connecting to you.** An OIDC or SAML flow
is a sequence of redirects and form posts performed by *the user's browser*. The
browser goes to the provider, the provider sends the browser back to your
redirect URI. Both ends only need to be reachable *from the browser*. This is why
`http://localhost:8000` works perfectly against Entra ID or Okta: your browser
can reach both.

**Provisioning is the provider connecting directly to you.** SCIM is a plain
REST API call made by the provider's own infrastructure to the tenant URL you
configured. Microsoft's provisioning service has no idea what your `localhost`
is, and cannot route to `10.x` or a private VNet address.

So:

| Feature | Works on localhost? | Why |
|---|---|---|
| OIDC sign-in | Yes | Browser-mediated |
| SAML sign-in | Yes | Browser-mediated |
| SAML single logout | Yes | Browser-mediated (redirect/POST binding) |
| Conditional Access testing | Yes | It is sign-in |
| **SCIM provisioning** | **No** | Direct inbound call from the provider |
| Access token inspection | Yes | The app makes outbound calls to fetch JWKS |

One caveat on the outbound direction: the app fetches discovery documents and
JWKS from the provider itself, and proxies the weather call. An environment with
no outbound internet access breaks those regardless of `BASE_URL`.

---

## Running locally

The default is `http://localhost:8000` and needs no changes for sign-in testing.

```bash
docker compose up --build
```

Register `http://localhost:8000/auth/oidc/<slug>/callback` as a redirect URI.
Most providers allow plain HTTP for `localhost` specifically, as an explicit
exception to their HTTPS requirement — Entra ID, Okta, Auth0, and Google all do.

If you use `127.0.0.1` in the browser but `localhost` in `BASE_URL`, or the
other way round, you will get a redirect-URI mismatch. They are different
origins as far as the provider is concerned. Pick one and use it everywhere.

---

## Provisioning against a local instance

You need a public HTTPS URL that forwards to your local port. Any tunnel works:

```bash
cloudflared tunnel --url http://localhost:8000
ngrok http 8000
devtunnel host -p 8000 --allow-anonymous
```

Then restart the app with `BASE_URL` set to the tunnel's hostname:

```bash
BASE_URL=https://your-tunnel-host.example docker compose up
```

This is not optional and it is not a shortcut — without it the provider's "Test
Connection" button will simply fail, because there is nothing at the address you
gave it.

Two consequences of changing `BASE_URL`:

- Every derived URL changes, so re-copy the redirect URI, ACS URL, and SCIM
  tenant URL into the provider. The connection pages show the current values.
- Tunnel hostnames from the free tiers are usually regenerated on each run.
  Either use a named/reserved tunnel, or expect to update the provider each
  session. This is the main argument for deploying somewhere with a stable
  hostname as soon as you are doing more than a one-off test.

---

## Deploying to a cloud

The Terraform modules deploy the same image to all three clouds with the same
environment contract. Each platform assigns a hostname:

| Platform | Assigned hostname shape | Predictable before deploy? |
|---|---|---|
| Azure Container Apps | `https://<app>.<env-domain>.<region>.azurecontainerapps.io` | **Yes** — the random part is the *environment's*, and it exists first |
| GCP Cloud Run | `https://<service>-<project-number>.<region>.run.app` | **Yes** — nothing random in it |
| AWS App Runner | `https://<generated-id>.<region>.awsapprunner.com` | No — random subdomain |

All three terminate TLS for you, so `BASE_URL` starts with `https://` and the
session cookie gets its `Secure` flag automatically.

Whatever the cloud, read the value from Terraform rather than constructing it:

```bash
cd terraform/examples/azure     # or aws, or gcp
terraform output app_url
terraform output login_url          # the link to hand to testers
terraform output idp_configuration  # every URL to register at the provider
```

Because these are public endpoints with public DNS and real certificates, SCIM
provisioning works against them without a tunnel. That is usually the reason to
deploy at all.

### How stable are these?

Predictable is not the same as permanent, and this matters once you have
registered a redirect URI at a provider and sent the link to twenty people.

| Cloud | Survives a redeploy? | Survives recreating the service? | Survives recreating everything? |
|---|---|---|---|
| Azure | Yes | Yes | No — the random part lives in the Container Apps environment |
| GCP | Yes | Yes | Yes — nothing in the URL is random |
| AWS | Yes | **No** — a new subdomain is minted | No |

### Custom domains

Setting `custom_domain` gives you a hostname immune to all of the above, which
is the right answer for anything more than an afternoon — and the one you want
if colleagues across the org are going to sign in to test Conditional Access
policies. `authlab.contoso.com` is something you can put in a ticket; a random
`azurecontainerapps.io` hostname invites people to assume it is phishing.

It also avoids the two-pass deploy on AWS entirely, because you know the
hostname before the service exists.

The variable tells the app what to call itself. It does **not** create the DNS
records or the certificate binding — the zone is usually managed elsewhere, and
a record pointed at the wrong place is worse than no record. Run
`terraform output custom_domain_dns` for exactly what to create, then complete
the binding on the platform so it can issue a certificate.

Do this *before* registering anything at a provider: until DNS resolves, the app
is advertising a URL that does not reach it.

---

## The chicken-and-egg problem

The app needs `BASE_URL` to equal its own public URL, and the obvious reading is
that this cannot be known until the service exists. That turns out to be true on
only one of the three:

| Cloud | Known before deploy? | Why |
|---|---|---|
| Azure Container Apps | **Yes** | The FQDN is `<app>.<environment domain>`, and the *environment* is created before the app |
| GCP Cloud Run | **Yes** | Deterministic `<service>-<project number>-<region>.run.app` — no random component |
| AWS App Runner | No | A random subdomain minted at creation, with nothing to compute it from |

So Azure and GCP are a single apply: the module computes the URL up front and
the app comes up with correct redirect URIs and SCIM tenant URL immediately. The
`url_is_predictable` output confirms the computed value matched what the
platform assigned, and `next_step` says what to do if it did not.

App Runner needs two passes: apply, read `generated_url`, set
`base_url_override` to it, apply again. Between the two, sign-in fails with a
redirect-URI mismatch and SCIM reports the wrong tenant URL, because the app is
still advertising a placeholder. Setting `custom_domain` avoids this.

### Reading the values to register

```bash
terraform output login_url          # send this to whoever is testing
terraform output idp_configuration  # everything to paste into the provider
```

`idp_configuration` gives the OIDC redirect URI, SAML ACS, SLS, and metadata
URLs, and the SCIM tenant URL, with `{slug}` where the connection slug goes.

---

## Testing with people across the organisation

Handing the app to colleagues so they can exercise a Conditional Access policy
from their own devices, networks, and identities is the point of deploying it.
A few things make that go better.

**Use a custom domain.** `authlab.contoso.com` is a link people will click. A
random `azurecontainerapps.io` hostname arriving in a message asking someone to
sign in with their corporate credentials looks exactly like a phishing test, and
some of your colleagues have been trained to report it. This is a real
consideration, not a cosmetic one.

**Turn off scale-to-zero for the session.** All three modules default to zero
minimum replicas, so the app costs nothing while idle — but the first request
after a quiet period pays a cold start, and that lands in the middle of an OAuth
redirect where it looks like a hang or a failure. Set `min_replicas` (Azure) or
`min_instances` (GCP) to `1` while people are actively testing, and back to `0`
afterwards.

**Keep the replica count low, or restart after config changes.** Discovery
documents and JWKS are cached in-process for an hour, and role mapping changes
take effect immediately but only on the replica that served the edit. With
several replicas and several testers, two people can legitimately get different
results from the same connection. For a testing session, one replica removes a
whole class of confusion.

**Do not IP-restrict the app while testing location-based policies.** It is the
*identity provider* that evaluates the location condition, using the address it
sees from the user's browser. The app only needs to be reachable. Restricting it
by IP will lock out exactly the remote users whose access you were trying to
test, and — because SCIM is a direct inbound call — will silently break
provisioning too.

**Check `TRUST_PROXY_HEADERS` before you start.** The dashboard shows the source
address the app recorded next to the `ipaddr` claim the provider asserted. If
they disagree, your record of who signed in from where is wrong, which matters
when the whole exercise is about network location. This is set correctly by all
three Terraform modules; it is worth a glance anyway.

**Give people the expectations, not the claim dump.** Attach expectations to the
connection (`amr contains mfa`, an expected role) and each tester's dashboard
reports pass or fail directly. Then `terraform output login_url` plus "tell me
what the Expected outcome card says" is a complete test instruction, and you can
read the aggregate afterwards:

```bash
curl -H "Authorization: Bearer $AUTHLAB_TOKEN"   "$(terraform output -raw app_url)/api/admin/events?format=csv&kind=login_success&since_minutes=240"   -o results.csv
```

**Local accounts are not the test.** Everyone testing a policy should be signing
in through the connection. The local account exists so *you* can still get in
when a policy blocks federated sign-in — which, when testing policies, is
regularly the intended result.

---

## Behind a load balancer

All three platforms put a proxy in front of the container. The inbound request
the app sees is plain HTTP on an internal port, and the real client address only
exists in `X-Forwarded-For`.

`TRUST_PROXY_HEADERS=true` (the default) makes the app honour those headers.
Turn it off only if the app is directly internet-facing with nothing in front of
it, because the header is caller-supplied and trivially spoofed when nothing
strips it.

This matters more here than in most applications for two reasons:

- **Source IP is a Conditional Access condition.** With this wrong, every
  sign-in is recorded against the load balancer's address, and your IP-based
  policy tests are meaningless. The dashboard shows the address the app recorded
  next to the `ipaddr` claim the provider saw — if those disagree, this is why.
- **SAML validates `Destination`.** The assertion carries the URL it was
  intended for, and it is compared against where the app thinks it is. The app
  deliberately builds that from `BASE_URL` rather than from request headers, in
  [app/auth/saml.py](../app/auth/saml.py), which is what prevents the
  "Destination mismatch" errors that look like an IdP problem but are not.

---

## Network restrictions and allowlisting

If you restrict inbound access to the deployed app, the provisioning service has
to be allowed through or SCIM stops working — while sign-in continues to work
perfectly, because that is browser-mediated. That asymmetry makes it a confusing
failure.

- **Entra ID** provisioning originates from Azure infrastructure. On Azure, the
  `AzureActiveDirectory` service tag covers it; elsewhere, Microsoft publishes
  the IP ranges.
- **Okta** publishes the egress IPs for each cell.

The Terraform modules deploy databases with **public endpoints and password
authentication** so a first deployment needs no VPC work. That is a lab default,
not a production one — `terraform/README.md` says so, and moving them behind
private networking is the first thing to change for anything that matters.

Note that putting the *app* behind private networking is the change that breaks
SCIM. Putting the *database* behind private networking does not.

---

## Symptoms and what they mean

| Symptom | Cause |
|---|---|
| `redirect_uri_mismatch`, `AADSTS50011` | `BASE_URL` does not match what is registered at the provider, or `localhost` vs `127.0.0.1` |
| Provider's SCIM "Test Connection" fails | The provider cannot reach `BASE_URL` — local without a tunnel, or a private endpoint |
| SAML "Destination mismatch" | `BASE_URL` is not the URL the browser actually used |
| Every sign-in logged from the same IP | `TRUST_PROXY_HEADERS` off, or the proxy is not forwarding |
| Sign-in works, provisioning does not | Exactly the split described above — check reachability, not credentials |
| Sessions dropped on every request over HTTPS | `BASE_URL` is `http://` so the cookie is not marked `Secure` |
| Everything worked, then stopped after redeploy | The platform assigned a new hostname; use `custom_domain` |
| Configuration change had no effect | Discovery documents are cached in-process for an hour, per replica — see the known limitations in the README |
