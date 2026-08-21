# Documentation

[The main README](../README.md) is the overview: what the app is, how it is laid
out, and what each feature is for. These are the two things that were too long
to live there.

## [providers.md](providers.md)

Per-provider setup for OIDC, SAML, and SCIM: **Microsoft Entra ID, Okta, Auth0,
AWS Cognito, Duo**, and anything else that speaks the protocols.

It opens with a capability matrix, because the honest answer to "can I use all
three protocols with all of these?" is no — Auth0 receives SCIM rather than
sending it, Cognito is a SAML service provider rather than an identity provider,
and Duo synchronises from a directory rather than provisioning onward. Knowing
that up front saves an afternoon looking for a menu that does not exist.

Also covers the traps that are not obvious from a provider's own documentation:

- **Entra NameID stability** — the default NameID is the UPN, which changes on
  rename, and `Persistent` format regenerates if the enterprise application is
  recreated. Both silently orphan provisioned records. The fix is to key on the
  immutable object id at both ends.
- **The Entra groups overage** — past roughly 150 groups the `groups` claim is
  replaced by a pointer to Microsoft Graph that this app does not follow.
- **Okta and Auth0 group claims** — neither emits groups until you configure it,
  on the authorization server and via an Action respectively.

## [deployment-urls.md](deployment-urls.md)

Everything about `BASE_URL`: what it produces, why it has to be right, and what
changes when the app leaves your laptop.

The central point is a distinction that catches people out. **Sign-in is carried
by the browser**, so `localhost` works fine against a cloud identity provider.
**SCIM is a direct inbound call** from the provider's own infrastructure, so it
cannot reach `localhost` or a private endpoint at all. Sign-in keeps working
while provisioning silently does not, which is a confusing way to lose an hour.

Also covers:

- Tunnelling to provision against a local instance.
- Which clouds produce a **predictable URL** before deployment and which do not.
- How stable each cloud's URL is across redeploys and recreation.
- Running a test with **people across the organisation** — custom domains, cold
  starts landing mid-redirect, replica count versus the per-process cache, and
  why IP-restricting the app breaks the location-condition testing you were
  trying to do.
- A symptom-to-cause table for flows that fail for reasons the error does not
  explain.

## Elsewhere

- [terraform/README.md](../terraform/README.md) — the modules, getting a
  predictable URL out of each cloud, and what to fix before using any of it for
  something real.
- `/docs` on a running instance — the generated OpenAPI reference, which is the
  browsable spec for the SCIM and automation endpoints.
- The admin console explains itself as you go; **Admin → Automation** lists the
  API endpoints with their scopes and a working `curl` example.
