# Terraform

Three modules, one per cloud, all deploying the same container image with the
same environment contract:

| Module | Compute | Database | Secrets |
|---|---|---|---|
| `modules/azure` | Container Apps (Consumption, scale-to-zero) | Postgres Flexible Server, B1ms | Key Vault |
| `modules/aws` | App Runner | RDS Postgres, db.t4g.micro | Secrets Manager |
| `modules/gcp` | Cloud Run (scale-to-zero) | Cloud SQL Postgres, db-f1-micro | Secret Manager |

Each module exposes the same variables (`image`, `app_secret_key`,
`bootstrap_admin_email`, …) and the same outputs (`app_url`, `database_host`),
so switching clouds is a matter of changing which module you call.

## Getting a predictable URL

The app needs `BASE_URL` to equal its own public URL, because OIDC redirect
URIs, SAML ACS URLs, and the SCIM tenant URL are all derived from it. You also
want that URL to be *stable*, so it can be registered at an identity provider
once and circulated to whoever is testing sign-in.

| Cloud | Known before deploy? | Passes needed |
|---|---|---|
| Azure Container Apps | Yes — composed from the environment's domain, which exists first | **One** |
| GCP Cloud Run | Yes — `<service>-<project number>-<region>.run.app` | **One** |
| AWS App Runner | No — a random subdomain minted at creation | Two, or a custom domain |

Azure and GCP compute the URL up front, so a first `apply` produces a working
deployment with correct redirect URIs and SCIM tenant URL. The
`url_is_predictable` output confirms the computed URL matched what the platform
assigned; if it is ever false, `next_step` tells you exactly what to set.

App Runner is the exception and unavoidably so — there is nothing to compute a
random subdomain from. Apply, read `generated_url`, set `base_url_override`,
apply again. Or set `custom_domain` and skip it.

### Stability

Predictable is not the same as permanent. What changes each URL:

- **Azure** — the random component lives in the Container Apps *environment*
  domain, so pushing a new image, redeploying, or even recreating the container
  app keeps the URL. Destroying the environment changes it.
- **GCP** — nothing in the URL is random, so it survives deleting and recreating
  the service entirely.
- **AWS** — the subdomain is regenerated whenever the service is recreated.

A `custom_domain` you own is immune to all of that, which is why it is the right
answer for anything more than an afternoon's testing — and it is what you want
anyway if colleagues across the org are going to be signing in to test
Conditional Access policies.

### What to give your identity provider

Rather than copying URLs out of the admin console, read them from Terraform:

```bash
terraform output idp_configuration
```

```
{
  "oidc_redirect_uri" = "https://.../auth/oidc/{slug}/callback"
  "saml_acs_url"      = "https://.../auth/saml/{slug}/acs"
  "saml_sls_url"      = "https://.../auth/saml/{slug}/sls"
  "saml_metadata_url" = "https://.../auth/saml/{slug}/metadata"
  "scim_tenant_url"   = "https://.../scim/v2"
}
```

Replace `{slug}` with the connection slug you choose in the admin console.
`terraform output login_url` is the link to send to whoever is testing.

### Custom domains

Setting `custom_domain` tells the app what to call itself. It does **not**
create DNS records or a certificate binding — the zone is usually managed
elsewhere, and a record pointed at the wrong place is worse than no record. Read
`terraform output custom_domain_dns` for exactly what to create, then complete
the binding on the platform so it can issue a certificate.

Until DNS resolves, the app will be advertising a URL that does not reach it, so
do this before registering anything at a provider.

## Usage

```bash
cd examples/azure          # or aws, or gcp
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars — at minimum set image and app_secret_key

terraform init
terraform apply

terraform output next_step           # says whether anything is left to do
terraform output login_url           # the link to sign in with
terraform output idp_configuration   # every URL to register at your provider
```

Generate `app_secret_key` with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

On Azure and GCP that is the whole deployment. On AWS, `next_step` will tell you
to set `base_url_override` and apply once more — see below for why.

## Before you use this for anything real

- **State contains secrets.** `app_secret_key` and the database password are
  stored in plaintext in Terraform state. Use a remote backend with encryption
  and restricted access; `.gitignore` already excludes `*.tfstate`.
- **Databases are the smallest available tier** and are publicly reachable with
  password authentication so a first deployment works without VPC plumbing. For
  anything beyond a lab, move them behind private networking.
- **No cost controls.** Azure and GCP scale to zero on compute; AWS App Runner
  and all three databases bill continuously. Destroy what you are not using.
