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

## The two-pass deploy

The app needs `BASE_URL` to equal its own public URL, because OIDC redirect
URIs, SAML ACS URLs, and the SCIM tenant URL are all derived from it. On every
one of these platforms that URL is only known after the service exists.

Each module handles this the same way:

1. `terraform apply` creates everything. `BASE_URL` is set from the platform's
   generated hostname where that hostname is predictable, and left at a
   placeholder where it is not.
2. Read the `app_url` output.
3. If `base_url_override` was needed, set it and apply again.

The module output tells you which case you are in. Set `custom_domain` and the
whole problem disappears, which is the better answer for anything long-lived.

## Usage

```bash
cd examples/azure          # or aws, or gcp
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars — at minimum set image and app_secret_key

terraform init
terraform apply
```

Generate `app_secret_key` with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Before you use this for anything real

- **State contains secrets.** `app_secret_key` and the database password are
  stored in plaintext in Terraform state. Use a remote backend with encryption
  and restricted access; `.gitignore` already excludes `*.tfstate`.
- **Databases are the smallest available tier** and are publicly reachable with
  password authentication so a first deployment works without VPC plumbing. For
  anything beyond a lab, move them behind private networking.
- **No cost controls.** Azure and GCP scale to zero on compute; AWS App Runner
  and all three databases bill continuously. Destroy what you are not using.
