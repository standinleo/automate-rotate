# Token Rotation — Setup Guide

## Files

| File | Purpose |
|---|---|
| `rotate.py` | Main orchestrator — run locally or via Actions |
| `rotate-tokens.yml` | GitHub Actions workflow (place in `.github/workflows/`) |
| `requirements.txt` | Python dependencies |
| `token-rotator-policy.hcl` | OpenBao Vault policy for the rotation service account |

---

## One-time bootstrap

### 1. OpenBao: create the AppRole

```bash
# Enable AppRole auth if not already enabled
vault auth enable approle

# Write the policy
vault policy write token-rotator token-rotator-policy.hcl

# Create the AppRole
vault write auth/approle/role/token-rotator \
  token_policies="token-rotator" \
  token_ttl=1h \
  token_max_ttl=2h \
  secret_id_ttl=0          # non-expiring; rotate secret_id separately if desired

# Retrieve role-id and secret-id
vault read auth/approle/role/token-rotator/role-id
vault write -f auth/approle/role/token-rotator/secret-id
```

### 2. OpenBao: seed initial secrets

```bash
# Enable KV v2 (if not already)
vault secrets enable -path=secret kv-v2
vault write secret/config max_versions=3

# JFrog — seed with your bootstrap admin token
vault kv put secret/tokens/jfrog \
  token="<initial-jfrog-token>" \
  token_id="<initial-jfrog-token-id>" \
  admin_token="<jfrog-admin-token>"

# GitHub App — seed private key PEM
vault kv put secret/tokens/github \
  app_private_key_pem=@/path/to/your-app.private-key.pem

# Azure — seed rotation service principal credentials
vault kv put secret/tokens/azure \
  sp_client_id="<service-principal-client-id>" \
  sp_client_secret="<service-principal-client-secret>" \
  client_id="<app-client-id-to-rotate>" \
  tenant_id="<your-tenant-id>"
```

### 3. GitHub Actions: set repository secrets

Go to **Settings → Secrets and variables → Actions → New repository secret**:

| Secret name | Value |
|---|---|
| `VAULT_ADDR` | Your OpenBao address, e.g. `https://vault.internal:8200` |
| `VAULT_ROLE_ID` | From step 1 |
| `VAULT_SECRET_ID` | From step 1 |
| `VAULT_NAMESPACE` | (optional) your Vault namespace |
| `VAULT_KV_MOUNT` | `secret` (default) |
| `JFROG_URL` | e.g. `https://myorg.jfrog.io` |
| `JFROG_ADMIN_TOKEN` | Bootstrap only — can remove after first successful rotation |
| `GH_APP_ID` | Your GitHub App numeric ID |
| `GH_APP_INSTALLATION_ID` | Installation ID for your org |
| `AZURE_TENANT_ID` | Your Azure tenant ID |
| `AZURE_CLIENT_ID` | Client ID of the app registration to rotate |
| `AZURE_APP_OBJECT_ID` | Object ID of the app registration (not the service principal) |
| `SLACK_WEBHOOK_URL` | (optional) Slack incoming webhook for notifications |

---

## Usage

### Dry-run (validate connectivity)
```bash
python rotate.py --dry-run
```

### Rotate all platforms (respects 180-day gate)
```bash
python rotate.py
```

### Force rotate a single platform
```bash
python rotate.py --platform jfrog --force
```

### Via GitHub Actions
- **Scheduled**: runs automatically every 180 days (cron defined in workflow)
- **Manual**: Actions → Rotate platform tokens → Run workflow → pick platform/options

---

## Vault secret structure (after rotation)

```
secret/tokens/jfrog
  token            string   Current access token
  token_id         string   JFrog token ID (for revocation)
  admin_token      string   Admin/bootstrap token (carried forward)
  rotated_at       string   ISO 8601 UTC timestamp
  expires_at       string   ISO 8601 UTC timestamp

secret/tokens/github
  app_private_key_pem   string   GitHub App private key (PEM)
  installation_token    string   Last minted installation token (1h TTL — always re-fetch)
  installation_token_expires_at  string
  rotated_at            string

secret/tokens/azure
  client_id        string   App registration client ID
  client_secret    string   Current client secret value
  key_id           string   Azure key ID (for targeted deletion)
  tenant_id        string   Azure tenant ID
  sp_client_id     string   Rotation service principal client ID
  sp_client_secret string   Rotation service principal secret
  rotated_at       string
  expires_at       string

secret/rotation/state
  jfrog_last_rotated    string   ISO 8601 timestamp
  github_last_rotated   string
  azure_last_rotated    string
  *_rotated_by          string   "rotate.py/github-actions"
```

---

## GitHub App vs. Classic PAT

Classic PATs **cannot be deleted via API** — manual intervention is always required.
GitHub Apps generate short-lived installation tokens on demand (1h TTL) and do not
need periodic rotation. Switch to a GitHub App for full automation:

1. Create a GitHub App in your org (Settings → Developer settings → GitHub Apps)
2. Grant repository permissions the workflow needs
3. Install the App on your org/repo
4. Download the private key PEM and seed it into OpenBao

The private key itself should be rotated manually every 180 days in GitHub → App settings → Private keys.

---

## Troubleshooting

| Error | Likely cause | Fix |
|---|---|---|
| `Vault authentication failed` | Wrong role-id or secret-id | Re-read from `vault write -f auth/approle/role/token-rotator/secret-id` |
| `[jfrog] No admin token available` | First run, vault not seeded | Run the bootstrap vault kv put command above |
| `[github] No GitHub App private key` | PEM not seeded in vault | `vault kv put secret/tokens/github app_private_key_pem=@key.pem` |
| `[azure] 403 Forbidden` | SP lacks Application.ReadWrite.OwnedBy | Grant the permission in Azure AD |
| `Rotation not due yet` | Last rotation was < 180 days ago | Use `--force` to override |
