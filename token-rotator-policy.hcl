# OpenBao / Vault policy for the token-rotator AppRole
# Apply with: vault policy write token-rotator token-rotator-policy.hcl

# Read and write all platform token secrets
path "secret/data/tokens/*" {
  capabilities = ["create", "read", "update"]
}

# Read secret metadata (for version history)
path "secret/metadata/tokens/*" {
  capabilities = ["read", "list"]
}

# Read and write rotation state (idempotency timestamps)
path "secret/data/rotation/state" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/rotation/state" {
  capabilities = ["read"]
}

# Allow reading own token info (for token renewal)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow AppRole login
path "auth/approle/login" {
  capabilities = ["create", "read"]
}
