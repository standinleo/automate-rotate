"""
rotate.py — Centralized token rotation orchestrator
Platforms: JFrog, GitHub (App), Azure Client Secret
Vault:     OpenBao (hvac-compatible KV v2)

Usage:
  python rotate.py                  # rotate all platforms
  python rotate.py --platform jfrog # rotate single platform
  python rotate.py --dry-run        # validate connectivity only, no changes
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import hvac
import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("rotate")


# ---------------------------------------------------------------------------
# Config — loaded entirely from environment variables (set via GH Actions secrets)
# ---------------------------------------------------------------------------
class Config:
    # OpenBao / Vault
    VAULT_ADDR: str       = os.environ["VAULT_ADDR"]             # e.g. https://vault.internal:8200
    VAULT_TOKEN: str      = os.environ.get("VAULT_TOKEN", "")    # static token (dev only)
    VAULT_ROLE_ID: str    = os.environ.get("VAULT_ROLE_ID", "")  # AppRole (production)
    VAULT_SECRET_ID: str  = os.environ.get("VAULT_SECRET_ID", "") # AppRole (production)
    VAULT_NAMESPACE: str  = os.environ.get("VAULT_NAMESPACE", "")
    VAULT_KV_MOUNT: str   = os.environ.get("VAULT_KV_MOUNT", "secret")

    # Vault secret paths
    PATH_STATE: str       = "rotation/state"
    PATH_JFROG: str       = "tokens/jfrog"
    PATH_GITHUB: str      = "tokens/github"
    PATH_AZURE: str       = "tokens/azure"

    # JFrog
    JFROG_URL: str        = os.environ.get("JFROG_URL", "")      # e.g. https://myorg.jfrog.io
    JFROG_ADMIN_TOKEN: str = os.environ.get("JFROG_ADMIN_TOKEN", "") # bootstrap admin token (stored in vault too)

    # GitHub App
    GITHUB_APP_ID: str        = os.environ.get("GITHUB_APP_ID", "")
    GITHUB_INSTALLATION_ID: str = os.environ.get("GITHUB_INSTALLATION_ID", "")
    # Private key PEM is stored in OpenBao, not env — fetched at runtime

    # Azure
    AZURE_TENANT_ID: str      = os.environ.get("AZURE_TENANT_ID", "")
    AZURE_CLIENT_ID: str      = os.environ.get("AZURE_CLIENT_ID", "")  # the app to rotate
    AZURE_APP_OBJECT_ID: str  = os.environ.get("AZURE_APP_OBJECT_ID", "")
    # Bootstrap client secret for the rotation service account (read from Vault)

    # Rotation window
    ROTATION_DAYS: int        = int(os.environ.get("ROTATION_DAYS", "180"))
    SECRET_LIFETIME_DAYS: int = int(os.environ.get("SECRET_LIFETIME_DAYS", "185"))  # +5d buffer


# ---------------------------------------------------------------------------
# Vault client
# ---------------------------------------------------------------------------
def build_vault_client(cfg: Config) -> hvac.Client:
    """Authenticate to OpenBao using AppRole (prod) or static token (dev)."""
    client = hvac.Client(
        url=cfg.VAULT_ADDR,
        namespace=cfg.VAULT_NAMESPACE or None,
    )

    if cfg.VAULT_ROLE_ID and cfg.VAULT_SECRET_ID:
        log.info("Authenticating to Vault via AppRole")
        client.auth.approle.login(
            role_id=cfg.VAULT_ROLE_ID,
            secret_id=cfg.VAULT_SECRET_ID,
        )
    elif cfg.VAULT_TOKEN:
        log.info("Authenticating to Vault via static token (dev mode)")
        client.token = cfg.VAULT_TOKEN
    else:
        raise RuntimeError(
            "No Vault credentials found. Set VAULT_ROLE_ID+VAULT_SECRET_ID or VAULT_TOKEN."
        )

    if not client.is_authenticated():
        raise RuntimeError("Vault authentication failed.")

    log.info("Vault authentication successful")
    return client


def vault_read(client: hvac.Client, cfg: Config, path: str) -> dict:
    """Read a KV v2 secret; returns the data dict or {} if not found."""
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=cfg.VAULT_KV_MOUNT,
            raise_on_deleted_version=True,
        )
        return resp["data"]["data"]
    except hvac.exceptions.InvalidPath:
        return {}


def vault_write(client: hvac.Client, cfg: Config, path: str, data: dict) -> None:
    """Write (or update) a KV v2 secret."""
    client.secrets.kv.v2.create_or_update_secret(
        path=path,
        secret=data,
        mount_point=cfg.VAULT_KV_MOUNT,
    )
    log.info("Wrote secret to vault path: %s/%s", cfg.VAULT_KV_MOUNT, path)


# ---------------------------------------------------------------------------
# Idempotency: rotation state
# ---------------------------------------------------------------------------
def should_rotate(client: hvac.Client, cfg: Config, platform: str, dry_run: bool) -> bool:
    """
    Returns True if it's time to rotate this platform.
    Reads last rotation timestamp from OpenBao rotation/state.
    """
    if dry_run:
        log.info("[%s] Dry-run: skipping rotation gate check", platform)
        return False

    state = vault_read(client, cfg, cfg.PATH_STATE)
    key = f"{platform}_last_rotated"
    last_rotated_str = state.get(key)

    if not last_rotated_str:
        log.info("[%s] No previous rotation found — will rotate", platform)
        return True

    last_rotated = datetime.fromisoformat(last_rotated_str)
    next_rotation = last_rotated + timedelta(days=cfg.ROTATION_DAYS)
    now = datetime.now(timezone.utc)

    if now >= next_rotation:
        log.info("[%s] Due for rotation (last: %s, next: %s)", platform, last_rotated_str, next_rotation.isoformat())
        return True

    log.info("[%s] Rotation not due yet (next: %s)", platform, next_rotation.isoformat())
    return False


def mark_rotated(client: hvac.Client, cfg: Config, platform: str) -> None:
    """Record successful rotation timestamp in OpenBao."""
    state = vault_read(client, cfg, cfg.PATH_STATE) or {}
    state[f"{platform}_last_rotated"] = datetime.now(timezone.utc).isoformat()
    state[f"{platform}_rotated_by"] = "rotate.py/github-actions"
    vault_write(client, cfg, cfg.PATH_STATE, state)


# ---------------------------------------------------------------------------
# JFrog rotation
# ---------------------------------------------------------------------------
def rotate_jfrog(client: hvac.Client, cfg: Config, dry_run: bool) -> bool:
    """
    Creates a new JFrog access token, writes it to OpenBao, then revokes the old one.
    The admin/bootstrap token itself is read from OpenBao (not from env) after first setup.
    """
    log.info("[jfrog] Starting rotation")

    # Prefer admin token from vault; fall back to env bootstrap
    existing = vault_read(client, cfg, cfg.PATH_JFROG)
    admin_token = existing.get("admin_token") or cfg.JFROG_ADMIN_TOKEN

    if not admin_token:
        raise ValueError("[jfrog] No admin token available — set JFROG_ADMIN_TOKEN env or vault path")

    old_token_id = existing.get("token_id")
    old_token = existing.get("token")

    if dry_run:
        log.info("[jfrog] Dry-run: would POST /access/api/v1/tokens and revoke %s", old_token_id)
        # Validate connectivity
        r = requests.get(
            f"{cfg.JFROG_URL}/access/api/v1/system/ping",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10,
        )
        r.raise_for_status()
        log.info("[jfrog] Connectivity OK (ping: %s)", r.status_code)
        return True

    expires_in = cfg.SECRET_LIFETIME_DAYS * 86400  # seconds

    r = requests.post(
        f"{cfg.JFROG_URL}/access/api/v1/tokens",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
        json={
            "scope": "applied-permissions/user",
            "description": f"rotated-{datetime.utcnow().date()}",
            "expires_in": expires_in,
        },
        timeout=30,
    )
    r.raise_for_status()
    payload = r.json()

    new_token = payload["access_token"]
    new_token_id = payload["token_id"]
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()

    vault_write(client, cfg, cfg.PATH_JFROG, {
        "token": new_token,
        "token_id": new_token_id,
        "admin_token": admin_token,  # carry forward
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "platform": "jfrog",
    })

    # Revoke old token (best-effort — don't fail rotation if revoke fails)
    if old_token_id:
        try:
            rev = requests.delete(
                f"{cfg.JFROG_URL}/access/api/v1/tokens/{old_token_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                timeout=15,
            )
            rev.raise_for_status()
            log.info("[jfrog] Revoked old token %s", old_token_id)
        except Exception as e:
            log.warning("[jfrog] Failed to revoke old token %s: %s (non-fatal)", old_token_id, e)

    log.info("[jfrog] Rotation complete. New token_id: %s, expires: %s", new_token_id, expires_at)
    return True


# ---------------------------------------------------------------------------
# GitHub App token rotation
# ---------------------------------------------------------------------------
def rotate_github(client: hvac.Client, cfg: Config, dry_run: bool) -> bool:
    """
    GitHub App installation tokens are short-lived (1h) and generated on demand.
    This rotation step refreshes the private key stored in OpenBao and validates
    that a new installation token can be minted. The private key itself is rotated
    in GitHub and updated in OpenBao.

    For classic PATs: GitHub does not support API-based deletion, so we only
    generate + store. Consider migrating to GitHub App.
    """
    import base64
    import hashlib
    import struct

    log.info("[github] Starting rotation")

    if not cfg.GITHUB_APP_ID or not cfg.GITHUB_INSTALLATION_ID:
        log.warning("[github] GITHUB_APP_ID or GITHUB_INSTALLATION_ID not set — skipping")
        return False

    existing = vault_read(client, cfg, cfg.PATH_GITHUB)
    private_key_pem = existing.get("app_private_key_pem", "")

    if not private_key_pem:
        log.warning("[github] No GitHub App private key in vault at %s — manual bootstrap required", cfg.PATH_GITHUB)
        log.warning("[github] Store the PEM under key 'app_private_key_pem' to enable automatic rotation")
        return False

    if dry_run:
        log.info("[github] Dry-run: would generate installation token for app %s / installation %s",
                 cfg.GITHUB_APP_ID, cfg.GITHUB_INSTALLATION_ID)
        # Just validate we can build a JWT
        _github_build_jwt(cfg.GITHUB_APP_ID, private_key_pem)
        log.info("[github] JWT generation OK")
        return True

    # Generate a fresh installation token to validate the key still works
    jwt_token = _github_build_jwt(cfg.GITHUB_APP_ID, private_key_pem)
    r = requests.post(
        f"https://api.github.com/app/installations/{cfg.GITHUB_INSTALLATION_ID}/access_tokens",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30,
    )
    r.raise_for_status()
    installation_token = r.json()["token"]
    expires_at = r.json().get("expires_at", "")

    # Store the freshly-minted installation token (consumers should always re-fetch)
    vault_write(client, cfg, cfg.PATH_GITHUB, {
        **existing,  # preserve private key and metadata
        "installation_token": installation_token,
        "installation_token_expires_at": expires_at,
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "github",
    })

    log.info("[github] Installation token refreshed, expires: %s", expires_at)
    log.info("[github] Note: rotate the App private key in GitHub Settings → Apps → Private keys manually every 180d, then update vault path %s/app_private_key_pem", cfg.PATH_GITHUB)
    return True


def _github_build_jwt(app_id: str, private_key_pem: str) -> str:
    """
    Build a GitHub App JWT using only stdlib + the private key PEM.
    Avoids requiring PyJWT for a simple RS256 JWT.
    Falls back to PyJWT if available.
    """
    try:
        import jwt as pyjwt
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
        return pyjwt.encode(payload, private_key_pem, algorithm="RS256")
    except ImportError:
        pass

    # Minimal RS256 JWT using cryptography library
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    import base64, json as _json

    header = base64.urlsafe_b64encode(_json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=")
    now = int(time.time())
    claims = _json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id}).encode()
    payload_b64 = base64.urlsafe_b64encode(claims).rstrip(b"=")
    signing_input = header + b"." + payload_b64

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")

    return (signing_input + b"." + sig_b64).decode()


# ---------------------------------------------------------------------------
# Azure client secret rotation
# ---------------------------------------------------------------------------
def rotate_azure(client: hvac.Client, cfg: Config, dry_run: bool) -> bool:
    """
    Adds a new client secret to the Azure App Registration, writes it to OpenBao,
    then deletes the old secret by key ID.

    Requires:
      - azure-identity
      - azure-mgmt-graphrbac (or msgraph-sdk for newer Graph API)
    """
    log.info("[azure] Starting rotation")

    if not cfg.AZURE_TENANT_ID or not cfg.AZURE_APP_OBJECT_ID:
        log.warning("[azure] AZURE_TENANT_ID or AZURE_APP_OBJECT_ID not set — skipping")
        return False

    # Bootstrap credential: read service principal secret from vault
    existing = vault_read(client, cfg, cfg.PATH_AZURE)
    sp_client_id = existing.get("sp_client_id") or cfg.AZURE_CLIENT_ID
    sp_client_secret = existing.get("sp_client_secret", "")

    if not sp_client_id or not sp_client_secret:
        log.warning("[azure] No service principal credentials in vault — manual bootstrap required")
        log.warning("[azure] Store sp_client_id and sp_client_secret under vault path %s", cfg.PATH_AZURE)
        return False

    old_key_id = existing.get("key_id")

    if dry_run:
        log.info("[azure] Dry-run: would add password to app object %s and delete key %s",
                 cfg.AZURE_APP_OBJECT_ID, old_key_id)
        # Validate token acquisition
        _azure_get_token(cfg.AZURE_TENANT_ID, sp_client_id, sp_client_secret)
        log.info("[azure] Token acquisition OK")
        return True

    # Use Microsoft Graph REST API directly to avoid heavy SDK dependency
    access_token = _azure_get_token(cfg.AZURE_TENANT_ID, sp_client_id, sp_client_secret)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    expires_at = (datetime.now(timezone.utc) + timedelta(days=cfg.SECRET_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    display_name = f"rotated-{datetime.utcnow().date()}"

    # Add new secret
    r = requests.post(
        f"https://graph.microsoft.com/v1.0/applications/{cfg.AZURE_APP_OBJECT_ID}/addPassword",
        headers=headers,
        json={
            "passwordCredential": {
                "displayName": display_name,
                "endDateTime": expires_at,
            }
        },
        timeout=30,
    )
    r.raise_for_status()
    new_secret_data = r.json()
    new_client_secret = new_secret_data["secretText"]  # only returned on creation
    new_key_id = new_secret_data["keyId"]

    # Write to vault BEFORE deleting old — rollback-safe ordering
    vault_write(client, cfg, cfg.PATH_AZURE, {
        "client_id": sp_client_id,
        "client_secret": new_client_secret,
        "tenant_id": cfg.AZURE_TENANT_ID,
        "key_id": new_key_id,
        "sp_client_id": sp_client_id,
        "sp_client_secret": sp_client_secret,  # carry forward rotation service account creds
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "platform": "azure",
        "display_name": display_name,
    })

    # Delete old secret (best-effort)
    if old_key_id:
        try:
            rd = requests.post(
                f"https://graph.microsoft.com/v1.0/applications/{cfg.AZURE_APP_OBJECT_ID}/removePassword",
                headers=headers,
                json={"keyId": old_key_id},
                timeout=15,
            )
            rd.raise_for_status()
            log.info("[azure] Removed old secret key_id: %s", old_key_id)
        except Exception as e:
            log.warning("[azure] Failed to remove old key %s: %s (non-fatal)", old_key_id, e)

    log.info("[azure] Rotation complete. new key_id: %s, expires: %s", new_key_id, expires_at)
    return True


def _azure_get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire a Microsoft Graph access token via client credentials flow."""
    r = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
def notify(platform: str, success: bool, detail: str = "") -> None:
    """Send Slack webhook notification if SLACK_WEBHOOK_URL is set."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return

    icon = "✅" if success else "❌"
    status = "succeeded" if success else "FAILED"
    text = f"{icon} Token rotation *{status}* for `{platform}`"
    if detail:
        text += f"\n>{detail}"
    text += f"\n_Run: {os.environ.get('GITHUB_RUN_ID', 'local')}_"

    try:
        requests.post(webhook_url, json={"text": text}, timeout=10)
    except Exception as e:
        log.warning("Slack notification failed: %s", e)


def github_actions_summary(results: dict) -> None:
    """Write a markdown summary to $GITHUB_STEP_SUMMARY if running in Actions."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        return

    lines = ["## Token rotation summary\n", f"Run at: {datetime.now(timezone.utc).isoformat()}\n\n",
             "| Platform | Result |\n", "|---|---|\n"]
    for platform, result in results.items():
        icon = "✅" if result else "❌"
        lines.append(f"| {platform} | {icon} |\n")

    with open(summary_path, "a") as f:
        f.writelines(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
ROTATORS = {
    "jfrog": rotate_jfrog,
    "github": rotate_github,
    "azure": rotate_azure,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Rotate platform tokens into OpenBao")
    parser.add_argument("--platform", choices=list(ROTATORS.keys()),
                        help="Rotate a single platform only (default: all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate connectivity without making changes")
    parser.add_argument("--force", action="store_true",
                        help="Skip 180-day gate and rotate immediately")
    args = parser.parse_args()

    cfg = Config()
    mode = "DRY-RUN" if args.dry_run else ("FORCED" if args.force else "SCHEDULED")
    log.info("=== rotate.py starting | mode: %s ===", mode)

    vault_client = build_vault_client(cfg)
    platforms = [args.platform] if args.platform else list(ROTATORS.keys())
    results = {}

    for platform in platforms:
        try:
            if not args.dry_run and not args.force:
                if not should_rotate(vault_client, cfg, platform, dry_run=False):
                    results[platform] = "skipped"
                    continue

            rotator = ROTATORS[platform]
            success = rotator(vault_client, cfg, dry_run=args.dry_run)

            if success and not args.dry_run:
                mark_rotated(vault_client, cfg, platform)

            results[platform] = "ok" if success else "failed"
            notify(platform, success)
            log.info("[%s] Result: %s", platform, results[platform])

        except Exception as e:
            log.error("[%s] Rotation failed with exception: %s", platform, e, exc_info=True)
            results[platform] = "error"
            notify(platform, success=False, detail=str(e))

    github_actions_summary(results)

    failed = [p for p, r in results.items() if r in ("failed", "error")]
    if failed:
        log.error("=== Rotation complete with failures: %s ===", failed)
        return 1

    log.info("=== Rotation complete. Results: %s ===", results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
