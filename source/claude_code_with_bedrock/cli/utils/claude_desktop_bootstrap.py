# ABOUTME: Generates MDM trust-anchor profiles for the Claude Desktop bootstrap server
# ABOUTME: Outputs .json, .mobileconfig (macOS), and .reg (Windows) — only contains
# ABOUTME: bootstrapUrl + bootstrapOidc keys. Per-user config is fetched from the
# ABOUTME: bootstrap server at sign-in.

"""Claude Desktop bootstrap MDM trust-anchor generation.

The trust-anchor is the minimal MDM payload pushed to every device. It contains
only the bootstrap URL and OIDC settings — everything else (region, models,
feature toggles) is delivered dynamically by the bootstrap Lambda based on the
user's group claims.

This is intentionally separate from cowork_3p.py because the trust-anchor has a
different set of keys (no inferenceProvider, no inferenceBedrockRegion, no
inferenceModels) and is deployed alongside, not instead of, an existing CoWork
MDM profile.
"""

import json
import uuid
from pathlib import Path

from rich.console import Console


def build_trust_anchor_config(profile, bootstrap_endpoint: str) -> dict:
    """Build the trust-anchor MDM config from a ccwb profile.

    Args:
        profile: Profile dataclass instance
        bootstrap_endpoint: Bootstrap server URL (from deploy output)

    Returns:
        Dict with bootstrapUrl, bootstrapOidc, and recommended toggles.
    """
    # Resolve OIDC issuer from provider config
    issuer = ""
    if profile.provider_type == "okta":
        auth_server = getattr(profile, "okta_auth_server_id", "default") or "default"
        issuer = f"https://{profile.provider_domain}/oauth2/{auth_server}"
    elif profile.provider_type == "auth0":
        issuer = f"https://{profile.provider_domain}/"
    elif profile.provider_type == "azure":
        tenant_id = profile.provider_domain.split(".")[0] if profile.provider_domain else ""
        issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    elif profile.provider_type == "cognito":
        pool_id = getattr(profile, "cognito_user_pool_id", "")
        if pool_id:
            pool_region = pool_id.split("_")[0] if "_" in pool_id else profile.aws_region
            issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
    elif profile.provider_type == "google":
        issuer = "https://accounts.google.com"

    # Client ID: dedicated bootstrap app if set, otherwise reuse the profile's main client
    client_id = (
        getattr(profile, "claude_desktop_bootstrap_oidc_client_id", None)
        or profile.client_id
    )

    # bootstrapOidc sub-fields per the Claude Desktop configuration reference:
    # clientId, issuer, authorizationUrl, tokenUrl (+ scopes for the groups claim).
    # Providing explicit endpoints avoids relying on OIDC discovery.
    oidc = {
        "issuer": issuer,
        "clientId": client_id,
        "scopes": "openid profile groups",
    }
    if issuer:
        if profile.provider_type == "okta":
            oidc["authorizationUrl"] = f"{issuer}/v1/authorize"
            oidc["tokenUrl"] = f"{issuer}/v1/token"
        else:
            # Standard OIDC discovery paths for the remaining providers.
            oidc["authorizationUrl"] = f"{issuer.rstrip('/')}/authorize"
            oidc["tokenUrl"] = f"{issuer.rstrip('/')}/token"

    # Per the config reference, ALL values are strings — including booleans.
    return {
        "bootstrapEnabled": "true",
        "bootstrapUrl": bootstrap_endpoint,
        "bootstrapOidc": oidc,
        "disableDeploymentModeChooser": "true",
    }


def _xml_escape(s: str) -> str:
    """Escape XML special characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_plist_value(value) -> str:
    """Render a Python value as plist XML (string, bool, dict, or JSON-encoded list/dict)."""
    if isinstance(value, bool):
        return "<true/>" if value else "<false/>"
    elif isinstance(value, dict):
        # bootstrapOidc is rendered as a nested dict, not a JSON string
        lines = ["<dict>"]
        for k, v in value.items():
            lines.append(f"\t\t\t\t<key>{_xml_escape(k)}</key>")
            if isinstance(v, bool):
                lines.append("\t\t\t\t" + ("<true/>" if v else "<false/>"))
            else:
                lines.append(f"\t\t\t\t<string>{_xml_escape(str(v))}</string>")
        lines.append("\t\t\t</dict>")
        return "\n".join(lines)
    elif isinstance(value, list):
        return f"<string>{_xml_escape(json.dumps(value))}</string>"
    else:
        return f"<string>{_xml_escape(str(value))}</string>"


def generate_json(output_dir: Path, config: dict) -> Path:
    """Write trust-anchor as raw JSON (reference / debugging)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "claude-desktop-trust-anchor.json"
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    return path


def generate_mobileconfig(output_dir: Path, config: dict) -> Path:
    """Write trust-anchor as a macOS .mobileconfig payload."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()

    payload_items = []
    for key, value in config.items():
        payload_items.append(f"\t\t\t<key>{_xml_escape(key)}</key>")
        payload_items.append(f"\t\t\t{_render_plist_value(value)}")

    payload_content = "\n".join(payload_items)

    mobileconfig = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.anthropic.claudefordesktop</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>{payload_uuid}</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.anthropic.claudefordesktop.bootstrap</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>Claude Desktop - Bootstrap Trust Anchor</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
{payload_content}
\t\t</dict>
\t</array>
\t<key>PayloadDisplayName</key>
\t<string>Claude Desktop Bootstrap Server</string>
\t<key>PayloadIdentifier</key>
\t<string>com.company.claude-desktop-bootstrap</string>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>{profile_uuid}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
</dict>
</plist>
"""
    path = output_dir / "claude-desktop-trust-anchor.mobileconfig"
    with open(path, "w") as f:
        f.write(mobileconfig)
    return path


def generate_reg_file(output_dir: Path, config: dict) -> Path:
    """Write trust-anchor as a Windows .reg file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    reg_key = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Anthropic\Claude Desktop"
    lines = ["Windows Registry Editor Version 5.00", "", f"[{reg_key}]"]

    for key, value in config.items():
        if isinstance(value, bool):
            lines.append(f'"{key}"=dword:{1 if value else 0:08x}')
        elif isinstance(value, dict):
            # Render dict as a JSON string (Windows MDM convention)
            escaped = json.dumps(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'"{key}"="{escaped}"')
        elif isinstance(value, list):
            escaped = json.dumps(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'"{key}"="{escaped}"')
        else:
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'"{key}"="{escaped}"')

    path = output_dir / "claude-desktop-trust-anchor.reg"
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def generate_all(output_dir: Path, config: dict, console: Console) -> list[str]:
    """Generate all three trust-anchor files (.json, .mobileconfig, .reg).

    Returns list of generated file paths (as strings).
    """
    paths = [
        generate_json(output_dir, config),
        generate_mobileconfig(output_dir, config),
        generate_reg_file(output_dir, config),
    ]
    for p in paths:
        console.print(f"  [green]✓[/green] {p.name}")
    return [str(p) for p in paths]
