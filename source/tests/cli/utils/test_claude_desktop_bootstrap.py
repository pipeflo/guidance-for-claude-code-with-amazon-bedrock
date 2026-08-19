# ABOUTME: Unit tests for the Claude Desktop bootstrap trust-anchor MDM generator
# ABOUTME: Validates JSON, .mobileconfig, and .reg output formats

"""Tests for claude_desktop_bootstrap utility."""

import json
from pathlib import Path

import pytest
from rich.console import Console

from claude_code_with_bedrock.cli.utils.claude_desktop_bootstrap import (
    build_trust_anchor_config,
    generate_all,
    generate_json,
    generate_mobileconfig,
    generate_reg_file,
)
from claude_code_with_bedrock.config import Profile


@pytest.fixture
def okta_profile():
    """Sample Okta profile with bootstrap endpoint set."""
    return Profile(
        name="test-okta",
        provider_domain="example.okta.com",
        client_id="0oa1234567890abcdef",
        credential_storage="session",
        aws_region="us-east-1",
        identity_pool_name="test-pool",
        provider_type="okta",
        okta_auth_server_id="aus1abc",
        claude_desktop_bootstrap_endpoint="https://api.example.com/config",
    )


@pytest.fixture
def google_profile():
    """Google OIDC profile."""
    return Profile(
        name="test-google",
        provider_domain="accounts.google.com",
        client_id="google-client-id",
        credential_storage="session",
        aws_region="us-east-1",
        identity_pool_name="test-pool",
        provider_type="google",
        claude_desktop_bootstrap_endpoint="https://api.example.com/config",
    )


class TestBuildTrustAnchorConfig:
    def test_okta_issuer_uses_auth_server(self, okta_profile):
        """Okta issuer URL includes the authorization server ID."""
        config = build_trust_anchor_config(okta_profile, "https://bootstrap.example.com/config")
        assert config["bootstrapOidc"]["issuer"] == "https://example.okta.com/oauth2/aus1abc"

    def test_okta_issuer_defaults_when_no_auth_server(self):
        """Okta issuer falls back to 'default' when no auth server set."""
        profile = Profile(
            name="t",
            provider_domain="ex.okta.com",
            client_id="cid",
            credential_storage="session",
            aws_region="us-east-1",
            identity_pool_name="p",
            provider_type="okta",
        )
        config = build_trust_anchor_config(profile, "https://b.example.com")
        assert config["bootstrapOidc"]["issuer"] == "https://ex.okta.com/oauth2/default"

    def test_google_issuer(self, google_profile):
        """Google uses fixed accounts.google.com issuer."""
        config = build_trust_anchor_config(google_profile, "https://b.example.com")
        assert config["bootstrapOidc"]["issuer"] == "https://accounts.google.com"

    def test_bootstrap_url_set(self, okta_profile):
        """bootstrapUrl in the config matches the endpoint passed in."""
        config = build_trust_anchor_config(okta_profile, "https://my-bootstrap.example.com/config")
        assert config["bootstrapUrl"] == "https://my-bootstrap.example.com/config"

    def test_reuses_profile_client_id(self, okta_profile):
        """Defaults to the profile's main OIDC client_id."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["bootstrapOidc"]["clientId"] == "0oa1234567890abcdef"

    def test_uses_dedicated_bootstrap_client_id(self, okta_profile):
        """Uses claude_desktop_bootstrap_oidc_client_id when set."""
        okta_profile.claude_desktop_bootstrap_oidc_client_id = "0oa_dedicated_bootstrap_app"
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["bootstrapOidc"]["clientId"] == "0oa_dedicated_bootstrap_app"

    def test_groups_scope_included(self, okta_profile):
        """OIDC scopes include 'groups' for zone/role resolution."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert "groups" in config["bootstrapOidc"]["scopes"]

    def test_disable_deployment_chooser(self, okta_profile):
        """End users don't see the provider selection screen. Per the config
        reference all values are strings, including booleans."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["disableDeploymentModeChooser"] == "true"

    def test_bootstrap_enabled_string_true(self, okta_profile):
        """bootstrapEnabled must be present and the string 'true'."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["bootstrapEnabled"] == "true"

    def test_okta_oidc_endpoints(self, okta_profile):
        """Okta authorization/token URLs are derived from the issuer."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        oidc = config["bootstrapOidc"]
        assert oidc["authorizationUrl"].endswith("/v1/authorize")
        assert oidc["tokenUrl"].endswith("/v1/token")

    def test_okta_fixed_redirect_port(self, okta_profile):
        """Okta needs a fixed loopback port (no dynamic ports); default 53180.
        redirectPort is an INTEGER inside the bootstrapOidc object (not a string —
        a string makes Claude Desktop fall back to device-code mode)."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["bootstrapOidc"]["redirectPort"] == 53180
        assert isinstance(config["bootstrapOidc"]["redirectPort"], int)

    def test_redirect_port_configurable(self, okta_profile):
        okta_profile.claude_desktop_redirect_port = 8123
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        assert config["bootstrapOidc"]["redirectPort"] == 8123


class TestGenerateJson:
    def test_writes_indented_json(self, okta_profile, tmp_path):
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        path = generate_json(tmp_path, config)
        assert path.exists()
        assert path.name == "claude-desktop-trust-anchor.json"
        data = json.loads(path.read_text())
        assert data["bootstrapUrl"] == "https://b.example.com"
        assert data["bootstrapOidc"]["clientId"] == "0oa1234567890abcdef"


class TestGenerateMobileconfig:
    def test_writes_mobileconfig(self, okta_profile, tmp_path):
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        path = generate_mobileconfig(tmp_path, config)
        assert path.exists()
        assert path.name == "claude-desktop-trust-anchor.mobileconfig"
        content = path.read_text()
        # XML structure
        assert "<?xml version" in content
        assert "<plist version=\"1.0\">" in content
        # Payload type matches Anthropic's expected MDM domain
        assert "com.anthropic.claudefordesktop" in content
        # bootstrapOidc rendered as a nested <dict>, not a JSON string
        assert "<key>bootstrapOidc</key>" in content
        assert "<key>issuer</key>" in content
        # bootstrapUrl rendered as a top-level string
        assert "<key>bootstrapUrl</key>" in content
        assert "https://b.example.com" in content

    def test_escapes_xml_special_chars(self, tmp_path):
        """Ampersands and quotes in values are XML-escaped."""
        config = {
            "bootstrapUrl": "https://example.com/path?foo=bar&baz=qux",
            "bootstrapOidc": {
                "issuer": "https://issuer.example.com",
                "clientId": 'client"id',
                "scopes": "openid",
            },
            "disableDeploymentModeChooser": True,
        }
        path = generate_mobileconfig(tmp_path, config)
        content = path.read_text()
        assert "&amp;" in content
        assert "&quot;" in content


class TestGenerateRegFile:
    def test_writes_reg_file(self, okta_profile, tmp_path):
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        path = generate_reg_file(tmp_path, config)
        assert path.exists()
        assert path.name == "claude-desktop-trust-anchor.reg"
        content = path.read_text()
        # Registry header
        assert "Windows Registry Editor Version 5.00" in content
        # Correct registry key path
        assert r"[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Claude]" in content
        # Per the config reference all values are strings, including booleans.
        assert '"disableDeploymentModeChooser"="true"' in content
        # URL string rendered with quotes
        assert '"bootstrapUrl"="https://b.example.com"' in content

    def test_does_not_use_nested_subkey(self, okta_profile, tmp_path):
        """Regression: values must NOT live under a nested subkey.

        Claude Desktop only reads HKLM\\SOFTWARE\\Policies\\Claude. Writing to
        ...\\Policies\\Anthropic\\Claude Desktop imports without error and is
        visible in regedit, but the app never picks it up -- so the trust anchor
        silently does nothing at fleet rollout.
        """
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        content = generate_reg_file(tmp_path, config).read_text()
        assert "Anthropic" not in content
        assert "Claude Desktop" not in content

    def test_values_are_directly_under_the_key(self, okta_profile, tmp_path):
        """Every value line must follow the single key header, with no other
        key header in between (values must be REG_SZ directly under the key)."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        lines = [ln for ln in generate_reg_file(tmp_path, config).read_text().splitlines() if ln.strip()]
        key_headers = [i for i, ln in enumerate(lines) if ln.startswith("[")]
        assert len(key_headers) == 1, "expected exactly one registry key header"
        # Everything after the key header is a quoted value assignment.
        for ln in lines[key_headers[0] + 1 :]:
            assert ln.startswith('"') and "=" in ln, f"not a value line: {ln!r}"

    def test_bootstrap_keys_present_as_reg_sz(self, okta_profile, tmp_path):
        """The keys the app actually needs are emitted as REG_SZ strings."""
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        content = generate_reg_file(tmp_path, config).read_text()
        assert '"bootstrapEnabled"="true"' in content
        assert '"bootstrapUrl"=' in content
        assert '"bootstrapOidc"=' in content
        # REG_EXPAND_SZ / dword forms would break parsing of these string keys.
        assert '"bootstrapUrl"=hex' not in content
        assert '"bootstrapUrl"=dword' not in content

    def test_escapes_backslashes_and_quotes(self, tmp_path):
        """Special characters in values are properly escaped for .reg format."""
        config = {
            "bootstrapUrl": "https://example.com",
            "bootstrapOidc": {
                "issuer": "https://issuer.com",
                "clientId": 'client"id',
                "scopes": "openid",
            },
        }
        path = generate_reg_file(tmp_path, config)
        content = path.read_text()
        # JSON-encoded dict with escaped quotes
        assert '\\"clientId\\"' in content

    def test_native_bool_still_renders_as_dword(self, tmp_path):
        """The renderer keeps its bool→DWORD branch for genuinely-boolean keys."""
        config = {"bootstrapUrl": "https://example.com", "someFlag": True}
        path = generate_reg_file(tmp_path, config)
        content = path.read_text()
        assert '"someFlag"=dword:00000001' in content


class TestGenerateAll:
    def test_generates_all_three_files(self, okta_profile, tmp_path):
        config = build_trust_anchor_config(okta_profile, "https://b.example.com")
        console = Console(record=True)
        paths = generate_all(tmp_path, config, console)

        assert len(paths) == 3
        assert (tmp_path / "claude-desktop-trust-anchor.json").exists()
        assert (tmp_path / "claude-desktop-trust-anchor.mobileconfig").exists()
        assert (tmp_path / "claude-desktop-trust-anchor.reg").exists()
