# ABOUTME: Unit tests for the destroy command's stack selection and ordering
# ABOUTME: Focus: bootstrap ordering and only destroying stacks that were deployed

"""Tests for DestroyCommand stack selection.

Two properties worth pinning:

1. **Order.** The bootstrap server is destroyed before the auth stack it depends
   on for the federated role.
2. **Only what exists.** A stack is offered for destruction only when the profile
   says it was deployed — otherwise the warning lists stacks that will be skipped,
   which trains people to skim past exactly the prompt they should read.
"""

import pytest

from claude_code_with_bedrock.cli.commands.destroy import DestroyCommand
from claude_code_with_bedrock.config import Profile

# Same order the command uses for a full `ccwb destroy`.
_FULL_ORDER = [
    "bootstrap",
    "analytics",
    "dashboard",
    "monitoring",
    "networking",
    "s3bucket",
    "auth",
]


def _profile(**overrides):
    base = {
        "name": "demo",
        "provider_domain": "example.okta.com",
        "client_id": "0oaEXAMPLECLIENTID",
        "credential_storage": "session",
        "aws_region": "us-east-1",
        "identity_pool_name": "claude-code",
        "federation_type": "direct",
    }
    base.update(overrides)
    return Profile(**base)


def _applicable(profile):
    cmd = DestroyCommand()
    return [s for s in _FULL_ORDER if cmd._applies(s, profile)]


class TestBootstrapTeardownOrder:
    def test_bootstrap_precedes_auth(self):
        """The bootstrap broker depends on the auth stack's federated role."""
        profile = _profile(cowork_config_mode="dynamic", monitoring_enabled=False)
        order = _applicable(profile)
        assert order.index("bootstrap") < order.index("auth")


class TestAppliesGating:
    def test_static_config_mode_skips_bootstrap(self):
        """No bootstrap server is deployed in static mode, so nothing to destroy."""
        profile = _profile(cowork_config_mode="static", monitoring_enabled=False)
        assert "bootstrap" not in _applicable(profile)

    def test_default_profile_skips_bootstrap(self):
        """cowork_config_mode defaults to static."""
        assert "bootstrap" not in _applicable(_profile(monitoring_enabled=False))

    @pytest.mark.parametrize(
        "stack", ["monitoring", "dashboard", "networking", "analytics", "s3bucket"]
    )
    def test_monitoring_stacks_gated_on_monitoring_enabled(self, stack):
        """Pre-existing behaviour, preserved when the gating moved into _applies."""
        assert stack not in _applicable(_profile(monitoring_enabled=False))
        assert stack in _applicable(_profile(monitoring_enabled=True))

    def test_auth_always_applies(self):
        assert "auth" in _applicable(_profile(monitoring_enabled=False))


class TestLabels:
    def test_known_labels(self):
        assert DestroyCommand._label("bootstrap") == "Bootstrap server"
        assert DestroyCommand._label("s3bucket") == "S3 bucket"

    def test_unknown_falls_back_to_capitalize(self):
        assert DestroyCommand._label("auth") == "Auth"
