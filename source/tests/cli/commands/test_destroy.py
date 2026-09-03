# ABOUTME: Unit tests for the destroy command's stack selection and ordering
# ABOUTME: Focus: bootstrap teardown order, and never deleting a customer-supplied VPC

"""Tests for DestroyCommand stack selection.

The two properties worth pinning:

1. **Order.** The bootstrap server must be destroyed before its VPC — the load
   balancer lives in that VPC, so deleting the VPC first fails.
2. **Never delete someone else's VPC.** `bootstrap-networking` may only be a
   destroy candidate when ccwb created the VPC itself. If the customer supplied a
   VPC, ccwb must not go anywhere near it.
"""

import pytest

from claude_code_with_bedrock.cli.commands.destroy import DestroyCommand
from claude_code_with_bedrock.config import Profile

# Same order the command uses for a full `ccwb destroy`.
_FULL_ORDER = [
    "bootstrap",
    "bootstrap-networking",
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
    def test_server_is_destroyed_before_its_vpc(self):
        """Deleting the VPC first would fail — the ALB is still in it."""
        profile = _profile(
            cowork_config_mode="dynamic",
            claude_desktop_create_vpc=True,
            monitoring_enabled=False,
        )
        order = _applicable(profile)
        assert order.index("bootstrap") < order.index("bootstrap-networking")

    def test_bootstrap_precedes_auth(self):
        """The bootstrap broker depends on the auth stack's federated role."""
        profile = _profile(cowork_config_mode="dynamic", monitoring_enabled=False)
        order = _applicable(profile)
        assert order.index("bootstrap") < order.index("auth")


class TestAppliesGating:
    def test_customer_supplied_vpc_is_never_a_destroy_candidate(self):
        """The critical one: if the customer gave us a VPC, ccwb must not delete it."""
        profile = _profile(
            cowork_config_mode="dynamic",
            claude_desktop_create_vpc=False,
            claude_desktop_vpc_id="vpc-0customersupplied",
            monitoring_enabled=False,
        )
        assert "bootstrap-networking" not in _applicable(profile)
        assert "bootstrap" in _applicable(profile)

    def test_created_vpc_is_a_destroy_candidate(self):
        profile = _profile(
            cowork_config_mode="dynamic",
            claude_desktop_create_vpc=True,
            monitoring_enabled=False,
        )
        assert "bootstrap-networking" in _applicable(profile)

    def test_static_config_mode_skips_both_bootstrap_stacks(self):
        """No bootstrap server is deployed in static mode, so nothing to destroy."""
        profile = _profile(
            cowork_config_mode="static",
            claude_desktop_create_vpc=True,  # stale flag must not resurrect it
            monitoring_enabled=False,
        )
        applicable = _applicable(profile)
        assert "bootstrap" not in applicable
        assert "bootstrap-networking" not in applicable

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
    def test_hyphenated_name_is_not_mangled(self):
        """`str.capitalize()` would render this as 'Bootstrap-networking'."""
        assert DestroyCommand._label("bootstrap-networking") == "Bootstrap VPC"

    def test_known_labels(self):
        assert DestroyCommand._label("bootstrap") == "Bootstrap server"
        assert DestroyCommand._label("s3bucket") == "S3 bucket"

    def test_unknown_falls_back_to_capitalize(self):
        assert DestroyCommand._label("auth") == "Auth"
