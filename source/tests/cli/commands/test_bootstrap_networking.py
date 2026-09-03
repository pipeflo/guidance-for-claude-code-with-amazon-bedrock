# ABOUTME: Tests for bootstrap-networking.yaml, the optional VPC for the bootstrap ALB
# ABOUTME: Asserts the scheme drives the shape: internal => no IGW/NAT/route out
"""Structural tests for the optional bootstrap VPC template.

These assert the properties customers depend on rather than exact resource
counts: an internal VPC must have NO path off the VPC, and NEITHER scheme may
create a NAT gateway (it would cost ~$32/month per AZ and route nothing, since
the ALB takes inbound only and the Lambda runs outside the VPC).
"""

from pathlib import Path

import pytest
import yaml

_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "deployment"
    / "infrastructure"
    / "bootstrap-networking.yaml"
)


class _CfnLoader(yaml.SafeLoader):
    """CloudFormation short-form tags (!Ref, !Sub, ...) aren't plain YAML."""


def _multi(loader, tag_suffix, node):
    return {"Fn::" + tag_suffix: getattr(node, "value", None)}


_CfnLoader.add_multi_constructor("!", _multi)


@pytest.fixture(scope="module")
def tpl():
    return yaml.load(_TEMPLATE.read_text(), Loader=_CfnLoader)


def _types(tpl):
    return sorted(r["Type"] for r in tpl["Resources"].values())


class TestBootstrapNetworkingTemplate:
    def test_template_exists_and_parses(self, tpl):
        assert "Resources" in tpl and "Outputs" in tpl

    def test_never_creates_a_nat_gateway(self, tpl):
        """A NAT would cost ~$32/month per AZ and route nothing here."""
        assert "AWS::EC2::NatGateway" not in _types(tpl)
        assert "AWS::EC2::EIP" not in _types(tpl)

    def test_creates_exactly_two_subnets(self, tpl):
        """An ALB needs two AZs; more would just consume address space."""
        subnets = [r for r in tpl["Resources"].values() if r["Type"] == "AWS::EC2::Subnet"]
        assert len(subnets) == 2
        azs = [s["Properties"]["AvailabilityZone"] for s in subnets]
        assert azs[0] != azs[1], "subnets must be in different AZs"

    def test_internet_resources_are_conditional_on_public(self, tpl):
        """The IGW, its attachment and the default route must ALL be gated, or an
        'internal' VPC would silently get a route to the internet."""
        for name in ("InternetGateway", "InternetGatewayAttachment", "DefaultPublicRoute"):
            assert tpl["Resources"][name].get("Condition") == "IsPublic", name

    def test_no_unconditional_route_off_the_vpc(self, tpl):
        """Every Route resource must be conditional — that is what makes
        AlbScheme=internal genuinely private."""
        routes = {
            n: r for n, r in tpl["Resources"].items() if r["Type"] == "AWS::EC2::Route"
        }
        assert routes, "expected at least one route resource"
        for name, res in routes.items():
            assert res.get("Condition"), f"{name} is not conditional"

    def test_is_public_condition_matches_scheme(self, tpl):
        cond = tpl["Conditions"]["IsPublic"]
        assert "internet-facing" in str(cond)

    def test_scheme_is_constrained(self, tpl):
        assert tpl["Parameters"]["AlbScheme"]["AllowedValues"] == ["internal", "internet-facing"]
        assert tpl["Parameters"]["AlbScheme"]["Default"] == "internal"

    def test_cidr_must_be_slash_16(self, tpl):
        """Subnets are carved with !Cidr assuming a /16; anything else breaks."""
        assert tpl["Parameters"]["VpcCidr"]["AllowedPattern"].endswith("/16$")

    def test_outputs_needed_by_the_bootstrap_stack(self, tpl):
        """deploy.py reads these to wire the ALB, so they must not be renamed."""
        for out in ("VpcId", "SubnetIds", "VpcCidr"):
            assert out in tpl["Outputs"], out

    def test_dns_enabled_for_private_hosted_zones(self, tpl):
        """A private Route 53 zone only resolves with both DNS attributes on."""
        vpc = tpl["Resources"]["Vpc"]["Properties"]
        assert vpc["EnableDnsSupport"] is True
        assert vpc["EnableDnsHostnames"] is True
