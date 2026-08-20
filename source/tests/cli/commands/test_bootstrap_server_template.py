# ABOUTME: Structural tests for bootstrap-server.yaml (ALB endpoint + optional ACM cert)
# ABOUTME: Focus: the certificate is only requested when it can actually be validated

"""Structural tests for the bootstrap server template.

The certificate path is the fragile one. CloudFormation BLOCKS until ACM issues,
so if the stack requests a certificate it cannot validate, the deploy sits waiting
rather than failing — a much worse experience than a clear up-front error. These
tests pin the guards that prevent that.
"""

from pathlib import Path

import pytest
import yaml

_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "deployment"
    / "infrastructure"
    / "bootstrap-server.yaml"
)


class _CfnLoader(yaml.SafeLoader):
    """CloudFormation short-form tags (!Ref, !If, ...) aren't plain YAML."""


_CfnLoader.add_multi_constructor(
    "!", lambda loader, tag_suffix, node: {"Fn::" + tag_suffix: getattr(node, "value", None)}
)


@pytest.fixture(scope="module")
def tpl():
    return yaml.load(_TEMPLATE.read_text(), Loader=_CfnLoader)


class TestCertificateCreation:
    def test_certificate_arn_accepts_empty(self, tpl):
        """Empty means 'request one for me'. An AllowedPattern requiring an ARN
        would make that impossible, so there must not be one."""
        param = tpl["Parameters"]["CertificateArn"]
        assert param.get("Default") == ""
        assert "AllowedPattern" not in param

    def test_create_condition_requires_domain_and_a_zone(self, tpl):
        """Requesting a cert needs something to request it FOR and somewhere to
        publish the validation record. Missing either => the stack would hang."""
        cond = str(tpl["Conditions"]["CreateCertificate"])
        assert "CertificateArn" in cond
        assert "DomainName" in cond
        assert "HostedZoneId" in cond

    def test_certificate_resource_is_conditional(self, tpl):
        assert tpl["Resources"]["BootstrapCertificate"].get("Condition") == "CreateCertificate"

    def test_certificate_uses_dns_validation(self, tpl):
        """Email validation needs a human to click a link — unusable in a deploy."""
        props = tpl["Resources"]["BootstrapCertificate"]["Properties"]
        assert props["ValidationMethod"] == "DNS"
        assert "DomainValidationOptions" in props

    def test_listener_picks_created_cert_or_supplied_one(self, tpl):
        listener = tpl["Resources"]["BootstrapHttpsListener"]["Properties"]
        rendered = str(listener["Certificates"])
        assert "CreateCertificate" in rendered
        assert "BootstrapCertificate" in rendered
        assert "CertificateArn" in rendered

    def test_validation_zone_falls_back_to_record_zone(self, tpl):
        """A separate validation zone is only needed when the record zone is
        private; otherwise reuse it rather than asking twice."""
        assert "UseSeparateValidationZone" in tpl["Conditions"]
        rendered = str(tpl["Resources"]["BootstrapCertificate"]["Properties"])
        assert "CertificateValidationZoneId" in rendered
        assert "HostedZoneId" in rendered


class TestEndpointHardening:
    def test_listener_default_action_is_404(self, tpl):
        """Only /config should reach the Lambda."""
        actions = tpl["Resources"]["BootstrapHttpsListener"]["Properties"]["DefaultActions"]
        assert actions[0]["Type"] == "fixed-response"
        assert actions[0]["FixedResponseConfig"]["StatusCode"] == "404"

    def test_config_path_rule_targets_the_lambda(self, tpl):
        rule = tpl["Resources"]["BootstrapConfigRule"]["Properties"]
        assert "/config" in str(rule["Conditions"])
        assert rule["Actions"][0]["Type"] == "forward"

    def test_target_group_health_checks_disabled(self, tpl):
        """A health check would invoke the Lambda with no bearer token, get a 401,
        and mark the only target unhealthy — the listener would 503 everyone."""
        tg = tpl["Resources"]["BootstrapTargetGroup"]["Properties"]
        assert tg["TargetType"] == "lambda"
        assert tg["HealthCheckEnabled"] is False

    def test_no_api_gateway_left(self, tpl):
        """The HTTP API could not be made private; it must be fully gone."""
        types = [r["Type"] for r in tpl["Resources"].values()]
        assert not any(t.startswith("AWS::ApiGatewayV2") for t in types)

    def test_lambda_role_stays_least_privilege(self, tpl):
        """AssumeRoleWithWebIdentity is authorized by the TARGET role's trust
        policy, not this one. Inline sts/bedrock grants would be a red flag."""
        role = tpl["Resources"]["BootstrapFunctionRole"]["Properties"]
        assert "Policies" not in role
        assert len(role["ManagedPolicyArns"]) == 1

    def test_scheme_is_constrained(self, tpl):
        assert tpl["Parameters"]["AlbScheme"]["AllowedValues"] == ["internal", "internet-facing"]
        assert tpl["Parameters"]["AlbScheme"]["Default"] == "internal"

    def test_outputs_for_external_dns(self, tpl):
        """Admins whose DNS lives outside Route 53 need these to wire it up."""
        for out in ("BootstrapUrl", "AlbDnsName", "AlbCanonicalHostedZoneId"):
            assert out in tpl["Outputs"], out
