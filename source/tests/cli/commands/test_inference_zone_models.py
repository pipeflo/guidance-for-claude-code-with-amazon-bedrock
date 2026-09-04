# ABOUTME: Regression tests for ccwb inference-zone model-ID parsing/discovery.
# ABOUTME: Guards that new families (fable) and major-only ids (sonnet-5) are matched.

"""Tests for Anthropic model-ID parsing in inference_zone.

The model picker in `ccwb inference-zone create` is populated by live Bedrock
discovery, filtered through `_parse_model_id` / `_ANTHROPIC_MODEL_RE`. A too-strict
regex silently drops models from the picker (this happened with fable-5 and the
major-only sonnet-5), so these tests pin the accepted ID shapes.
"""

import pytest

from claude_code_with_bedrock.cli.commands.inference_zone import (
    ModelChoice,
    _model_display,
    _model_short,
    _parse_model_id,
)


class TestParseModelId:
    @pytest.mark.parametrize(
        "model_id,expected",
        [
            # Family + major + minor (classic)
            ("anthropic.claude-opus-4-8", ("opus", 4, 8)),
            ("anthropic.claude-sonnet-4-6", ("sonnet", 4, 6)),
            # With date / -v / :N suffixes
            ("anthropic.claude-haiku-4-5-20251001-v1:0", ("haiku", 4, 5)),
            ("anthropic.claude-opus-4-5-20251101-v1:0", ("opus", 4, 5)),
            ("anthropic.claude-opus-4-6-v1", ("opus", 4, 6)),
            # CRIS zone-prefixed ids
            ("us.anthropic.claude-opus-4-8", ("opus", 4, 8)),
            ("global.anthropic.claude-sonnet-4-6", ("sonnet", 4, 6)),
            # NEW: major-only ids (no minor version)
            ("anthropic.claude-sonnet-5", ("sonnet", 5, None)),
            ("anthropic.claude-fable-5", ("fable", 5, None)),
            ("us.anthropic.claude-sonnet-5", ("sonnet", 5, None)),
            ("us.anthropic.claude-fable-5", ("fable", 5, None)),
        ],
    )
    def test_recognized_ids(self, model_id, expected):
        assert _parse_model_id(model_id) == expected

    @pytest.mark.parametrize(
        "model_id",
        [
            # Non-anthropic / non-claude
            "amazon.nova-pro-v1:0",
            "us.meta.llama3-1-8b-instruct-v1:0",
            # Legacy claude-3 shape has the digit BEFORE the family — not our format
            "anthropic.claude-3-sonnet-20240229-v1:0:200k",
            # Embeddings / unrelated
            "cohere.embed-v4:0",
        ],
    )
    def test_unrecognized_ids(self, model_id):
        assert _parse_model_id(model_id) is None


class TestShortAndDisplay:
    def test_short_with_minor(self):
        assert _model_short("opus", 4, 8) == "opus-4-8"

    def test_short_major_only(self):
        assert _model_short("sonnet", 5, None) == "sonnet-5"
        assert _model_short("fable", 5, None) == "fable-5"

    def test_display_with_minor(self):
        assert _model_display("opus", 4, 8) == "Claude Opus 4.8"

    def test_display_major_only(self):
        assert _model_display("sonnet", 5, None) == "Claude Sonnet 5"
        assert _model_display("fable", 5, None) == "Claude Fable 5"


class TestModelChoiceOrdering:
    def _mc(self, family, major, minor):
        return ModelChoice(
            short_name=_model_short(family, major, minor),
            display_name=_model_display(family, major, minor),
            family=family,
            major=major,
            minor=minor,
            foundation_arn_template="",
            cris_profile_id=None,
        )

    def test_major_only_sorts_newest_within_family(self):
        """sonnet-5 (major-only) must sort ahead of sonnet-4-6 (older major)."""
        s5 = self._mc("sonnet", 5, None)
        s46 = self._mc("sonnet", 4, 6)
        assert sorted([s46, s5]) == [s5, s46]

    def test_family_order_puts_fable_after_haiku(self):
        opus = self._mc("opus", 4, 8)
        fable = self._mc("fable", 5, None)
        haiku = self._mc("haiku", 4, 5)
        assert sorted([fable, haiku, opus]) == [opus, haiku, fable]

    def test_major_only_sorts_below_same_major_minor(self):
        """A hypothetical sonnet-5-1 should sort ahead of bare sonnet-5."""
        s5 = self._mc("sonnet", 5, None)
        s51 = self._mc("sonnet", 5, 1)
        assert sorted([s5, s51]) == [s51, s5]


class TestZoneTagDiscovery:
    """Live tag discovery used by `inference-zone list/delete` when the local
    zone_inference_profiles map is empty or has drifted from AWS."""

    def _fake_boto3(self, monkeypatch, profiles_by_region):
        """Patch boto3.client so bedrock in each region returns the given
        APPLICATION profiles. profiles_by_region: {region: [(arn, name, {tags})]}.
        A region mapped to the sentinel 'BOOM' raises (unusable region)."""
        from unittest.mock import MagicMock
        import claude_code_with_bedrock.cli.commands.inference_zone as iz

        def factory(service, region_name=None, **kw):
            entries = profiles_by_region.get(region_name)
            if entries == "BOOM":
                raise RuntimeError("region unusable (disabled opt-in)")
            client = MagicMock()
            summaries = [
                {"inferenceProfileArn": arn, "inferenceProfileName": name, "status": "ACTIVE"}
                for (arn, name, _tags) in (entries or [])
            ]
            paginator = MagicMock()
            paginator.paginate.return_value = [{"inferenceProfileSummaries": summaries}]
            client.get_paginator.return_value = paginator
            tags_by_arn = {arn: tags for (arn, _n, tags) in (entries or [])}
            client.list_tags_for_resource.side_effect = lambda resourceARN: {
                "tags": [{"key": k, "value": v} for k, v in tags_by_arn.get(resourceARN, {}).items()]
            }
            return client

        monkeypatch.setattr(iz.boto3, "client", factory)
        return iz

    def test_filters_by_zone_tag(self, monkeypatch):
        iz = self._fake_boto3(monkeypatch, {
            "us-west-2": [
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/a",
                 "usa-opus-4-8", {"Zone": "usa", "ccwb:Model": "opus-4-8"}),
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/b",
                 "europe-opus-4-8", {"Zone": "europe", "ccwb:Model": "opus-4-8"}),
            ],
        })
        found = iz._discover_zone_profiles_by_tag(["us-west-2"], zone="usa")
        assert [p["model"] for p in found] == ["opus-4-8"]
        assert found[0]["zone"] == "usa"
        assert found[0]["region"] == "us-west-2"

    def test_returns_duplicates_same_short_name(self, monkeypatch):
        iz = self._fake_boto3(monkeypatch, {
            "us-west-2": [
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/h1",
                 "usa-haiku-4-5", {"Zone": "usa", "ccwb:Model": "haiku-4-5"}),
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/h2",
                 "usa-haiku-4-5", {"Zone": "usa", "ccwb:Model": "haiku-4-5"}),
            ],
        })
        found = iz._discover_zone_profiles_by_tag(["us-west-2"], zone="usa")
        assert len(found) == 2
        assert {p["arn"].rsplit("/", 1)[1] for p in found} == {"h1", "h2"}

    def test_skips_unusable_region_without_aborting(self, monkeypatch):
        iz = self._fake_boto3(monkeypatch, {
            "ap-southeast-7": "BOOM",  # disabled opt-in region raises
            "us-west-2": [
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/a",
                 "usa-opus-4-8", {"Zone": "usa", "ccwb:Model": "opus-4-8"}),
            ],
        })
        found = iz._discover_zone_profiles_by_tag(["ap-southeast-7", "us-west-2"], zone="usa")
        assert [p["model"] for p in found] == ["opus-4-8"]

    def test_untagged_and_wrong_zone_excluded(self, monkeypatch):
        iz = self._fake_boto3(monkeypatch, {
            "us-west-2": [
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/x",
                 "no-zone-tag", {"ccwb:Model": "opus-4-8"}),  # no Zone tag
            ],
        })
        assert iz._discover_zone_profiles_by_tag(["us-west-2"], zone="usa") == []

    def test_dedupes_arn_across_regions(self, monkeypatch):
        # Same ARN surfaced from two scanned regions -> counted once.
        entry = ("arn:aws:bedrock:us-west-2:1:application-inference-profile/a",
                 "usa-opus-4-8", {"Zone": "usa", "ccwb:Model": "opus-4-8"})
        iz = self._fake_boto3(monkeypatch, {"us-east-1": [entry], "us-west-2": [entry]})
        found = iz._discover_zone_profiles_by_tag(["us-east-1", "us-west-2"], zone="usa")
        assert len(found) == 1
