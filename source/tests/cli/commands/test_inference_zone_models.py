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
