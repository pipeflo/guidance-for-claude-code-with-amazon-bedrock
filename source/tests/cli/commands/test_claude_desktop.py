# ABOUTME: Unit tests for the `ccwb claude-desktop generate` command
# ABOUTME: Focus: profile resolution when --profile is omitted (the default invocation)

"""Tests for ClaudeDesktopGenerateCommand.

This command shipped broken. It resolved the profile with::

    config.get_profile(name) if name else config.get_active_profile()

but ``Config`` has no ``get_active_profile``, so the *default* invocation --
``ccwb claude-desktop generate`` with no flags, which is what the docs tell
admins to run -- always died with::

    'Config' object has no attribute 'get_active_profile'

Passing ``--profile <name>`` took the other branch and worked, which is why it
went unnoticed. The generator util this command wraps was thoroughly tested; the
command itself had no tests at all. These fill that gap.
"""

from pathlib import Path

import pytest

from claude_code_with_bedrock.cli.commands.claude_desktop import (
    ClaudeDesktopGenerateCommand,
)
from claude_code_with_bedrock.config import Config, Profile

_ENDPOINT = "https://abc123-vpce-0123456789abcdef0.execute-api.us-west-2.amazonaws.com/prod/config"


def _profile(**overrides):
    base = {
        "name": "demo",
        "provider_domain": "example.okta.com",
        "client_id": "0oaEXAMPLECLIENTID",
        "credential_storage": "session",
        "aws_region": "us-east-1",
        "identity_pool_name": "claude-code",
        "federation_type": "direct",
        "provider_type": "okta",
        "claude_desktop_bootstrap_endpoint": _ENDPOINT,
    }
    base.update(overrides)
    return Profile(**base)


class _FakeConfig:
    """Stands in for Config, exposing only what the command may legitimately use."""

    def __init__(self, profile):
        self._profile = profile
        self.requested = []

    def get_profile(self, name=None):
        self.requested.append(name)
        return self._profile


class _Cmd(ClaudeDesktopGenerateCommand):
    """Bypasses Cleo's IO so handle() can be driven directly."""

    def __init__(self, **opts):
        super().__init__()
        self._opts = opts

    def option(self, name):  # noqa: D102 - mirrors Cleo's signature
        return self._opts.get(name)


class TestConfigApiContract:
    """The bug was a call to a method that does not exist."""

    def test_config_has_no_get_active_profile(self):
        """If someone ever adds this method, the guard below stops being the fix
        and the command should be revisited deliberately rather than by accident."""
        assert not hasattr(Config, "get_active_profile")

    def test_get_profile_accepts_none(self):
        """The fix relies on get_profile(None) meaning 'the active profile'."""
        import inspect

        sig = inspect.signature(Config.get_profile)
        assert sig.parameters["name"].default is None


class TestProfileResolution:
    def test_generate_without_profile_option_succeeds(self, tmp_path, monkeypatch):
        """The regression. No --profile must not raise AttributeError."""
        fake = _FakeConfig(_profile())
        monkeypatch.setattr(Config, "load", staticmethod(lambda: fake))

        cmd = _Cmd(profile=None, output=str(tmp_path), endpoint=None)
        rc = cmd.handle()

        assert rc == 0
        # None is forwarded verbatim so Config resolves the active profile.
        assert fake.requested == [None]

    def test_explicit_profile_is_forwarded(self, tmp_path, monkeypatch):
        fake = _FakeConfig(_profile(name="other"))
        monkeypatch.setattr(Config, "load", staticmethod(lambda: fake))

        cmd = _Cmd(profile="other", output=str(tmp_path), endpoint=None)
        assert cmd.handle() == 0
        assert fake.requested == ["other"]

    def test_missing_profile_returns_1_not_a_traceback(self, tmp_path, monkeypatch):
        class _NoProfile(_FakeConfig):
            def get_profile(self, name=None):
                return None

        monkeypatch.setattr(Config, "load", staticmethod(lambda: _NoProfile(None)))
        cmd = _Cmd(profile=None, output=str(tmp_path), endpoint=None)
        assert cmd.handle() == 1


class TestOutputs:
    @pytest.mark.parametrize(
        "filename",
        [
            "claude-desktop-trust-anchor.reg",
            "claude-desktop-trust-anchor.mobileconfig",
            "claude-desktop-trust-anchor.json",
        ],
    )
    def test_all_three_payloads_written(self, tmp_path, monkeypatch, filename):
        monkeypatch.setattr(Config, "load", staticmethod(lambda: _FakeConfig(_profile())))
        assert _Cmd(profile=None, output=str(tmp_path), endpoint=None).handle() == 0
        assert (tmp_path / filename).is_file()

    def test_reg_targets_the_key_claude_desktop_actually_reads(self, tmp_path, monkeypatch):
        """Nesting these values under a subkey makes `reg import` succeed while
        Claude Desktop silently ignores them -- see generate_reg_file."""
        monkeypatch.setattr(Config, "load", staticmethod(lambda: _FakeConfig(_profile())))
        _Cmd(profile=None, output=str(tmp_path), endpoint=None).handle()

        text = (tmp_path / "claude-desktop-trust-anchor.reg").read_text()
        assert r"[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Claude]" in text

    def test_endpoint_option_overrides_the_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "load", staticmethod(lambda: _FakeConfig(_profile())))
        override = "https://override.execute-api.us-west-2.amazonaws.com/prod/config"

        _Cmd(profile=None, output=str(tmp_path), endpoint=override).handle()

        text = (tmp_path / "claude-desktop-trust-anchor.json").read_text()
        assert override in text
        assert _ENDPOINT not in text

    def test_no_endpoint_anywhere_returns_1(self, tmp_path, monkeypatch):
        blank = _profile(claude_desktop_bootstrap_endpoint="")
        monkeypatch.setattr(Config, "load", staticmethod(lambda: _FakeConfig(blank)))

        cmd = _Cmd(profile=None, output=str(tmp_path), endpoint=None)
        assert cmd.handle() == 1
        assert not list(Path(tmp_path).glob("*trust-anchor*"))
