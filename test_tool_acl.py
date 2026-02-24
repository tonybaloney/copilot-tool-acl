"""Unit tests for the ToolAcl engine."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from tool_acl import ToolAcl, _Rule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _acl_from_yaml(text: str) -> ToolAcl:
    """Parse a YAML string directly via ToolAcl._parse."""
    return ToolAcl._parse(yaml.safe_load(textwrap.dedent(text)), source="<test>")


# Minimal permission-request builders
def _shell(command: str) -> dict:
    return {"kind": "shell", "fullCommandText": command}


def _read(path: str) -> dict:
    return {"kind": "read", "path": path}


def _write(file_name: str) -> dict:
    return {"kind": "write", "fileName": file_name}


def _url(url: str) -> dict:
    return {"kind": "url", "url": url}


def _mcp(tool: str, server: str = "my-server") -> dict:
    return {"kind": "mcp", "toolName": tool, "serverName": server}


# ===========================================================================
# ToolAcl.from_file
# ===========================================================================


class TestFromFile:
    def test_loads_valid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text(
            textwrap.dedent("""\
                version: "1"
                default_action: allow
                rules: []
            """)
        )
        acl = ToolAcl.from_file(p)
        assert acl is not None
        assert acl._default == "allow"

    def test_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ToolAcl.from_file(tmp_path / "nonexistent.yaml")

    def test_raises_on_unsupported_version(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text('version: "99"\ndefault_action: allow\nrules: []\n')
        with pytest.raises(ValueError, match="Unsupported ACL version"):
            ToolAcl.from_file(p)

    def test_raises_on_bad_default_action(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text('version: "1"\ndefault_action: maybe\nrules: []\n')
        with pytest.raises(ValueError, match="default_action must be"):
            ToolAcl.from_file(p)

    def test_raises_on_bad_rule_action(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text(
            textwrap.dedent("""\
                version: "1"
                rules:
                  - kind: shell
                    action: maybe
            """)
        )
        with pytest.raises(ValueError, match="action must be"):
            ToolAcl.from_file(p)

    def test_raises_on_invalid_regex(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text(
            textwrap.dedent("""\
                version: "1"
                rules:
                  - kind: shell
                    action: deny
                    when:
                      command: "[unclosed"
            """)
        )
        with pytest.raises(ValueError, match="invalid regex"):
            ToolAcl.from_file(p)

    def test_repr_contains_source(self, tmp_path: Path) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text('version: "1"\nrules: []\n')
        acl = ToolAcl.from_file(p)
        assert str(p) in repr(acl)


# ===========================================================================
# ToolAcl.from_env
# ===========================================================================


class TestFromEnv:
    def test_returns_none_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TOOL_ACL_PATH", raising=False)
        assert ToolAcl.from_env("TOOL_ACL_PATH") is None

    def test_loads_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text('version: "1"\ndefault_action: allow\nrules: []\n')
        monkeypatch.setenv("TOOL_ACL_PATH", str(p))
        acl = ToolAcl.from_env("TOOL_ACL_PATH")
        assert acl is not None
        assert acl._default == "allow"

    def test_custom_env_var_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        p = tmp_path / "acl.yaml"
        p.write_text('version: "1"\nrules: []\n')
        monkeypatch.setenv("MY_ACL", str(p))
        acl = ToolAcl.from_env("MY_ACL")
        assert acl is not None


# ===========================================================================
# Default action
# ===========================================================================


class TestDefaultAction:
    def test_default_deny_is_deny(self) -> None:
        acl = _acl_from_yaml('version: "1"\nrules: []')
        assert acl.evaluate(_shell("echo hi")) == "deny"

    def test_explicit_allow_default(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules: []
        """)
        assert acl.evaluate(_shell("rm -rf /")) == "allow"

    def test_is_allowed_reflects_default(self) -> None:
        acl = _acl_from_yaml('version: "1"\ndefault_action: allow\nrules: []')
        assert acl.is_allowed(_shell("anything")) is True


# ===========================================================================
# Rule evaluation — first-match-wins
# ===========================================================================


class TestFirstMatchWins:
    def test_first_deny_blocks_later_allow(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: shell
                action: deny
                when:
                  command: "^rm"
              - kind: shell
                action: allow
        """)
        assert acl.evaluate(_shell("rm -rf /")) == "deny"

    def test_allow_before_deny_wins(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: shell
                action: allow
                when:
                  command: "^echo"
              - kind: shell
                action: deny
        """)
        assert acl.evaluate(_shell("echo hello")) == "allow"

    def test_no_match_uses_default(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: url
                action: allow
                when:
                  url: "microsoft"
        """)
        assert acl.evaluate(_shell("echo hello")) == "deny"


# ===========================================================================
# Kind filtering
# ===========================================================================


class TestKindFiltering:
    def test_kind_filter_only_matches_its_kind(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: shell
                action: allow
        """)
        assert acl.evaluate(_shell("echo")) == "allow"
        assert acl.evaluate(_read("/tmp/x")) == "deny"

    def test_no_kind_matches_all_kinds(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - action: allow      # no kind field
        """)
        assert acl.evaluate(_shell("echo")) == "allow"
        assert acl.evaluate(_read("/tmp/x")) == "allow"
        assert acl.evaluate(_url("https://example.com")) == "allow"


# ===========================================================================
# Shell rules
# ===========================================================================


class TestShellRules:
    def test_allows_safe_echo(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: shell
                action: allow
                when:
                  command: "^echo "
        """)
        assert acl.is_allowed(_shell("echo hello")) is True
        assert acl.is_allowed(_shell("rm -rf /")) is False

    def test_regex_is_search_not_fullmatch(self) -> None:
        """re.search semantics — pattern can appear anywhere."""
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: shell
                action: deny
                when:
                  command: "\\\\brm\\\\b"
        """)
        assert acl.evaluate(_shell("git rm file.txt")) == "deny"


# ===========================================================================
# Read rules
# ===========================================================================


class TestReadRules:
    def test_denies_ssh_dir(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: read
                action: deny
                when:
                  path: '\\.ssh'
        """)
        assert acl.is_allowed(_read("/home/user/.ssh/id_rsa")) is False
        assert acl.is_allowed(_read("/tmp/output.txt")) is True

    def test_allows_tmp(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: read
                action: allow
                when:
                  path: "^/tmp/"
        """)
        assert acl.is_allowed(_read("/tmp/foo.txt")) is True
        assert acl.is_allowed(_read("/etc/passwd")) is False


# ===========================================================================
# Write rules
# ===========================================================================


class TestWriteRules:
    def test_write_uses_filename_field(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: write
                action: allow
                when:
                  path: "^/tmp/"
        """)
        assert acl.is_allowed(_write("/tmp/report.txt")) is True
        assert acl.is_allowed(_write("/etc/hosts")) is False


# ===========================================================================
# URL rules
# ===========================================================================


class TestUrlRules:
    def test_allows_microsoft_domain(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: url
                action: allow
                when:
                  url: "microsoft\\\\.com"
        """)
        assert acl.is_allowed(_url("https://learn.microsoft.com/en-us/")) is True
        assert acl.is_allowed(_url("https://evil.example.com/")) is False

    def test_denies_specific_service(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: url
                action: deny
                when:
                  url: "ngrok\\\\.io"
        """)
        assert acl.is_allowed(_url("https://abc.ngrok.io/hook")) is False
        assert acl.is_allowed(_url("https://github.com/repo")) is True


# ===========================================================================
# MCP rules
# ===========================================================================


class TestMcpRules:
    def test_denies_destructive_mcp_tool(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: mcp
                action: deny
                when:
                  tool: "^(write_|create_|delete_)"
        """)
        assert acl.is_allowed(_mcp("delete_file")) is False
        assert acl.is_allowed(_mcp("read_file")) is True

    def test_filters_by_server_name(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: mcp
                action: deny
                when:
                  server: "untrusted-server"
        """)
        assert acl.is_allowed(_mcp("read_file", server="untrusted-server")) is False
        assert acl.is_allowed(_mcp("read_file", server="trusted-server")) is True

    def test_and_condition_tool_and_server(self) -> None:
        """Both tool AND server must match for the rule to fire."""
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: allow
            rules:
              - kind: mcp
                action: deny
                when:
                  tool: "delete"
                  server: "dangerous"
        """)
        # Both match → deny
        assert acl.is_allowed(_mcp("delete_file", server="dangerous")) is False
        # Tool matches, server doesn't → no deny → default allow
        assert acl.is_allowed(_mcp("delete_file", server="safe")) is True
        # Server matches, tool doesn't → no deny → default allow
        assert acl.is_allowed(_mcp("read_file", server="dangerous")) is True


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_empty_rule_list_uses_default(self) -> None:
        acl = _acl_from_yaml('version: "1"\ndefault_action: deny\nrules: []')
        assert acl.evaluate({"kind": "shell", "fullCommandText": "anything"}) == "deny"

    def test_rule_without_when_matches_any_of_kind(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: read
                action: allow
        """)
        assert acl.is_allowed(_read("/any/path")) is True
        assert acl.is_allowed(_shell("echo")) is False

    def test_unknown_kind_falls_through_to_default(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: shell
                action: allow
        """)
        assert acl.evaluate({"kind": "unknown-future-kind"}) == "deny"

    def test_rule_with_null_when_matches(self) -> None:
        """A rule with ``when: null`` (or omitted) matches any request of its kind."""
        acl = _acl_from_yaml("""\
            version: "1"
            default_action: deny
            rules:
              - kind: url
                action: allow
                when:
        """)
        assert acl.is_allowed(_url("https://anything.io")) is True

    def test_is_allowed_false_for_deny(self) -> None:
        acl = _acl_from_yaml('version: "1"\ndefault_action: deny\nrules: []')
        assert acl.is_allowed(_shell("echo")) is False

    def test_repr_shows_rule_count(self) -> None:
        acl = _acl_from_yaml("""\
            version: "1"
            rules:
              - kind: shell
                action: deny
              - kind: read
                action: allow
        """)
        r = repr(acl)
        assert "rules=2" in r


# ===========================================================================
# Example YAML files parse without errors
# ===========================================================================


class TestExampleFiles:
    """Ensure all bundled example YAML files are valid."""

    @pytest.fixture(params=["strict", "permissive", "mcp_only", "custom_tools"])
    def example_path(self, request: pytest.FixtureRequest) -> Path:
        return Path(__file__).parent / "examples" / f"{request.param}.yaml"

    def test_example_parses(self, example_path: Path) -> None:
        if not example_path.exists():
            pytest.skip(f"{example_path.name} not found")
        acl = ToolAcl.from_file(example_path)
        assert acl is not None

    def test_strict_denies_rm(self) -> None:
        p = Path(__file__).parent / "examples" / "strict.yaml"
        if not p.exists():
            pytest.skip("strict.yaml not found")
        acl = ToolAcl.from_file(p)
        assert acl.is_allowed(_shell("rm -rf /")) is False
        assert acl.is_allowed(_shell("echo hello")) is True

    def test_permissive_allows_echo(self) -> None:
        p = Path(__file__).parent / "examples" / "permissive.yaml"
        if not p.exists():
            pytest.skip("permissive.yaml not found")
        acl = ToolAcl.from_file(p)
        assert acl.is_allowed(_shell("echo hello")) is True
