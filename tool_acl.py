"""YAML-based tool Access Control List (ACL) for the Copilot SDK.

Drop this single file into any project that uses the GitHub Copilot SDK
and point the ``TOOL_ACL_PATH`` environment variable at a YAML rule file to
control which tools, shell commands, file reads/writes, URLs, and MCP
operations the agent is permitted to use.

Rules are evaluated **in order** — the first matching rule wins.  If no rule
matches, the ``default_action`` is applied (defaults to ``"deny"``).

Quick start
-----------
1. Copy ``tool_acl.py`` into your project.
2. Create a ``tools_acl.yaml`` file (see the examples/ directory).
3. Set the environment variable or load explicitly::

       export TOOL_ACL_PATH=tools_acl.yaml

   Or in Python::

       from tool_acl import ToolAcl
       acl = ToolAcl.from_file("tools_acl.yaml")

4. Wire the ACL into the Copilot SDK permission callback::

       if acl.is_allowed(permission_request):
           ...

See README.md for the full schema reference and integration guide.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

_Action = Literal["allow", "deny"]

# ---------------------------------------------------------------------------
# Internal data model (parsed from YAML)
# ---------------------------------------------------------------------------


class _Rule:
    """A single ACL rule."""

    __slots__ = ("kind", "action", "when")

    def __init__(
        self,
        kind: Optional[str],
        action: _Action,
        when: Dict[str, re.Pattern],  # type: ignore[type-arg]
    ) -> None:
        self.kind = kind
        self.action = action
        self.when = when  # field_name → compiled regex

    def matches(self, req: Dict[str, Any]) -> bool:
        """Return True if this rule applies to the given permission request."""
        if self.kind is not None and req.get("kind") != self.kind:
            return False
        for field, pattern in self.when.items():
            value = self._extract_field(req, field)
            if value is None:
                return False  # field absent → rule doesn't apply
            if not pattern.search(str(value)):
                return False
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_field(req: Dict[str, Any], field: str) -> Optional[str]:
        """Map a YAML ``when`` key to the corresponding request field.

        The Copilot SDK uses different field names depending on the
        permission kind.  This method normalises the mapping so that
        YAML authors can use short, intuitive names like ``command``,
        ``path``, ``url``, ``tool``, and ``server``.
        """
        if field == "command":
            return req.get("fullCommandText")
        if field == "path":
            # ``read`` uses ``path``; ``write`` uses ``fileName``
            return req.get("path") or req.get("fileName")
        if field == "url":
            return req.get("url")
        if field == "tool":
            return req.get("toolName")
        if field == "server":
            return req.get("serverName")
        # Fallback: try the field name directly
        return req.get(field)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ToolAcl:
    """Evaluates Copilot SDK permission requests against a YAML rule-set.

    Parameters
    ----------
    rules:
        Ordered list of :class:`_Rule` objects.
    default_action:
        Action taken when no rule matches (``"allow"`` or ``"deny"``).
        Defaults to ``"deny"`` (safe-by-default).
    source:
        Human-readable description of where the ACL was loaded from
        (used in log messages).
    """

    def __init__(
        self,
        rules: List[_Rule],
        default_action: _Action = "deny",
        source: str = "<inline>",
    ) -> None:
        self._rules = rules
        self._default = default_action
        self._source = source

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "ToolAcl":
        """Load a ``ToolAcl`` from a YAML file.

        :param path: Path to the YAML ACL file.
        :raises FileNotFoundError: If *path* does not exist.
        :raises ValueError: If the YAML is invalid or the version is
            unsupported.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load a tool ACL file.  "
                "Install it with: pip install PyYAML"
            ) from exc

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Tool ACL file not found: {p}")

        with p.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        return cls._parse(data, source=str(p))

    @classmethod
    def from_env(cls, env_var: str = "TOOL_ACL_PATH") -> Optional["ToolAcl"]:
        """Load a ``ToolAcl`` from the path given in an environment variable.

        Returns *None* if the variable is unset so callers can fall back to
        approve-all behaviour.

        :param env_var: Name of the environment variable
            (default ``TOOL_ACL_PATH``).
        """
        path = os.getenv(env_var)
        if not path:
            return None
        return cls.from_file(path)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, req: Dict[str, Any]) -> _Action:
        """Return ``"allow"`` or ``"deny"`` for the given permission request.

        Rules are checked in declaration order; the first matching rule's
        action is returned.  Falls back to *default_action* when nothing
        matches.
        """
        kind = req.get("kind", "?")
        text = _describe(req)
        for idx, rule in enumerate(self._rules):
            if rule.matches(req):
                logger.debug(
                    "ACL rule #%d (%s) matched %r: %s",
                    idx + 1,
                    rule.action,
                    kind,
                    text,
                )
                return rule.action
        logger.debug(
            "ACL default (%s) applied to %r: %s", self._default, kind, text
        )
        return self._default

    def is_allowed(self, req: Dict[str, Any]) -> bool:
        """Convenience wrapper: return *True* when :meth:`evaluate` yields ``"allow"``."""
        return self.evaluate(req) == "allow"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @classmethod
    def _parse(cls, data: Any, source: str) -> "ToolAcl":
        if not isinstance(data, dict):
            raise ValueError(
                f"ACL file must be a YAML mapping, got {type(data).__name__}: {source}"
            )

        version = str(data.get("version", "1"))
        if version != "1":
            raise ValueError(
                f"Unsupported ACL version {version!r} in {source}"
            )

        raw_default = data.get("default_action", "deny")
        if raw_default not in ("allow", "deny"):
            raise ValueError(
                f"default_action must be 'allow' or 'deny', "
                f"got {raw_default!r} in {source}"
            )
        default_action: _Action = raw_default  # type: ignore[assignment]

        rules: List[_Rule] = []
        for i, entry in enumerate(data.get("rules", []), start=1):
            if not isinstance(entry, dict):
                raise ValueError(f"Rule #{i} must be a mapping in {source}")
            kind = entry.get("kind")  # None means "any kind"
            raw_action = entry.get("action", "deny")
            if raw_action not in ("allow", "deny"):
                raise ValueError(
                    f"Rule #{i} action must be 'allow' or 'deny', "
                    f"got {raw_action!r} in {source}"
                )
            action: _Action = raw_action  # type: ignore[assignment]
            when_raw = entry.get("when", {}) or {}
            when: Dict[str, re.Pattern] = {}  # type: ignore[type-arg]
            for field, pattern in when_raw.items():
                try:
                    when[field] = re.compile(pattern)
                except re.error as exc:
                    raise ValueError(
                        f"Rule #{i} when.{field} contains an invalid "
                        f"regex {pattern!r}: {exc}"
                    ) from exc
            rules.append(_Rule(kind=kind, action=action, when=when))

        n = len(rules)
        logger.info(
            "Loaded tool ACL from %s: %d rule%s, default=%r",
            source,
            n,
            "s" if n != 1 else "",
            default_action,
        )
        return cls(rules=rules, default_action=default_action, source=source)

    def __repr__(self) -> str:
        return (
            f"ToolAcl(rules={len(self._rules)}, default={self._default!r}, "
            f"source={self._source!r})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _describe(req: Dict[str, Any]) -> str:
    """Return a short human-readable description of a permission request."""
    kind = req.get("kind", "?")
    if kind == "shell":
        return repr(req.get("fullCommandText", ""))
    if kind == "read":
        return repr(req.get("path", ""))
    if kind == "write":
        return repr(req.get("fileName", ""))
    if kind == "url":
        return repr(req.get("url", ""))
    if kind == "mcp":
        return (
            f"tool={req.get('toolName', '?')!r} "
            f"server={req.get('serverName', '?')!r}"
        )
    return repr(req)
