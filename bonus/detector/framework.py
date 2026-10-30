"""
framework.py — the small rule engine behind rules.py (Bonus Task A).

You normally don't edit this file. Write your signatures as `Rule(...)` entries
in rules.py; anything a regex can't express goes in a plain Python function
there (see detect_deserialization).

A Rule is scoped three ways, which is how you keep false positives down:
    tools   — which MCP tools it applies to: "server.tool" or "server.*"
    params  — which parameters it inspects (None = every string parameter)
    pattern — what to look for, after `normalize` and `strip` are applied

and runs in one of two modes:
    expect=False (default)  alert when `pattern` is FOUND   (signature / blocklist)
    expect=True             alert when the value does NOT fully match `pattern`
                            (shape / allowlist: "a region looks like us-east-1")
"""

import re
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Pattern, Tuple
from urllib.parse import unquote


@dataclass
class Detection:
    rule_id: str
    vuln_class: str
    server: str
    tool: str
    parameter: str
    severity: str     # "low" | "medium" | "high"
    excerpt: str      # the (normalized) text that triggered the rule


def _identity(value):
    return value


@dataclass(frozen=True)
class Rule:
    rule_id: str
    vuln_class: str
    tools: Tuple[str, ...]
    params: Optional[Tuple[str, ...]]
    pattern: Pattern
    severity: str = "high"
    normalize: Callable[[str], str] = _identity
    expect: bool = False
    strip: Optional[Pattern] = None

    def applies_to(self, call):
        server, tool = call.get("server"), call.get("tool")
        return any(t == "%s.%s" % (server, tool) or t == "%s.*" % server for t in self.tools)


# ---------------------------------------------------------------------------
# normalizers — decode the value the way the vulnerable sink will see it
# ---------------------------------------------------------------------------
def url_decode(value, rounds=3):
    """Undo (possibly repeated) %-encoding and treat backslashes as slashes."""
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value.replace("\\", "/")


def string_params(call, names=None):
    # type: (dict, Optional[Tuple[str, ...]]) -> Iterator[Tuple[str, str]]
    """Yield (name, value) for the call's string parameters, optionally filtered by name."""
    for key, value in (call.get("parameters") or {}).items():
        if isinstance(value, str) and (names is None or key in names):
            yield key, value


def excerpt(text, limit=70):
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def run_rules(rules, call):
    # type: (List[Rule], dict) -> List[Detection]
    """Apply every in-scope rule to every in-scope parameter; return all hits."""
    hits = []
    for rule in rules:
        if not rule.applies_to(call):
            continue
        for key, raw in string_params(call, rule.params):
            value = rule.normalize(raw)
            if rule.strip is not None:
                value = rule.strip.sub("", value)
            if rule.expect:
                fired = bool(value) and not rule.pattern.fullmatch(value)
            else:
                fired = rule.pattern.search(value) is not None
            if fired:
                hits.append(Detection(rule.rule_id, rule.vuln_class, call.get("server"),
                                      call.get("tool"), key, rule.severity, excerpt(value)))
    return hits


__all__ = ["Detection", "Rule", "run_rules", "string_params", "url_decode", "excerpt", "re"]
