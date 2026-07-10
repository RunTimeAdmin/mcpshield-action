#!/usr/bin/env python3
"""
MCPShield config scanner for CI (shift-left).

Statically scans committed MCP config files (claude_desktop_config.json,
mcp.json, cline_mcp_settings.json, ...) and scores each server the same way
MCPShield's dashboard does, so risky servers get caught in a PR before they
ever reach a developer's machine.

Self-contained on purpose: standard library only, no pip install, no API key,
no network. That keeps the GitHub Action zero-friction to adopt.

The scoring here is a faithful port of backend/app/utils/risk_scorer.py and
frontend/lib/riskScorer.ts (same weights, regexes, and factor strings). Only
the config-level sections run — tool-list and CVE/KEV scoring need a live
connection to a running server, which CI doesn't have. Parity with the other
copies is pinned by test-fixtures/risk_scoring_cases.json via --self-test.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Compiled patterns — mirror risk_scorer.py / riskScorer.ts exactly
# ---------------------------------------------------------------------------

_HIGH_RISK_RE = re.compile(
    r"\b(?:execute|shell|bash|cmd|command|run|eval|script|system|process|spawn|fork|terminal)\b",
    re.IGNORECASE,
)
_FILESYSTEM_WRITE_RE = re.compile(
    r"\b(?:write|delete|remove|create|modify|edit|move|rename|copy|mkdir|rmdir|truncate)\b",
    re.IGNORECASE,
)
_NETWORK_RE = re.compile(
    r"\b(?:http|fetch|request|api|curl|socket|connect|download|upload|send|post|get)\b",
    re.IGNORECASE,
)
_SENSITIVE_ENV_RE = re.compile(
    r"(?:password|secret|key|token|credential|auth|api_key|apikey|private|access)",
    re.IGNORECASE,
)

_SHELL_TYPE_PATTERNS = ("shell", "terminal", "command", "exec")
_NETWORK_TYPE_PATTERNS = ("http", "fetch", "api", "browser")
_DB_TYPE_PATTERNS = ("postgres", "mysql", "sqlite", "mongo", "database")

_HIGH_RISK_TOOL_NAMES = frozenset(
    [
        "execute_command", "run_shell", "bash_execute", "powershell",
        "exec", "shell_command", "run_command", "terminal_exec",
    ]
)

_SENSITIVE_PATHS = [
    "/etc", "/root", "/home", "~/.ssh", "~/.aws", "~/.config",
    "/var/log", "/var/run", "/tmp", "/private",
    "C:\\Windows", "C:\\Users", "C:\\Program Files",
    "%APPDATA%", "%USERPROFILE%", "%SYSTEMROOT%",
]

_SHELL_NAMES = frozenset(["bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"])

_WEIGHTS = {
    "shell_command": 35,
    "high_risk_tool": 25,
    "filesystem_write": 15,
    "network_access": 10,
    "sensitive_path": 20,
    "sensitive_env": 15,
    "many_tools": 5,
    "no_description": 3,
    "docker_access": 20,
    "database_access": 15,
}


# ---------------------------------------------------------------------------
# Scoring — public API
# ---------------------------------------------------------------------------

def calculate_risk_score(server: dict[str, Any]) -> dict[str, Any]:
    """Score one server dict (server_type / command / scope / env_vars /
    tools / tool_findings). Returns {score, factors, details}."""
    score = 0.0
    factors: list[str] = []
    details: dict[str, Any] = {}

    def apply(section: str, result: dict[str, Any]) -> None:
        nonlocal score
        score += result["score"]
        factors.extend(result["factors"])
        details[section] = result

    if server.get("server_type"):
        apply("server_type", _analyze_server_type(server["server_type"]))
    if server.get("command"):
        apply("command", _analyze_command(server["command"]))
    if server.get("scope"):
        apply("scope", _analyze_scope(server["scope"]))
    if server.get("tools"):
        apply("tools", _analyze_tools(server["tools"]))
    if server.get("env_vars"):
        apply("env_vars", _analyze_env_vars(server["env_vars"]))
    if server.get("tool_findings"):
        apply("tool_poisoning", _analyze_tool_findings(server["tool_findings"]))

    score = min(100.0, score)
    return {
        "score": round(score, 1),
        "factors": _dedupe_preserving_order(factors),
        "details": details,
    }


def get_risk_level(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Scoring — section helpers (line-for-line with the canonical engine)
# ---------------------------------------------------------------------------

def _dedupe_preserving_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _basename(p: str) -> str:
    return re.split(r"[/\\]", p)[-1]


def _analyze_server_type(server_type: str) -> dict[str, Any]:
    score = 0.0
    factors: list[str] = []
    t = server_type.lower()
    if any(p in t for p in _SHELL_TYPE_PATTERNS):
        score += _WEIGHTS["shell_command"]
        factors.append("Shell/command execution capability")
    if "filesystem" in t or "file" in t:
        score += _WEIGHTS["filesystem_write"]
        factors.append("Filesystem access")
    if any(p in t for p in _DB_TYPE_PATTERNS):
        score += _WEIGHTS["database_access"]
        factors.append("Database access")
    if "docker" in t or "container" in t:
        score += _WEIGHTS["docker_access"]
        factors.append("Docker/container access")
    if any(p in t for p in _NETWORK_TYPE_PATTERNS):
        score += _WEIGHTS["network_access"]
        factors.append("Network/HTTP access")
    return {"score": score, "factors": factors}


def _analyze_command(command: str) -> dict[str, Any]:
    score = 0.0
    factors: list[str] = []
    lower = command.lower()
    parts = lower.split()
    if parts:
        base = _basename(parts[0])
        if base in _SHELL_NAMES:
            score += _WEIGHTS["shell_command"]
            factors.append(f"Direct shell execution ({base})")
    if "docker" in lower and "run" in lower:
        score += _WEIGHTS["docker_access"]
        factors.append("Docker container execution")
    if "sudo" in lower:
        score += 15
        factors.append("Elevated privileges (sudo)")
    return {"score": score, "factors": factors}


def _analyze_scope(scope: str) -> dict[str, Any]:
    score = 0.0
    factors: list[str] = []
    scope_lower = scope.lower()
    if scope in ("/", "C:\\", "C:/"):
        score += _WEIGHTS["sensitive_path"] * 1.5
        factors.append("Root filesystem access")
    else:
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.lower() in scope_lower:
                score += _WEIGHTS["sensitive_path"]
                factors.append(f"Access to sensitive path: {sensitive}")
                break
    if not factors and (scope.startswith("~") or "/home/" in scope or "/Users/" in scope):
        score += _WEIGHTS["sensitive_path"] * 0.5
        factors.append("Home directory access")
    return {"score": score, "factors": factors}


def _analyze_tools(tools: list[dict[str, Any]]) -> dict[str, Any]:
    score = 0.0
    high_risk: list[str] = []
    write: list[str] = []
    network: list[str] = []
    for tool in tools:
        name = tool.get("name", "")
        name_lower = name.lower()
        desc = tool.get("description") or ""
        text = f"{name_lower} {desc.lower()}"
        is_high = name_lower in _HIGH_RISK_TOOL_NAMES
        if not is_high and _HIGH_RISK_RE.search(text):
            is_high = True
        if is_high:
            score += _WEIGHTS["high_risk_tool"]
            high_risk.append(name)
        if _FILESYSTEM_WRITE_RE.search(text):
            score += _WEIGHTS["filesystem_write"]
            write.append(name)
        if _NETWORK_RE.search(text):
            score += _WEIGHTS["network_access"]
            network.append(name)
        if not desc:
            score += _WEIGHTS["no_description"]
    if len(tools) > 10:
        score += ((len(tools) - 10) // 5) * _WEIGHTS["many_tools"]
    score = min(50.0, score)
    factors: list[str] = []
    if high_risk:
        factors.append(f"High-risk tools: {', '.join(high_risk[:3])}")
    if write:
        factors.append(f"Filesystem modification: {', '.join(write[:3])}")
    if network:
        factors.append(f"Network access: {', '.join(network[:3])}")
    if len(tools) > 15:
        factors.append(f"Large tool surface ({len(tools)} tools)")
    return {"score": score, "factors": factors}


def _analyze_env_vars(env_vars: list[str]) -> dict[str, Any]:
    score = 0.0
    sensitive: list[str] = []
    for name in env_vars:
        if _SENSITIVE_ENV_RE.search(name):
            score += _WEIGHTS["sensitive_env"]
            sensitive.append(name)
    factors: list[str] = []
    if sensitive:
        factors.append(f"Sensitive env vars: {', '.join(sensitive[:3])}")
    return {"score": score, "factors": factors}


def _analyze_tool_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not findings:
        return {"score": 0.0, "factors": []}
    raw = sum(min(1.0, f.get("score", 0)) for f in findings) * 30
    score = min(40.0, raw)
    poisoned = [f["tool"] for f in findings if f.get("score", 0) > 0]
    factors = [f"Tool description poisoning detected: {', '.join(poisoned[:3])}"]
    if len(findings) > 1:
        factors.append(f"{len(findings)} tools with injected instructions")
    return {"score": score, "factors": factors}


# ---------------------------------------------------------------------------
# Config parsing — mirrors frontend/lib/configParser.ts
# ---------------------------------------------------------------------------

def _extract_server_type(args: list[str]) -> str | None:
    for arg in args:
        if arg.startswith("@") and "/" in arg:
            return arg
    return None


def _extract_scope(args: list[str]) -> str | None:
    if not args:
        return None
    last = args[-1]
    if any(ch in last for ch in ("/", "\\", ":")):
        return last
    return None


def parse_config_text(text: str) -> list[dict[str, Any]]:
    """Extract scoreable server entries from a config file's raw text."""
    config = json.loads(text)
    if not isinstance(config, dict):
        return []
    mcp_servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(mcp_servers, dict):
        return []

    servers: list[dict[str, Any]] = []
    for name, raw in mcp_servers.items():
        if not isinstance(raw, dict):
            continue
        command = raw.get("command", "") if isinstance(raw.get("command"), str) else ""
        args = [str(a) for a in raw.get("args", [])] if isinstance(raw.get("args"), list) else []
        env = raw.get("env", {}) if isinstance(raw.get("env"), dict) else {}
        full_command = f"{command} {' '.join(args)}" if args else command
        servers.append(
            {
                "server_name": name,
                "server_type": _extract_server_type(args) or "unknown",
                "command": full_command,
                "scope": _extract_scope(args),
                "env_vars": list(env.keys()),
            }
        )
    return servers


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_NAMES = [
    "claude_desktop_config.json",
    "mcp.json",
    ".mcp.json",
    "cline_mcp_settings.json",
    "mcp_settings.json",
]
_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", ".next"}


def discover_files(root: Path, patterns: list[str]) -> list[Path]:
    if patterns:
        found: list[Path] = []
        for pat in patterns:
            found.extend(sorted(root.glob(pat)))
    else:
        found = []
        for name in _DEFAULT_CONFIG_NAMES:
            found.extend(sorted(root.rglob(name)))
    result: list[Path] = []
    seen: set[Path] = set()
    for p in found:
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            result.append(p)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_LEVEL_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🟣"}


def _scan_paths(files: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in files:
        try:
            servers = parse_config_text(path.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # noqa: BLE001 — surface, don't crash the build
            rows.append({"path": str(path), "error": str(exc)})
            continue
        for s in servers:
            result = calculate_risk_score(s)
            level = get_risk_level(result["score"])
            rows.append(
                {
                    "path": str(path),
                    "name": s["server_name"],
                    "score": result["score"],
                    "level": level,
                    "factors": result["factors"],
                }
            )
    return rows


def _render_summary(rows: list[dict[str, Any]], fail_on: str) -> str:
    servers = [r for r in rows if "error" not in r]
    errors = [r for r in rows if "error" in r]
    lines = ["## 🛡️ MCPShield MCP config scan", ""]
    if not servers and not errors:
        lines.append("No MCP servers found in the scanned config files. ✅")
        return "\n".join(lines) + "\n"
    if servers:
        lines.append("| Server | Risk | Score | Signals |")
        lines.append("|---|---|---:|---|")
        for r in sorted(servers, key=lambda x: -x["score"]):
            emoji = _LEVEL_EMOJI.get(r["level"], "")
            sig = "; ".join(r["factors"][:3]) if r["factors"] else "none"
            lines.append(
                f"| `{r['name']}` <br><sub>{r['path']}</sub> "
                f"| {emoji} {r['level'].upper()} | {r['score']} | {sig} |"
            )
        lines.append("")
    for e in errors:
        lines.append(f"> ⚠️ Could not parse `{e['path']}`: {e['error']}")
    threshold = _LEVEL_ORDER.get(fail_on, 99)
    blocked = [r for r in servers if _LEVEL_ORDER[r["level"]] >= threshold]
    if fail_on != "never" and blocked:
        lines.append("")
        lines.append(
            f"❌ **{len(blocked)} server(s) at or above `{fail_on}`** — failing the check. "
            "Run the free MCPShield agent for a deep scan (tool-poisoning + CVE/KEV): "
            "https://mcpshield.app"
        )
    return "\n".join(lines) + "\n"


def _emit_annotations(rows: list[dict[str, Any]], fail_on: str) -> None:
    threshold = _LEVEL_ORDER.get(fail_on, 99)
    for r in rows:
        if "error" in r:
            print(f"::warning file={r['path']}::Could not parse MCP config: {r['error']}")
            continue
        msg = f"MCP server '{r['name']}' scored {r['score']} ({r['level']}): {'; '.join(r['factors'][:3]) or 'no signals'}"
        cmd = "error" if (fail_on != "never" and _LEVEL_ORDER[r["level"]] >= threshold) else "warning"
        if cmd == "error" or r["level"] != "low":
            print(f"::{cmd} file={r['path']}::{msg}")


def _write_github_output(rows: list[dict[str, Any]]) -> None:
    servers = [r for r in rows if "error" not in r]
    max_score = max((r["score"] for r in servers), default=0.0)
    max_level = get_risk_level(max_score) if servers else "low"
    out = os.environ.get("GITHUB_OUTPUT")
    payload = {
        "max-score": max_score,
        "max-level": max_level,
        "server-count": len(servers),
    }
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for k, v in payload.items():
                fh.write(f"{k}={v}\n")
            fh.write("findings-json<<__MCPSHIELD_EOF__\n")
            fh.write(json.dumps(servers) + "\n")
            fh.write("__MCPSHIELD_EOF__\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    return summary


# ---------------------------------------------------------------------------
# PR comment (opt-in) — one sticky comment, stdlib urllib only (keeps zero deps)
# ---------------------------------------------------------------------------

_COMMENT_MARKER = "<!-- mcpshield-scan -->"


def _gh_api(method: str, url: str, token: str, data: dict[str, Any] | None = None) -> Any:
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "mcpshield-action")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else None


def _pr_number() -> int | None:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    except Exception:  # noqa: BLE001
        return None
    pr = event.get("pull_request")
    if isinstance(pr, dict) and isinstance(pr.get("number"), int):
        return pr["number"]
    return None


def _find_sticky_comment(api: str, repo: str, pr: int, token: str) -> int | None:
    for page in range(1, 11):  # scan up to 1000 comments for our marker
        comments = _gh_api(
            "GET", f"{api}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token
        )
        if not comments:
            return None
        for c in comments:
            if _COMMENT_MARKER in (c.get("body") or ""):
                return c.get("id")
        if len(comments) < 100:
            return None
    return None


def post_pr_comment(summary_md: str) -> None:
    """Post or update a single sticky findings comment on the PR. Best-effort:
    a comment failure logs a warning but never fails the build."""
    token = os.environ.get("MCPSHIELD_GITHUB_TOKEN", "").strip()
    if not token:
        print("::warning::comment mode is on but no github-token was provided; skipping PR comment.")
        return
    pr = _pr_number()
    if pr is None:
        print("comment: not a pull_request event; skipping PR comment.")
        return
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not repo:
        print("::warning::GITHUB_REPOSITORY is unset; skipping PR comment.")
        return
    body = f"{_COMMENT_MARKER}\n{summary_md}"
    try:
        existing = _find_sticky_comment(api, repo, pr, token)
        if existing is not None:
            _gh_api("PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
            print(f"comment: updated sticky comment #{existing} on PR #{pr}.")
        else:
            _gh_api("POST", f"{api}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
            print(f"comment: posted findings comment on PR #{pr}.")
    except urllib.error.HTTPError as exc:
        hint = (
            " — needs `permissions: pull-requests: write`; note fork PRs get a read-only token"
            if exc.code in (403, 404)
            else ""
        )
        print(f"::warning::comment: GitHub API returned HTTP {exc.code}{hint}; skipping.")
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::comment: failed to post PR comment: {exc}")


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.working_directory or ".")
    patterns = [p.strip() for p in re.split(r"[,\n]", args.paths or "") if p.strip()]
    files = discover_files(root, patterns)
    rows = _scan_paths(files)

    summary_md = _render_summary(rows, args.fail_on)
    if args.github:
        _emit_annotations(rows, args.fail_on)
        summary_path = _write_github_output(rows)
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(summary_md)
    if args.comment:
        post_pr_comment(summary_md)
    print(summary_md)

    if args.fail_on == "never":
        return 0
    threshold = _LEVEL_ORDER.get(args.fail_on, 99)
    servers = [r for r in rows if "error" not in r]
    blocked = [r for r in servers if _LEVEL_ORDER[r["level"]] >= threshold]
    return 1 if blocked else 0


# ---------------------------------------------------------------------------
# Parity self-test — pins this port to the shared fixtures
# ---------------------------------------------------------------------------

def run_self_test(fixtures_path: str) -> int:
    cases = json.loads(Path(fixtures_path).read_text(encoding="utf-8"))
    failures = 0
    for case in cases:
        server = {
            "server_type": case.get("server_type"),
            "command": case.get("command"),
            "scope": case.get("scope"),
            "env_vars": case.get("env_vars") or [],
            "tools": case.get("tools") or [],
            "tool_findings": case.get("tool_findings") or [],
        }
        result = calculate_risk_score(server)
        level = get_risk_level(result["score"])
        exp_score = case["expected_score"]
        exp_level = case["expected_level"]
        if result["score"] != exp_score or level != exp_level:
            failures += 1
            print(
                f"DRIFT [{case['name']}]: got {result['score']}/{level}, "
                f"expected {exp_score}/{exp_level}"
            )
    total = len(cases)
    if failures:
        print(f"\n❌ self-test: {failures}/{total} cases drifted from the canonical engine")
        return 1
    print(f"✅ self-test: {total}/{total} cases match the canonical MCPShield engine")
    return 0


def main() -> int:
    # GitHub runners are UTF-8; a Windows dev console may be cp1252 and choke on
    # the emoji in the report. Force UTF-8 so output is identical everywhere.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass

    parser = argparse.ArgumentParser(description="MCPShield CI config scanner")
    parser.add_argument("--paths", default="", help="comma/newline-separated globs")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low", "never"],
        help="fail the run if any server is at or above this level",
    )
    parser.add_argument("--working-directory", default=".")
    parser.add_argument("--github", action="store_true", help="emit annotations + job summary")
    parser.add_argument(
        "--comment",
        action="store_true",
        help="post/update a sticky findings comment on the PR (reads MCPSHIELD_GITHUB_TOKEN)",
    )
    parser.add_argument("--self-test", metavar="FIXTURES", help="run parity check and exit")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test(args.self_test)
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
