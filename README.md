# MCPShield MCP Config Scan

[![CI](https://github.com/RunTimeAdmin/mcpshield-action/actions/workflows/ci.yml/badge.svg)](https://github.com/RunTimeAdmin/mcpshield-action/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-mcpshield--action-2ea44f?logo=github&logoColor=white)](https://github.com/marketplace/actions/mcpshield-mcp-config-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

Static, shift-left risk scan for **MCP config files** committed to a repo
(`mcp.json`, `.cursor/mcp.json`, `cline_mcp_settings.json`,
`claude_desktop_config.json`, ...). It scores every MCP server the same way the
[MCPShield](https://mcpshield.app) dashboard does and can fail a PR before a
risky server ever reaches a developer's machine.

- **Zero dependencies** — standard-library Python only. No `pip install`, no API
  key, no network call. Nothing leaves the runner.
- **Same engine** — a faithful port of MCPShield's risk scorer, pinned to the
  same fixtures as the backend, dashboard, and desktop app.

## Usage

```yaml
name: MCP config scan
on: [pull_request]

jobs:
  mcp-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RunTimeAdmin/mcpshield-action@v1
        with:
          fail-on: high   # critical | high | medium | low | never
```

With no `paths`, it auto-discovers common MCP config filenames across the repo
(skipping `node_modules`, `.git`, build dirs). To scan specific files:

```yaml
      - uses: RunTimeAdmin/mcpshield-action@v1
        with:
          paths: |
            .cursor/mcp.json
            config/*.mcp.json
          fail-on: critical
```

### Comment on the pull request

Post the findings table as a sticky comment on the PR (updated in place on each
run, never duplicated). Requires `pull-requests: write` permission:

```yaml
jobs:
  mcp-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: RunTimeAdmin/mcpshield-action@v1
        with:
          fail-on: high
          comment: true
```

> Pull requests from forks get a read-only token, so GitHub blocks comments on
> them. The scan still runs and the job summary is always posted.

## Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | *(auto-discover)* | Comma/newline-separated globs of config files to scan. |
| `fail-on` | `high` | Fail the job if any server is at or above this level, or `never` to report only. |
| `working-directory` | `.` | Directory to scan from. |
| `comment` | `false` | Post/update a sticky findings comment on the PR. Needs `pull-requests: write`. |
| `github-token` | workflow token | Token used to post the PR comment. |

## Outputs

| Output | Description |
|---|---|
| `max-score` | Highest risk score found (0-100). |
| `max-level` | Highest risk level (`low`/`medium`/`high`/`critical`). |
| `server-count` | Number of MCP servers scanned. |
| `findings-json` | JSON array of scored servers. |

## What it sees (and doesn't)

This scores **config-level** signals: shell/exec server types, direct shell
commands, sensitive filesystem scopes, and credential-shaped env var names. It
**cannot** see what a server's tools actually do — tool-description poisoning and
CVE/KEV enrichment need a live connection to the running server. For that, run
the free [MCPShield agent](https://mcpshield.app) with `--deep`. This action is
the fast pre-merge gate; the agent is the deep scan on the machine.

## Results

Findings render to the job summary and as inline annotations. Example:

| Server | Risk | Score | Signals |
|---|---|---:|---|
| `shell-exec` | 🟠 HIGH | 70.0 | Shell/command execution; Access to sensitive path: /etc; Sensitive env vars |
| `filesystem-home` | 🟡 MEDIUM | 35.0 | Filesystem access; Access to sensitive path: /home |
| `notes` | 🟢 LOW | 0.0 | none |

## License

MIT — see [LICENSE](LICENSE).
