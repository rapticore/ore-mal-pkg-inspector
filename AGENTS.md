# OreWatch — OpenAI Codex Integration Guide

This repository uses the `orewatch` MCP server to enforce supply-chain safety
before any dependency is introduced. Codex **must** follow the rules in this
file whenever it adds or updates a dependency.

---

## Prerequisites

| Requirement | Check |
|---|---|
| Python 3.14+ | `python3.14 --version` |
| OreWatch installed | `orewatch --help` |
| Monitor running | `orewatch monitor status` → `running: true` |
| MCP configured | MCP block in Codex settings (see below) |

## Installation

Install OreWatch using one of these methods:

```bash
# Recommended — isolated user-level install
pipx install --python python3.14 orewatch

# macOS Homebrew tap
brew install rapticore/tap/orewatch

# Standard pip (CI, virtualenvs)
python3.14 -m pip install orewatch
```

### Start the Monitor and Generate the MCP Block

```bash
# One-command setup — installs, starts, watches your project, prints MCP block
orewatch monitor quickstart /path/to/project --client codex
```

### Register the MCP Server with Codex

Copy the printed JSON block into your Codex MCP configuration:

```json
{
  "mcpServers": {
    "orewatch": {
      "command": "/absolute/path/to/orewatch",
      "args": ["monitor", "mcp"]
    }
  }
}
```

> **Tip:** `orewatch monitor ide-bootstrap --client codex` regenerates this
> block at any time. It resolves the absolute path to the local binary so you
> don't need to guess.

### Verify

```bash
orewatch monitor status          # running: true, api_listening: true
orewatch monitor connection-info # shows base_url, token_path, mcp_server
orewatch monitor doctor          # full diagnostic dump
```

---

## MCP Tools Reference

Once connected, Codex has access to six OreWatch tools:

### `orewatch_health`

Health check — call this first to confirm the monitor is reachable.

**Parameters:** none

**Returns:** `running`, `api_listening`, `data_health`, `supported_ecosystems`,
per-ecosystem `database_statuses`, active finding count, recent notifications.

---

### `orewatch_check_dependency_add`

**The primary gate.** Call this **before** running any package-manager command
or editing a manifest to add/update a dependency.

**Parameters:**

| Field | Type | Required | Notes |
|---|---|---|---|
| `client_type` | string | yes | Always `"codex"` |
| `project_path` | string | yes | Absolute path to the project root |
| `ecosystem` | string | yes | `npm`, `pypi`, `maven`, `rubygems`, `go`, `cargo` |
| `package_manager` | string | yes | `npm`, `pip`, `poetry`, `cargo`, etc. |
| `operation` | string | yes | `add`, `install`, `update` |
| `dependencies` | array | yes | See dependency object below |
| `source.kind` | string | yes | `"agent_command"` when a command is known |
| `source.command` | string | conditional | The exact intended command |

**Dependency object:**

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |
| `version` | string | use for simple exact versions |
| `requested_spec` | string | canonical — use instead of `version` when a range/constraint is involved |
| `resolved_version` | string | canonical resolved version |
| `dev_dependency` | boolean | no |

> Do **not** send `version` together with `requested_spec`/`resolved_version`
> — OreWatch rejects that as ambiguous.

**Example call:**

```json
{
  "client_type": "codex",
  "project_path": "/Users/dev/my-app",
  "ecosystem": "pypi",
  "package_manager": "pip",
  "operation": "add",
  "dependencies": [
    { "name": "requests", "version": "2.33.1" }
  ],
  "source": {
    "kind": "agent_command",
    "command": "pip install requests==2.33.1"
  }
}
```

**Response — allowed:**

```json
{
  "check_id": "check-abc123",
  "decision": "allow",
  "data_health": "complete",
  "results": [
    { "name": "requests", "status": "clean", "severity": "none" }
  ],
  "monitor_message": "All requested dependencies passed OreWatch checks"
}
```

**Response — blocked:**

```json
{
  "check_id": "check-xyz789",
  "decision": "override_required",
  "results": [
    { "name": "evil-pkg", "status": "malicious", "severity": "critical",
      "sources": ["openssf", "osv"] }
  ],
  "monitor_message": "1 dependency blocked — malicious match in threat data"
}
```

---

### `orewatch_check_manifest`

Audit a full manifest file. Call this **after** directly editing a supported
manifest (e.g. `requirements.txt`, `package.json`, `pyproject.toml`).

**Parameters:**

| Field | Type | Required |
|---|---|---|
| `client_type` | string | yes — `"codex"` |
| `project_path` | string | yes |
| `ecosystem` | string | yes |
| `manifest_path` | string | yes — absolute path to the manifest file |
| `dependencies` | array | no — omit to let OreWatch parse automatically |

**Returns:** `check_id`, `decision`, `manifest_status` (`clean` / `warning` /
`blocked`), `results[]`.

---

### `orewatch_override_dependency_add`

Record an explicit user override for a previously blocked dependency.

**Parameters:**

| Field | Type | Required |
|---|---|---|
| `client_type` | string | yes — `"codex"` |
| `check_id` | string | yes — from the original blocked check |
| `actor` | string | yes — session or user identifier |
| `reason` | string | yes — why the override is acceptable |

**Returns:** `override_id`, `expires_at`, `decision: "allow"`.

---

### `orewatch_list_active_findings`

Retrieve current open findings from the background monitor.

**Parameters:** `project_path` (optional), `limit` (optional),
`min_severity` (optional).

---

### `orewatch_list_notifications`

Retrieve recent alert messages from the monitor.

**Parameters:** `project_path` (optional), `limit` (optional).

---

## Required Dependency Safety Flow

### Before Any Dependency Change

1. **Call `orewatch_check_dependency_add`** with `client_type: "codex"`,
   the project path, ecosystem, dependency list, and the intended command.
2. **Wait for the decision.**
   - `allow` → proceed with the install/edit.
   - `override_required` → **stop**, report the finding to the user, and
     wait for an explicit override before continuing.
3. **Do not** run the package-manager command or edit the manifest until
   OreWatch returns `allow`.

### After Editing a Manifest Directly

4. **Call `orewatch_check_manifest`** for the saved file and report the result.

### Before Finishing Dependency Work

5. **Call `orewatch_list_active_findings`** and
   **`orewatch_list_notifications`** for the affected project and surface any
   active alerts to the user.

### If OreWatch Is Unavailable

- **State clearly** that the OreWatch preflight dependency safety check could
  not be performed.
- **Do not** silently bypass OreWatch for dependency changes.

---

## Applies To

- npm, pnpm, yarn dependency additions
- pip, poetry, pipenv dependency additions
- go, cargo, bundler, gem, maven, gradle dependency additions
- Direct edits to supported manifests: `package.json`, `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `setup.py`,
  `pyproject.toml`, `Pipfile`, `poetry.lock`, `pom.xml`, `build.gradle`,
  `Gemfile`, `Gemfile.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`

## Supported Ecosystems

| Ecosystem | Package Managers | Key Manifests |
|---|---|---|
| npm | npm, yarn, pnpm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | pip, poetry, pipenv | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` |
| Maven | maven, gradle | `pom.xml`, `build.gradle` |
| RubyGems | bundler, gem | `Gemfile`, `Gemfile.lock` |
| Go | go | `go.mod`, `go.sum` |
| Cargo | cargo | `Cargo.toml`, `Cargo.lock` |

## Decision Policy

OreWatch returns `allow` only when **all** of these hold:

- Threat data is `complete`
- Every dependency resolves to an exact version
- No dependency matches malicious-package intelligence

OreWatch returns `override_required` when **any** of these apply:

- A dependency matches malicious intelligence
- Threat data is `partial` or `failed`
- Exact version resolution fails
- The monitor API is unavailable after one auto-start attempt

## Troubleshooting

| Symptom | Fix |
|---|---|
| MCP tools not visible | Re-run `orewatch monitor ide-bootstrap --client codex` and update your MCP config |
| `orewatch_health` fails | Run `orewatch monitor start` then `orewatch monitor status` |
| `data_health: partial` | Run `orewatch monitor scan-now` to trigger a threat-data refresh |
| `override_required` on safe package | Ask the user to confirm, then call `orewatch_override_dependency_add` |
| Token / auth errors | Check `orewatch monitor connection-info` for the correct `token_path` |

## Further Reading

- [docs/adoption-guide.md](docs/adoption-guide.md) — quickstart walkthrough
- [docs/local-api.md](docs/local-api.md) — full HTTP API and MCP contract
- [docs/e2e-testing.md](docs/e2e-testing.md) — contributor testing guide
- [ARCHITECTURE.md](ARCHITECTURE.md) — technical deep-dive
