# OreWatch Adoption Guide

This guide is for teams and individual developers who want to get OreWatch running quickly without reading the full README first.

## Choose your path

| If you want to... | Use | Start here |
|-------------------|-----|------------|
| scan a repo once | CLI scan | `orewatch /path/to/project` |
| keep projects watched in the background | singleton monitor | `orewatch monitor quickstart /path/to/project --client claude_code` |
| protect Cursor, Claude Code, or Codex sessions | MCP bridge | `orewatch monitor quickstart /path/to/project --client <cursor|claude_code|codex>` |
| integrate with VS Code, PyCharm, or Xcode | localhost API | `orewatch monitor quickstart /path/to/project --client vscode` |
| get visible macOS alerts | menu bar app | `orewatch monitor menubar` |

## 5-minute setup

### 1. Install

```bash
git clone https://github.com/rapticore/ore-mal-pkg-inspector.git
cd ore-mal-pkg-inspector
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

### 2. Start the singleton monitor

Pick the client you actually use:

```bash
orewatch monitor quickstart /path/to/project --client cursor
orewatch monitor quickstart /path/to/project --client claude_code
orewatch monitor quickstart /path/to/project --client vscode
orewatch monitor quickstart /path/to/project --client jetbrains
orewatch monitor quickstart /path/to/project --client xcode
```

What this does:

- installs or refreshes the per-user OreWatch monitor
- starts it if needed
- adds the project to the watch list
- prints the MCP or API bootstrap block for the selected client
- on macOS, the menu bar app keeps the newest alert pinned at the top until you open the menu

### 3. Verify health

```bash
orewatch monitor status
orewatch monitor connection-info
```

You want to see:

- `running: true`
- `api_listening: true`
- a valid `api_base_url`

## Client setup

### Cursor, Claude Code, Codex

Use the MCP bootstrap block:

```bash
orewatch monitor ide-bootstrap --client cursor
orewatch monitor ide-bootstrap --client claude_code
orewatch monitor ide-bootstrap --client codex
```

These clients should use:

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

`orewatch monitor ide-bootstrap --client <client>` now prefers the absolute local OreWatch binary path when it can resolve one. If your existing MCP config still uses bare `orewatch`, regenerate the block and replace the older entry.

OreWatch MCP tools include:

- `orewatch_health`
- `orewatch_check_dependency_add`
- `orewatch_check_manifest`
- `orewatch_override_dependency_add`
- `orewatch_list_active_findings`
- `orewatch_list_notifications`

### VS Code and JetBrains / PyCharm

Use the localhost API bootstrap block:

```bash
orewatch monitor ide-bootstrap --client vscode
orewatch monitor ide-bootstrap --client jetbrains
```

The local integration shape is:

```json
{
  "orewatch": {
    "baseUrl": "http://127.0.0.1:48736",
    "tokenPath": "/path/to/api.token"
  }
}
```

Recommended API usage:

- `POST /v1/check/dependency-add` before dependency-install flows
- `POST /v1/check/manifest` when supported manifests are saved or rechecked
- `GET /v1/findings/active` for current open findings
- `GET /v1/notifications` for recent alert messages

### Xcode

Xcode should also use the localhost API:

```bash
orewatch monitor ide-bootstrap --client xcode
```

Current fit:

- good for alert visibility and background monitor status
- good for mixed-language repos that include supported manifests like `package.json`, `pyproject.toml`, or `Cargo.toml`
- not yet full native Apple dependency protection

Current boundary:

- OreWatch does not yet parse `Package.resolved`, `Podfile.lock`, or `Cartfile`

## macOS menu bar app

If you want a native local UI and popup notifications on macOS, choose the
command that matches your install method:

```bash
# pip / source-checkout install
python3.14 -m pip install 'orewatch[mac-menubar]'

# existing pipx install
pipx inject orewatch pyobjc-framework-Cocoa
orewatch monitor menubar
```

If you installed OreWatch with Homebrew and want the menu bar app, reinstall it
with `pipx` or `pip` using `orewatch[mac-menubar]` so the Cocoa bindings live
in the same environment as `orewatch`.

What you get:

- a menu bar status indicator
- a persistent compact red/bold alert state for newly detected alerts until you review them
- recent notifications and active findings
- one-click access to reports and config
- workspace-folder enrollment from the menu
- native popup delivery through the menu bar companion

## What users will see

When OreWatch finds something in a watched project:

- the finding is stored in the monitor state
- JSON and HTML reports are written under the singleton reports directory
- a recent notification is recorded
- `orewatch monitor findings` and `orewatch monitor notifications` surface it
- on macOS, the menu bar app can show a popup notification

Useful commands:

```bash
orewatch monitor findings
orewatch monitor notifications
orewatch monitor findings --project /path/to/project
orewatch monitor notifications --project /path/to/project
```

## Recommended rollout order

### For an individual developer

1. Run a one-off scan.
2. Enable the monitor on your main repo.
3. Connect your editor or coding agent.
4. On macOS, add the menu bar app.

### For a team

1. Start with a small pilot on one or two repos.
2. Standardize the `monitor quickstart` flow per editor.
3. Verify that findings and notifications are visible to users.
4. Add CI scans after local workflows are stable.
5. Add webhooks only after the local alert path is understood.

If you are deploying OreWatch through Kandji, Jamf Pro, Intune, Munki, or another managed-software system, use [managed-rollout.md](managed-rollout.md) alongside this guide.

## Documents to use next

- [README.md](../README.md): full product and operational reference
- [local-api.md](local-api.md): exact API and MCP contract
- [e2e-testing.md](e2e-testing.md): contributor validation and synthetic client matrix
- [managed-rollout.md](managed-rollout.md): enterprise and MDM rollout guidance
- [roadmap.md](roadmap.md): current direction and known boundaries
