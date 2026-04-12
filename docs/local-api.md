# OreWatch Local API

OreWatch exposes a localhost-only monitor API for agents and IDE integrations.

If you are adopting OreWatch for the first time, start with [docs/adoption-guide.md](adoption-guide.md) and then come back here for the exact API and MCP contract.

## Discovery

Use:

```bash
# Same command after installing the package from PyPI
orewatch monitor quickstart . --client claude_code
orewatch monitor --workspace-root /path/to/workspace connection-info
orewatch monitor connection-info
orewatch monitor ide-bootstrap --client claude_code
```

OreWatch is now a per-user singleton. One local monitor instance can watch many projects anywhere on disk and serve many concurrent Claude Code, Codex, Cursor, VS Code, JetBrains / PyCharm, and Xcode clients. `--workspace-root /path/to/workspace` is still accepted as a deprecated compatibility alias, but it no longer changes the monitor identity, token path, or MCP command.

That returns:

- `base_url`
- `token_path`
- `running`
- `api_listening`
- `monitor_scope`
- `monitor_home`
- `final_data_dir`
- `workspace_root` (deprecated compatibility alias)
- `repo_root` (deprecated compatibility alias)
- `installed_service_manager`
- `auto_start_on_client`
- `mcp_server`
- `supported_bootstrap_clients`

The API token is a per-user bearer token stored outside the repo with owner-only permissions.

## Authentication

Send the token in the `Authorization` header:

```http
Authorization: Bearer <token>
```

Requests sent directly to `127.0.0.1:48736` without that header will return `401 Unauthorized` by design.

## Endpoints

### `GET /v1/health`

Returns:

- daemon/API status
- last refresh and live-promotion state
- DB-backed `data_health`
- DB-backed `data_health_details`
- per-ecosystem `database_statuses`
- `final_data_dir`
- active finding count and highest active severity
- recent notifications preview
- supported ecosystems
- supported package managers
- supported client types
- supported manifest filenames

### `GET /v1/findings/active`

Returns active background-monitor findings.

Supported query params:

- `project_path`
- `limit`
- `min_severity`

Response includes:

- `count`
- `returned`
- `limit`
- `min_severity`
- `highest_severity`
- `findings`

Each finding includes:

- `fingerprint`
- `project_path`
- `project_name`
- `finding_type`
- `severity`
- `title`
- `first_seen_at`
- `last_seen_at`
- `report_path`
- `payload`

Malicious-package findings also include:

- `package_name`
- `package_version`
- `ecosystem`

### `GET /v1/notifications`

Returns recent stored monitor notifications.

Supported query params:

- `project_path`
- `limit`

Response includes:

- `count`
- `returned`
- `limit`
- `notifications`

Each notification includes:

- `id`
- `project_path`
- `project_name`
- `kind`
- `message`
- `created_at`

### `POST /v1/check/dependency-add`

Request:

```json
{
  "client_type": "codex",
  "project_path": "/path/to/project",
  "ecosystem": "npm",
  "package_manager": "npm",
  "operation": "add",
  "dependencies": [
    {
      "name": "chalk",
      "requested_spec": "5.4.1",
      "resolved_version": "5.4.1",
      "dev_dependency": false
    }
  ],
  "source": {
    "kind": "agent_command",
    "command": "npm install chalk@5.4.1"
  }
}
```

Dependency objects support:

- `name` required
- `version` as a convenience alias for exact versions
- `requested_spec` and `resolved_version` as the canonical fields
- `dev_dependency` optional

Do not send `version` together with `requested_spec` or `resolved_version`; OreWatch rejects that as ambiguous.

`source.kind` must be one of:

- `agent_command`
- `ide_action`

Response:

```json
{
  "check_id": "check-...",
  "decision": "allow",
  "data_health": "complete",
  "results": [
    {
      "name": "chalk",
      "requested_spec": "5.4.1",
      "resolved_version": "5.4.1",
      "status": "clean",
      "severity": "none",
      "sources": [],
      "reason": "No malicious match found in current threat data"
    }
  ],
  "monitor_message": "All requested dependencies passed OreWatch checks",
  "override_allowed": true
}
```

### `POST /v1/check/manifest`

Request:

```json
{
  "client_type": "vscode",
  "project_path": "/path/to/project",
  "ecosystem": "pypi",
  "manifest_path": "/path/to/project/requirements.txt"
}
```

Response includes:

- `check_id`
- `decision`
- `manifest_status`
- `data_health`
- `data_health_details`
- `results`
- `monitor_message`
- `override_allowed`

If `dependencies` is omitted or empty, OreWatch parses `manifest_path` automatically when the filename matches a supported manifest for the selected ecosystem.

`manifest_status` is:

- `clean`
- `warning`
- `blocked`

### `POST /v1/checks/<check_id>/override`

Request:

```json
{
  "client_type": "codex",
  "actor": "session-123",
  "reason": "Accepted for isolated local testing"
}
```

Response:

```json
{
  "override_id": "override-...",
  "expires_at": "2026-04-02T18:00:00Z",
  "decision": "allow"
}
```

Overrides are one-time and scoped to the original `check_id`.

## Decision Policy

OreWatch returns `allow` only when:

- threat data is `complete`
- every dependency resolves to an exact version
- no dependency matches malicious-package intelligence

OreWatch returns `override_required` when:

- any dependency matches malicious intelligence
- threat data is `partial` or `failed`
- exact version resolution fails
- the monitor API is unavailable after one auto-start attempt in the MCP bridge

## MCP Bridge

Run the bridge with:

```bash
orewatch monitor mcp
```

`orewatch monitor mcp` is a stdio server. When launched by hand it will appear idle after startup because it is waiting for an MCP client to send `initialize` and tool calls. It keeps stdout reserved for MCP frames and only writes startup hints for interactive/manual runs.

The bridge exposes:

- `orewatch_health`
- `orewatch_check_dependency_add`
- `orewatch_check_manifest`
- `orewatch_override_dependency_add`
- `orewatch_list_active_findings`
- `orewatch_list_notifications`

This allows MCP clients to retrieve background detections and recent alert messages after the original scan has completed.

The bridge proactively checks the local OreWatch API on startup and auto-starts the local monitor once when `auto_start_on_client` is enabled.

If you want the monitor daemon available whenever the IDE starts, install it once:

```bash
orewatch monitor install
```

To print copy-paste MCP/API bootstrap snippets for supported clients:

```bash
orewatch monitor quickstart . --client claude_code
orewatch monitor install --ide-bootstrap
orewatch monitor ide-bootstrap --client codex
orewatch monitor ide-bootstrap --client xcode
```

`orewatch monitor quickstart` is the recommended first-run command. It:

- installs the local OreWatch monitor service
- starts watching the target project
- prints the MCP or API bootstrap block for the selected client
- falls back to the local background mode if native `launchd` or `systemd` setup is unavailable

The generated MCP command is now just `orewatch monitor mcp`, because all clients share the same per-user singleton daemon.

## Editor Integration Patterns

Use MCP for:

- Claude Code
- Codex
- Cursor

Use the localhost API for:

- VS Code
- JetBrains / PyCharm
- Xcode

Common API integration pattern:

1. Discover `base_url` and `token_path` with `orewatch monitor connection-info` or `orewatch monitor ide-bootstrap --client <client>`.
2. Read the bearer token from `token_path`.
3. Call `POST /v1/check/dependency-add` before dependency-install flows.
4. Call `POST /v1/check/manifest` when a supported manifest is saved or explicitly rechecked.
5. Poll `GET /v1/findings/active` and `GET /v1/notifications` for durable background-monitor alerts.

Xcode caveat:

- OreWatch does not yet parse native Apple dependency manifests such as `Package.resolved`, `Podfile.lock`, or `Cartfile`.
- Xcode integration is therefore best for alert visibility, mixed-language repositories, and supported manifests that coexist alongside Apple project files.

For the higher-level rollout view, see [docs/roadmap.md](roadmap.md).

## Review Surfaces

OreWatch background detections are intentionally available through multiple surfaces:

- CLI:
  - `orewatch monitor findings`
  - `orewatch monitor notifications`
- Local API:
  - `GET /v1/findings/active`
  - `GET /v1/notifications`
- MCP:
  - `orewatch_list_active_findings`
  - `orewatch_list_notifications`

Desktop and terminal notifications are still best-effort local alert channels, but the supported durable review path is the stored findings/notifications surface above.

On macOS, OreWatch also has a native menu bar app. Choose the command that
matches your install method:

```bash
# pip / source-checkout install
python3.14 -m pip install 'orewatch[mac-menubar]'

# existing pipx install
pipx inject orewatch pyobjc-framework-Cocoa
orewatch monitor menubar
```

`orewatch monitor menubar` relaunches the app in the background by default and returns the terminal immediately. Use `orewatch monitor menubar --foreground` only for debugging.

If you installed OreWatch with Homebrew and want the menu bar app, reinstall it
with `pipx` or `pip` using `orewatch[mac-menubar]` so the optional Cocoa
bindings live in the same environment as `orewatch`.

The menu bar app uses the same singleton monitor and findings store. It is an additional native review surface, not a second daemon.

On macOS, when desktop notifications and the menu bar app are enabled, OreWatch prefers the singleton menu bar app as the popup delivery path for new findings. The watcher remains a single daemon; the menu bar app is the singleton native UI companion.

The menu bar app can also:

- add a watched workspace folder through the native folder picker and run an initial quick scan
- toggle the common notification and menu bar preferences without editing YAML by hand
- open the monitor config file and config folder directly
