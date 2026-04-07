# OreWatch End-to-End Testing

This guide covers the full client-validation path for OreWatch’s dependency preflight checks.

This is primarily a contributor and validation document. If you are trying to adopt OreWatch in daily development, start with [adoption-guide.md](adoption-guide.md) instead.

It is designed to answer one question:

> When Claude Code, Codex, or Cursor tries to add a dependency, does OreWatch check it first and return the right decision for every supported ecosystem?

## What this validates

The current E2E harness validates:

- all 6 supported ecosystems: npm, PyPI, Maven, RubyGems, Go, Cargo
- safe exact-version dependency adds
- synthetic compromised exact-version dependency adds
- the localhost monitor API
- the MCP bridge used by Claude Code and Codex
- the same MCP contract with `client_type=cursor`

The synthetic malicious packages are fixture-only names such as:

- `orewatch-bad-npm@1.0.0`
- `orewatch-bad-pypi==1.0.0`
- `com.orewatch:bad-maven:1.0.0`
- `orewatch-bad-ruby 1.0.0`
- `example.com/orewatch/bad-go v1.0.0`
- `orewatch-bad-cargo 1.0.0`

They exist only in the generated signed fixture dataset used for testing.

## 1. Create an isolated E2E workspace

```bash
python3 scripts/setup_e2e_workspace.py /tmp/orewatch-e2e --force
```

This creates:

- a copied OreWatch runtime repo under `/tmp/orewatch-e2e/orewatch-runtime`
- synthetic SQLite threat-data fixtures under that copied repo
- one minimal demo project per ecosystem under `/tmp/orewatch-e2e/projects`
- a generated manual checklist at `/tmp/orewatch-e2e/client-checklist.md`
- a manifest file at `/tmp/orewatch-e2e/workspace.json`

## 2. Run the automated local E2E matrix

```bash
python3 scripts/run_e2e_matrix.py /tmp/orewatch-e2e
```

Equivalent make target:

```bash
make test-e2e-clients E2E_WORKSPACE=/tmp/orewatch-e2e
```

By default this validates:

- API path with `client_type=codex`
- MCP path with `client_type=claude_code,codex,cursor`

Expected result:

- safe exact versions return `allow`
- synthetic compromised exact versions return `override_required`

If you want subprocess logs:

```bash
python3 scripts/run_e2e_matrix.py /tmp/orewatch-e2e --verbose
```

## 3. Manual client validation

Use the copied runtime repo from the workspace so the clients point at the synthetic threat-data fixtures instead of your normal local monitor state.

The MCP command is:

```bash
python3 /tmp/orewatch-e2e/orewatch-runtime/malicious_package_scanner.py monitor mcp
```

If you want to inspect the advertised MCP tools using the same lifecycle a real client uses:

```bash
OREWATCH_CONFIG_HOME=/tmp/orewatch-e2e/config-home \
OREWATCH_STATE_HOME=/tmp/orewatch-e2e/state-home \
python3 scripts/orewatch_client.py \
  --cwd /tmp/orewatch-e2e/orewatch-runtime \
  --list-tools
```

The generated checklist at `/tmp/orewatch-e2e/client-checklist.md` contains the project paths and suggested prompts.

### Claude Code

Configure Claude Code to use the MCP command above, open one of the demo projects, then ask it to add both the safe and malicious test dependencies.

Example:

```text
Add dependency orewatch-bad-npm 1.0.0 using npm.
Check OreWatch first and tell me the decision before making changes.
```

Expected behavior:

- Claude calls `orewatch_check_dependency_add`
- OreWatch returns `override_required`
- Claude reports that decision before changing the manifest

### Codex

Use the same MCP command and the same project fixtures.

Expected behavior:

- Codex performs the OreWatch check before dependency add work
- safe versions are allowed
- malicious versions are blocked pending explicit override

### Cursor

If your Cursor setup supports MCP or command-based tool integrations, point it at the same MCP command and run the same prompts.

If your Cursor setup does not yet support MCP directly, use the automated matrix plus manual manifest checks until the dedicated plugin path is in place.

## MCP contract note

The local client helper in `scripts/orewatch_client.py` is intentionally a real MCP session client, not a one-shot `tools/call` shortcut.

It performs:

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. `tools/call`

on one persistent process. The automated client matrix uses that same flow.

## 4. Ecosystem coverage

The current generated project set includes:

- `/tmp/orewatch-e2e/projects/npm-demo/package.json`
- `/tmp/orewatch-e2e/projects/pypi-demo/requirements.txt`
- `/tmp/orewatch-e2e/projects/maven-demo/pom.xml`
- `/tmp/orewatch-e2e/projects/rubygems-demo/Gemfile`
- `/tmp/orewatch-e2e/projects/go-demo/go.mod`
- `/tmp/orewatch-e2e/projects/cargo-demo/Cargo.toml`

Parser coverage for the broader manifest set remains in the normal unit suite:

- `tests/test_manifest_fixtures.py`
- `tests/test_client_e2e.py`
- `tests/test_monitor.py`

## 5. Expected pass criteria

Treat the run as successful only when all are true:

- every ecosystem returns `allow` for the safe exact version
- every ecosystem returns `override_required` for the synthetic compromised version
- Claude Code and Codex both report the OreWatch decision before proceeding
- Cursor shows the same behavior when run through the MCP path
- no client silently treats unresolved or compromised versions as allowed

## 6. Current scope

This E2E harness currently covers:

- the monitor API
- the MCP bridge
- synthetic cross-ecosystem dependency adds

It does not yet cover:

- first-party VS Code plugin UX
- first-party JetBrains/PyCharm plugin UX
- arbitrary terminal-command interception inside IDE terminals

Those should be added after the dedicated IDE extensions exist.
