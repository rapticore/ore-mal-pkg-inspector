# OreWatch Dependency Safety

This repository expects Codex to use the `orewatch` MCP server before
introducing dependencies.

## Required Flow

- Before any dependency add, install, or update command, call
  `orewatch_check_dependency_add`.
- Use `client_type: "codex"`.
- Use `project_path` as the affected project root.
- When a package-manager command is known, use `source.kind: "agent_command"`
  and populate `source.command` with the exact intended command.
- Do not run the package-manager command or edit the manifest until OreWatch
  returns an allow decision.
- If OreWatch returns `override_required` or otherwise blocks the dependency,
  stop, report the decision, and wait for an explicit user override before
  proceeding.
- After directly editing a supported manifest to add or change dependencies,
  call `orewatch_check_manifest` for the saved manifest and report the result.
- Before finishing dependency-related work, call
  `orewatch_list_active_findings` and `orewatch_list_notifications` for the
  affected project and surface any active alerts.

## Applies To

- npm, pnpm, and yarn dependency additions
- pip, poetry, and pipenv dependency additions
- go, cargo, bundler, gem, maven, and gradle dependency additions
- Direct edits to supported manifests such as `package.json`,
  `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, and
  `Gemfile`

## If OreWatch Is Unavailable

- State that the OreWatch preflight dependency safety check could not be
  performed.
- Do not silently bypass OreWatch for dependency changes.
