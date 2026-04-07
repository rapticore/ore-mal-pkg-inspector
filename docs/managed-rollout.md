# OreWatch Managed Rollout

This guide is for IT and platform teams rolling OreWatch out with managed-software tools such as Kandji, Jamf Pro, Intune, Munki, or similar package distribution systems.

## Executive summary

Use two layers:

1. **Machine-scope package install**
   - deploy the OreWatch runtime as a signed macOS flat package
2. **User-scope activation**
   - activate the per-user monitor from the logged-in user context

Do **not** treat OreWatch like a pure device daemon. The runtime can be machine-installed, but the monitor itself is intentionally per-user.

## Current product reality

Today OreWatch is primarily shipped as a Python package.

That means:

- developers can install it directly with `pipx` or `pip`
- CI can install a pinned version directly from PyPI or an internal mirror
- managed macOS fleets should wrap the runtime into a signed `.pkg` instead of trying to deploy a wheel directly

Important boundary:

- this repo does **not** currently ship a first-party notarized macOS installer package

So the recommended enterprise path is:

- publish the OreWatch wheel internally or use the public release artifact
- build a thin signed macOS installer package around that runtime
- distribute that `.pkg` through your device-management system

## Why rollout is two-phase

OreWatch has two different scopes:

### Machine scope

Good fit for MDM/package distribution:

- the CLI/runtime files
- optional menu bar dependencies
- shared baseline defaults or helper scripts

### User scope

Must be handled per logged-in user:

- the singleton monitor install
- the user LaunchAgent
- the API token
- the user-owned config and state directories
- per-user menu bar activation

This split exists by design. It prevents a repo checkout or machine-scope package from silently pre-seeding monitor behavior into a user’s private state.

## Recommended artifact strategy

### 1. Runtime package

Recommended managed artifact:

- a signed macOS flat package (`.pkg`)

Recommended contents:

- a dedicated OreWatch runtime under a stable path such as `/Library/Application Support/OreWatch/runtime`
- a stable executable shim such as `/usr/local/bin/orewatch`
- version metadata that your MDM can detect and upgrade cleanly

Optional variant:

- a second package that includes the `mac-menubar` extra for fleets that want the native menu bar UX on macOS

### 2. Threat-data channel

Do not bundle threat-data snapshots into the same installer package.

Recommended model:

- ship code/runtime separately
- use signed snapshot hosting or live updates for threat data

Why:

- threat data changes on a different cadence than code
- bundling snapshots into the app package creates unnecessary package churn
- the monitor already supports a separate trust and refresh model for threat data

## Recommended rollout flows

### Option A: Developer-first managed rollout

Best when developers have local editor or agent integrations.

1. Deploy the OreWatch runtime package to managed Macs.
2. Let users activate it with:

```bash
orewatch monitor quickstart /path/to/project --client cursor
```

or the client they actually use.

3. If you want macOS popups and a visible UI, also install and launch:

```bash
orewatch monitor menubar
```

This is usually the lowest-friction rollout because the user activation happens in the right account context.

### Option B: Managed bootstrap with user onboarding

Best when IT wants a more guided enterprise rollout.

1. Deploy the runtime package to the machine.
2. Provide a user-facing onboarding action:
   - Self Service item
   - login helper
   - onboarding script
   - managed terminal snippet
3. The onboarding action runs the OreWatch monitor bootstrap in the user session:

```bash
orewatch monitor install
orewatch monitor watch add /path/to/project
orewatch monitor ide-bootstrap --client vscode
```

Use `quickstart` if you want one command instead of separate steps.

## Vendor-specific guidance

### Kandji

Recommended fit:

- use a **Custom App** with an installer package (`.pkg`)
- use a user-facing follow-up step for monitor activation

Practical recommendation:

- deploy the base runtime package with Kandji
- use Self Service, onboarding instructions, or a user-context script for first monitor activation

Why:

- the runtime is machine-installable
- the monitor is user-scoped

### Jamf Pro

Recommended fit:

- deploy the runtime via a Jamf Package and Policy
- use Self Service or another user-context path for activation when needed

Practical recommendation:

- package install through Jamf policy
- user activation through Self Service or a managed helper command

### Microsoft Intune

Recommended fit:

- deploy the runtime as a macOS LOB app using a real `.pkg`

Important constraint:

- Intune is stricter than some other channels; plan for a properly signed installer package rather than a loose script or wheel-only artifact

### Munki

Recommended fit:

- publish the runtime package plus package metadata
- use Munki’s standard managed software flow

Practical recommendation:

- treat OreWatch like any other managed macOS package
- use a separate onboarding step for per-user monitor activation if you want background monitoring

### Other macOS software distribution systems

If the system can do both of these, it can usually carry OreWatch well:

- deploy a standard macOS flat package
- optionally provide a user-context bootstrap step

## What not to do

Avoid these rollout mistakes:

- do not bundle mutable threat data into every app package release
- do not assume a machine-scope install should directly create every user’s monitor state
- do not assume `launchd` activation from root equals correct per-user monitor activation
- do not make menu bar UX a dependency for CLI-only or CI rollouts

## Recommended adoption order for enterprise teams

1. Pilot with a small group of developers.
2. Deploy the runtime package to managed Macs.
3. Validate one editor or coding-agent path first.
4. Validate `orewatch monitor findings` and `orewatch monitor notifications`.
5. Add the menu bar path for macOS users who need visible local alerts.
6. Add webhooks and CI after local workflows are stable.

## Future packaging priorities

The most useful future improvements for managed rollout are:

- a first-party signed/notarized macOS `.pkg`
- a documented package build pipeline for enterprise admins
- managed baseline configuration examples
- clearer user-bootstrap helpers for editor and agent fleets

## Reference docs

- [README.md](../README.md)
- [adoption-guide.md](adoption-guide.md)
- [local-api.md](local-api.md)
- [roadmap.md](roadmap.md)

## Vendor references

These official docs informed the rollout recommendations:

- Kandji Custom Apps: https://support.kandji.io/kb/es-mx/deploying-custom-apps
- Jamf package deployment docs: https://learn.jamf.com/
- Microsoft Intune macOS LOB apps: https://learn.microsoft.com/intune/intune-service/apps/lob-apps-macos
- Munki project documentation: https://github.com/munki/munki
