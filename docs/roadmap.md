# OreWatch Roadmap

This document is meant to help adopters understand what is solid today, what is improving next, and where the current product boundaries still are.

## What is ready now

OreWatch is already suitable for:

- one-off malicious package and IoC scans from the CLI
- one per-user background monitor watching many projects
- MCP integrations for Cursor, Claude Code, and Codex
- localhost API integrations for VS Code, JetBrains / PyCharm, and Xcode helpers
- macOS menu bar review and popup notifications
- HTML and JSON reporting for detections

## Near-term priorities

These are the areas that most directly improve day-to-day adoption:

- better onboarding and setup guidance for editors and coding agents
- stronger user-facing alerting and notification review flows
- first-party or near-first-party integration examples for VS Code and JetBrains / PyCharm
- first-party managed-rollout guidance for Kandji, Jamf Pro, Intune, and Munki-style deployments
- easier monitor policy management without hand-editing config
- continued hardening of singleton monitor behavior and upgrade flows

## Mid-term priorities

These are the next product-shaping improvements:

- richer monitor and MCP workflows for scanning and policy review
- better organization-level deployment and rollout guidance
- stronger external notification channels such as webhooks and team alerting patterns
- editor-specific UX improvements beyond raw API integration
- better managed-software rollout assets and packaging guidance
- broader platform parity for local UI and notification surfaces

## Known boundaries today

These are important adoption caveats rather than hidden limitations:

- Xcode integration is currently best for alert visibility, menu bar UX, and mixed-language repositories
- OreWatch does not yet parse native Apple dependency manifests such as `Package.resolved`, `Podfile.lock`, or `Cartfile`
- VS Code and JetBrains / PyCharm currently rely on the localhost API contract; there is no bundled first-party extension in this repo yet
- the macOS menu bar experience is the most mature local UI path today
- the recommended managed fleet path is currently guidance-based; this repo does not yet ship a first-party notarized macOS installer package

## Longer-term direction

These are the areas that would materially expand adoption if implemented:

- native Apple ecosystem manifest support
- stronger first-party editor integrations
- first-party signed/notarized macOS installer artifacts for fleet rollout
- baseline managed configuration and bootstrap helpers for enterprise deployment tools
- broader OS-native local UI support beyond the current macOS path
- deeper organization and policy management workflows

## How to read this roadmap

Use it as a planning aid:

- if you need immediate local protection, OreWatch is already usable now
- if you need deep native IDE UX, check whether the current API or MCP path is sufficient
- if you need native Apple manifest coverage, plan around that current gap

## How to influence priorities

The roadmap is shaped most strongly by:

- security impact
- real deployment blockers
- repeated adoption friction from users
- implementation quality and maintainability

If you want to influence it, open a concrete issue with:

- your editor or agent environment
- what you tried to adopt
- where the friction appeared
- what success would look like in your workflow
