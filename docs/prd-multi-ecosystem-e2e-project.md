# PRD: Multi-Ecosystem End-to-End Test Project for OreWatch

## Document Status

- Status: Draft for implementation
- Audience: Claude Code, Codex, Cursor, and human contributors
- Purpose: Define a concrete project that an AI coding agent can build to validate OreWatch integrations end to end

## 1. Overview

Build a self-contained multi-ecosystem sample project that exists only to test OreWatch integration behavior across all supported ecosystems.

The project must let us prove the following:

1. OreWatch can be integrated into an agent- or IDE-driven workflow before dependency changes are made.
2. OreWatch returns `allow` for safe exact-version dependencies.
3. OreWatch returns `override_required` for known bad dependencies.
4. This behavior works across all supported ecosystems:
   - npm
   - PyPI
   - Maven
   - RubyGems
   - Go
   - Cargo
5. A single command can trigger a deterministic end-to-end run that attempts to add known-bad dependencies to each ecosystem and verifies the expected OreWatch decision.

This project is not meant to be a production app. It is a deterministic integration target and demo harness.

## 2. Product Goal

Create a polyglot monorepo-style test project that:

- contains one minimal project per OreWatch-supported ecosystem
- can run locally on developer machines without external services
- integrates OreWatch through the local monitor API and MCP bridge
- provides automation to simulate dependency-add actions
- records and verifies whether OreWatch blocked or allowed those actions
- is simple enough that Claude, Codex, or Cursor can build and reason about it from this PRD alone

## 3. Success Criteria

The project is successful when all of the following are true:

1. A single command prepares the test workspace and installs or configures all ecosystem fixtures.
2. A single command runs the end-to-end validation suite.
3. The suite checks both:
   - a safe dependency add
   - a malicious dependency add
4. The suite covers all 6 ecosystems.
5. OreWatch is queried before dependency mutation logic proceeds.
6. The results are emitted in a machine-readable summary file and a human-readable console report.
7. The project can be driven by:
   - Claude Code through MCP
   - Codex through MCP
   - Cursor through MCP or the same local integration contract

## 4. Non-Goals

The project does not need to:

- ship real application features
- connect to databases or cloud services
- build deployable artifacts
- prove package-manager install success against public registries
- test VS Code or JetBrains extension UX in this phase
- test arbitrary IDE terminal interception

The goal is OreWatch integration validation, not full package-manager correctness.

## 5. Primary Use Cases

### Use Case A: Automated local validation

A developer runs one command and gets a pass/fail summary showing whether OreWatch correctly blocked compromised dependency adds across all ecosystems.

### Use Case B: Agent integration validation

A developer points Claude Code, Codex, or Cursor at the project and asks it to add a dependency. The agent should check OreWatch first and report the decision before proceeding.

### Use Case C: Demo environment

A maintainer uses the project to demonstrate OreWatch blocking malicious dependencies across multiple languages in one repo.

## 6. Users

- OreWatch maintainers
- Contributors adding IDE or agent integrations
- Security reviewers validating the integration model
- Developer advocates demoing OreWatch

## 7. Required Deliverables

The implementation must include all of the following.

### 7.1 Polyglot fixture repo

A new test project or fixture workspace with one minimal module per ecosystem:

- `apps/npm-app/`
- `apps/python-app/`
- `apps/maven-app/`
- `apps/ruby-app/`
- `apps/go-app/`
- `apps/rust-app/`

Each module must have:

- the canonical manifest for its ecosystem
- one minimal source file
- one safe dependency path
- one malicious dependency path used only by the test harness

### 7.2 OreWatch integration layer

The project must integrate OreWatch through the existing local contract:

- `orewatch monitor connection-info`
- localhost API
- `orewatch monitor mcp`

The implementation must not invent a parallel integration path.

### 7.3 Add-dependency simulation runner

A script or runner must exist that:

- iterates through all ecosystems
- attempts a safe dependency add
- attempts a malicious dependency add
- queries OreWatch before proceeding
- records the decision
- only mutates manifests when policy allows or when the test explicitly requests override behavior

### 7.4 End-to-end report

The project must output:

- structured JSON summary
- human-readable console summary
- per-ecosystem request/decision details

## 8. Functional Requirements

### FR-1: Multi-ecosystem layout

The project must contain six independent modules, one per supported ecosystem.

Required manifests:

- npm: `package.json`
- PyPI: `requirements.txt` or `pyproject.toml`
- Maven: `pom.xml`
- RubyGems: `Gemfile`
- Go: `go.mod`
- Cargo: `Cargo.toml`

### FR-2: Safe and malicious dependency fixtures

Each ecosystem module must define:

- one safe exact-version dependency
- one malicious exact-version dependency
- optionally one unresolved/range dependency case

The malicious dependency names must be synthetic fixture names, not real packages.

Recommended names:

- npm: `orewatch-bad-npm@1.0.0`
- PyPI: `orewatch-bad-pypi==1.0.0`
- Maven: `com.orewatch:bad-maven:1.0.0`
- RubyGems: `orewatch-bad-ruby 1.0.0`
- Go: `example.com/orewatch/bad-go v1.0.0`
- Cargo: `orewatch-bad-cargo 1.0.0`

Recommended safe names:

- npm: `orewatch-good-npm@2.0.0`
- PyPI: `orewatch-good-pypi==2.0.0`
- Maven: `com.orewatch:good-maven:2.0.0`
- RubyGems: `orewatch-good-ruby 2.0.0`
- Go: `example.com/orewatch/good-go v2.0.0`
- Cargo: `orewatch-good-cargo 2.0.0`

### FR-3: OreWatch-first decision flow

Before any add/update action is performed, the project’s automation must call OreWatch.

Required behavior:

- if OreWatch returns `allow`, the simulated add path may proceed
- if OreWatch returns `override_required`, the runner must mark the action as blocked unless the test explicitly exercises override behavior

### FR-4: All ecosystems exercised in one run

The runner must test all ecosystems in one pass.

Minimum scenarios per ecosystem:

1. safe add -> expect `allow`
2. malicious add -> expect `override_required`

Optional third scenario:

3. unresolved/range version -> expect `override_required`

### FR-5: Agent-ready commands

The project must expose clear commands that an AI agent can run without guessing.

Required top-level commands:

1. `setup`
2. `test:e2e`
3. `test:e2e:clients`

These can be shell scripts, Python scripts, Make targets, or package scripts, but they must be documented and deterministic.

### FR-6: MCP-based agent validation

The project must include instructions and optionally scripts to validate:

- Claude Code using the OreWatch MCP bridge
- Codex using the OreWatch MCP bridge
- Cursor using the OreWatch MCP bridge or the same local API contract

### FR-7: JSON summary output

The E2E run must write a JSON file with at least:

- timestamp
- OreWatch connection info
- ecosystems tested
- safe test result per ecosystem
- malicious test result per ecosystem
- override result where applicable
- overall success boolean
- failures array

## 9. Technical Design Requirements

### 9.1 Repository shape

Recommended structure:

```text
orewatch-e2e-project/
├── README.md
├── package.json
├── Makefile
├── scripts/
│   ├── setup.sh
│   ├── run_e2e.py
│   ├── add_dependency.py
│   ├── client_checklist.md.tmpl
│   └── verify_results.py
├── config/
│   ├── orewatch.json
│   └── dependency-matrix.json
├── apps/
│   ├── npm-app/
│   ├── python-app/
│   ├── maven-app/
│   ├── ruby-app/
│   ├── go-app/
│   └── rust-app/
└── output/
```

### 9.2 OreWatch dependency

The project must not reimplement OreWatch logic. It must consume the running monitor through:

- `orewatch monitor connection-info`
- the localhost API
- the MCP bridge

### 9.3 Deterministic fixture data

The project must assume OreWatch is backed by synthetic deterministic fixture data, not live threat feeds.

It must either:

- point at a prepared OreWatch E2E workspace, or
- generate one if not present

### 9.4 Package manager actions

Real package-manager execution is optional.

For v1, the runner may simulate add operations by:

- composing the dependency-add request
- checking OreWatch
- optionally editing the manifest only when allowed

This is acceptable because the product goal is OreWatch decision validation, not registry/network installation success.

### 9.5 Minimal source files

Each app should contain one tiny source file so the project looks like a real polyglot workspace:

- npm: `src/index.js`
- Python: `app.py`
- Maven: `src/main/java/...`
- Ruby: `app.rb`
- Go: `main.go`
- Rust: `src/main.rs`

These can be minimal “hello world” stubs.

## 10. Integration Modes

### Mode A: Fully automated local E2E

The runner directly calls OreWatch’s localhost API for all ecosystems.

Purpose:

- fast deterministic CI validation

### Mode B: MCP client validation

The runner or checklist uses the OreWatch MCP bridge and exercises the same tool calls that Claude Code, Codex, and Cursor should use.

Purpose:

- validate the AI-agent integration contract

### Mode C: Manual real-client validation

The project includes prompts and instructions so a human can open Claude Code, Codex, or Cursor and ask it to add dependencies while OreWatch is attached.

Purpose:

- validate actual agent behavior, not just the transport contract

## 11. Required Scripts

### `scripts/setup.sh` or equivalent

Must:

- verify Python and required tooling exist
- prepare any local workspace config
- verify OreWatch is available
- write any generated config needed by the E2E project

### `scripts/run_e2e.py`

Must:

- discover OreWatch connection info
- iterate through all ecosystems
- run safe and malicious checks
- write JSON summary
- exit non-zero on failures

### `scripts/add_dependency.py`

Must:

- accept ecosystem, client type, scenario, and project path
- call OreWatch first
- return structured output
- optionally mutate the target manifest only when explicitly requested

### `scripts/verify_results.py`

Must:

- read the generated JSON summary
- assert all required success criteria
- print clear failure explanations

## 12. Test Matrix

The implementation must encode this minimum matrix.

| Ecosystem | Safe exact version | Malicious exact version | Optional unresolved |
|---|---|---|---|
| npm | required | required | recommended |
| PyPI | required | required | recommended |
| Maven | required | required | recommended |
| RubyGems | required | required | recommended |
| Go | required | required | recommended |
| Cargo | required | required | recommended |

Client coverage:

- Claude Code: required
- Codex: required
- Cursor: required

## 13. Acceptance Criteria

The work is complete only when:

1. The multi-ecosystem project exists and runs locally.
2. The E2E runner covers all six ecosystems.
3. Safe dependencies return `allow` in all ecosystems.
4. Known bad dependencies return `override_required` in all ecosystems.
5. A manual checklist exists for Claude Code, Codex, and Cursor.
6. The project emits machine-readable JSON results.
7. The implementation is documented well enough that another agent can rerun the same tests without reverse engineering the repo.

## 14. Nice-to-Have Enhancements

These are not required for v1 but are good follow-on work:

- add manifest watcher validation after direct file edits
- add explicit override-flow tests
- add GitHub Actions workflow for the synthetic E2E run
- add per-client summary sections in the JSON output
- add first-party VS Code and JetBrains extension validation once those integrations exist

## 15. Implementation Guidance for AI Agents

If Claude Code, Codex, or Cursor is implementing this PRD, it should proceed in this order:

1. Create the polyglot fixture workspace structure.
2. Add the dependency matrix config.
3. Implement the OreWatch integration helper.
4. Implement the E2E runner.
5. Add output verification.
6. Write the README for the test project.
7. Add manual client prompts/checklists.

The implementation should favor:

- explicit config files over hidden conventions
- synthetic dependency names over real public packages
- exact versions over ranges
- deterministic local behavior over network-heavy behavior

## 16. Definition of Done

This PRD is complete when an implementer can build the project without additional product clarification.

The resulting project must:

- be multi-ecosystem
- be OreWatch-integrated
- support deterministic malicious dependency testing
- support Claude Code, Codex, and Cursor validation
- produce reproducible end-to-end results
