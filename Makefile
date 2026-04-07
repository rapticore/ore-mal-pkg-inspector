PYTHON ?= python3
E2E_WORKSPACE ?= /tmp/orewatch-e2e
E2E_CLIENTS ?= claude_code,codex,cursor

.PHONY: setup-e2e-workspace test-e2e-clients start-e2e-monitor start-e2e-mcp list-e2e-mcp-tools

setup-e2e-workspace:
	$(PYTHON) scripts/setup_e2e_workspace.py $(E2E_WORKSPACE) --force

test-e2e-clients: setup-e2e-workspace
	$(PYTHON) scripts/run_e2e_matrix.py $(E2E_WORKSPACE) --clients $(E2E_CLIENTS)

start-e2e-monitor: setup-e2e-workspace
	OREWATCH_CONFIG_HOME=$(E2E_WORKSPACE)/config-home OREWATCH_STATE_HOME=$(E2E_WORKSPACE)/state-home \
		$(PYTHON) $(E2E_WORKSPACE)/orewatch-runtime/malicious_package_scanner.py monitor run

start-e2e-mcp: setup-e2e-workspace
	OREWATCH_CONFIG_HOME=$(E2E_WORKSPACE)/config-home OREWATCH_STATE_HOME=$(E2E_WORKSPACE)/state-home \
		$(PYTHON) $(E2E_WORKSPACE)/orewatch-runtime/malicious_package_scanner.py monitor mcp

list-e2e-mcp-tools: setup-e2e-workspace
	OREWATCH_CONFIG_HOME=$(E2E_WORKSPACE)/config-home OREWATCH_STATE_HOME=$(E2E_WORKSPACE)/state-home \
		$(PYTHON) scripts/orewatch_client.py --cwd $(E2E_WORKSPACE)/orewatch-runtime --list-tools
