#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_orewatch_demo.sh [options]

Run a short scripted OreWatch demo that is suitable for recording.

Options:
  --workspace DIR     Workspace path for generated demo fixtures.
                      Default: /tmp/orewatch-demo
  --mode MODE         Demo mode: quick or matrix. Default: quick
  --python BIN        Python executable to use. Default: $PYTHON_BIN or python3
  --sleep SECONDS     Delay between visible steps. Default: 0.4
  --dry-run           Print commands without executing them.
  --help              Show this help text.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="/tmp/orewatch-demo"
mode="quick"
sleep_seconds="0.4"
dry_run=0
python_bin="${PYTHON_BIN:-python3}"
test_python_bin="${TEST_PYTHON_BIN:-}"
orewatch_bin="${OREWATCH_BIN:-orewatch}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      workspace="$2"
      shift 2
      ;;
    --mode)
      mode="$2"
      shift 2
      ;;
    --python)
      python_bin="$2"
      shift 2
      ;;
    --sleep)
      sleep_seconds="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$mode" != "quick" && "$mode" != "matrix" ]]; then
  echo "Unsupported mode: $mode" >&2
  exit 1
fi

if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python executable not found: $python_bin" >&2
  exit 1
fi

if [[ -z "$test_python_bin" ]]; then
  if command -v python3.14 >/dev/null 2>&1; then
    test_python_bin="python3.14"
  else
    test_python_bin="$python_bin"
  fi
fi

if command -v "$orewatch_bin" >/dev/null 2>&1; then
  orewatch_cmd="$(printf '%q' "$orewatch_bin")"
else
  orewatch_cmd="$(printf '%q %q' "$python_bin" "$repo_root/malicious_package_scanner.py")"
fi

python_cmd="$(printf '%q' "$python_bin")"
test_python_cmd="$(printf '%q' "$test_python_bin")"
repo_root_q="$(printf '%q' "$repo_root")"
workspace_q="$(printf '%q' "$workspace")"
setup_output="$(dirname "$workspace")/$(basename "$workspace")-setup.json"
summary_output="$(dirname "$workspace")/$(basename "$workspace")-summary.json"
setup_output_q="$(printf '%q' "$setup_output")"
summary_output_q="$(printf '%q' "$summary_output")"
quick_demo_dir="/tmp/orewatch-quick-demo"
quick_demo_dir_q="$(printf '%q' "$quick_demo_dir")"
quick_manifest="$quick_demo_dir/requirements.txt"
quick_manifest_q="$(printf '%q' "$quick_manifest")"
quick_report="$quick_demo_dir/scan-report.json"
quick_report_q="$(printf '%q' "$quick_report")"

if [[ "$mode" == "quick" ]]; then
  clients="codex"
else
  clients="claude_code,codex,cursor"
fi

run_step() {
  local command="$1"
  printf '\n$ %s\n' "$command"
  if [[ $dry_run -eq 0 ]]; then
    bash -lc "cd $repo_root_q && $command"
  fi
  if [[ "$sleep_seconds" != "0" ]]; then
    sleep "$sleep_seconds"
  fi
}

printf 'OreWatch scripted demo\n'
printf 'Repo: %s\n' "$repo_root"
printf 'Workspace: %s\n' "$workspace"
printf 'Mode: %s\n' "$mode"

run_step "$orewatch_cmd --help | sed -n '1,18p'"
run_step "$orewatch_cmd --list-supported-files"

if [[ "$mode" == "quick" ]]; then
  run_step "mkdir -p $quick_demo_dir_q"
  run_step "printf 'requests==2.33.1\nPyYAML==6.0.3\n' > $quick_manifest_q"
  run_step "$orewatch_cmd --file $quick_manifest_q --ecosystem pypi --no-ioc --output $quick_report_q"
  run_step "$test_python_cmd -m unittest tests.test_packaging -v"

  printf '\nArtifacts:\n'
  printf '  %s\n' "$quick_manifest"
  printf '  %s\n' "$quick_report"
else
  run_step "$python_cmd scripts/setup_e2e_workspace.py $workspace_q --force > $setup_output_q"
  run_step "sed -n '1,40p' $setup_output_q"
  run_step "$python_cmd scripts/run_e2e_matrix.py $workspace_q --clients $clients > $summary_output_q"
  run_step "rg '\"success\"|\"failures\"|\"safe_decision\"|\"malicious_decision\"' $summary_output_q"

  printf '\nArtifacts:\n'
  printf '  %s\n' "$setup_output"
  printf '  %s\n' "$summary_output"
fi
