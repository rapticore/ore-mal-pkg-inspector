#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: record_terminal_demo.sh [options]

Record the scripted OreWatch terminal demo with asciinema and render an animated
SVG via svg-term.

Options:
  --output-dir DIR       Directory for recording artifacts.
                         Default: /tmp/orewatch-recordings
  --workspace DIR        Demo workspace path. Default: /tmp/orewatch-demo
  --mode MODE            quick or matrix. Default: quick
  --title TITLE          Recording title. Default: OreWatch Terminal Demo
  --idle-limit SECONDS   Idle time compression. Default: 1
  --cols COLS            Terminal width. Default: 110
  --rows ROWS            Terminal height. Default: 32
  --sleep SECONDS        Delay between scripted steps. Default: 0.4
  --no-render            Skip SVG rendering and keep only the .cast file.
  --dry-run              Print commands without executing them.
  --help                 Show this help text.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="/tmp/orewatch-recordings"
workspace="/tmp/orewatch-demo"
mode="quick"
title="OreWatch Terminal Demo"
idle_limit="1"
cols="110"
rows="32"
sleep_seconds="0.4"
render_svg=1
dry_run=0
python_bin="${PYTHON_BIN:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      output_dir="$2"
      shift 2
      ;;
    --workspace)
      workspace="$2"
      shift 2
      ;;
    --mode)
      mode="$2"
      shift 2
      ;;
    --title)
      title="$2"
      shift 2
      ;;
    --idle-limit)
      idle_limit="$2"
      shift 2
      ;;
    --cols)
      cols="$2"
      shift 2
      ;;
    --rows)
      rows="$2"
      shift 2
      ;;
    --sleep)
      sleep_seconds="$2"
      shift 2
      ;;
    --no-render)
      render_svg=0
      shift
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

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema is not installed or not on PATH" >&2
  exit 1
fi

if [[ $render_svg -eq 1 ]] && ! command -v svg-term >/dev/null 2>&1; then
  echo "svg-term is not installed or not on PATH" >&2
  exit 1
fi

mkdir -p "$output_dir"

timestamp="$(date +%Y%m%d-%H%M%S)"
base_name="orewatch-${mode}-terminal-${timestamp}"
cast_file="$output_dir/${base_name}.cast"
svg_file="$output_dir/${base_name}.svg"

demo_command=(
  "$repo_root/scripts/demo/run_orewatch_demo.sh"
  --workspace "$workspace"
  --mode "$mode"
  --python "$python_bin"
  --sleep "$sleep_seconds"
)
demo_command_str="$(printf '%q ' "${demo_command[@]}")"

printf 'Output directory: %s\n' "$output_dir"
printf 'Cast file: %s\n' "$cast_file"
printf 'SVG file: %s\n' "$svg_file"
printf 'Demo command: %s\n' "$demo_command_str"

if [[ $dry_run -eq 1 ]]; then
  exit 0
fi

asciinema rec \
  --overwrite \
  --quiet \
  --idle-time-limit "$idle_limit" \
  --cols "$cols" \
  --rows "$rows" \
  --title "$title" \
  --command "$demo_command_str" \
  "$cast_file"

if [[ $render_svg -eq 1 ]]; then
  svg-term \
    --in "$cast_file" \
    --out "$svg_file" \
    --window \
    --width "$cols" \
    --height "$rows" \
    --padding 12
fi

printf '\nArtifacts created:\n'
printf '  %s\n' "$cast_file"
if [[ $render_svg -eq 1 ]]; then
  printf '  %s\n' "$svg_file"
fi
