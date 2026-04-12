#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: record_screen_demo.sh [options]

Capture the current macOS screen with ffmpeg while an OreWatch demo command runs.

Options:
  --list-devices         Print available AVFoundation devices and exit.
  --output FILE          Output MP4 path.
                         Default: /tmp/orewatch-recordings/orewatch-screen-<timestamp>.mp4
  --workspace DIR        Demo workspace path. Default: /tmp/orewatch-demo
  --mode MODE            quick or matrix for the default demo command. Default: quick
  --screen-index IDX     AVFoundation screen device index. Default: first detected screen.
  --audio-index IDX      AVFoundation audio device index or none. Default: none
  --fps FPS              Capture frame rate. Default: 30
  --countdown SECONDS    Delay before running the demo command. Default: 3
  --sleep SECONDS        Delay between scripted demo steps. Default: 0.25
  --command CMD          Command to run while recording. Defaults to the scripted demo.
  --dry-run              Print commands without executing them.
  --help                 Show this help text.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="/tmp/orewatch-recordings"
workspace="/tmp/orewatch-demo"
mode="quick"
screen_index=""
audio_index="none"
fps="30"
countdown="3"
sleep_seconds="0.25"
dry_run=0
list_devices=0
command_override=""
python_bin="${PYTHON_BIN:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list-devices)
      list_devices=1
      shift
      ;;
    --output)
      output_file="$2"
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
    --screen-index)
      screen_index="$2"
      shift 2
      ;;
    --audio-index)
      audio_index="$2"
      shift 2
      ;;
    --fps)
      fps="$2"
      shift 2
      ;;
    --countdown)
      countdown="$2"
      shift 2
      ;;
    --sleep)
      sleep_seconds="$2"
      shift 2
      ;;
    --command)
      command_override="$2"
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

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg is not installed or not on PATH" >&2
  exit 1
fi

if [[ $list_devices -eq 1 ]]; then
  ffmpeg -f avfoundation -list_devices true -i "" 2>&1 || true
  exit 0
fi

detect_first_screen() {
  (ffmpeg -f avfoundation -list_devices true -i "" 2>&1 || true) |
    sed -n 's/.*\[\([0-9][0-9]*\)\] Capture screen.*/\1/p' |
    head -n 1
}

if [[ -z "${output_file:-}" ]]; then
  mkdir -p "$output_dir"
  timestamp="$(date +%Y%m%d-%H%M%S)"
  output_file="$output_dir/orewatch-screen-${timestamp}.mp4"
else
  mkdir -p "$(dirname "$output_file")"
fi

if [[ -z "$screen_index" ]]; then
  screen_index="$(detect_first_screen)"
fi

if [[ -z "$screen_index" ]]; then
  echo "Unable to auto-detect a screen device. Run with --list-devices." >&2
  exit 1
fi

if [[ -n "$command_override" ]]; then
  demo_command="$command_override"
else
  demo_command="$(printf '%q ' \
    "$repo_root/scripts/demo/run_orewatch_demo.sh" \
    --workspace "$workspace" \
    --mode "$mode" \
    --python "$python_bin" \
    --sleep "$sleep_seconds")"
fi

output_file_q="$(printf '%q' "$output_file")"
log_file="${output_file%.*}.ffmpeg.log"
log_file_q="$(printf '%q' "$log_file")"
input_device="${screen_index}:${audio_index}"

cleanup() {
  local signal
  local attempt

  if [[ -n "${ffmpeg_pid:-}" ]] && kill -0 "$ffmpeg_pid" >/dev/null 2>&1; then
    for signal in INT TERM KILL; do
      kill "-$signal" "$ffmpeg_pid" >/dev/null 2>&1 || true
      for attempt in $(seq 1 20); do
        if ! kill -0 "$ffmpeg_pid" >/dev/null 2>&1; then
          wait "$ffmpeg_pid" || true
          return
        fi
        sleep 0.25
      done
    done

    wait "$ffmpeg_pid" || true
  fi
}

printf 'Output file: %s\n' "$output_file"
printf 'Capture device: %s\n' "$input_device"
printf 'ffmpeg log: %s\n' "$log_file"
printf 'Demo command: %s\n' "$demo_command"

if [[ $dry_run -eq 1 ]]; then
  exit 0
fi

trap cleanup EXIT INT TERM

ffmpeg \
  -y \
  -f avfoundation \
  -capture_cursor 1 \
  -capture_mouse_clicks 1 \
  -framerate "$fps" \
  -i "$input_device" \
  -pix_fmt yuv420p \
  -c:v libx264 \
  -preset veryfast \
  -crf 23 \
  -movflags +faststart \
  "$output_file" >"$log_file" 2>&1 &
ffmpeg_pid=$!

sleep 1

if [[ "$countdown" != "0" ]]; then
  for remaining in $(seq "$countdown" -1 1); do
    printf 'Recording starts in %s...\n' "$remaining"
    sleep 1
  done
fi

bash -lc "cd $(printf '%q' "$repo_root") && $demo_command"

cleanup
trap - EXIT INT TERM

printf '\nArtifacts created:\n'
printf '  %s\n' "$output_file"
printf '  %s\n' "$log_file"
