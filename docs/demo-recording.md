# OreWatch Demo Recording

This repo now includes a small demo toolkit for recording OreWatch runs and test passes.

## Files

- `scripts/demo/run_orewatch_demo.sh`
- `scripts/demo/record_terminal_demo.sh`
- `scripts/demo/record_screen_demo.sh`

## 1. Scripted demo sequence

Use this when you want a repeatable command sequence that shows OreWatch running and then exercising the E2E validation harness.

Quick demo:

```bash
scripts/demo/run_orewatch_demo.sh --mode quick
```

Full matrix demo:

```bash
scripts/demo/run_orewatch_demo.sh --mode matrix
```

What it does:

- prints the top of `orewatch --help`
- prints `orewatch --list-supported-files`
- creates a tiny PyPI manifest under `/tmp/orewatch-quick-demo`
- runs a real OreWatch scan against that manifest
- runs the lightweight packaging test suite

Quick-mode artifact:

- `/tmp/orewatch-quick-demo/requirements.txt`
- `/tmp/orewatch-quick-demo/scan-report.json`

Matrix mode adds the full E2E workspace and summary artifacts under `/tmp`:

- `/tmp/orewatch-demo-setup.json`
- `/tmp/orewatch-demo-summary.json`

## 2. Terminal-only recording workflow

Use this when you want a terminal-native recording artifact with no full-screen capture.

```bash
scripts/demo/record_terminal_demo.sh --mode quick
```

This creates:

- an `asciinema` cast file
- an animated SVG rendered by `svg-term`

Default output directory:

```bash
/tmp/orewatch-recordings
```

Useful variants:

```bash
scripts/demo/record_terminal_demo.sh --mode matrix
scripts/demo/record_terminal_demo.sh --output-dir /tmp/orewatch-demos --no-render
```

This workflow is best for README assets, docs, release posts, and fast terminal-only shares.

## 3. Screen-recording workflow

Use this when you want a real MP4 of a terminal window or an install/test flow.

List available capture devices first:

```bash
scripts/demo/record_screen_demo.sh --list-devices
```

Then record the default scripted demo:

```bash
scripts/demo/record_screen_demo.sh
```

Or record a Homebrew validation clip:

```bash
scripts/demo/record_screen_demo.sh \
  --command 'brew test rapticore/tap/orewatch'
```

If you specifically want an install-style clip and are comfortable reinstalling:

```bash
scripts/demo/record_screen_demo.sh \
  --command 'brew reinstall rapticore/tap/orewatch && brew test rapticore/tap/orewatch'
```

Notes:

- the script auto-detects the first available `Capture screen` device if you do not pass `--screen-index`
- output is an MP4 plus an ffmpeg log file
- macOS may ask you to grant Screen Recording permission to your terminal app

## Suggested usage

Use the terminal workflow when you want a compact terminal asset.

Use the screen workflow when you want a true video file for website, product, or social clips.
