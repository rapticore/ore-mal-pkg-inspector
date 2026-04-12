# Deployment Guide

This guide documents the release process for the PyPI package `orewatch` and
the Homebrew tap `rapticore/tap/orewatch`.

## Prerequisites

- GitHub CLI authenticated with push access to:
  - `rapticore/ore-mal-pkg-inspector`
  - `rapticore/homebrew-tap`
- Python 3.14 available locally
- Packaging tools installed:
  - `python3.14 -m pip install --upgrade build twine`
- Homebrew installed locally if you want to audit or test the formula
- A local `.env` file with PyPI credentials for `twine` fallback:
  - `TWINE_USERNAME=__token__`
  - `TWINE_PASSWORD=<pypi token>`

## Release Files To Update

For each release, update these files together:

- `pyproject.toml`
- `scanners/__init__.py`
- `package.json`
- `README.md` pinned install example
- `CHANGELOG.md`

## 1. Prepare The Release

1. Update the version metadata to the new release number.
2. Add the release notes to `CHANGELOG.md`.
3. Verify there are no stale version strings left behind:

```bash
rg -n "1\.2\.0|v1\.2\.0"
```

Replace the version string in the command above with the previous release.

## 2. Verify The Release Locally

Run the release checks before tagging:

```bash
python3.14 -m unittest tests.test_monitor tests.test_regressions tests.test_packaging
python3.14 -m build --outdir /tmp/orewatch-<version>-dist
python3.14 -m twine check /tmp/orewatch-<version>-dist/*
shasum -a 256 /tmp/orewatch-<version>-dist/orewatch-<version>.tar.gz
```

Keep the source tarball SHA256. The Homebrew formula will need it.

## 3. Create The Git Release

Commit the release, tag it, and push both the branch tip and the tag:

```bash
git add CHANGELOG.md README.md pyproject.toml package.json scanners/__init__.py
git commit -m "Release OreWatch <version>"
git tag -a v<version> -F /tmp/orewatch-v<version>-release-notes.md
git push origin HEAD:main
git push origin v<version>
gh release create v<version> \
  --repo rapticore/ore-mal-pkg-inspector \
  --title "OreWatch <version>" \
  --notes-file /tmp/orewatch-v<version>-release-notes.md
```

The tag push triggers `.github/workflows/publish-pypi.yml`.

## 4. Publish To PyPI

### Preferred Path: GitHub Trusted Publishing

The repository is configured to publish from GitHub Actions on tag push:

```bash
gh run list --repo rapticore/ore-mal-pkg-inspector --workflow publish-pypi.yml --limit 5
gh run watch <run-id> --repo rapticore/ore-mal-pkg-inspector --interval 10
```

### Fallback Path: `twine` With `.env`

If trusted publishing fails, publish the already-verified artifacts directly:

```bash
set -a
source .env
set +a
python3.14 -m twine upload --non-interactive --skip-existing /tmp/orewatch-<version>-dist/*
```

Verify the published release:

```bash
python3.14 -c "import json,urllib.request; data=json.load(urllib.request.urlopen('https://pypi.org/pypi/orewatch/<version>/json')); print(data['info']['version'])"
python3.14 -c "import json,urllib.request; data=json.load(urllib.request.urlopen('https://pypi.org/pypi/orewatch/<version>/json')); print(next(u['url'] for u in data['urls'] if u['packagetype']=='sdist'))"
```

## 5. Update The Homebrew Tap

Once the PyPI sdist is live:

1. Clone the tap repo.
2. Update `Formula/orewatch.rb` with:
   - the published PyPI sdist URL
   - the source tarball SHA256 from the local build
3. Commit and push the formula update.

Example:

```bash
gh repo clone rapticore/homebrew-tap /tmp/homebrew-tap-orewatch-<version>
git -C /tmp/homebrew-tap-orewatch-<version> add Formula/orewatch.rb
git -C /tmp/homebrew-tap-orewatch-<version> commit -m "orewatch <version>"
git -C /tmp/homebrew-tap-orewatch-<version> push origin main
```

If you want an audit pass, run it after the formula exists in the tap context:

```bash
brew audit --strict rapticore/tap/orewatch
```

## 6. Post-Release Checks

Confirm each distribution channel resolves to the new version:

```bash
gh release view v<version> --repo rapticore/ore-mal-pkg-inspector
python3.14 -m pip index versions orewatch
brew info rapticore/tap/orewatch
```

## Troubleshooting

### PyPI Trusted Publisher Fails With `invalid-publisher`

If GitHub Actions fails with a message like this:

```text
invalid-publisher: valid token, but no corresponding publisher
```

the PyPI trusted publisher configuration does not match the repository,
workflow, environment, or tag context being used. Either:

- fix the trusted publisher on PyPI, or
- use the `.env` + `twine upload` fallback above

### `twine` Fails With Missing Credentials

Confirm `.env` contains `TWINE_USERNAME` and `TWINE_PASSWORD`, then rerun:

```bash
set -a
source .env
set +a
python3.14 -m twine upload --non-interactive --skip-existing /tmp/orewatch-<version>-dist/*
```

### Homebrew Formula Cannot Be Audited By File Path

Recent Homebrew versions reject `brew audit` against a raw file path. Audit the
formula by tap name after it has been pushed:

```bash
brew audit --strict rapticore/tap/orewatch
```
