#!/usr/bin/env python3
"""
Snapshot build, publish, and update support for the monitor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from monitor.config import ensure_monitor_layout
from scanner_engine import ensure_threat_data


SIGNATURE_ALGORITHM = "rsa-sha256-openssl"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    """Return the SHA-256 digest for one file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_openssl(command: list[str]) -> subprocess.CompletedProcess:
    """Run an OpenSSL command and capture output."""
    return subprocess.run(
        command,
        check=False,
        text=False,
        capture_output=True,
    )


def _canonical_signed_bytes(document: Dict) -> bytes:
    payload = dict(document)
    payload.pop("signature", None)
    payload.pop("signature_algorithm", None)
    payload.pop("key_id", None)
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _ensure_openssl_available() -> None:
    result = _run_openssl(["openssl", "version"])
    if result.returncode != 0:
        raise RuntimeError("OpenSSL is required for public-key snapshot signing")


def _read_bytes(source: str) -> bytes:
    """Read bytes from a local path or URL."""
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in ("http", "https", "file"):
        with urllib.request.urlopen(source, timeout=30) as response:
            return response.read()
    with open(source, "rb") as handle:
        return handle.read()


def _read_json(source: str) -> Dict:
    """Read JSON from a local path or URL."""
    return json.loads(_read_bytes(source).decode("utf-8"))


def _resolve_relative_source(base_source: str, relative_path: str) -> str:
    """Resolve a relative path against a local path or URL."""
    parsed = urllib.parse.urlparse(base_source)
    if parsed.scheme in ("http", "https", "file"):
        return urllib.parse.urljoin(base_source, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(base_source)), relative_path)


def _resolve_entry_source(manifest_source: str, entry: Dict) -> str:
    """Resolve one snapshot entry source."""
    if entry.get("url"):
        return entry["url"]
    return _resolve_relative_source(manifest_source, entry["filename"])


def fingerprint_public_key(public_key_path: str) -> str:
    """Return a stable key fingerprint for one PEM public key."""
    digest = hashlib.sha256()
    with open(public_key_path, "rb") as handle:
        digest.update(handle.read())
    return digest.hexdigest()[:24]


def _derive_public_key_from_private(private_key_path: str) -> str:
    """Derive a temporary PEM public key from a PEM private key."""
    _ensure_openssl_available()
    temp_dir = tempfile.mkdtemp(prefix="snapshot-key-")
    public_key_path = os.path.join(temp_dir, "derived_public.pem")
    result = _run_openssl(
        [
            "openssl",
            "pkey",
            "-in",
            private_key_path,
            "-pubout",
            "-out",
            public_key_path,
        ]
    )
    if result.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(
            result.stderr.decode("utf-8", errors="ignore") or "Failed to derive public key"
        )
    return public_key_path


def generate_keypair(output_dir: str) -> Dict[str, str]:
    """Generate a PEM-encoded RSA keypair for snapshot signing."""
    _ensure_openssl_available()
    os.makedirs(output_dir, exist_ok=True)
    private_key_path = os.path.join(output_dir, "snapshot_signing_private.pem")
    public_key_path = os.path.join(output_dir, "snapshot_signing_public.pem")

    generate = _run_openssl(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            private_key_path,
        ]
    )
    if generate.returncode != 0:
        raise RuntimeError(
            generate.stderr.decode("utf-8", errors="ignore") or "Failed to generate private key"
        )

    export_public = _run_openssl(
        [
            "openssl",
            "pkey",
            "-in",
            private_key_path,
            "-pubout",
            "-out",
            public_key_path,
        ]
    )
    if export_public.returncode != 0:
        raise RuntimeError(
            export_public.stderr.decode("utf-8", errors="ignore") or "Failed to derive public key"
        )

    return {
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
        "key_id": fingerprint_public_key(public_key_path),
    }


def sign_document(
    document: Dict,
    private_key_path: str,
    public_key_path: Optional[str] = None,
) -> Dict:
    """Return signature metadata for one JSON document."""
    _ensure_openssl_available()
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    cleanup_public_key = None
    if public_key_path is None:
        cleanup_public_key = _derive_public_key_from_private(private_key_path)
        public_key_path = cleanup_public_key

    try:
        with tempfile.TemporaryDirectory(prefix="snapshot-sign-") as temp_dir:
            payload_path = os.path.join(temp_dir, "payload.json")
            signature_path = os.path.join(temp_dir, "signature.bin")

            with open(payload_path, "wb") as handle:
                handle.write(_canonical_signed_bytes(document))

            sign = _run_openssl(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    private_key_path,
                    "-out",
                    signature_path,
                    payload_path,
                ]
            )
            if sign.returncode != 0:
                raise RuntimeError(
                    sign.stderr.decode("utf-8", errors="ignore") or "Failed to sign document"
                )

            with open(signature_path, "rb") as handle:
                signature = base64.b64encode(handle.read()).decode("ascii")

        return {
            "signature": signature,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "key_id": fingerprint_public_key(public_key_path),
        }
    finally:
        if cleanup_public_key:
            shutil.rmtree(os.path.dirname(cleanup_public_key), ignore_errors=True)


def verify_document_signature(document: Dict, public_key_path: str) -> bool:
    """Verify the signature on one JSON document."""
    _ensure_openssl_available()
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found: {public_key_path}")
    if document.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise ValueError("Unsupported snapshot signature algorithm")
    if document.get("key_id") and document["key_id"] != fingerprint_public_key(public_key_path):
        raise ValueError("Snapshot key ID does not match the configured public key")

    with tempfile.TemporaryDirectory(prefix="snapshot-verify-") as temp_dir:
        payload_path = os.path.join(temp_dir, "payload.json")
        signature_path = os.path.join(temp_dir, "signature.bin")

        with open(payload_path, "wb") as handle:
            handle.write(_canonical_signed_bytes(document))

        with open(signature_path, "wb") as handle:
            handle.write(base64.b64decode(document["signature"]))

        verify = _run_openssl(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                public_key_path,
                "-signature",
                signature_path,
                payload_path,
            ]
        )
        return verify.returncode == 0


def _require_verified_document(
    document: Dict,
    public_key_path: str,
    kind: str,
) -> None:
    """Require a document to be signed and verifiable."""
    if not document.get("signature"):
        raise ValueError(f"{kind} is not signed")
    if not public_key_path:
        raise ValueError(f"{kind} is signed but no public key was configured")
    if not verify_document_signature(document, public_key_path):
        raise ValueError(f"{kind} signature verification failed")


def _resolve_channel_manifest(
    channel_source: str,
    public_key_path: str = "",
) -> Tuple[Dict, str, Optional[Dict]]:
    """
    Resolve a snapshot source that can be either a channel descriptor or a manifest.
    """
    document = _read_json(channel_source)
    if "files" in document:
        _require_verified_document(document, public_key_path, "Snapshot manifest")
        return document, channel_source, None

    if "manifest_url" not in document:
        raise ValueError("Snapshot source must be a manifest or channel descriptor")

    _require_verified_document(document, public_key_path, "Snapshot channel")

    manifest_source = document["manifest_url"]
    manifest = _read_json(manifest_source)
    _require_verified_document(manifest, public_key_path, "Snapshot manifest")
    return manifest, manifest_source, document


def _copy_snapshot_files(source_db_dir: str, destination_dir: str, base_url: str = "") -> Dict:
    """Copy SQLite DB files into one snapshot directory and return manifest metadata."""
    manifest = {
        "version": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "generated_at": _utcnow(),
        "files": [],
    }

    os.makedirs(destination_dir, exist_ok=True)
    for filename in sorted(os.listdir(source_db_dir)):
        if not filename.endswith(".db"):
            continue
        source_path = os.path.join(source_db_dir, filename)
        destination_path = os.path.join(destination_dir, filename)
        shutil.copy2(source_path, destination_path)
        entry = {
            "filename": filename,
            "sha256": sha256_file(destination_path),
            "size": os.path.getsize(destination_path),
        }
        if base_url:
            entry["url"] = urllib.parse.urljoin(base_url.rstrip("/") + "/", filename)
        manifest["files"].append(entry)

    return manifest


def build_snapshot(
    source_db_dir: str,
    output_dir: str,
    private_key_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> str:
    """Build a versioned snapshot manifest from local SQLite DB files."""
    manifest = _copy_snapshot_files(source_db_dir, output_dir)
    if private_key_path:
        manifest.update(
            sign_document(
                manifest,
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        )

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    return manifest_path


def publish_snapshot(
    source_db_dir: str,
    output_dir: str,
    base_url: str,
    channel: str = "stable",
    private_key_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> Dict[str, str]:
    """
    Publish a snapshot into a static-hosting-friendly layout.
    """
    version = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    versions_dir = os.path.join(output_dir, "versions", version)
    channels_dir = os.path.join(output_dir, "channels")
    os.makedirs(versions_dir, exist_ok=True)
    os.makedirs(channels_dir, exist_ok=True)

    version_base_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", f"versions/{version}/")
    manifest = _copy_snapshot_files(source_db_dir, versions_dir, base_url=version_base_url)
    manifest["version"] = version
    if private_key_path:
        manifest.update(
            sign_document(
                manifest,
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        )

    manifest_path = os.path.join(versions_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    manifest_url = urllib.parse.urljoin(version_base_url, "manifest.json")
    channel_document = {
        "channel": channel,
        "updated_at": _utcnow(),
        "current_version": version,
        "manifest_url": manifest_url,
    }
    if private_key_path:
        channel_document.update(
            sign_document(
                channel_document,
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        )

    channel_path = os.path.join(channels_dir, f"{channel}.json")
    with open(channel_path, "w", encoding="utf-8") as handle:
        json.dump(channel_document, handle, indent=2, sort_keys=True)

    return {
        "version": version,
        "manifest_path": manifest_path,
        "manifest_url": manifest_url,
        "channel_path": channel_path,
        "channel_url": urllib.parse.urljoin(
            base_url.rstrip("/") + "/",
            f"channels/{channel}.json",
        ),
        "key_id": channel_document.get("key_id", manifest.get("key_id", "")),
    }


class SnapshotUpdater:
    """Update local threat-data databases from snapshots or live collection."""

    def __init__(self, repo_root: Optional[str], monitor_config: Dict, state):
        self.repo_root = os.path.abspath(repo_root) if repo_root else None
        self.config = monitor_config
        self.state = state
        self.paths = ensure_monitor_layout(repo_root)
        self.final_data_dir = os.path.join(self.repo_root, "collectors", "final-data")

    def _record_refresh_result(self, result: Dict[str, object]) -> None:
        """Persist refresh attempt metadata without treating failures as fresh data."""
        timestamp = _utcnow()
        self.state.set_agent_state("last_threat_refresh_attempt_at", timestamp)
        self.state.set_agent_state(
            "last_threat_refresh_status",
            "success" if result.get("success") else "failed",
        )
        self.state.set_agent_state(
            "last_threat_refresh_message",
            str(result.get("message", "")),
        )
        if result.get("success"):
            self.state.set_agent_state("last_threat_refresh_at", timestamp)
            if result.get("version"):
                self.state.set_agent_state("current_snapshot_version", result["version"])
            if result.get("key_id"):
                self.state.set_agent_state("current_snapshot_key_id", result["key_id"])

    def refresh_if_due(self, force: bool = False) -> Dict[str, object]:
        """Refresh threat data when the configured interval has elapsed."""
        interval_seconds = int(
            self.config.get("snapshots", {}).get("refresh_interval_seconds", 6 * 60 * 60)
        )
        last_refresh = self.state.get_agent_state("last_threat_refresh_at")
        if not force and last_refresh:
            last_refresh_dt = datetime.strptime(last_refresh, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            if (datetime.now(timezone.utc) - last_refresh_dt).total_seconds() < interval_seconds:
                return {
                    "success": True,
                    "skipped": True,
                    "message": "Threat data refresh interval has not elapsed",
                }

        snapshots_config = self.config.get("snapshots", {})
        snapshot_source = snapshots_config.get("channel_url") or snapshots_config.get("manifest_url")
        public_key_path = snapshots_config.get("public_key_path", "")
        if snapshot_source:
            result = self.apply_snapshot(snapshot_source, public_key_path=public_key_path)
        elif snapshots_config.get("use_live_collection_fallback", True):
            result = ensure_threat_data(
                force_update=True,
                include_experimental_sources=self.config.get("defaults", {}).get(
                    "include_experimental_sources",
                    False,
                ),
                allow_unverified_live_collection=True,
            )
        else:
            result = {
                "success": False,
                "message": "No snapshot source configured and live fallback disabled",
            }

        if not snapshot_source:
            self._record_refresh_result(result)
        return result

    def _prepare_staged_snapshot(self, manifest: Dict, manifest_source: str) -> Tuple[str, str]:
        """Download and validate one snapshot into a staged directory."""
        staged_dir = tempfile.mkdtemp(prefix="snapshot-stage-", dir=self.paths["snapshots"])
        final_stage_dir = os.path.join(staged_dir, "final-data")
        os.makedirs(final_stage_dir, exist_ok=True)

        for entry in manifest.get("files", []):
            entry_source = _resolve_entry_source(manifest_source, entry)
            destination = os.path.join(final_stage_dir, entry["filename"])
            with open(destination, "wb") as handle:
                handle.write(_read_bytes(entry_source))

            if sha256_file(destination) != entry["sha256"]:
                raise ValueError(f"Snapshot checksum mismatch for {entry['filename']}")
            if os.path.getsize(destination) != entry["size"]:
                raise ValueError(f"Snapshot size mismatch for {entry['filename']}")

        return staged_dir, final_stage_dir

    def _refresh_current_snapshot_metadata(
        self,
        manifest: Dict,
        channel_document: Optional[Dict] = None,
    ) -> None:
        """Refresh the monitor's current snapshot cache."""
        current_snapshot_dir = os.path.join(self.paths["snapshots"], "current")
        if os.path.exists(current_snapshot_dir):
            shutil.rmtree(current_snapshot_dir)
        shutil.copytree(self.final_data_dir, current_snapshot_dir)

        with open(os.path.join(current_snapshot_dir, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)

        if channel_document is not None:
            with open(
                os.path.join(current_snapshot_dir, "channel.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump(channel_document, handle, indent=2, sort_keys=True)

    def _promote_staged_directory(
        self,
        staged_final_dir: str,
        version: str,
        manifest: Dict,
        channel_document: Optional[Dict] = None,
    ) -> None:
        """
        Replace the live final-data directory with a staged snapshot and roll back on failure.
        """
        os.makedirs(os.path.dirname(self.final_data_dir), exist_ok=True)
        backup_archive_dir = os.path.join(self.paths["snapshots"], "backups", version)
        temp_swap_root = tempfile.mkdtemp(prefix="snapshot-swap-", dir=self.paths["snapshots"])
        temporary_backup_dir = os.path.join(temp_swap_root, "previous-final-data")
        had_existing = os.path.exists(self.final_data_dir)

        try:
            if had_existing:
                os.replace(self.final_data_dir, temporary_backup_dir)

            try:
                os.replace(staged_final_dir, self.final_data_dir)
            except Exception:
                if had_existing and os.path.exists(temporary_backup_dir) and not os.path.exists(self.final_data_dir):
                    os.replace(temporary_backup_dir, self.final_data_dir)
                raise

            if had_existing and os.path.exists(temporary_backup_dir):
                if os.path.exists(backup_archive_dir):
                    shutil.rmtree(backup_archive_dir)
                shutil.copytree(temporary_backup_dir, backup_archive_dir)

            self._refresh_current_snapshot_metadata(manifest, channel_document=channel_document)
        finally:
            shutil.rmtree(temp_swap_root, ignore_errors=True)

    def apply_snapshot(self, snapshot_source: str, public_key_path: str = "") -> Dict[str, object]:
        """Download, verify, and atomically apply a snapshot source."""
        try:
            manifest, manifest_source, channel_document = _resolve_channel_manifest(
                snapshot_source,
                public_key_path=public_key_path,
            )
        except Exception as exc:
            result = {"success": False, "message": str(exc)}
            self._record_refresh_result(result)
            return result

        try:
            staged_root, staged_final_dir = self._prepare_staged_snapshot(manifest, manifest_source)
            self._promote_staged_directory(
                staged_final_dir,
                manifest.get("version", datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")),
                manifest,
                channel_document=channel_document,
            )
        except Exception as exc:
            result = {"success": False, "message": f"Snapshot apply failed: {exc}"}
            self._record_refresh_result(result)
            return result
        finally:
            if "staged_root" in locals():
                shutil.rmtree(staged_root, ignore_errors=True)

        result = {
            "success": True,
            "version": manifest.get("version"),
            "key_id": manifest.get("key_id", ""),
            "message": "Snapshot applied successfully",
        }
        if channel_document:
            result["channel"] = channel_document.get("channel")
            result["channel_version"] = channel_document.get("current_version")
        self._record_refresh_result(result)
        return result
