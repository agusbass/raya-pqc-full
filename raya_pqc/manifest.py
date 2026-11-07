"""File manifest: sign and verify the integrity of a repository tree.

Builds a JSON manifest of SHA3-256 hashes for all tracked source files,
then signs the manifest bytes with the hybrid DSA key. The manifest and
its detached signature are stored in ``.raya/`` and are safe to commit.

Manifest format v2:
  {
    "raya_manifest_version": 2,
    "repo": "<dirname>",
    "timestamp": "<ISO-8601>",
    "hash_algorithm": "sha3-256",
    "files": { "<rel-path>": "<hex-digest>", ... }
  }
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from . import dsa as _dsa
from .exceptions import RayaManifestError

_MANIFEST_VERSION = 2

SIGN_EXTS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".java", ".c", ".cpp", ".h",
    ".json", ".yaml", ".yml", ".toml",
    ".md", ".sh", ".env.example",
}

_DEFAULT_EXCLUDE: Set[str] = {
    ".raya", "node_modules", "__pycache__", ".git",
    ".venv", "venv", ".mypy_cache", ".ruff_cache",
    "*.raya",
}


def sha3_256_file(path: Path) -> str:
    """Return the lowercase hex SHA3-256 digest of a file."""
    h = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build(
    root: Path,
    sk_dsa: bytes,
    exclude: Optional[Set[str]] = None,
) -> Tuple[dict, bytes, bytes]:
    """Hash all tracked source files and sign the manifest.

    Args:
        root:    Repository root directory.
        sk_dsa:  4064-byte hybrid DSA private key.
        exclude: Additional glob patterns / directory names to exclude.

    Returns:
        (manifest_dict, manifest_bytes, signature)
        Caller should write manifest_bytes → ``.raya/MANIFEST.json``
        and signature → ``.raya/MANIFEST.sig``.
    """
    excl = _DEFAULT_EXCLUDE | (exclude or set())
    files: Dict[str, str] = {}

    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(root)
        rel_str = str(rel)

        # Skip if any path component matches an exclude pattern
        if _should_exclude(p, rel_str, excl):
            continue
        if p.suffix.lower() not in SIGN_EXTS:
            continue

        files[rel_str.replace("\\", "/")] = sha3_256_file(p)

    manifest: dict = {
        "raya_manifest_version": _MANIFEST_VERSION,
        "repo": root.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "sha3-256",
        "files": files,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    signature = _dsa.sign(sk_dsa, manifest_bytes)
    return manifest, manifest_bytes, signature


def verify(
    root: Path,
    pk_dsa: bytes,
    manifest_dir: str = ".raya",
) -> Tuple[bool, dict | str, dict]:
    """Verify the manifest signature and check every listed file.

    Args:
        root:         Repository root directory.
        pk_dsa:       1984-byte hybrid DSA public key.
        manifest_dir: Subdirectory where MANIFEST.json / MANIFEST.sig live.

    Returns:
        (ok, manifest_or_error_string, changed_files)
        ok is True only when the signature is valid AND no files are
        missing or modified. changed_files maps path → "MODIFIED" | "MISSING".

    Raises:
        RayaManifestError: If the manifest or signature file does not exist.
    """
    md = root / manifest_dir
    manifest_path = md / "MANIFEST.json"
    sig_path = md / "MANIFEST.sig"

    if not manifest_path.exists():
        raise RayaManifestError(
            f"Manifest not found: '{manifest_path}'. "
            "Run: raya-pqc sign <repo>"
        )
    if not sig_path.exists():
        raise RayaManifestError(
            f"Signature not found: '{sig_path}'. "
            "Run: raya-pqc sign <repo>"
        )

    manifest_bytes = manifest_path.read_bytes()
    signature = sig_path.read_bytes()

    if not _dsa.verify(pk_dsa, manifest_bytes, signature):
        return False, "Signature invalid — manifest may have been tampered with", {}

    manifest: dict = json.loads(manifest_bytes)
    changed: Dict[str, str] = {}

    for rel, expected_hash in manifest.get("files", {}).items():
        actual_path = root / rel
        if not actual_path.exists():
            changed[rel] = "MISSING"
        else:
            if sha3_256_file(actual_path) != expected_hash:
                changed[rel] = "MODIFIED"

    return len(changed) == 0, manifest, changed


def _should_exclude(p: Path, rel_str: str, excl: Set[str]) -> bool:
    for pattern in excl:
        if pattern.startswith("*"):
            if p.match(pattern):
                return True
        else:
            # Match any path component exactly
            if pattern in rel_str.replace("\\", "/").split("/"):
                return True
    return False
