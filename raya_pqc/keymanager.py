"""Key lifecycle management for RAYA-PQC.

Features:
  - JSON key files with metadata (key_id, algorithm, created_at, expires_at)
  - Environment-variable override for CI/CD (RAYA_KEM_PUBLIC_KEY etc.)
  - Key rotation with timestamped archive of old keys
  - Expiry enforcement on load
  - Explicit error when v0.1 (.bin) key format is detected

Key file layout:
  .raya/
  └── keys/
      ├── pk_kem.json        ← commit (1216-byte hybrid public key)
      ├── pk_dsa.json        ← commit (1984-byte hybrid public key)
      ├── sk_kem.json        ← DO NOT COMMIT
      ├── sk_dsa.json        ← DO NOT COMMIT
      └── archive/           ← rotated keys (keep for decrypting old blobs)
          └── sk_kem_20260602T120000Z.json

Environment variable override (CI/CD, Docker):
  RAYA_KEM_PUBLIC_KEY  — base64-encoded hybrid KEM public key
  RAYA_KEM_SECRET_KEY  — base64-encoded hybrid KEM private key
  RAYA_DSA_PUBLIC_KEY  — base64-encoded hybrid DSA public key
  RAYA_DSA_SECRET_KEY  — base64-encoded hybrid DSA private key
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from . import dsa as _dsa
from . import kem as _kem
from .exceptions import (
    RayaKeyExpiredError,
    RayaKeyFormatError,
    RayaKeyNotFoundError,
)

_KEY_VERSION = 2

_ALG_KEM = "HYBRID-ML-KEM-768-X25519"
_ALG_DSA = "HYBRID-ML-DSA-65-Ed25519"

_ENV_VARS: dict[str, str] = {
    "pk_kem.json": "RAYA_KEM_PUBLIC_KEY",
    "sk_kem.json": "RAYA_KEM_SECRET_KEY",
    "pk_dsa.json": "RAYA_DSA_PUBLIC_KEY",
    "sk_dsa.json": "RAYA_DSA_SECRET_KEY",
}


class KeyManager:
    """Manage RAYA-PQC keypairs for a repository.

    Args:
        key_dir: Path to the key directory (default: ``.raya/keys``).
    """

    def __init__(self, key_dir: str | Path = ".raya/keys") -> None:
        self.key_dir = Path(key_dir)

    # ── Generation ────────────────────────────────────────────────────────────

    def generate_kem(self, expires_in_days: Optional[int] = None) -> Tuple[bytes, bytes]:
        """Generate and persist a new hybrid KEM keypair.

        Args:
            expires_in_days: Optional key expiry. None means no expiry.

        Returns:
            (public_key, private_key) bytes.
        """
        pk, sk = _kem.keygen()
        self._save("pk_kem.json", pk, "kem_public", _ALG_KEM, expires_in_days)
        self._save("sk_kem.json", sk, "kem_private", _ALG_KEM, expires_in_days)
        return pk, sk

    def generate_dsa(self, expires_in_days: Optional[int] = None) -> Tuple[bytes, bytes]:
        """Generate and persist a new hybrid DSA keypair.

        Args:
            expires_in_days: Optional key expiry. None means no expiry.

        Returns:
            (public_key, private_key) bytes.
        """
        pk, sk = _dsa.keygen()
        self._save("pk_dsa.json", pk, "dsa_public", _ALG_DSA, expires_in_days)
        self._save("sk_dsa.json", sk, "dsa_private", _ALG_DSA, expires_in_days)
        return pk, sk

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_kem_public(self) -> bytes:
        """Load hybrid KEM public key. Checks env var RAYA_KEM_PUBLIC_KEY first."""
        return self._load("pk_kem.json")

    def load_kem_private(self) -> bytes:
        """Load hybrid KEM private key. Checks env var RAYA_KEM_SECRET_KEY first."""
        return self._load("sk_kem.json")

    def load_dsa_public(self) -> bytes:
        """Load hybrid DSA public key. Checks env var RAYA_DSA_PUBLIC_KEY first."""
        return self._load("pk_dsa.json")

    def load_dsa_private(self) -> bytes:
        """Load hybrid DSA private key. Checks env var RAYA_DSA_SECRET_KEY first."""
        return self._load("sk_dsa.json")

    # ── Rotation ──────────────────────────────────────────────────────────────

    def rotate_kem(self, expires_in_days: Optional[int] = None) -> Tuple[bytes, bytes]:
        """Archive the current KEM keypair and generate a fresh one.

        The old private key is preserved in ``archive/`` so you can still
        decrypt files that were encrypted with the old public key.

        Returns:
            (new_public_key, new_private_key) bytes.
        """
        self._archive("pk_kem.json")
        self._archive("sk_kem.json")
        return self.generate_kem(expires_in_days)

    def rotate_dsa(self, expires_in_days: Optional[int] = None) -> Tuple[bytes, bytes]:
        """Archive the current DSA keypair and generate a fresh one.

        Returns:
            (new_public_key, new_private_key) bytes.
        """
        self._archive("pk_dsa.json")
        self._archive("sk_dsa.json")
        return self.generate_dsa(expires_in_days)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def write_gitignore(self) -> None:
        """Write .raya/.gitignore that blocks private keys from git."""
        gitignore = self.key_dir.parent / ".gitignore"
        gitignore.write_text(
            "# RAYA-PQC private keys — NEVER commit\n"
            "keys/sk_*.json\n"
            "keys/archive/sk_*.json\n",
            encoding="utf-8",
        )

    # ── Private ───────────────────────────────────────────────────────────────

    def _save(
        self,
        filename: str,
        key_data: bytes,
        key_type: str,
        algorithm: str,
        expires_in_days: Optional[int],
    ) -> None:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        expires_at: Optional[str] = None
        if expires_in_days is not None:
            expires_at = (now + timedelta(days=expires_in_days)).isoformat()
        record = {
            "raya_key_version": _KEY_VERSION,
            "key_id": str(uuid.uuid4()),
            "algorithm": algorithm,
            "key_type": key_type,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "key_data": base64.b64encode(key_data).decode(),
        }
        (self.key_dir / filename).write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )

    def _load(self, filename: str) -> bytes:
        # CI/CD: env var takes precedence over files
        env_var = _ENV_VARS.get(filename)
        if env_var:
            val = os.environ.get(env_var)
            if val:
                try:
                    return base64.b64decode(val)
                except Exception as exc:
                    raise RayaKeyFormatError(
                        f"Environment variable {env_var} is not valid base64"
                    ) from exc

        path = self.key_dir / filename

        if not path.exists():
            # Detect old v0.1 binary format and give a helpful error
            old_path = self.key_dir / filename.replace(".json", ".bin")
            if old_path.exists():
                raise RayaKeyFormatError(
                    f"Old v0.1 key format detected at '{old_path}'. "
                    "Re-initialize with: raya-pqc init <repo>"
                )
            raise RayaKeyNotFoundError(
                f"Key file not found: '{path}'. "
                "Run: raya-pqc init <repo>"
            )

        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RayaKeyFormatError(f"Key file '{path}' is not valid JSON") from exc

        version = record.get("raya_key_version")
        if version != _KEY_VERSION:
            raise RayaKeyFormatError(
                f"Unsupported key format version {version!r} in '{path}'. "
                "Re-initialize: raya-pqc init <repo>"
            )

        expires_at = record.get("expires_at")
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at)
            except ValueError as exc:
                raise RayaKeyFormatError(
                    f"Invalid expires_at value in '{path}': {expires_at!r}"
                ) from exc
            if datetime.now(timezone.utc) > expiry:
                raise RayaKeyExpiredError(
                    f"Key '{filename}' expired at {expires_at}. "
                    "Rotate with: raya-pqc rotate <repo>"
                )

        try:
            return base64.b64decode(record["key_data"])
        except (KeyError, Exception) as exc:
            raise RayaKeyFormatError(
                f"Key file '{path}' has missing or invalid key_data"
            ) from exc

    def _archive(self, filename: str) -> None:
        path = self.key_dir / filename
        if not path.exists():
            return
        archive_dir = self.key_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = filename.replace(".json", "")
        path.rename(archive_dir / f"{stem}_{ts}.json")
