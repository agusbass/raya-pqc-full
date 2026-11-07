"""Custom exception hierarchy for RAYA-PQC."""
from __future__ import annotations


class RayaError(Exception):
    """Base exception for all RAYA-PQC errors."""


class RayaBackendError(RayaError):
    """Required cryptographic backend (liboqs) is unavailable."""


class RayaKeyError(RayaError):
    """Base exception for key-related errors."""


class RayaKeyExpiredError(RayaKeyError):
    """Key has passed its configured expiry date."""


class RayaKeyFormatError(RayaKeyError):
    """Key data has an unexpected format, size, or version."""


class RayaKeyNotFoundError(RayaKeyError):
    """Required key file does not exist."""


class RayaVerificationError(RayaError):
    """Signature verification failed in a context where success was required."""


class RayaDecryptionError(RayaError):
    """Decryption failed (wrong key, corrupted blob, or wrong format)."""


class RayaManifestError(RayaError):
    """Manifest file is missing, unreadable, or structurally invalid."""


class RayaIntegrityError(RayaError):
    """File integrity check found tampered or missing files."""
