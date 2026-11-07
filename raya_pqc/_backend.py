"""Backend detection for RAYA-PQC.

Production backend : liboqs — constant-time C implementations of ML-KEM / ML-DSA.
Without liboqs     : RayaBackendError is raised for any crypto operation.

Install: pip install liboqs
Docs   : https://github.com/open-quantum-safe/liboqs-python
"""
from __future__ import annotations

from .exceptions import RayaBackendError

try:
    import oqs as _oqs_module  # type: ignore[import-untyped]
    _OQS_AVAILABLE = True
except ImportError:
    _oqs_module = None  # type: ignore[assignment]
    _OQS_AVAILABLE = False

_BACKEND_ERROR_MSG = (
    "liboqs is required for production use.\n"
    "  Install : pip install liboqs\n"
    "  Docs    : https://github.com/open-quantum-safe/liboqs-python"
)


def is_liboqs_available() -> bool:
    """Return True if liboqs is installed and importable."""
    return _OQS_AVAILABLE


def get_oqs():  # type: ignore[return]
    """Return the oqs module, or raise RayaBackendError if not installed."""
    if not _OQS_AVAILABLE:
        raise RayaBackendError(_BACKEND_ERROR_MSG)
    return _oqs_module
