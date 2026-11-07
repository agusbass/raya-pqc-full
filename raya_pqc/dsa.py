"""Hybrid Digital Signature: Ed25519 + ML-DSA-65 (NIST FIPS 204).

Security model: secure if at least one of Ed25519 or ML-DSA-65 is secure.
Both signatures must be valid for verification to succeed. Follows the
"dual-signature" hybrid construction used by Signal (PQXDH) and OpenSSH.

Key / signature sizes (bytes):
  public_key  = 32   (Ed25519) + 1952 (ML-DSA-65) = 1984
  private_key = 32   (Ed25519) + 4032 (ML-DSA-65) = 4064
  signature   = 64   (Ed25519) + 3309 (ML-DSA-65) = 3373  (fixed)

Requires: pip install liboqs
"""
from __future__ import annotations

from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from ._backend import get_oqs
from .exceptions import RayaKeyFormatError

_DSA_ALG = "ML-DSA-65"

ED25519_PK_SZ = 32
ED25519_SK_SZ = 32
ED25519_SIG_SZ = 64
MLDSA65_PK_SZ = 1952
MLDSA65_SK_SZ = 4032
MLDSA65_SIG_SZ = 3309

PUBLIC_KEY_SIZE = ED25519_PK_SZ + MLDSA65_PK_SZ    # 1984
PRIVATE_KEY_SIZE = ED25519_SK_SZ + MLDSA65_SK_SZ   # 4064
SIGNATURE_SIZE = ED25519_SIG_SZ + MLDSA65_SIG_SZ   # 3373


def keygen() -> Tuple[bytes, bytes]:
    """Generate a hybrid Ed25519 + ML-DSA-65 keypair.

    Returns:
        (public_key, private_key) as raw bytes.
        public_key  is 1984 bytes — safe to publish / commit.
        private_key is 4064 bytes — keep secret, never commit.
    """
    oqs = get_oqs()

    ed_sk = Ed25519PrivateKey.generate()
    ed_pk_bytes = ed_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ed_sk_bytes = ed_sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

    with oqs.Signature(_DSA_ALG) as dsa:
        mldsa_pk = dsa.generate_keypair()
        mldsa_sk = dsa.export_secret_key()

    _assert_mldsa_key_sizes(mldsa_pk, mldsa_sk)
    return ed_pk_bytes + mldsa_pk, ed_sk_bytes + mldsa_sk


def sign(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with the hybrid private key.

    Args:
        private_key: 4064-byte hybrid private key from keygen().
        message:     Arbitrary bytes to sign.

    Returns:
        3373-byte hybrid signature (Ed25519 || ML-DSA-65, fixed size).
    """
    if len(private_key) != PRIVATE_KEY_SIZE:
        raise RayaKeyFormatError(
            f"Expected {PRIVATE_KEY_SIZE}-byte private key, got {len(private_key)}"
        )

    oqs = get_oqs()
    ed_sk_bytes = private_key[:ED25519_SK_SZ]
    mldsa_sk_bytes = private_key[ED25519_SK_SZ:]

    ed_sig = Ed25519PrivateKey.from_private_bytes(ed_sk_bytes).sign(message)

    with oqs.Signature(_DSA_ALG, mldsa_sk_bytes) as dsa:
        mldsa_sig = dsa.sign(message)

    _assert_mldsa_sig_size(mldsa_sig)
    return ed_sig + mldsa_sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a hybrid signature. Both Ed25519 and ML-DSA-65 must be valid.

    Args:
        public_key: 1984-byte hybrid public key.
        message:    The original message bytes.
        signature:  3373-byte hybrid signature.

    Returns:
        True if both component signatures are valid, False otherwise.
        Never raises on verification failure — only on malformed key input.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise RayaKeyFormatError(
            f"Expected {PUBLIC_KEY_SIZE}-byte public key, got {len(public_key)}"
        )
    if len(signature) != SIGNATURE_SIZE:
        return False

    oqs = get_oqs()
    ed_pk_bytes = public_key[:ED25519_PK_SZ]
    mldsa_pk_bytes = public_key[ED25519_PK_SZ:]
    ed_sig = signature[:ED25519_SIG_SZ]
    mldsa_sig = signature[ED25519_SIG_SZ:]

    try:
        Ed25519PublicKey.from_public_bytes(ed_pk_bytes).verify(ed_sig, message)
    except InvalidSignature:
        return False

    try:
        with oqs.Signature(_DSA_ALG) as verifier:
            return bool(verifier.verify(message, mldsa_sig, mldsa_pk_bytes))
    except Exception:
        return False


def _assert_mldsa_key_sizes(pk: bytes, sk: bytes) -> None:
    if len(pk) != MLDSA65_PK_SZ or len(sk) != MLDSA65_SK_SZ:
        raise RayaKeyFormatError(
            f"liboqs returned unexpected ML-DSA-65 sizes: "
            f"pk={len(pk)} (expected {MLDSA65_PK_SZ}), "
            f"sk={len(sk)} (expected {MLDSA65_SK_SZ}). "
            "Update liboqs: pip install --upgrade liboqs"
        )


def _assert_mldsa_sig_size(sig: bytes) -> None:
    if len(sig) != MLDSA65_SIG_SZ:
        raise RayaKeyFormatError(
            f"liboqs returned ML-DSA-65 signature of {len(sig)} bytes, "
            f"expected {MLDSA65_SIG_SZ}. Update liboqs."
        )
