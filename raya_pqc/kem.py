"""Hybrid Key Encapsulation: X25519 + ML-KEM-768 (NIST FIPS 203).

Security model: IND-CCA2 assuming at least one of X25519 or ML-KEM-768 is
secure. An attacker must break BOTH the classical and post-quantum components.
This matches the hybrid construction used by Google TLS (X25519MLKEM768) and
Cloudflare in 2025-2026.

Key / ciphertext sizes (bytes):
  public_key   = 32  (X25519)     + 1184 (ML-KEM-768) = 1216
  private_key  = 32  (X25519)     + 2400 (ML-KEM-768) = 2432
  ciphertext   = 32  (X25519-eph) + 1088 (ML-KEM-768) = 1120
  shared_secret = 32

Requires: pip install liboqs
"""
from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._backend import get_oqs
from .exceptions import RayaKeyFormatError, RayaDecryptionError

_KEM_ALG = "ML-KEM-768"
# KDF label binds ciphertext and ephemeral key to prevent cross-context attacks
_KEM_LABEL = b"RAYA-KEM-v2|ML-KEM-768+X25519"

X25519_PK_SZ = 32
X25519_SK_SZ = 32
MLKEM768_PK_SZ = 1184
MLKEM768_SK_SZ = 2400
MLKEM768_CT_SZ = 1088

PUBLIC_KEY_SIZE = X25519_PK_SZ + MLKEM768_PK_SZ    # 1216
PRIVATE_KEY_SIZE = X25519_SK_SZ + MLKEM768_SK_SZ   # 2432
CIPHERTEXT_SIZE = X25519_PK_SZ + MLKEM768_CT_SZ    # 1120


def keygen() -> Tuple[bytes, bytes]:
    """Generate a hybrid X25519 + ML-KEM-768 keypair.

    Returns:
        (public_key, private_key) as raw bytes.
        public_key  is 1216 bytes — safe to publish.
        private_key is 2432 bytes — keep secret, never commit.
    """
    oqs = get_oqs()

    x25519_sk = X25519PrivateKey.generate()
    x25519_pk_bytes = x25519_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    x25519_sk_bytes = x25519_sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

    with oqs.KeyEncapsulation(_KEM_ALG) as kem:
        mlkem_pk = kem.generate_keypair()
        mlkem_sk = kem.export_secret_key()

    _assert_mlkem_sizes(mlkem_pk, mlkem_sk)
    return x25519_pk_bytes + mlkem_pk, x25519_sk_bytes + mlkem_sk


def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Derive a shared secret and produce a ciphertext from a hybrid public key.

    Args:
        public_key: 1216-byte hybrid public key from keygen().

    Returns:
        (ciphertext, shared_secret)
        ciphertext    is 1120 bytes — send to the key holder.
        shared_secret is  32 bytes — use to derive an AES key; never transmit.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise RayaKeyFormatError(
            f"Expected {PUBLIC_KEY_SIZE}-byte hybrid public key, got {len(public_key)}"
        )

    oqs = get_oqs()
    x25519_pk_bytes = public_key[:X25519_PK_SZ]
    mlkem_pk_bytes = public_key[X25519_PK_SZ:]

    # Classical leg: fresh ephemeral X25519 key per encapsulation
    eph_sk = X25519PrivateKey.generate()
    eph_pk_bytes = eph_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ss_classical = eph_sk.exchange(X25519PublicKey.from_public_bytes(x25519_pk_bytes))

    # PQC leg: ML-KEM-768
    with oqs.KeyEncapsulation(_KEM_ALG) as kem:
        ct_pqc, ss_pqc = kem.encap_secret(mlkem_pk_bytes)

    ss = _combine(ss_classical, ss_pqc, eph_pk_bytes, ct_pqc)
    return eph_pk_bytes + ct_pqc, ss


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Recover the shared secret from a hybrid private key and ciphertext.

    Args:
        private_key: 2432-byte hybrid private key from keygen().
        ciphertext:  1120-byte ciphertext from encapsulate().

    Returns:
        shared_secret (32 bytes) — identical to what encapsulate() returned.
    """
    if len(private_key) != PRIVATE_KEY_SIZE:
        raise RayaKeyFormatError(
            f"Expected {PRIVATE_KEY_SIZE}-byte private key, got {len(private_key)}"
        )
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise RayaDecryptionError(
            f"Expected {CIPHERTEXT_SIZE}-byte ciphertext, got {len(ciphertext)}"
        )

    oqs = get_oqs()
    x25519_sk_bytes = private_key[:X25519_SK_SZ]
    mlkem_sk_bytes = private_key[X25519_SK_SZ:]
    eph_pk_bytes = ciphertext[:X25519_PK_SZ]
    ct_pqc = ciphertext[X25519_PK_SZ:]

    x25519_sk = X25519PrivateKey.from_private_bytes(x25519_sk_bytes)
    ss_classical = x25519_sk.exchange(X25519PublicKey.from_public_bytes(eph_pk_bytes))

    with oqs.KeyEncapsulation(_KEM_ALG, mlkem_sk_bytes) as kem:
        ss_pqc = kem.decap_secret(ct_pqc)

    return _combine(ss_classical, ss_pqc, eph_pk_bytes, ct_pqc)


def _combine(ss_classical: bytes, ss_pqc: bytes, eph_pk: bytes, ct_pqc: bytes) -> bytes:
    """Combine classical + PQC shared secrets via HKDF-SHA256.

    Binding eph_pk and ct_pqc in the info field prevents reuse attacks across
    different encapsulation contexts (per HPKE / hybrid-KEM best practice).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_KEM_LABEL + eph_pk + ct_pqc,
    )
    return hkdf.derive(ss_classical + ss_pqc)


def _assert_mlkem_sizes(pk: bytes, sk: bytes) -> None:
    if len(pk) != MLKEM768_PK_SZ or len(sk) != MLKEM768_SK_SZ:
        raise RayaKeyFormatError(
            f"liboqs returned unexpected ML-KEM-768 sizes: "
            f"pk={len(pk)} (expected {MLKEM768_PK_SZ}), "
            f"sk={len(sk)} (expected {MLKEM768_SK_SZ}). "
            "Update liboqs: pip install --upgrade liboqs"
        )
