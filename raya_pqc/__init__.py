"""
RAYA-PQC — Post-Quantum Cryptography Library
Implements NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), designed for code protection.

Usage:
    from raya_pqc import raya
    pk_kem, sk_kem = raya.kem_keygen()
    pk_dsa, sk_dsa = raya.dsa_keygen()
"""
__version__ = "0.1.0"
__author__  = "RAYA-PQC Contributors"
__license__ = "MIT"
