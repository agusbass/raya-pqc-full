# RAYA-PQC

**Post-Quantum Cryptography library for code protection.**  
Implements NIST FIPS 203 (ML-KEM-512) and FIPS 204 (ML-DSA-44) — pure Python, no native dependencies.

> ⚠️ **Note:** The underlying algorithms (ML-KEM, ML-DSA) are standardized by NIST.  
> RAYA-PQC is an independent Python implementation for code signing & secret encryption workflows.

---

## What it does

| Feature | Algorithm | Use case |
|---|---|---|
| **Sign** source files | ML-DSA-44 (FIPS 204) | Detect tampering, verify releases |
| **Encrypt** secrets | ML-KEM-512 + AES-256-GCM | Safely commit `.env` to GitHub |
| **Verify** integrity | ML-DSA-44 | GitHub Actions, CI/CD |

---

## Install

```bash
pip install cryptography   # only dependency
# clone this repo, then:
pip install -e .
```

---

## Quick Start (for your repo)

### 1. Initialize
```bash
python cli.py init myrepo/
```
Generates two keypairs. **Never commit `sk_*.bin`.**

### 2. Sign all source files
```bash
python cli.py sign myrepo/
```
Creates `.raya/MANIFEST.json` + `.raya/MANIFEST.sig` — commit both.

### 3. Encrypt secrets
```bash
python cli.py encrypt myrepo/ myrepo/.env
```
Creates `.env.raya` — safe to commit. Delete the original `.env`.

### 4. Verify anytime
```bash
python cli.py verify myrepo/
```

### 5. Decrypt (on your machine)
```bash
python cli.py decrypt myrepo/ myrepo/.env.raya
```

---

## GitHub Actions

Copy `.github/workflows/raya-verify.yml` to your repo.  
Every push/PR is automatically verified — tampered files block the merge.

---

## File structure after init

```
your-repo/
├── .raya/
│   ├── keys/
│   │   ├── pk_kem.bin   ← commit (public key, 800B)
│   │   ├── pk_dsa.bin   ← commit (public key, 1312B)
│   │   ├── sk_kem.bin   ← DO NOT COMMIT (in .gitignore)
│   │   └── sk_dsa.bin   ← DO NOT COMMIT (in .gitignore)
│   ├── MANIFEST.json    ← commit (file hashes)
│   └── MANIFEST.sig     ← commit (quantum-safe signature)
├── .env.raya            ← commit (encrypted secrets)
├── .gitignore           ← commit (blocks sk_*.bin and .env)
└── .github/
    └── workflows/
        └── raya-verify.yml  ← commit (auto-verify on push)
```

---

## Python API

```python
import sys
sys.path.insert(0, 'raya_pqc')
import raya

# Key generation
pk_kem, sk_kem = raya.kem_keygen()
pk_dsa, sk_dsa = raya.dsa_keygen()

# Sign & verify a file
sig = raya.sign_file(sk_dsa, "myfile.py")
ok  = raya.verify_file(pk_dsa, "myfile.py", sig)

# Encrypt & decrypt
raya.encrypt_file(pk_kem, ".env", ".env.raya")
raya.decrypt_file(sk_kem, ".env.raya", ".env")

# Full manifest (sign entire repo)
manifest, mbytes, sig = raya.build_manifest(".", sk_dsa)
ok, manifest, changed  = raya.verify_manifest(".", pk_dsa)
```

---

## Algorithms

| Component | Standard | Parameters |
|---|---|---|
| Key Encapsulation | NIST FIPS 203 ML-KEM-512 | n=256, q=3329, k=2 |
| Digital Signature | NIST FIPS 204 ML-DSA-44 | n=256, q=8380417, k=4, l=4 |
| Symmetric Encryption | AES-256-GCM | 256-bit key, 96-bit nonce |
| File Hashing | SHA3-256 | — |

---

## License

MIT — free to use, modify, distribute.  
NIST algorithms are public domain standards.
