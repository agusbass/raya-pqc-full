"""
RAYA-PQC — Code Protection for BCMS
Implements: Sign + Verify (ML-DSA-44) | Encrypt + Decrypt (ML-KEM-512 + AES-256-GCM)
"""
import os, sys, json, hashlib, base64, struct
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0, str(Path(__file__).parent))
import kyber, dilithium
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RAYA_VERSION = "0.1.0"
RAYA_MAGIC   = b"RAYA-PQC-v01"

# ── Key Management ───────────────────────────────────────────────
def kem_keygen():
    return kyber.keygen()

def dsa_keygen():
    return dilithium.keygen()

def save_keys(pk_kem, sk_kem, pk_dsa, sk_dsa, key_dir=".raya/keys"):
    d = Path(key_dir); d.mkdir(parents=True, exist_ok=True)
    (d/"pk_kem.bin").write_bytes(pk_kem)
    (d/"pk_dsa.bin").write_bytes(pk_dsa)
    (d/"sk_kem.bin").write_bytes(sk_kem)   # NEVER commit this
    (d/"sk_dsa.bin").write_bytes(sk_dsa)   # NEVER commit this
    gitignore = Path(".raya")/"keys"/".."/".gitignore"
    gitignore.parent.mkdir(parents=True, exist_ok=True)
    gitignore.write_text("# RAYA-PQC — private keys NEVER committed\nsk_*.bin\n")
    return d

def load_pk(key_dir=".raya/keys"):
    d = Path(key_dir)
    return (d/"pk_kem.bin").read_bytes(), (d/"pk_dsa.bin").read_bytes()

def load_sk(key_dir=".raya/keys"):
    d = Path(key_dir)
    return (d/"sk_kem.bin").read_bytes(), (d/"sk_dsa.bin").read_bytes()

# ── Signing ───────────────────────────────────────────────────────
def sign_bytes(sk_dsa, data: bytes) -> bytes:
    return dilithium.sign(sk_dsa, data)

def verify_bytes(pk_dsa, data: bytes, sig: bytes) -> bool:
    return dilithium.verify(pk_dsa, data, sig)

def file_hash(path) -> bytes:
    h = hashlib.sha3_256()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.digest()

def sign_file(sk_dsa, path) -> bytes:
    digest = file_hash(path)
    sig    = sign_bytes(sk_dsa, digest)
    return RAYA_MAGIC + struct.pack('>I', len(sig)) + sig

def verify_file(pk_dsa, path, sig_bytes: bytes) -> bool:
    if not sig_bytes.startswith(RAYA_MAGIC): return False
    sig_len = struct.unpack('>I', sig_bytes[12:16])[0]
    sig     = sig_bytes[16:16+sig_len]
    digest  = file_hash(path)
    return verify_bytes(pk_dsa, digest, sig)

# ── Encryption ────────────────────────────────────────────────────
def encrypt_bytes(pk_kem, plaintext: bytes) -> bytes:
    ct_kem, ss = kyber.encaps(pk_kem)      # 32-byte shared secret
    nonce = os.urandom(12)
    aes   = AESGCM(ss)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    # Format: MAGIC | kem_ct_len | kem_ct | nonce | ciphertext
    return (RAYA_MAGIC +
            struct.pack('>I', len(ct_kem)) + ct_kem +
            nonce + ciphertext)

def decrypt_bytes(sk_kem, blob: bytes) -> bytes:
    if not blob.startswith(RAYA_MAGIC): raise ValueError("Not a RAYA-PQC blob")
    off    = 12
    ct_len = struct.unpack('>I', blob[off:off+4])[0]; off+=4
    ct_kem = blob[off:off+ct_len]; off+=ct_len
    nonce  = blob[off:off+12];     off+=12
    ciphertext = blob[off:]
    ss = kyber.decaps(sk_kem, ct_kem)
    return AESGCM(ss).decrypt(nonce, ciphertext, None)

def encrypt_file(pk_kem, src_path, dst_path=None):
    src = Path(src_path)
    dst = Path(dst_path or str(src)+".raya")
    blob = encrypt_bytes(pk_kem, src.read_bytes())
    dst.write_bytes(blob)
    return dst

def decrypt_file(sk_kem, src_path, dst_path=None):
    src = Path(src_path)
    dst = Path(dst_path or str(src).removesuffix(".raya"))
    plain = decrypt_bytes(sk_kem, src.read_bytes())
    dst.write_bytes(plain)
    return dst

# ── Manifest (sign all project files) ────────────────────────────
SIGN_EXTS = {'.py','.js','.ts','.jsx','.tsx','.go','.rs',
             '.java','.c','.cpp','.h','.json','.yaml','.yml',
             '.toml','.md','.sh','.env.example'}

def build_manifest(root, sk_dsa, exclude=None):
    root  = Path(root)
    excl  = set(exclude or ['.raya','node_modules','__pycache__','.git','*.raya'])
    files = {}
    for p in sorted(root.rglob('*')):
        if p.is_dir(): continue
        rel = p.relative_to(root)
        parts = rel.parts
        if any(e.lstrip('*') in str(parts) or
               any(p.match(e) for e in excl) for e in excl): continue
        if p.suffix.lower() not in SIGN_EXTS: continue
        h = file_hash(p).hex()
        files[str(rel)] = h
    manifest = {
        "version":   RAYA_VERSION,
        "repo":      root.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files":     files
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    sig = sign_bytes(sk_dsa, manifest_bytes)
    return manifest, manifest_bytes, sig

def verify_manifest(root, pk_dsa, manifest_dir=".raya"):
    root = Path(root); md = root/manifest_dir
    manifest_bytes = (md/"MANIFEST.json").read_bytes()
    sig            = (md/"MANIFEST.sig").read_bytes()
    if not verify_bytes(pk_dsa, manifest_bytes, sig):
        return False, "❌ Signature invalid — manifest tampered!", {}
    manifest = json.loads(manifest_bytes)
    changed  = {}
    for rel, expected_hash in manifest["files"].items():
        actual_path = root/rel
        if not actual_path.exists():
            changed[rel] = "MISSING"
        else:
            actual = file_hash(actual_path).hex()
            if actual != expected_hash:
                changed[rel] = "MODIFIED"
    return len(changed)==0, manifest, changed
