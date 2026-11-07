#!/usr/bin/env python3
"""
RAYA-PQC CLI — Post-Quantum Code Protection
Usage: python cli.py <command> <repo_path> [file]
"""
import sys, json, time
from pathlib import Path

# Support both: python cli.py (from repo root) or pip install
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "raya_pqc"))
import raya

def cmd_init(repo_path):
    print(f"  Generating ML-KEM-512 keypair...")
    t = time.time()
    pk_kem, sk_kem = raya.kem_keygen()
    print(f"  Generating ML-DSA-44 keypair...")
    pk_dsa, sk_dsa = raya.dsa_keygen()
    key_dir = str(Path(repo_path) / ".raya" / "keys")
    raya.save_keys(pk_kem, sk_kem, pk_dsa, sk_dsa, key_dir)
    print(f"\n  ✓ Done in {time.time()-t:.1f}s")
    print(f"\n  COMMIT these (public keys):")
    print(f"    .raya/keys/pk_kem.bin  ({len(pk_kem)}B)")
    print(f"    .raya/keys/pk_dsa.bin  ({len(pk_dsa)}B)")
    print(f"\n  DO NOT COMMIT (already in .gitignore):")
    print(f"    .raya/keys/sk_kem.bin  ({len(sk_kem)}B)")
    print(f"    .raya/keys/sk_dsa.bin  ({len(sk_dsa)}B)")

def cmd_sign(repo_path):
    key_dir = str(Path(repo_path) / ".raya" / "keys")
    _, sk_dsa = raya.load_sk(key_dir)
    print(f"  Signing source files in '{repo_path}'...")
    t = time.time()
    manifest, mbytes, sig = raya.build_manifest(repo_path, sk_dsa)
    md = Path(repo_path) / ".raya"
    (md / "MANIFEST.json").write_bytes(mbytes)
    (md / "MANIFEST.sig").write_bytes(sig)
    n = len(manifest["files"])
    print(f"  ✓ {n} files signed in {time.time()-t:.1f}s")
    for f, h in manifest["files"].items():
        print(f"    {h[:16]}...  {f}")

def cmd_verify(repo_path):
    key_dir = str(Path(repo_path) / ".raya" / "keys")
    pk_kem, pk_dsa = raya.load_pk(key_dir)
    print(f"  Verifying '{repo_path}'...")
    t = time.time()
    ok, manifest, changed = raya.verify_manifest(repo_path, pk_dsa)
    if ok:
        n = len(manifest["files"])
        print(f"  ✓ ALL CLEAR — {n} files intact ({time.time()-t:.2f}s)")
        print(f"  Signed: {manifest.get('timestamp','?')}")
    else:
        if isinstance(manifest, str):
            print(f"  ✗ {manifest}")
        else:
            print(f"  ✗ INTEGRITY VIOLATION ({len(changed)} file(s) affected):")
            for f, status in changed.items():
                print(f"    {status}: {f}")
        sys.exit(1)

def cmd_encrypt(repo_path, file_path):
    key_dir = str(Path(repo_path) / ".raya" / "keys")
    pk_kem, _ = raya.load_pk(key_dir)
    print(f"  Encrypting {file_path}...")
    t = time.time()
    dst = raya.encrypt_file(pk_kem, file_path)
    orig = Path(file_path).stat().st_size
    enc  = dst.stat().st_size
    print(f"  ✓ {Path(file_path).name} ({orig}B) → {dst.name} ({enc}B)  [{time.time()-t:.2f}s]")
    print(f"  ✓ Safe to commit: {dst}")
    print(f"  ✗ Add to .gitignore: {file_path}")

def cmd_decrypt(repo_path, file_path):
    key_dir = str(Path(repo_path) / ".raya" / "keys")
    sk_kem, _ = raya.load_sk(key_dir)
    print(f"  Decrypting {file_path}...")
    t = time.time()
    dst = raya.decrypt_file(sk_kem, file_path)
    print(f"  ✓ → {dst}  [{time.time()-t:.2f}s]")

def cmd_status(repo_path):
    md = Path(repo_path) / ".raya"
    has_pk  = (md / "keys" / "pk_dsa.bin").exists()
    has_sk  = (md / "keys" / "sk_dsa.bin").exists()
    has_mf  = (md / "MANIFEST.json").exists()
    has_sig = (md / "MANIFEST.sig").exists()
    print(f"  Keys (public) : {'✓' if has_pk  else '✗  → run: init'}")
    print(f"  Keys (private): {'✓ present (DO NOT COMMIT)' if has_sk else '✗ missing'}")
    print(f"  Manifest      : {'✓' if has_mf  else '✗  → run: sign'}")
    print(f"  Signature     : {'✓' if has_sig else '✗  → run: sign'}")
    if has_mf:
        m = json.loads((md / "MANIFEST.json").read_bytes())
        print(f"  Files signed  : {len(m['files'])}")
        print(f"  Last signed   : {m.get('timestamp', '?')}")
    encrypted = list(Path(repo_path).rglob("*.raya"))
    if encrypted:
        print(f"  Encrypted     : {len(encrypted)} file(s)")
        for f in encrypted:
            print(f"    {f.relative_to(repo_path)}")

HELP = """
RAYA-PQC v0.1.0 — Post-Quantum Code Protection
Algorithms: ML-KEM-512 (FIPS 203) + ML-DSA-44 (FIPS 204)

Usage:
  python cli.py init    <repo>          Generate keypair
  python cli.py sign    <repo>          Sign all source files
  python cli.py verify  <repo>          Verify integrity
  python cli.py encrypt <repo> <file>   Encrypt a secret file
  python cli.py decrypt <repo> <file>   Decrypt an encrypted file
  python cli.py status  <repo>          Show protection status

Examples:
  python cli.py init    ./bcms
  python cli.py sign    ./bcms
  python cli.py encrypt ./bcms ./bcms/.env
  python cli.py verify  ./bcms
"""

def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help', 'help'):
        print(HELP)
        return
    cmd  = args[0]
    repo = args[1] if len(args) > 1 else "."
    print(f"\nRAYA-PQC — {cmd.upper()}")
    print("─" * 44)
    if   cmd == "init":    cmd_init(repo)
    elif cmd == "sign":    cmd_sign(repo)
    elif cmd == "verify":  cmd_verify(repo)
    elif cmd == "status":  cmd_status(repo)
    elif cmd == "encrypt":
        if len(args) < 3: print("  Usage: encrypt <repo> <file>"); return
        cmd_encrypt(repo, args[2])
    elif cmd == "decrypt":
        if len(args) < 3: print("  Usage: decrypt <repo> <file>"); return
        cmd_decrypt(repo, args[2])
    else:
        print(f"  Unknown command: {cmd}"); print(HELP)
    print()

if __name__ == "__main__":
    main()
