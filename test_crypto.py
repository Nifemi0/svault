"""Standalone round-trip test for svault crypto — no Hermes needed."""
import sys

from crypto import (
    decrypt_bytes,
    encrypt_bytes,
    generate_keypair,
    private_to_bytes,
    public_from_bytes,
)

plaintext = b"TOP SECRET: solPrivateKey 172 users\n"


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        sys.exit(1)


print("1. agent round-trip")
priv_a, pub_a = generate_keypair()
priv_b, pub_b = generate_keypair()
doc = encrypt_bytes(plaintext, file_name="db.json", agents=[("admin", pub_a)])
out = decrypt_bytes(doc, agent_name="admin", agent_priv=priv_a)
check("decrypt as correct agent -> identical", out == plaintext)

print("2. wrong agent is denied")
try:
    decrypt_bytes(doc, agent_name="admin", agent_priv=priv_b)
    check("wrong agent rejected", False)
except Exception as e:
    check(f"wrong agent rejected ({e})", True)

print("3. tamper detection (GCM auth)")
tampered = dict(doc)
c = bytearray(__import__("base64").b64decode(tampered["ciphertext"]))
c[0] ^= 0xFF
tampered["ciphertext"] = __import__("base64").b64encode(bytes(c)).decode()
try:
    decrypt_bytes(tampered, agent_name="admin", agent_priv=priv_a)
    check("tampered ciphertext rejected", False)
except Exception:
    check("tampered ciphertext rejected", True)

print("4. passphrase round-trip")
doc2 = encrypt_bytes(plaintext, file_name="db.json", passphrase="correct horse battery staple")
check("passphrase decrypt -> identical", decrypt_bytes(doc2, passphrase="correct horse battery staple") == plaintext)
try:
    decrypt_bytes(doc2, passphrase="wrong password")
    check("wrong passphrase rejected", False)
except Exception:
    check("wrong passphrase rejected", True)

print("5. metadata only in header (no plaintext leak)")
import json
s = json.dumps(doc)
check("plaintext NOT present in vault doc", b"solPrivateKey" not in s.encode())
check("ciphertext IS present", "ciphertext" in s)

print("\nALL CRYPTO TESTS PASSED")
