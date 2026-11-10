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

print("6. header is authenticated (format v2)")
check("new documents are v2", doc["version"] == 2)
for key, value in (("file", "other.json"), ("created", doc["created"] + 1)):
    forged = dict(doc)
    forged[key] = value
    try:
        decrypt_bytes(forged, agent_name="admin", agent_priv=priv_a)
        check(f"edited '{key}' rejected", False)
    except Exception:
        check(f"edited '{key}' rejected", True)
forged = json.loads(json.dumps(doc))
forged["recipients"].append({"type": "agent", "agent": "mallory", "epk": "", "nonce": "", "wrapped_dek": ""})
try:
    decrypt_bytes(forged, agent_name="admin", agent_priv=priv_a)
    check("added recipient rejected", False)
except Exception:
    check("added recipient rejected", True)
try:
    decrypt_bytes(dict(doc, version=99), agent_name="admin", agent_priv=priv_a)
    check("unknown version rejected", False)
except ValueError:
    check("unknown version rejected", True)

print("7. v1 documents (no AAD, scrypt n=2^14) still decrypt")
import crypto as c

dek = c.random(32)
epk, wn, wrapped = c.wrap_dek_for_agent(dek, pub_a)
salt = c.random(16)
pn, pwrapped = c._seal(c.scrypt_key("old pass", salt, 2**14, 8, 1), dek)
bn, body = c._seal(dek, plaintext)
v1 = {
    "magic": "SVAULT", "version": 1, "file": "db.json", "created": 1,
    "recipients": [
        {"type": "agent", "agent": "admin", "epk": c.b64e(epk), "nonce": c.b64e(wn), "wrapped_dek": c.b64e(wrapped)},
        {"type": "passphrase", "salt": c.b64e(salt), "n": 2**14, "r": 8, "p": 1, "nonce": c.b64e(pn), "wrapped_dek": c.b64e(pwrapped)},
    ],
    "nonce": c.b64e(bn), "ciphertext": c.b64e(body),
}
check("v1 agent decrypt", decrypt_bytes(v1, agent_name="admin", agent_priv=priv_a) == plaintext)
check("v1 passphrase decrypt", decrypt_bytes(v1, passphrase="old pass") == plaintext)
check("stored scrypt parameters are recorded", doc2["recipients"][0]["n"] == c.SCRYPT_N)
huge = json.loads(json.dumps(doc2))
huge["recipients"][0]["n"] = 2**30
try:
    decrypt_bytes(huge, passphrase="correct horse battery staple")
    check("absurd scrypt cost rejected", False)
except ValueError:
    check("absurd scrypt cost rejected", True)

print("\nALL CRYPTO TESTS PASSED")
