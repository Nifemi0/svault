"""Standalone test for svault field-level database protection — no Hermes needed."""
import json
import sys

from crypto import generate_keypair
import db

# Build a sample database like a custodial bot's key store
database = {
    "504006010": {"username": "bill", "solAddress": "addr1", "solPrivateKey": "SECRETKEY_AAA"},
    "564622369": {"username": "hrvojelee", "solAddress": "addr2", "solPrivateKey": "SECRETKEY_BBB"},
    "8107156898": {"username": "chris", "ethPrivateKey": "0xSECRET_ETH"},
}

priv, pub = generate_keypair()
agents = [("admin", pub)]


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        sys.exit(1)


print("1. protect encrypts named fields in place")
n = db.protect(database, {"solPrivateKey", "ethPrivateKey"}, agents)
check("3 values encrypted", n == 3)
check("solPrivateKey is now a marker", "__svault_enc__" in database["504006010"]["solPrivateKey"])
check("plaintext key is gone", "SECRETKEY_AAA" not in json.dumps(database))
check("non-sensitive field untouched", database["504006010"]["username"] == "bill")

print("2. redact hides encrypted values but keeps structure")
redacted = db.redact(database)
check("marker redacted", redacted["504006010"]["solPrivateKey"] == {"__svault_enc__": db.REDACTED})
check("username still readable", redacted["504006010"]["username"] == "bill")
check("redacted has no plaintext", "SECRETKEY_AAA" not in json.dumps(redacted))

print("3. reveal recovers a single value with the right key")
val = db.reveal(database, "504006010", "solPrivateKey", "admin", priv)
check("revealed value correct", val == "SECRETKEY_AAA")

print("4. wrong key is rejected on reveal")
priv2, _ = generate_keypair()
try:
    db.reveal(database, "504006010", "solPrivateKey", "admin", priv2)
    check("wrong key rejected", False)
except Exception:
    check("wrong key rejected", True)

print("5. secrets of any shape are encrypted, never skipped")
shaped = {
    "a": {"apiKey": {"id": "k1", "secret": "NESTED_SECRET"}},
    "b": {"apiKey": ["LIST_SECRET_1", "LIST_SECRET_2"]},
    "c": {"apiKey": None},
    "d": [{"apiKey": 12345}],
}
n = db.protect(shaped, {"apiKey"}, agents)
check("4 values encrypted (object, list, null, number)", n == 4)
check("no plaintext left", "SECRET" not in json.dumps(shaped))
check("count_plaintext reports none left", db.count_plaintext(shaped, {"apiKey"}) == 0)
check("object round-trips", db.reveal(shaped, "a", "apiKey", "admin", priv) == {"id": "k1", "secret": "NESTED_SECRET"})
check("list round-trips", db.reveal(shaped, "b", "apiKey", "admin", priv) == ["LIST_SECRET_1", "LIST_SECRET_2"])
check("list-indexed record round-trips", db.reveal(shaped["d"], "0", "apiKey", "admin", priv) == 12345)

print("6. protect is idempotent")
before = json.dumps(shaped)
check("second run encrypts nothing", db.protect(shaped, {"apiKey", "file", "nonce", "ciphertext"}, agents) == 0)
check("envelopes are not re-encrypted or corrupted", json.dumps(shaped) == before)

print("7. a ciphertext cannot be moved to another field")
shaped["a"]["other"] = shaped["a"]["apiKey"]
try:
    db.reveal(shaped, "a", "other", "admin", priv)
    check("moved ciphertext rejected", False)
except ValueError:
    check("moved ciphertext rejected", True)

print("\nALL DB PROTECTION TESTS PASSED")
