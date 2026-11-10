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

print("\nALL DB PROTECTION TESTS PASSED")
