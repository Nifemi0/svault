"""svault crypto primitives — AES-256-GCM, X25519, HKDF-SHA256, Scrypt.

Pure `cryptography`-only; no Hermes imports, so this module is independently
testable and auditable. Never hand-rolled: every primitive is from the audited
`cryptography` package (the same one behind TLS in CPython ecosystems).

Design (envelope encryption):
  1. A random 32-byte data-encryption key (DEK) seals the file body with
     AES-256-GCM.
  2. Per agent: an ephemeral X25519 key does ECDH with the agent's static
     public key -> HKDF-SHA256 -> wrapping key -> AES-256-GCM wraps the DEK.
  3. Optional passphrase recipient: Scrypt (memory-hard KDF) -> wrapping key.
  4. Format v2 authenticates the whole header (file name, recipients, ...) as
     AES-GCM associated data, so the envelope metadata cannot be edited
     without decryption failing. v1 documents (no AAD) still decrypt.
"""
from __future__ import annotations

import base64
import json
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = "SVAULT"
FORMAT_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
NONCE_LEN = 12  # AES-GCM standard nonce length
DEK_LEN = 32
HKDF_INFO = b"svault-v1-dek-wrap"
SCRYPT_N = 2**17  # ~128 MiB; the parameters used are stored per recipient
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAX_N = 2**20  # refuse absurd stored parameters (memory DoS)
_BODY_KEYS = ("nonce", "ciphertext")  # everything else is authenticated header


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def random(n: int) -> bytes:
    return os.urandom(n)


# --- X25519 agent keys ---------------------------------------------------

def generate_keypair():
    """Return (private_key, public_key) X25519 objects."""
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()


def private_to_bytes(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_to_bytes(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def private_from_bytes(raw: bytes):
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def public_from_bytes(raw: bytes):
    return x25519.X25519PublicKey.from_public_bytes(raw)


# --- Key derivation ------------------------------------------------------

def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


def scrypt_key(passphrase: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:
    if not (isinstance(n, int) and 2 <= n <= SCRYPT_MAX_N and n & (n - 1) == 0):
        raise ValueError("unsupported scrypt n")
    if not (isinstance(r, int) and 1 <= r <= 32 and isinstance(p, int) and 1 <= p <= 16):
        raise ValueError("unsupported scrypt r/p")
    return Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    ).derive(passphrase.encode("utf-8"))


# --- AEAD helpers --------------------------------------------------------

def _seal(key: bytes, plaintext: bytes, aad: bytes | None = None):
    nonce = random(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def _open(key: bytes, nonce: bytes, ct: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


def _header_aad(doc: dict) -> bytes | None:
    """Canonical bytes of every header field, bound to the body as GCM AAD (v2+)."""
    if doc.get("version") == 1:
        return None
    header = {k: v for k, v in doc.items() if k not in _BODY_KEYS}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --- Envelope ------------------------------------------------------------

def wrap_dek_for_agent(dek: bytes, agent_pub):
    """Wrap the DEK to an agent's public key. Returns (epk, nonce, wrapped)."""
    ephemeral = x25519.X25519PrivateKey.generate()
    epk = ephemeral.public_key()
    shared = ephemeral.exchange(agent_pub)
    wrap_key = _hkdf(shared, HKDF_INFO)
    nonce, wrapped = _seal(wrap_key, dek)
    return public_to_bytes(epk), nonce, wrapped


def unwrap_dek_for_agent(agent_priv, epk_bytes: bytes, nonce: bytes, wrapped: bytes) -> bytes:
    epk = public_from_bytes(epk_bytes)
    shared = agent_priv.exchange(epk)
    wrap_key = _hkdf(shared, HKDF_INFO)
    return _open(wrap_key, nonce, wrapped)


def wrap_dek_for_passphrase(dek: bytes, passphrase: str):
    salt = random(16)
    wrap_key = scrypt_key(passphrase, salt)
    nonce, wrapped = _seal(wrap_key, dek)
    return salt, nonce, wrapped


def unwrap_dek_for_passphrase(passphrase: str, salt: bytes, nonce: bytes, wrapped: bytes,
                              n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    wrap_key = scrypt_key(passphrase, salt, n, r, p)
    return _open(wrap_key, nonce, wrapped)


# --- File format ---------------------------------------------------------

def encrypt_bytes(plaintext: bytes, *, file_name: str, agents=None, passphrase=None) -> dict:
    """Encrypt `plaintext` to the given `(name, public_key)` pairs and/or a
    passphrase. Returns a JSON-serialisable svault document."""
    if not agents and not passphrase:
        raise ValueError("at least one recipient (agent or passphrase) is required")

    dek = random(DEK_LEN)
    recipients = []

    for name, pub in (agents or []):
        epk, nonce, wrapped = wrap_dek_for_agent(dek, pub)
        recipients.append({
            "type": "agent",
            "agent": name,
            "epk": b64e(epk),
            "nonce": b64e(nonce),
            "wrapped_dek": b64e(wrapped),
        })

    if passphrase:
        salt, nonce, wrapped = wrap_dek_for_passphrase(dek, passphrase)
        recipients.append({
            "type": "passphrase",
            "salt": b64e(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "nonce": b64e(nonce),
            "wrapped_dek": b64e(wrapped),
        })

    doc = {
        "magic": MAGIC,
        "version": FORMAT_VERSION,
        "file": file_name,
        "created": int(time.time()),
        "recipients": recipients,
    }
    nonce, ct = _seal(dek, plaintext, _header_aad(doc))
    doc["nonce"] = b64e(nonce)
    doc["ciphertext"] = b64e(ct)
    return doc


def decrypt_bytes(doc: dict, *, agent_name=None, agent_priv=None, passphrase=None) -> bytes:
    """Decrypt an svault document with an agent private key or a passphrase."""
    if not isinstance(doc, dict) or doc.get("magic") != MAGIC:
        raise ValueError("not a svault file (bad magic)")
    if doc.get("version") not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported svault format version: {doc.get('version')!r}")

    dek = None
    if passphrase is not None:
        for r in doc["recipients"]:
            if r["type"] == "passphrase":
                # v1 files were always written with n=2**14, r=8, p=1.
                dek = unwrap_dek_for_passphrase(
                    passphrase, b64d(r["salt"]), b64d(r["nonce"]), b64d(r["wrapped_dek"]),
                    n=r.get("n", 2**14), r=r.get("r", 8), p=r.get("p", 1),
                )
                break
        if dek is None:
            raise ValueError("file has no passphrase recipient")
    elif agent_name and agent_priv is not None:
        for r in doc["recipients"]:
            if r["type"] == "agent" and r["agent"] == agent_name:
                dek = unwrap_dek_for_agent(
                    agent_priv, b64d(r["epk"]), b64d(r["nonce"]), b64d(r["wrapped_dek"])
                )
                break
        if dek is None:
            raise ValueError(f"agent '{agent_name}' is not a recipient of this file")
    else:
        raise ValueError("decrypt requires an agent key or a passphrase")

    return _open(dek, b64d(doc["nonce"]), b64d(doc["ciphertext"]), _header_aad(doc))


def load_doc(path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def atomic_write_bytes(path, data: bytes) -> None:
    """Write via a temp file in the same directory + os.replace, so a crash
    mid-write never leaves a half-written (corrupt) file behind."""
    path = os.fspath(path)
    tmp = f"{path}.svault-tmp-{os.getpid()}"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_doc(doc: dict, path) -> None:
    atomic_write_bytes(path, json.dumps(doc, indent=2).encode("utf-8"))
