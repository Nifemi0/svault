"""Field-level database protection for svault.

Encrypt sensitive fields in place (at rest), redact them on read, and reveal
a single value on demand. The crypto is `crypto.py`; this module is the
JSON-walking application layer — pure logic, no Hermes imports.
"""
from __future__ import annotations

import json

try:
    from . import crypto
except ImportError:  # standalone/test context — not loaded as a package
    import crypto

MARKER_KEY = "__svault_enc__"
REDACTED = "••• REDACTED •••"


def is_marker(v) -> bool:
    """True for an already-encrypted value: ``{"__svault_enc__": {...}}``."""
    return isinstance(v, dict) and MARKER_KEY in v


def protect(obj, fields: set, agents) -> int:
    """Encrypt every value under a sensitive field name, in place.

    Any JSON value is encrypted whole — strings and numbers, but also nested
    objects and arrays, so a secret is never silently left in plaintext
    because of its shape. Values that are already encrypted are left alone,
    which makes protect() safe to run again on the same database.

    Returns the number of values encrypted.
    """
    count = 0
    if isinstance(obj, dict):
        if is_marker(obj):
            return 0
        for k in list(obj.keys()):
            v = obj[k]
            if is_marker(v):
                continue
            if k in fields:
                blob = crypto.encrypt_bytes(
                    json.dumps(v).encode("utf-8"),
                    file_name=k,
                    agents=agents,
                )
                obj[k] = {MARKER_KEY: blob}
                count += 1
            else:
                count += protect(v, fields, agents)
    elif isinstance(obj, list):
        for v in obj:
            count += protect(v, fields, agents)
    return count


def count_plaintext(obj, fields: set) -> int:
    """Count values under a sensitive field name that are NOT encrypted."""
    count = 0
    if isinstance(obj, dict):
        if is_marker(obj):
            return 0
        for k, v in obj.items():
            if is_marker(v):
                continue
            count += 1 if k in fields else count_plaintext(v, fields)
    elif isinstance(obj, list):
        for v in obj:
            count += count_plaintext(v, fields)
    return count


def redact(obj):
    """Return a deep copy with every encrypted value replaced by a redaction marker."""
    if isinstance(obj, dict):
        if MARKER_KEY in obj:
            return {MARKER_KEY: REDACTED}
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def get_marker(obj, record_key, field) -> dict:
    """Return the encrypted envelope stored at obj[record_key][field]."""
    if isinstance(obj, dict):
        record = obj.get(record_key)
    elif isinstance(obj, list):
        try:
            record = obj[int(record_key)]
        except (ValueError, IndexError) as e:
            raise ValueError(f"record index '{record_key}' not found") from e
    else:
        raise ValueError("database must be an object or an array")

    if not isinstance(record, dict) or field not in record:
        raise ValueError(f"field '{field}' not found in record '{record_key}'")

    marker = record[field]
    if not is_marker(marker) or not isinstance(marker[MARKER_KEY], dict):
        raise ValueError(f"field '{field}' is not encrypted")
    return marker[MARKER_KEY]


def reveal(obj, record_key, field, agent_name, agent_priv):
    """Decrypt the single encrypted value at obj[record_key][field]."""
    blob = get_marker(obj, record_key, field)
    # The envelope records which field it was sealed for (authenticated in
    # format v2), so a ciphertext moved under another field name is refused.
    if blob.get("file") != field:
        raise ValueError(f"encrypted value was not sealed for field '{field}'")
    plain = crypto.decrypt_bytes(
        blob,
        agent_name=agent_name,
        agent_priv=agent_priv,
    )
    return json.loads(plain.decode("utf-8"))
