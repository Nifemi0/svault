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


def _is_scalar(v) -> bool:
    return isinstance(v, (str, int, float, bool)) or v is None


def protect(obj, fields: set, agents) -> int:
    """Encrypt every value under a sensitive field name, in place.

    Returns the number of values encrypted.
    """
    count = 0
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            v = obj[k]
            if k in fields and _is_scalar(v):
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


def redact(obj):
    """Return a deep copy with every encrypted value replaced by a redaction marker."""
    if isinstance(obj, dict):
        if MARKER_KEY in obj:
            return {MARKER_KEY: REDACTED}
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def reveal(obj, record_key, field, agent_name, agent_priv):
    """Decrypt the single encrypted value at obj[record_key][field]."""
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
    if not (isinstance(marker, dict) and MARKER_KEY in marker):
        raise ValueError(f"field '{field}' is not encrypted")

    plain = crypto.decrypt_bytes(
        marker[MARKER_KEY],
        agent_name=agent_name,
        agent_priv=agent_priv,
    )
    return json.loads(plain.decode("utf-8"))
