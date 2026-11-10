"""svault — field-level secrets protection for Hermes Agent.

Protects the sensitive fields in a database (or an entire file) so that the
agent can READ the data but never SEE the secrets: sensitive values are
encrypted at rest and redacted on read, and revealing a single value is a
human-approved slash command.

Agent private keys live at ~/.svault/agents/<name>.key (0600). Override the
directory with SVAULT_HOME.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import crypto, db


def _vault_dir() -> Path:
    base = Path(os.environ.get("SVAULT_HOME", str(Path.home() / ".svault")))
    (base / "agents").mkdir(parents=True, exist_ok=True)
    return base


def _agents_dir() -> Path:
    return _vault_dir() / "agents"


def _agent_key_path(name: str) -> Path:
    return _agents_dir() / f"{name}.key"


def _save_agent_key(name: str, priv) -> bytes:
    path = _agent_key_path(name)
    if path.exists():
        raise ValueError(f"agent '{name}' already exists")
    raw = crypto.private_to_bytes(priv)
    path.write_text(crypto.b64e(raw))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return crypto.public_to_bytes(priv.public_key())


def _load_agent_private(name: str):
    path = _agent_key_path(name)
    if not path.exists():
        raise ValueError(f"agent '{name}' not found")
    raw = crypto.b64d(path.read_text().strip())
    return crypto.private_from_bytes(raw)


def _load_agent_public(name: str):
    return _load_agent_private(name).public_key()


def _list_agents() -> list:
    _vault_dir()
    out = []
    for p in sorted(_agents_dir().glob("*.key")):
        name = p.stem
        try:
            pub = crypto.public_to_bytes(_load_agent_private(name).public_key())
            out.append({"name": name, "public_key": crypto.b64e(pub)})
        except Exception as e:  # noqa: BLE001
            out.append({"name": name, "error": str(e)})
    return out


# --- Tool handlers -------------------------------------------------------

def _handle_agent_new(params, **kwargs):
    del kwargs
    name = str(params.get("name", "")).strip()
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        return json.dumps({"error": "name must be alphanumeric (plus - and _)"})
    try:
        pub = _save_agent_key(name, crypto.generate_keypair()[0])
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"success": True, "agent": name, "public_key": crypto.b64e(pub)})


def _handle_agent_list(params, **kwargs):
    del params, kwargs
    return json.dumps({"agents": _list_agents()})


def _handle_encrypt(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    to = params.get("to") or []
    if not path:
        return json.dumps({"error": "path is required"})
    p = Path(path)
    if not p.exists():
        return json.dumps({"error": f"file not found: {path}"})
    if not to:
        return json.dumps({"error": "at least one --to agent is required"})
    try:
        agents = [(str(a), _load_agent_public(str(a))) for a in to]
        doc = crypto.encrypt_bytes(p.read_bytes(), file_name=p.name, agents=agents)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)})
    out = Path(str(p) + ".svault")
    crypto.save_doc(doc, out)
    return json.dumps({
        "success": True, "encrypted": str(p), "output": str(out),
        "recipients": [a for a, _ in agents],
    })


def _handle_protect_db(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    fields = {str(f) for f in (params.get("fields") or [])}
    to = [str(a) for a in (params.get("to") or [])]
    if not path or not fields or not to:
        return json.dumps({"error": "path, fields, and to are all required"})
    p = Path(path)
    if not p.exists():
        return json.dumps({"error": f"file not found: {path}"})
    try:
        data = json.loads(p.read_text())
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"not valid JSON: {e}"})
    try:
        agents = [(str(a), _load_agent_public(str(a))) for a in to]
        n = db.protect(data, fields, agents)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)})
    p.write_text(json.dumps(data, indent=2))
    return json.dumps({
        "success": True,
        "encrypted_values": n,
        "fields": sorted(fields),
        "protected_file": str(p),
        "note": "Sensitive fields are now ciphertext at rest. Read this DB with svault_read_db to see redacted values.",
    })


def _handle_read_db(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    if not path:
        return json.dumps({"error": "path is required"})
    p = Path(path)
    if not p.exists():
        return json.dumps({"error": f"file not found: {path}"})
    try:
        data = json.loads(p.read_text())
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"not valid JSON: {e}"})
    return json.dumps(db.redact(data))


def _handle_decrypt(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    agent = str(params.get("agent", ""))
    hint = f"/svault decrypt {path}" + (f" --agent {agent}" if agent else "")
    return json.dumps({
        "denied": True,
        "reason": "decryption requires human approval",
        "instruction": f"Run `{hint}` in your terminal to approve and decrypt.",
    })


def _handle_reveal(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    record = str(params.get("record", ""))
    field = str(params.get("field", ""))
    agent = str(params.get("agent", ""))
    hint = f"/svault reveal {path} {record} {field}" + (f" --agent {agent}" if agent else "")
    return json.dumps({
        "denied": True,
        "reason": "revealing a protected value requires human approval",
        "instruction": f"Run `{hint}` in your terminal to approve and reveal.",
    })


def _handle_list(params, **kwargs):
    del kwargs
    d = str(params.get("path", ".")) or "."
    p = Path(d)
    if not p.is_dir():
        return json.dumps({"error": f"not a directory: {d}"})
    files = []
    for f in sorted(p.glob("*.svault")):
        try:
            doc = crypto.load_doc(f)
            recips = [r["agent"] if r["type"] == "agent" else "passphrase" for r in doc["recipients"]]
            files.append({"file": f.name, "orig": doc["file"], "recipients": recips})
        except Exception as e:  # noqa: BLE001
            files.append({"file": f.name, "error": str(e)})
    return json.dumps({"vault_files": files})


# --- Slash command -------------------------------------------------------

def _decrypt_to(agent: str, src: Path, out: Path) -> None:
    doc = crypto.load_doc(src)
    priv = _load_agent_private(agent)
    out.write_bytes(crypto.decrypt_bytes(doc, agent_name=agent, agent_priv=priv))


def _strip_svault(p: Path) -> Path:
    name = p.name
    if name.endswith(".svault"):
        name = name[: -len(".svault")]
    return p.with_name(name)


def register(ctx):
    ts = "svault"

    def _tool(name, description, props, required, handler):
        ctx.register_tool(
            name=name,
            toolset=ts,
            schema={
                "name": name,
                "description": description,
                "parameters": {"type": "object", "properties": props, "required": required},
            },
            handler=handler,
        )

    _tool(
        "svault_agent_new",
        "Generate a new X25519 agent keypair for svault. Agents are the identities secrets are sealed to; the private key stays local and is never exposed.",
        {"name": {"type": "string", "description": "Agent name (alphanumeric, - and _)"}},
        ["name"],
        _handle_agent_new,
    )
    _tool(
        "svault_agent_list",
        "List svault agents and their public keys. Private keys are never returned.",
        {}, [],
        _handle_agent_list,
    )
    _tool(
        "svault_encrypt",
        "Encrypt an entire file to one or more svault agents. Writes a .svault file beside the original. The agent cannot decrypt it back.",
        {
            "path": {"type": "string", "description": "Path to the file to encrypt"},
            "to": {"type": "array", "items": {"type": "string"}, "description": "Agent names to encrypt to"},
        },
        ["path", "to"],
        _handle_encrypt,
    )
    _tool(
        "svault_protect_db",
        "Protect sensitive fields in a JSON database: encrypt each named field's value in place (at rest). The agent can still read the DB with svault_read_db but sees redacted values for those fields. Returns how many values were encrypted.",
        {
            "path": {"type": "string", "description": "Path to the JSON database"},
            "fields": {"type": "array", "items": {"type": "string"}, "description": "Sensitive field names to encrypt (e.g. solPrivateKey, apiKey)"},
            "to": {"type": "array", "items": {"type": "string"}, "description": "Agent names to seal the values to"},
        },
        ["path", "fields", "to"],
        _handle_protect_db,
    )
    _tool(
        "svault_read_db",
        "Read a protected JSON database with every encrypted field redacted. Use this instead of reading the raw file so secrets are never shown.",
        {"path": {"type": "string", "description": "Path to the protected JSON database"}},
        ["path"],
        _handle_read_db,
    )
    _tool(
        "svault_decrypt",
        "Request decryption of a svault file. Always returns DENIED: decryption is human-only via the /svault slash command.",
        {
            "path": {"type": "string", "description": "Path to the .svault file"},
            "agent": {"type": "string", "description": "Agent identity to decrypt as"},
        },
        ["path"],
        _handle_decrypt,
    )
    _tool(
        "svault_reveal",
        "Request to reveal a protected field value. Always returns DENIED: revealing is human-only via the /svault reveal slash command.",
        {
            "path": {"type": "string", "description": "Path to the protected JSON database"},
            "record": {"type": "string", "description": "Record key (or index) holding the field"},
            "field": {"type": "string", "description": "The protected field name"},
            "agent": {"type": "string", "description": "Agent identity to reveal as"},
        },
        ["path", "record", "field"],
        _handle_reveal,
    )
    _tool(
        "svault_list",
        "List .svault files in a directory with their original filenames and recipients.",
        {"path": {"type": "string", "description": "Directory to scan (default current)"}},
        [],
        _handle_list,
    )

    def _svault_cmd(raw_args: str, **session_kw) -> str:
        del session_kw
        parts = raw_args.strip().split()
        if not parts:
            return (
                "svault — field-level secrets protection\n"
                "  /svault decrypt <file.svault> [--agent <name>]\n"
                "  /svault reveal <db> <record> <field> [--agent <name>]\n"
                "  /svault agents\n"
                "  /svault list [dir]"
            )

        sub = parts[0]

        if sub == "agents":
            agents = _list_agents()
            if not agents:
                return "No agents yet. Ask me to run svault_agent_new."
            return "Agents:\n" + "\n".join(
                f"{a['name']}: {a.get('public_key', a.get('error'))}" for a in agents
            )

        if sub == "list":
            d = parts[1] if len(parts) > 1 else "."
            files = []
            for f in sorted(Path(d).glob("*.svault")):
                try:
                    doc = crypto.load_doc(f)
                    recips = ", ".join(
                        r["agent"] if r["type"] == "agent" else "passphrase"
                        for r in doc["recipients"]
                    )
                    files.append(f"{f.name}  (orig: {doc['file']}, recipients: {recips})")
                except Exception as e:  # noqa: BLE001
                    files.append(f"{f.name}  (error: {e})")
            return "Vault files:\n" + "\n".join(files) if files else "No .svault files found."

        if sub in ("decrypt", "reveal"):
            rest = parts[1:]
            agent = None
            positional = []
            i = 0
            while i < len(rest):
                if rest[i] == "--agent" and i + 1 < len(rest):
                    agent = rest[i + 1]
                    i += 2
                else:
                    positional.append(rest[i])
                    i += 1

            if sub == "decrypt":
                if not positional:
                    return "Usage: /svault decrypt <file.svault> [--agent <name>]"
                src = Path(positional[0])
                if not src.exists():
                    return f"File not found: {positional[0]}"
                if not agent:
                    try:
                        doc = crypto.load_doc(src)
                        agent = next(
                            (r["agent"] for r in doc["recipients"] if r["type"] == "agent"), None
                        )
                    except Exception as e:  # noqa: BLE001
                        return f"Could not read {src}: {e}"
                    if not agent:
                        return "This file has no agent recipients."
                choice = ctx.ask_choice(
                    f"Approve decryption of {src.name} as agent '{agent}'?",
                    ["Approve", "Deny"],
                )
                if choice != "Approve":
                    return "Decryption denied."
                out = _strip_svault(src)
                try:
                    _decrypt_to(agent, src, out)
                except Exception as e:  # noqa: BLE001
                    return f"Decryption failed: {e}"
                return f"Decrypted {src.name} -> {out.name}"

            # reveal
            if len(positional) < 3:
                return "Usage: /svault reveal <db> <record> <field> [--agent <name>]"
            dbpath, record, field = positional[0], positional[1], positional[2]
            p = Path(dbpath)
            if not p.exists():
                return f"File not found: {dbpath}"
            try:
                data = json.loads(p.read_text())
            except Exception as e:  # noqa: BLE001
                return f"Not valid JSON: {e}"
            if not agent:
                rec = data.get(record) if isinstance(data, dict) else None
                if isinstance(rec, dict) and isinstance(rec.get(field), dict) and "__svault_enc__" in rec[field]:
                    marker = rec[field]["__svault_enc__"]
                    agent = next(
                        (r["agent"] for r in marker["recipients"] if r["type"] == "agent"), None
                    )
                if not agent:
                    return "Could not determine an agent for this field. Pass --agent <name>."
            choice = ctx.ask_choice(
                f"Reveal '{field}' of record '{record}' in {p.name} as agent '{agent}'?",
                ["Approve", "Deny"],
            )
            if choice != "Approve":
                return "Reveal denied."
            try:
                val = db.reveal(data, record, field, agent, _load_agent_private(agent))
            except Exception as e:  # noqa: BLE001
                return f"Reveal failed: {e}"
            return f"Revealed {record}.{field} = {val}"

        return (
            "Unknown svault subcommand. Try:\n"
            "  /svault decrypt <file.svault> [--agent <name>]\n"
            "  /svault reveal <db> <record> <field> [--agent <name>]\n"
            "  /svault agents\n"
            "  /svault list [dir]"
        )

    ctx.register_command(
        "svault",
        handler=_svault_cmd,
        description="Secrets vault: decrypt/reveal (human-approved), list agents, list vault files",
        args_hint="decrypt|reveal|agents|list",
    )
