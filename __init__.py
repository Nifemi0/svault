"""svault — field-level secrets protection for Hermes Agent.

Protects the sensitive fields in a database (or an entire file) so that the
agent can READ the data but never SEE the secrets: sensitive values are
encrypted at rest and redacted on read, and revealing a single value is a
human-approved slash command.

Agent private keys live under Hermes's per-profile plugin-data directory
(`<HERMES_HOME>/plugin-data/svault/agents`, 0600). A `pre_tool_call` guard
blocks the agent's other tools (terminal, read_file, ...) from touching that
directory, and every tool refuses paths Hermes core itself refuses.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

from . import crypto, db

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Surfaces where the person typing is at the machine. Reveal/decrypt from a
# messaging platform would post a secret into a (possibly shared) chat.
_LOCAL_SURFACES = {"", "cli", "tui", "desktop", "local"}

_CTX = None


def _cfg(key: str, default):
    """Read a plugin setting from Hermes config (ctx.get_config), with an env
    fallback for standalone/test contexts."""
    if _CTX is not None:
        try:
            return _CTX.get_config(key, default=default)
        except Exception:  # noqa: BLE001
            pass
    env_map = {"guard": "SVAULT_GUARD", "allow_remote_reveal": "SVAULT_ALLOW_REMOTE_REVEAL"}
    env = env_map.get(key)
    if env and env in os.environ:
        v = os.environ[env].strip()
        if isinstance(default, bool):
            return v.lower() not in ("", "0", "off", "false", "no")
        return v
    return default


def _vault_dir() -> Path:
    try:
        from hermes_constants import get_hermes_home
        base = Path(get_hermes_home()) / "plugin-data" / "svault"
    except Exception:  # noqa: BLE001 — standalone/test context
        base = Path(os.environ.get("SVAULT_HOME", str(Path.home() / ".svault")))
    (base / "agents").mkdir(parents=True, exist_ok=True)
    for d in (base, base / "agents"):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return base


def _agents_dir() -> Path:
    return _vault_dir() / "agents"


def _agent_key_path(name: str) -> Path:
    # Names come from tool arguments; never let one escape the agents dir.
    if not _NAME_RE.match(name or ""):
        raise ValueError("agent name must be 1-64 characters: letters, digits, - and _")
    return _agents_dir() / f"{name}.key"


def _save_agent_key(name: str, priv) -> bytes:
    path = _agent_key_path(name)
    raw = crypto.private_to_bytes(priv)
    # O_EXCL: never overwrite an existing key. Mode 0600 from creation, so the
    # key is never briefly world-readable (POSIX; Windows uses the user profile ACL).
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError(f"agent '{name}' already exists") from None
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(crypto.b64e(raw))
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


# --- Paths ---------------------------------------------------------------

def _session_cwd() -> Path:
    """The session's working directory. Handlers run in the gateway process,
    whose own cwd is not the user's, so relative paths resolve against this."""
    try:
        from agent.runtime_cwd import resolve_agent_cwd
        return Path(resolve_agent_cwd())
    except Exception:  # noqa: BLE001 — standalone/test context, or older Hermes
        return Path.cwd()


def _resolve(path: str) -> Path:
    p = Path(path).expanduser()
    return p if p.is_absolute() else _session_cwd() / p


def _in_vault(p: Path) -> bool:
    try:
        p.resolve().relative_to(_vault_dir().resolve())
        return True
    except (ValueError, OSError):
        return False


def _hermes_home():
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:  # noqa: BLE001
        return None


def _session_root():
    try:
        from agent.runtime_cwd import resolve_agent_cwd
        root = resolve_agent_cwd()
        return Path(root) if root else None
    except Exception:  # noqa: BLE001
        return None


def _guard_path(p: Path, *, write: bool):
    """Refuse paths Hermes itself refuses: its own home and anything outside the
    session working directory. Uses only public plugin APIs (`hermes_constants`,
    `agent.runtime_cwd`)."""
    del write
    if _in_vault(p):
        return "refusing to operate on the svault key directory"
    try:
        rp = p.resolve()
    except OSError:
        return "cannot resolve path"
    home = _hermes_home()
    if home is not None:
        try:
            rp.relative_to(home.resolve())
            return "refusing to operate on Hermes's own files (config, credentials, state)"
        except ValueError:
            pass
    root = _session_root()
    if root is not None:
        try:
            rp.relative_to(root.resolve())
        except ValueError:
            return "refusing to operate outside the session working directory"
    return None


def _read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


# --- Tool handlers -------------------------------------------------------

def _handle_agent_new(params, **kwargs):
    del kwargs
    name = str(params.get("name", "")).strip()
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
    to = [str(a) for a in (params.get("to") or [])]
    keep_original = bool(params.get("keep_original", True))
    if not path:
        return json.dumps({"error": "path is required"})
    p = _resolve(path)
    if not p.is_file():
        return json.dumps({"error": f"file not found: {path}"})
    if not to:
        return json.dumps({"error": "at least one --to agent is required"})
    if err := _guard_path(p, write=True):
        return json.dumps({"error": err})
    if p.name.endswith(".svault"):
        return json.dumps({"error": f"{p.name} is already a svault file"})
    out = Path(str(p) + ".svault")
    if out.exists():
        return json.dumps({"error": f"{out.name} already exists; remove it first"})
    try:
        agents = [(a, _load_agent_public(a)) for a in to]
        plaintext = p.read_bytes()
        doc = crypto.encrypt_bytes(plaintext, file_name=p.name, agents=agents)
        # Prove the ciphertext decrypts before the plaintext is removed.
        check = crypto.decrypt_bytes(doc, agent_name=to[0], agent_priv=_load_agent_private(to[0]))
        if check != plaintext:
            raise ValueError("round-trip verification failed; original left untouched")
        crypto.save_doc(doc, out)
        if not keep_original:
            p.unlink()
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)})
    return json.dumps({
        "success": True, "encrypted": str(p), "output": str(out),
        "recipients": to,
        "original_removed": not keep_original,
        "note": (
            "The plaintext original was deleted." if not keep_original else
            "The plaintext original is STILL ON DISK (keep_original=true)."
        ) + " Copies elsewhere (backups, git history, editor swap files) are not affected.",
    })


def _handle_protect_db(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    fields = {str(f) for f in (params.get("fields") or [])}
    to = [str(a) for a in (params.get("to") or [])]
    if not path or not fields or not to:
        return json.dumps({"error": "path, fields, and to are all required"})
    p = _resolve(path)
    if not p.is_file():
        return json.dumps({"error": f"file not found: {path}"})
    if err := _guard_path(p, write=True):
        return json.dumps({"error": err})
    try:
        data = _read_json(p)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"not valid JSON: {e}"})
    try:
        agents = [(a, _load_agent_public(a)) for a in to]
        n = db.protect(data, fields, agents)
        left = db.count_plaintext(data, fields)
        if left:
            raise ValueError(f"{left} value(s) could not be encrypted; database left untouched")
        if n:
            crypto.atomic_write_bytes(
                p, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
            )
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)})
    return json.dumps({
        "success": True,
        "encrypted_values": n,
        "fields": sorted(fields),
        "protected_file": str(p),
        "note": (
            "Sensitive fields are now ciphertext at rest. Read this DB with svault_read_db to see "
            "redacted values. Older copies (backups, git history) still hold the plaintext."
            if n else
            "No plaintext values were found under those field names (already protected, or the "
            "field names do not match). Nothing was changed."
        ),
    })


def _handle_read_db(params, **kwargs):
    del kwargs
    path = str(params.get("path", ""))
    if not path:
        return json.dumps({"error": "path is required"})
    p = _resolve(path)
    if not p.is_file():
        return json.dumps({"error": f"file not found: {path}"})
    if err := _guard_path(p, write=True):
        return json.dumps({"error": err})
    try:
        data = _read_json(p)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"not valid JSON: {e}"})
    return json.dumps(db.redact(data), ensure_ascii=False)


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
    p = _resolve(d)
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


# --- Key-directory guard -------------------------------------------------

def _guard_needles() -> list:
    needles = {"/.svault", ".svault/agents", "svault_home"}
    try:
        base = _vault_dir()
        needles.add(str(base).replace("\\", "/").lower())
        needles.add(str(base.resolve()).replace("\\", "/").lower())
    except OSError:
        pass
    return sorted(n for n in needles if n)


def _pre_tool_call_guard(tool_name: str = "", args=None, **kwargs):
    """Veto any non-svault tool call whose arguments mention the key vault.

    Without this, an agent with a terminal or file-read tool could simply read
    ~/.svault/agents/<name>.key and decrypt everything itself. This is a
    best-effort string match on the tool arguments (it stops the direct path,
    not an attacker who obfuscates a shell command) — see the README.
    """
    del kwargs
    if _cfg("guard", True) is False:
        return None
    if tool_name == "svault_encrypt" and isinstance(args, dict) and not args.get("keep_original", True):
        return {
            "action": "approve",
            "message": (
                f"svault_encrypt will delete the plaintext original ({args.get('path', '')}). "
                "Approve the deletion?"
            ),
        }
    if str(tool_name).startswith("svault_"):
        return None
    try:
        blob = json.dumps(args, default=str)
    except Exception:  # noqa: BLE001
        blob = str(args)
    blob = re.sub(r"/+", "/", blob.replace("\\", "/")).lower()
    for needle in _guard_needles():
        if needle in blob:
            return {
                "action": "block",
                "message": (
                    "svault: blocked. This tool call references the svault key directory, which "
                    "the agent may not read, list, copy or modify. Protected values are revealed "
                    "only by a human with `/svault reveal`."
                ),
            }
    return None


# --- Slash command -------------------------------------------------------

def _decrypt_to(agent: str, src: Path, out: Path) -> None:
    doc = crypto.load_doc(src)
    priv = _load_agent_private(agent)
    crypto.atomic_write_bytes(out, crypto.decrypt_bytes(doc, agent_name=agent, agent_priv=priv))


def _strip_svault(p: Path) -> Path:
    name = p.name
    if name.endswith(".svault"):
        name = name[: -len(".svault")]
    return p.with_name(name)


def _split_args(raw: str) -> list:
    try:
        parts = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError:
        parts = raw.split()
    return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]


def register(ctx):
    global _CTX
    _CTX = ctx
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
        "Encrypt an entire file to one or more svault agents. Writes a .svault file beside the original and, once the ciphertext is verified, deletes the plaintext original. The agent cannot decrypt it back.",
        {
            "path": {"type": "string", "description": "Path to the file to encrypt"},
            "to": {"type": "array", "items": {"type": "string"}, "description": "Agent names to encrypt to"},
            "keep_original": {"type": "boolean", "description": "Leave the plaintext original on disk (default true). Setting false deletes it, which requires human approval"},
        },
        ["path", "to"],
        _handle_encrypt,
    )
    _tool(
        "svault_protect_db",
        "Protect sensitive fields in a JSON database: encrypt each named field's value in place (at rest), whatever its type. The agent can still read the DB with svault_read_db but sees redacted values for those fields. Safe to run again. Returns how many values were encrypted.",
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

    # Keep the agent's other tools out of the key directory.
    try:
        ctx.register_hook("pre_tool_call", _pre_tool_call_guard)
    except Exception:  # noqa: BLE001 — hooks unavailable; tools still work
        pass

    def _svault_cmd(raw_args: str, **session_kw) -> str:
        platform = str(session_kw.get("platform") or "").lower()
        parts = _split_args(raw_args.strip())
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
            for f in sorted(_resolve(d).glob("*.svault")):
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
            if platform not in _LOCAL_SURFACES and not _cfg("allow_remote_reveal", False):
                return (
                    f"/svault {sub} is only available from a local session (CLI, TUI, Desktop), "
                    f"not from {platform}: the secret would be posted into this chat. "
                    "Enable the svault 'allow_remote_reveal' setting to override."
                )
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
                src = _resolve(positional[0])
                if not src.is_file():
                    return f"File not found: {positional[0]}"
                out = _strip_svault(src)
                if out == src:
                    return f"{src.name} does not end in .svault."
                if out.exists():
                    return f"{out.name} already exists; move it away first. Nothing was overwritten."
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
                try:
                    _decrypt_to(agent, src, out)
                except Exception as e:  # noqa: BLE001
                    return f"Decryption failed: {e}"
                return (
                    f"Decrypted {src.name} -> {out.name}\n"
                    f"Note: {out.name} is plaintext on disk again, where the agent can read it."
                )

            # reveal
            if len(positional) < 3:
                return "Usage: /svault reveal <db> <record> <field> [--agent <name>]"
            dbpath, record, field = positional[0], positional[1], positional[2]
            p = _resolve(dbpath)
            if not p.is_file():
                return f"File not found: {dbpath}"
            try:
                data = _read_json(p)
            except Exception as e:  # noqa: BLE001
                return f"Not valid JSON: {e}"
            if not agent:
                try:
                    blob = db.get_marker(data, record, field)
                    agent = next(
                        (r["agent"] for r in blob["recipients"] if r["type"] == "agent"), None
                    )
                except Exception as e:  # noqa: BLE001
                    return f"Reveal failed: {e}"
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
