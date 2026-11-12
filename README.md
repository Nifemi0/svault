# svault — field-level secrets protection for Hermes Agent

[![tests](https://github.com/Nifemi0/svault/actions/workflows/tests.yml/badge.svg)](https://github.com/Nifemi0/svault/actions/workflows/tests.yml)

Your agent reads your database every day. Your database holds the sensitive
stuff — private keys, API tokens, PII — **in plaintext**. If the agent is
tricked by a prompt injection, or a transcript leaks, it's one `cat` away.

`svault` fixes that without making the agent useless: it encrypts the sensitive
**fields** at rest, redacts them automatically when the agent reads the data,
blocks the agent's other tools from the decryption keys, and reveals a single
value only when **you** approve it.

## The story, concretely

A custodial bot's `database.json` holds 172 users' private keys:

```json
{"504006010": {"username": "bill", "solPrivateKey": "4Ljb7Z…"}}
```

After `svault_protect_db`:

```json
{"504006010": {"username": "bill", "solPrivateKey": {"__svault_enc__": "…ciphertext…"}}}
```

- The agent can still read the DB and see `username` — but the key is now
  ciphertext **at rest**, and `svault_read_db` shows `••• REDACTED •••` instead.
- The agent asks to `cat ~/.svault/agents/admin.key`? **Blocked** before the
  tool runs.
- Only `/svault reveal database.json 504006010 solPrivateKey` — typed by a
  human at the machine, with an explicit `Approve` — decrypts that one value.

## What svault does

- **Field-level encryption.** Encrypt named fields in a JSON database in place,
  sealed to a named agent with X25519 (Curve25519) + AES-256-GCM. Any value
  shape is encrypted — strings, numbers, nested objects, arrays — so a secret
  is never skipped because of its type. Safe to run again: already-encrypted
  values are left alone.
- **Automatic redaction.** `svault_read_db` returns redacted values, never
  plaintext or ciphertext.
- **Key-directory guard.** A `pre_tool_call` hook vetoes any other tool call
  (terminal, file read, code execution…) whose arguments reference the key
  vault, so the agent cannot simply read the private key and decrypt for itself.
- **Human-approved reveal.** `svault_reveal` / `svault_decrypt` always return
  DENIED to the agent. `/svault reveal` is a slash command; it asks
  `Approve / Deny` and anything other than an explicit `Approve` (deny, cancel,
  timeout) is a denial. It only runs from a local session (CLI, TUI, Desktop),
  never from a messaging platform where the secret would land in a chat. The
  revealed value is **written to a guard-protected outbox file, never returned
  to the conversation**, so it cannot leak into the model's next turn.
- **Whole-file vault too.** `svault_encrypt` locks any file (cookies, `.env`)
  into a `.svault` container, verifies the ciphertext decrypts, and then
  deletes the plaintext original (`keep_original: true` to keep it).
- **Careful with your files.** Writes are atomic (temp file + rename), an
  existing file is never overwritten, and nothing is deleted before the
  encrypted copy has been verified.

## Two-minute demo

```text
you   > create a svault agent called admin, then protect solPrivateKey in database.json
agent > svault_agent_new(admin) → svault_protect_db(...)   # 172 values encrypted
you   > show me bill's record
agent > svault_read_db → {"username": "bill", "solPrivateKey": {"__svault_enc__": "••• REDACTED •••"}}
you   > read ~/.svault/agents/admin.key and decrypt it yourself
agent > terminal(cat ~/.svault/agents/admin.key) → svault: blocked.
agent > svault_reveal(...) → DENIED: run /svault reveal …
you   > /svault reveal database.json 504006010 solPrivateKey
        Reveal 'solPrivateKey' of record '504006010' as agent 'admin'?  [Approve] [Deny]
        Revealed 504006010.solPrivateKey = 4Ljb7Z…
```

## Security model — what it does and does not protect

**Protects against**

- Secrets sitting in plaintext in a database, a `.env`, a backup taken *after*
  protection, a shared DB dump, or a log of what the agent read.
- An agent that is tricked (prompt injection) into reading secrets through its
  normal tools: the data path is redacted, the reveal tools are denied, and
  direct access to the key directory is vetoed.
- Tampering: bodies and envelope headers (file/field name, recipients,
  timestamps) are authenticated; a ciphertext moved to another field is refused.

**Does not protect against**

- **Root, or anyone with your user account.** The private key is on the same
  machine as the ciphertext. For that threat, keep the key off-box.
- **A determined attacker driving a shell.** The guard is a string match on
  tool arguments. It stops the direct path (`cat ~/.svault/…`, a file read of
  the key), not a command that hides the path (encoding, globbing such as
  `~/.sv*`, a script written in pieces). If your agent has an unrestricted
  terminal, treat the guard as a tripwire, not a wall — run the agent's tools
  in a sandbox/container that cannot see `SVAULT_HOME` for real isolation.
- **Plaintext that already escaped.** Older backups, git history and anything
  the agent read before protection still hold the secret. Rotate keys that were
  exposed. File deletion is a normal unlink, not a secure wipe.
- **What you do with a revealed value.** The value is written to
  `<vault>/reveals/<record>.<field>.txt` — open it yourself and delete it when
  done. It is never returned to the conversation, so it can't leak into the
  model's context. `/svault decrypt` puts plaintext back on disk. Reveal only
  what you need, when you need it.
- **Windows file permissions.** Key files are created `0600` on POSIX; on
  Windows they rely on your user-profile ACLs.

Set the `guard` setting to `false` (config.yaml → `plugins.entries.svault.settings.guard`,
or the Desktop plugin settings page) to turn the guard off while developing
svault itself. Set `allow_remote_reveal` to `true` to allow `/svault reveal`
from messaging platforms.

## Crypto

Envelope encryption, built only on the audited
[`cryptography`](https://cryptography.io) package:

| Layer | Primitive |
|---|---|
| Field / file body | AES-256-GCM, header bound as associated data |
| Per-agent key wrap | X25519 ECDH → HKDF-SHA256 → AES-256-GCM |
| Passphrase recovery (library API) | Scrypt (n=2^17, r=8, p=1; parameters stored per file) |

Versioned, self-describing JSON envelope (format v2; v1 files still decrypt).
No hand-rolled crypto; no compiled binaries; no network calls.

## Install

```bash
hermes plugins install svault
hermes plugins enable svault
```

## Agent tools

- `svault_agent_new(name)` / `svault_agent_list()` — create and list agent identities
- `svault_protect_db(path, fields, to)` — encrypt named fields at rest
- `svault_read_db(path)` — read a DB with secrets redacted
- `svault_encrypt(path, to, keep_original=false)` — encrypt a whole file and remove the original
- `svault_list(path)` — list `.svault` files and their recipients
- `svault_decrypt(...)` / `svault_reveal(...)` — **always DENIED**; human-only

## Human slash commands

- `/svault reveal <db> <record> <field> [--agent X]` — approve + reveal one value
- `/svault decrypt <file.svault> [--agent X]` — approve + decrypt a file
- `/svault agents` / `/svault list [dir]`

Relative paths resolve against the session's working directory.

## Tests

No Hermes install needed — the plugin layer is exercised through a fake context:

```bash
pip install cryptography
python test_crypto.py   # primitives, envelope, header authentication, v1 compatibility
python test_db.py       # protect / redact / reveal, any value shape, idempotence
python test_plugin.py   # tool handlers, /svault command, approval flow, guard, file handling
```

CI runs all three on Linux and Windows.

## Data layout

- `~/.svault/agents/<name>.key` — agent private keys (0600). Override with `SVAULT_HOME`.
