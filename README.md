# svault — field-level secrets protection for Hermes Agent

Your agent reads your database every day. Your database holds the sensitive
stuff — private keys, API tokens, PII — **in plaintext**. If the agent is
compromised, or anyone reaches the box, it's one `cat` away.

`svault` fixes that without making the agent useless: it encrypts the sensitive
**fields** at rest, redacts them automatically when the agent reads the data,
and reveals a single value only when **you** approve it.

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
- Only `/svault reveal database.json 504006010 solPrivateKey` — typed by a
  human, with an explicit `Approve` — decrypts that one value.

## What svault does

- **Field-level encryption.** Encrypt named fields in a JSON database in place,
  sealed to a named agent with X25519 (Curve25519) + AES-256-GCM.
- **Automatic redaction.** The agent's read path returns redacted values, never
  plaintext — there is no code path for the agent to see a secret back.
- **Human-approved reveal.** `/svault reveal` is a slash command only a human
  can run; it asks `Approve / Deny` before decrypting a single field.
- **Whole-file vault too.** `svault_encrypt` locks any file (cookies, `.env`)
  into a `.svault` container the agent cannot open.

## Crypto

Envelope encryption, built only on the audited
[`cryptography`](https://cryptography.io) package:

| Layer | Primitive |
|---|---|
| Field / file body | AES-256-GCM |
| Per-agent key wrap | X25519 ECDH → HKDF-SHA256 → AES-256-GCM |
| Passphrase recovery | Scrypt (n=2^14, r=8, p=1) |

Versioned, self-describing JSON envelope. No hand-rolled crypto; no compiled
binaries; no network calls.

## Install

```bash
hermes plugins install svault
hermes plugins enable svault
```

## Agent tools

- `svault_agent_new(name)` / `svault_agent_list()` — create and list agent identities
- `svault_protect_db(path, fields, to)` — encrypt named fields at rest
- `svault_read_db(path)` — read a DB with secrets redacted
- `svault_encrypt(path, to)` — encrypt a whole file
- `svault_decrypt(...)` / `svault_reveal(...)` — **always DENIED**; human-only

## Human slash commands

- `/svault reveal <db> <record> <field> [--agent X]` — approve + reveal one value
- `/svault decrypt <file.svault> [--agent X]` — approve + decrypt a file
- `/svault agents` / `/svault list`

## Security model

`svault` protects against agent compromise and accidental exposure, **not**
full root compromise: if the agent private key lives on the same box as the
ciphertext, a root attacker can decrypt. For root-compromise protection, keep
the agent key off-box.

## Data layout

- `~/.svault/agents/<name>.key` — agent private keys (0600). Override with `SVAULT_HOME`.
