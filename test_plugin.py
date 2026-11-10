"""Standalone test for the svault plugin layer — tool handlers, the /svault
slash command, the key-directory guard and file handling. No Hermes needed:
a small fake `ctx` stands in for the plugin context.
"""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="svault-test-"))
VAULT = TMP / "vault-home"
WORK = TMP / "work"
WORK.mkdir()
os.environ["SVAULT_HOME"] = str(VAULT)
os.environ.pop("SVAULT_GUARD", None)
os.environ.pop("SVAULT_ALLOW_REMOTE_REVEAL", None)
os.chdir(WORK)

# The plugin is a package whose __init__.py sits at the repo root.
spec = importlib.util.spec_from_file_location(
    "svault_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
svault = importlib.util.module_from_spec(spec)
sys.modules["svault_plugin"] = svault
spec.loader.exec_module(svault)


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        sys.exit(1)


class FakeCtx:
    def __init__(self):
        self.tools, self.commands, self.hooks = {}, {}, {}
        self.answer = "Deny"
        self.asked = []

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = handler

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_hook(self, hook_name, callback, **kw):
        self.hooks[hook_name] = callback

    def ask_choice(self, question, choices):
        self.asked.append(question)
        return self.answer


ctx = FakeCtx()
svault.register(ctx)


def tool(tool_name, /, **params):
    return json.loads(ctx.tools[tool_name](params))


def cmd(args, **kw):
    return ctx.commands["svault"](args, **kw)


print("1. registration")
declared = [
    line.strip()[2:] for line in (ROOT / "plugin.yaml").read_text().splitlines()
    if line.strip().startswith("- svault_")
]
check("8 tools registered", len(ctx.tools) == 8)
check("registered tools match plugin.yaml", sorted(ctx.tools) == sorted(declared))
check("/svault command registered", "svault" in ctx.commands)
check("pre_tool_call guard registered", "pre_tool_call" in ctx.hooks)

print("2. agent identities")
r = tool("svault_agent_new", name="admin")
check("agent created", r.get("success") is True and r.get("public_key"))
key_file = VAULT / "agents" / "admin.key"
check("key file exists", key_file.is_file())
if os.name == "posix":
    check("key file is 0600", (key_file.stat().st_mode & 0o777) == 0o600)
check("duplicate agent refused", "already exists" in tool("svault_agent_new", name="admin").get("error", ""))
check("path-traversal name refused", "error" in tool("svault_agent_new", name="../evil"))
check("no file escaped the agents dir", not (VAULT / "evil.key").exists())
listed = tool("svault_agent_list")["agents"]
check("list shows public key only", listed == [{"name": "admin", "public_key": r["public_key"]}])

print("3. whole-file encryption removes the plaintext")
env = WORK / ".env"
env.write_text("API_TOKEN=sk-live-TOPSECRET\n")
r = tool("svault_encrypt", path=".env", to=["admin"])
check("encrypt succeeded (relative path)", r.get("success") is True)
check("plaintext original deleted", not env.exists() and r["original_removed"] is True)
check(".svault written", (WORK / ".env.svault").is_file())
check("no plaintext in .svault", "TOPSECRET" not in (WORK / ".env.svault").read_text())
cookies = WORK / "cookies.txt"
cookies.write_text("session=abc")
r = tool("svault_encrypt", path=str(cookies), to=["admin"], keep_original=True)
check("keep_original leaves the file and says so", cookies.exists() and "STILL ON DISK" in r["note"])
r = tool("svault_encrypt", path=str(cookies), to=["admin"])
check("existing .svault is never overwritten", "already exists" in r.get("error", "") and cookies.exists())
other = WORK / "other.txt"
other.write_text("keep me")
r = tool("svault_encrypt", path=str(other), to=["nobody"])
check("unknown agent -> error, original untouched", "error" in r and other.read_text() == "keep me")
r = tool("svault_encrypt", path=str(other), to=["../../admin"])
check("traversal in recipient name refused", "error" in r and other.exists())
r = tool("svault_encrypt", path=str(key_file), to=["admin"])
check("refuses to touch the key directory", "key directory" in r.get("error", "") and key_file.exists())

print("4. field-level database protection")
dbfile = WORK / "database.json"
original = {
    "504006010": {"username": "bïll", "solPrivateKey": "SECRETKEY_AAA"},
    "564622369": {"username": "lee", "solPrivateKey": {"hex": "SECRETKEY_NESTED", "parts": ["SECRETKEY_LIST"]}},
    "8107156898": {"username": "chris", "wallets": [{"ethPrivateKey": "0xSECRET_ETH"}]},
}
dbfile.write_text(json.dumps(original, ensure_ascii=False), encoding="utf-8")
r = tool("svault_protect_db", path="database.json", fields=["solPrivateKey", "ethPrivateKey"], to=["admin"])
check("3 values encrypted", r.get("encrypted_values") == 3)
raw = dbfile.read_text(encoding="utf-8")
check("no plaintext secret left on disk", "SECRET" not in raw)
check("nested object/list secrets encrypted too", "SECRETKEY_NESTED" not in raw and "SECRETKEY_LIST" not in raw)
check("non-ASCII data preserved", "bïll" in raw)
check("no temp file left behind", [p.name for p in WORK.glob("*svault-tmp*")] == [])
r = tool("svault_protect_db", path="database.json", fields=["solPrivateKey", "ethPrivateKey"], to=["admin"])
check("second run is a no-op", r.get("encrypted_values") == 0 and dbfile.read_text(encoding="utf-8") == raw)
bad = WORK / "bad.json"
bad.write_text("{not json")
check("invalid JSON reported", "not valid JSON" in tool("svault_protect_db", path=str(bad), fields=["x"], to=["admin"]).get("error", ""))
check("missing args reported", "error" in tool("svault_protect_db", path=str(dbfile), fields=[], to=["admin"]))

print("5. agent read path is redacted")
r = tool("svault_read_db", path="database.json")
check("usernames readable", r["504006010"]["username"] == "bïll")
check("secret redacted", r["504006010"]["solPrivateKey"] == {"__svault_enc__": svault.db.REDACTED})
check("no ciphertext or plaintext in agent view", "ciphertext" not in json.dumps(r) and "SECRET" not in json.dumps(r))

print("6. agent tools cannot decrypt")
check("svault_reveal denied", tool("svault_reveal", path="database.json", record="504006010", field="solPrivateKey").get("denied") is True)
check("svault_decrypt denied", tool("svault_decrypt", path=".env.svault").get("denied") is True)

print("7. /svault reveal needs a human Approve")
ctx.answer = "Deny"
check("Deny -> denied", cmd("reveal database.json 504006010 solPrivateKey") == "Reveal denied.")
ctx.answer = None
check("no answer (timeout/unanswerable) -> denied", cmd("reveal database.json 504006010 solPrivateKey") == "Reveal denied.")
ctx.answer = "Approve"
out = cmd("reveal database.json 504006010 solPrivateKey")
check("Approve -> value revealed", out.endswith("= SECRETKEY_AAA"))
out = cmd("reveal database.json 564622369 solPrivateKey --agent admin")
check("nested secret round-trips", "SECRETKEY_NESTED" in out)
check("not-encrypted field refused", cmd("reveal database.json 504006010 username").startswith("Reveal failed"))
asked = len(ctx.asked)
out = cmd("reveal database.json 504006010 solPrivateKey", platform="telegram")
check("refused from a messaging platform", "only available from a local session" in out and "SECRETKEY" not in out)
check("...without even prompting", len(ctx.asked) == asked)
check("allowed from the CLI surface", cmd("reveal database.json 504006010 solPrivateKey", platform="cli").endswith("= SECRETKEY_AAA"))
tampered = json.loads(raw)
blob = tampered["504006010"]["solPrivateKey"]["__svault_enc__"]
tampered["504006010"]["username"] = {"__svault_enc__": dict(blob)}
(WORK / "tampered.json").write_text(json.dumps(tampered))
check("ciphertext moved to another field refused", cmd("reveal tampered.json 504006010 username").startswith("Reveal failed"))
blob["created"] = blob["created"] + 1
(WORK / "tampered.json").write_text(json.dumps(tampered))
check("edited envelope header refused", cmd("reveal tampered.json 504006010 solPrivateKey").startswith("Reveal failed"))

print("8. /svault decrypt")
ctx.answer = "Deny"
check("Deny -> nothing written", cmd("decrypt .env.svault") == "Decryption denied." and not env.exists())
ctx.answer = "Approve"
out = cmd("decrypt .env.svault")
check("Approve -> file restored", env.read_text() == "API_TOKEN=sk-live-TOPSECRET\n" and "plaintext on disk" in out)
env.write_text("newer content")
out = cmd("decrypt .env.svault")
check("never overwrites an existing file", "already exists" in out and env.read_text() == "newer content")
check("agents subcommand", "admin:" in cmd("agents"))
check("list subcommand", ".env.svault" in cmd("list"))
check("help on no args", "/svault reveal" in cmd(""))

print("9. guard keeps other tools out of the key directory")
guard = ctx.hooks["pre_tool_call"]


def blocked(tool_name, args):
    res = guard(tool_name=tool_name, args=args, task_id="t")
    return isinstance(res, dict) and res.get("action") == "block" and bool(res.get("message"))


check("terminal `cat ~/.svault/...` blocked", blocked("terminal", {"command": "cat ~/.svault/agents/admin.key"}))
check("read_file on the real key path blocked", blocked("read_file", {"path": str(key_file)}))
check("relative .svault/agents blocked", blocked("terminal", {"command": "cd ~ && ls .svault/agents"}))
check("SVAULT_HOME lookup blocked", blocked("terminal", {"command": "ls $SVAULT_HOME"}))
check("nested argument blocked", blocked("execute_code", {"files": [{"src": "open('/home/u/.svault/agents/a.key')"}]}))
check("ordinary tool call allowed", guard(tool_name="terminal", args={"command": "ls -la"}) is None)
check("reading an encrypted .svault file allowed", guard(tool_name="read_file", args={"path": "data/cookies.txt.svault"}) is None)
check("svault's own tools allowed", guard(tool_name="svault_read_db", args={"path": str(key_file)}) is None)
check("...but they refuse the key dir themselves", "error" in tool("svault_read_db", path=str(key_file)))

print("\nALL PLUGIN TESTS PASSED")
