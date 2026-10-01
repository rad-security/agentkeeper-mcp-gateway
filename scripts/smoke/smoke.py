#!/usr/bin/env python3
"""End-to-end smoke test for a built agentkeeper-mcp-gateway binary.

    python3 scripts/smoke/smoke.py path/to/agentkeeper-mcp-gateway[.exe]

The same script runs on Linux, macOS and Windows with only the standard
library. Every child process gets a throwaway home directory: nothing reads
or writes the real one, and nothing touches the network.

The binary must keep its release name (agentkeeper-mcp-gateway, plus .exe on
Windows): configure-ide only writes its own absolute path when it recognises
that name.

The gateway needs an MCP server to proxy, so this file is also that server:
the gateway config launches it again with --fake-upstream.
"""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

UPSTREAM = "fake-upstream"
TOOLS = ("echo", "show_arguments", "get_report")
GATEWAY_ENTRY = "agentkeeper-mcp-gateway"
SECRET = "AKIAIOSFODNN7EXAMPLE"  # the documented AWS example key, not a credential
BIG_INT = 9007199254740993  # 2**53 + 1, which a float64 cannot represent
TIMEOUT = 30  # seconds; every wait is bounded so a hang fails a step, not CI


def fake_upstream():
    """A minimal MCP server: newline-delimited JSON-RPC on stdio.

    The streams are used in binary mode on purpose. In text mode Windows
    would write CRLF and decode stdin with the ANSI code page, not UTF-8.
    """
    tools = [
        {"name": "echo", "description": "Return the text argument.",
         "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
        {"name": "show_arguments", "description": "Return the arguments as JSON.",
         "inputSchema": {"type": "object"}},
        {"name": "get_report", "description": "Return a fixed sample report.",
         "inputSchema": {"type": "object"}},
    ]
    for line in sys.stdin.buffer:
        request = json.loads(line) if line.strip() else {}
        if "id" not in request:
            continue  # blank line or notification: nothing to answer
        params = request.get("params") or {}
        reply = {"jsonrpc": "2.0", "id": request["id"]}
        if request.get("method") == "initialize":
            reply["result"] = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": UPSTREAM, "version": "0.0.0"},
            }
        elif request.get("method") == "tools/list":
            reply["result"] = {"tools": tools}
        elif request.get("method") == "tools/call":
            arguments = params.get("arguments") or {}
            text = {
                "echo": arguments.get("text", ""),
                "show_arguments": json.dumps(arguments, sort_keys=True),
                "get_report": "sample report: access key " + SECRET,
            }.get(params.get("name"), "unknown tool")
            reply["result"] = {"content": [{"type": "text", "text": text}]}
        else:
            reply["error"] = {"code": -32601, "message": "Method not found"}
        sys.stdout.buffer.write(json.dumps(reply, ensure_ascii=False).encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


class Server:
    """A running `server` command, spoken to as an MCP client would."""

    def __init__(self, command, env, cwd, stderr):
        self.proc = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=stderr)
        self.lines = queue.Queue()
        self.last_id = 0
        # A reader thread is the portable way to put a timeout on a pipe read.
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _send(self, message):
        self.proc.stdin.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def notify(self, method):
        self._send({"jsonrpc": "2.0", "method": method})

    def request(self, method, params=None):
        self.last_id += 1
        self._send({"jsonrpc": "2.0", "id": self.last_id, "method": method, "params": params or {}})
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                line = self.lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise TimeoutError("no response to %s within %ss" % (method, TIMEOUT))
            expect(line is not None, "server closed stdout before answering " + method)
            message = json.loads(line)
            if message.get("id") != self.last_id or "method" in message:
                continue  # a notification or a server-to-client request
            expect("error" not in message, "%s failed: %s" % (method, message.get("error")))
            return message["result"]


class Smoke:
    def __init__(self, binary, root):
        self.binary = str(binary)
        self.counts = {"PASS": 0, "FAIL": 0, "INFO": 0}
        self.server = None
        self.health = ""
        self.stderr_path = root / "server.stderr"
        self.stderr = open(self.stderr_path, "wb")

        # The gateway derives all of these from the home directory, which Go's
        # os.UserHomeDir reads from $HOME on Unix and %USERPROFILE% on Windows.
        # The layout below it is the same on every OS.
        self.home = root / "home"
        self.state = self.home / ".config" / "agentkeeper-mcp-gateway"
        self.config = self.state / "config.json"  # internal/config ResolveConfigPath
        self.events = self.state / "events.jsonl"  # internal/logging NewLogger
        self.cursor = self.home / ".cursor" / "mcp.json"  # internal/ideconfig cursorAdapter
        self.upstream = self.home / "fake upstream.py"
        self.state.mkdir(parents=True)

        # AGENTKEEPER_* would redirect the config, name another binary or
        # supply an API key (and so a network connection), so none are inherited.
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith("AGENTKEEPER_")}
        self.env.update({
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "APPDATA": str(self.home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(self.home / "AppData" / "Local"),
        })

    # --- helpers -----------------------------------------------------------

    def run(self, *args):
        done = subprocess.run([self.binary] + list(args), env=self.env, cwd=str(self.home),
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=2 * TIMEOUT)
        out = done.stdout.decode("utf-8", "replace")
        err = done.stderr.decode("utf-8", "replace")
        expect(done.returncode == 0,
               "`%s` exited %d: %s" % (" ".join(args), done.returncode, (err or out).strip()))
        return out

    def call(self, tool, arguments):
        result = self.server.request("tools/call", {"name": UPSTREAM + "__" + tool, "arguments": arguments})
        return result["content"][0]["text"]

    def snapshot(self):
        return {str(p): p.read_bytes() if p.is_file() else None for p in self.home.rglob("*")}

    def cursor_servers(self):
        return json.loads(self.cursor.read_bytes().decode("utf-8"))["mcpServers"]

    def step(self, name, check, status="PASS"):
        try:
            detail = check()
        except Exception as exc:  # one failed step must not hide the others
            detail = "%s: %s" % (type(exc).__name__, exc)
            status = "FAIL" if status == "PASS" else status
        self.counts[status] += 1
        print("%s  %s: %s" % (status, name, detail), flush=True)

    # --- steps -------------------------------------------------------------

    def version(self):
        first = self.run("version").splitlines()[0]
        expect(first.startswith("agentkeeper-mcp-gateway "), "unexpected version line %r" % first)
        return first

    def write_config(self):
        shutil.copy(__file__, str(self.upstream))
        entry = {"name": UPSTREAM, "command": sys.executable,
                 "args": [str(self.upstream), "--fake-upstream"]}
        self.config.write_bytes(json.dumps({"servers": [entry]}, indent=2).encode("utf-8"))
        listed = json.loads(self.run("list", "--json"))
        expect(listed == [entry], "gateway read the config as %s" % listed)
        return str(self.config)

    def handshake(self):
        self.server = Server([self.binary, "server"], self.env, str(self.home), self.stderr)
        self.server.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                           "clientInfo": {"name": "smoke", "version": "0"}})
        self.server.notify("notifications/initialized")
        # Upstream tools are discovered in the background, so an early
        # tools/list may hold only the built-in tools.
        wanted = {UPSTREAM + "__" + tool for tool in TOOLS} | {"agentkeeper_status"}
        deadline = time.monotonic() + TIMEOUT
        while True:
            names = {tool["name"] for tool in self.server.request("tools/list")["tools"]}
            if wanted <= names or time.monotonic() > deadline:
                break
            time.sleep(0.5)
        expect(wanted <= names, "missing %s in %s" % (sorted(wanted - names), sorted(names)))
        return ", ".join(sorted(names))

    def echo(self):
        text = "quote \" and ' \\ café 日本語 \U0001f680"
        got = self.call("echo", {"text": text})
        expect(got == text, "sent %s, got %s" % (ascii(text), ascii(got)))
        return ascii(got)

    def big_integer(self):
        received = self.call("show_arguments", {"number": BIG_INT})
        kept = received == json.dumps({"number": BIG_INT})
        return "sent %d, upstream received %s (%s)" % (BIG_INT, received, "exact" if kept else "changed")

    def detection(self):
        self.call("get_report", {})
        deadline = time.monotonic() + 5
        while True:
            log = self.events.read_bytes() if self.events.exists() else b""
            hits = [event for event in map(json.loads, log.splitlines())
                    if event.get("event_type") == "mcp.tool_call"
                    and event.get("category") == "sensitive_data"
                    and (event.get("server_name"), event.get("tool_name")) == (UPSTREAM, "get_report")]
            if hits or time.monotonic() > deadline:
                break
            time.sleep(0.2)
        expect(hits, "no mcp.tool_call event with category sensitive_data in %s" % self.events)
        expect(SECRET.encode() not in log, "the secret was written to %s" % self.events)
        return "%s recorded as %s, secret not in the event log" % (
            hits[0].get("pattern_name"), hits[0].get("verdict"))

    def stdin_close(self):
        started = time.monotonic()
        self.server.proc.stdin.close()
        try:
            code = self.server.proc.wait(timeout=10)
        finally:
            self.server.proc.kill()  # no-op once it has exited
        expect(code == 0, "exit code %s" % code)
        return "exit code 0 after %.1fs" % (time.monotonic() - started)

    def list_health(self):
        self.health = self.run("list", "--health")
        expect(UPSTREAM in self.health, "upstream not named in:\n" + self.health)
        return "names " + UPSTREAM

    def scan(self):
        rows = [line.split() for line in self.run("scan").splitlines()]
        expect(["SERVER", "TRANSPORT", "RESULT"] in rows, "no result table in %s" % rows)
        row = next((row for row in rows if row[:1] == [UPSTREAM]), None)
        expect(row is not None, "upstream missing from the table: %s" % rows)
        return " ".join(row)

    def configure_dry_run(self):
        # A second, never-started server for configure-ide to migrate. CRLF so
        # the rollback has to restore bytes, not re-encode JSON.
        notes = {"command": sys.executable, "args": [str(self.upstream), "--fake-upstream"]}
        text = json.dumps({"mcpServers": {"notes": notes}}, indent=2)
        self.cursor_original = text.replace("\n", "\r\n").encode("utf-8")
        self.cursor.parent.mkdir(parents=True)
        self.cursor.write_bytes(self.cursor_original)
        before = self.snapshot()
        out = self.run("configure-ide", "--ide=cursor", "--dry-run")
        after = self.snapshot()
        changed = sorted(p for p in set(before) | set(after) if before.get(p, 0) != after.get(p, 0))
        expect(not changed, "dry run changed %s" % changed)
        expect("notes" in out, "dry run did not mention the server to migrate:\n" + out)
        return "nothing under the home directory changed"

    def configure_apply(self):
        self.run("configure-ide", "--ide=cursor")
        servers = self.cursor_servers()
        expect(list(servers) == [GATEWAY_ENTRY], "Cursor servers are %s" % list(servers))
        command = servers[GATEWAY_ENTRY]["command"]
        expect(os.path.isabs(command) and os.path.samefile(command, self.binary),
               "command %r is not the absolute path of %s" % (command, self.binary))
        migrated = [server["name"] for server in json.loads(self.run("list", "--json"))]
        expect("notes" in migrated, "notes was not migrated into the gateway config: %s" % migrated)
        return "only %s, command %s" % (GATEWAY_ENTRY, command)

    def configure_rollback(self):
        report = json.loads(self.run("configure-ide", "--ide=cursor", "--remove-routing"))
        expect(report.get("result") == "removed", "report is %s" % report)
        expect(self.cursor.read_bytes() == self.cursor_original,
               "Cursor config is not byte-identical to the original")
        return 'report "result": "removed", Cursor config byte-identical to the original'

    def space_in_path(self):
        expect(" " in str(self.config), "test bug: no space in %s" % self.config)
        line = "Config: %s" % self.config
        expect(line in self.health.splitlines(), "list --health did not print %r" % line)
        return line

    def main(self):
        self.step("1 version", self.version)
        self.step("2 config with one stdio upstream", self.write_config)
        self.step("3 handshake and tools/list", self.handshake)
        self.step("4 echo round trip", self.echo)
        self.step("4 large integer argument", self.big_integer, status="INFO")
        self.step("5 sensitive data detection", self.detection)
        self.step("6 exit on stdin close", self.stdin_close)
        self.step("7 list --health", self.list_health)
        self.step("8 scan", self.scan)
        self.step("9 configure-ide dry run", self.configure_dry_run)
        self.step("9 configure-ide apply", self.configure_apply)
        self.step("9 configure-ide rollback", self.configure_rollback)
        self.step("10 config path with a space", self.space_in_path)

    def close(self):
        if self.server and self.server.proc.poll() is None:
            self.server.proc.kill()
            self.server.proc.wait(timeout=10)
        self.stderr.close()
        if self.counts["FAIL"]:
            print("--- server stderr ---")
            print(self.stderr_path.read_bytes().decode("utf-8", "replace").strip())


def main():
    if "--fake-upstream" in sys.argv[1:]:
        return fake_upstream()
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        sys.exit(__doc__)
    # Windows consoles and CI logs are not always UTF-8; never die on a print.
    sys.stdout.reconfigure(errors="backslashreplace")
    # The space is deliberate: Windows home directories often have one.
    root = Path(tempfile.mkdtemp(prefix="gateway smoke ")).resolve()
    smoke = Smoke(Path(sys.argv[1]).resolve(), root)
    try:
        smoke.main()
    finally:
        smoke.close()
        shutil.rmtree(str(root), ignore_errors=True)
    print("SUMMARY: %(PASS)d passed, %(FAIL)d failed, %(INFO)d info" % smoke.counts)
    sys.exit(1 if smoke.counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
