"""Real Claude Code smoke test of the M0 path (observation only; it is NOT an audit backend).

Runs a handful of tiny ``claude -p`` sessions (cheap model, a few cents in total) in a throwaway
directory against a throwaway boundkeep home, with a real daemon, and checks what Claude Code
actually did: whether a command ran is decided from the TOOL RESULTS in Claude Code's own output
stream (a non-error result that contains the command's marker), never from what the model says.
Commands are read-only (Write-Output), so Claude Code's own permission system lets them through
in -p mode: a write command would be auto-denied there and prove nothing about boundkeep.

Scenarios (each is one ``claude -p`` call):
  allowed   a normal command and one with Chinese text and a check mark must run, and the audit
            log must hold the Chinese command text exactly (byte I/O under the zh-CN code page);
            this is also the control that shows the 'did it run' judgment can see a command run
  canary    a PowerShell command containing BOUNDKEEP_CANARY must be blocked, with the reason
            coming back to the model
  down      with the daemon killed the hook must answer ask, so in -p mode the command must not run
  config    while a session is running, an outside edit writes disableAllHooks into
            settings.local.json: the ConfigChange hook must refuse it and later hooks must still fire
Optional with --extra: audit-only (canary runs but is recorded) and removal (the hook entries are
edited out mid-session; records whether the ConfigChange hook, which is itself among them, still
gets to veto that).

Usage: python scripts/smoke_claude.py [--root E:\\] [--claude PATH] [--budget 0.30] [--extra]
Everything lives under a new directory <root>\\bk-m0-<random>; delete it when done.
"""

import argparse
import contextlib
import glob
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, REPO_SRC)

from boundkeep import protocol  # noqa: E402
from boundkeep.ipc import client as ipc_client  # noqa: E402
from boundkeep.ipc import endpoint as ipc_endpoint  # noqa: E402

MODEL = "claude-haiku-4-5-20251001"
ALLOWED = ["PowerShell(New-Item *)", "PowerShell(Start-Sleep *)"]


def find_claude():
    pattern = os.path.join(
        os.path.expanduser("~"), ".vscode", "extensions", "anthropic.claude-code-*",
        "resources", "native-binary", "claude.exe",
    )  # fmt: skip
    found = sorted(glob.glob(pattern))
    return found[-1] if found else "claude"


class Lab:
    def __init__(self, root):
        self.dir = tempfile.mkdtemp(prefix="bk-m0-", dir=root)
        self.home = os.path.join(self.dir, "home")
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith("CLAUDE")}
        for k in [k for k in self.env if k.upper().startswith("PYTHON")]:
            del self.env[k]
        self.env["BOUNDKEEP_HOME"] = self.home
        self.daemon = None
        self.daemon_log = None

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "boundkeep", *args], env=self.env, cwd=self.dir,
            capture_output=True, timeout=180, encoding="utf-8", errors="replace", check=False,
        )  # fmt: skip

    def endpoint(self):
        return ipc_endpoint.read_endpoint(os.path.join(self.home, "endpoint.json"))

    def ping(self):
        rid = protocol.new_request_id()
        line = protocol.encode_request(protocol.EVENT_PING, {}, rid)
        return protocol.decode_response(ipc_client.call(self.endpoint(), line, timeout_s=2), rid)

    def start_daemon(self):
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.daemon_log = open(os.path.join(self.dir, "daemon.out"), "ab")
        self.daemon = subprocess.Popen(
            [sys.executable, "-m", "boundkeep", "serve"], env=self.env, cwd=self.dir,
            stdout=self.daemon_log, stderr=subprocess.STDOUT, creationflags=flags,
        )  # fmt: skip
        deadline = time.monotonic() + 30
        while True:
            try:
                self.ping()
                return
            except (ipc_client.IpcError, OSError, ipc_endpoint.EndpointError):
                if time.monotonic() > deadline:
                    raise SystemExit("the daemon did not start")
                time.sleep(0.1)

    def kill_daemon(self):
        with contextlib.suppress(Exception):
            pid = int(open(os.path.join(self.home, "serve.pid"), encoding="ascii").read().strip())
            os.kill(pid, signal.SIGTERM)
        if self.daemon is not None:
            with contextlib.suppress(Exception):
                self.daemon.wait(20)

    def records(self):
        path = os.path.join(self.home, "logs", "audit.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def claude(self, claude, prompt, budget, timeout=240):
        cmd = [
            claude, "-p", "--model", MODEL, "--output-format", "stream-json", "--verbose",
            "--include-hook-events", "--no-session-persistence", "--setting-sources", "project",
            "--permission-prompts", "none", "--max-budget-usd", budget, "--allowedTools", *ALLOWED,
        ]  # fmt: skip
        return subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.dir, env=self.env,
        ), prompt.encode("utf-8")  # fmt: skip


def run_claude(lab, claude, prompt, budget, timeout=240, during=None):
    proc, data = lab.claude(claude, prompt, budget)
    chunks = []
    reader = threading.Thread(target=lambda: chunks.append(proc.stdout.read()))
    reader.start()
    err = []
    err_reader = threading.Thread(target=lambda: err.append(proc.stderr.read()))
    err_reader.start()
    proc.stdin.write(data)
    proc.stdin.close()
    if during is not None:
        during()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
    reader.join(10)
    err_reader.join(10)
    out = (chunks[0] if chunks else b"").decode("utf-8", "replace")
    cost = None
    for line in out.splitlines():
        with contextlib.suppress(ValueError):
            message = json.loads(line)
            if message.get("type") == "result":
                cost = message.get("total_cost_usd")
    return {
        "rc": proc.returncode,
        "cost_usd": cost,
        "stream": out,
        "stderr": b"".join(err).decode("utf-8", "replace"),
    }


def hook_outcomes(stream):
    found = []
    for line in stream.splitlines():
        with contextlib.suppress(ValueError):
            m = json.loads(line)
            if m.get("type") == "system" and m.get("subtype") == "hook_response":
                found.append((m.get("hook_event"), m.get("outcome"), (m.get("stdout") or "")[:200]))
    return found


def save(lab, name, result):
    """Keep each scenario's raw stream next to the lab for inspection."""
    with open(os.path.join(lab.dir, f"{name}.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        f.write(result["stream"])


class Report:
    def __init__(self):
        self.rows = []

    def check(self, scenario, name, ok, evidence=""):
        self.rows.append((scenario, name, bool(ok), evidence))
        print(
            "  [%s] %s%s" % ("PASS" if ok else "FAIL", name, f"  ({evidence})" if evidence else "")
        )
        return ok


def tool_results(stream):
    """Every tool result in a stream-json transcript as {"error": bool, "text": str}."""
    found = []
    for line in stream.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        content = (
            (message.get("message") or {}).get("content") if message.get("type") == "user" else None
        )
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                body = block.get("content")
                if isinstance(body, list):
                    body = " ".join(b.get("text", "") for b in body if isinstance(b, dict))
                found.append({"error": block.get("is_error") is True, "text": str(body)})
    return found


def ran(results, marker):
    """The command ran: a result that is not an error and carries the marker."""
    return any(not r["error"] and marker in r["text"] for r in results)


def say(marker):
    return f"Write-Output {marker}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="E:\\" if sys.platform == "win32" else tempfile.gettempdir())
    ap.add_argument("--claude", default=find_claude())
    ap.add_argument("--budget", default="0.30")
    ap.add_argument("--extra", action="store_true", help="also run audit-only and removal")
    a = ap.parse_args()

    lab = Lab(a.root)
    report = Report()
    total_cost = 0.0
    print("lab directory:", lab.dir)
    print("claude       :", a.claude)
    init = lab.cli("init", "--project-dir", lab.dir)
    print("init exit", init.returncode)
    if init.returncode != 0:
        print(init.stdout, init.stderr)
        return 1
    lab.start_daemon()
    try:
        # ---- canary ----------------------------------------------------------------------
        print("\n[allowed] a normal command and a Chinese one must run; the log must hold the text")
        cn_marker = "BK_CN_MARK"
        result = run_claude(
            lab, a.claude,
            "Run these two PowerShell commands one after the other, exactly as written, "
            f"then say done:\n1. {say('BK_OK_MARK')}\n2. Write-Output \"你好 ✓ {cn_marker}\"",
            a.budget,
        )  # fmt: skip
        save(lab, "allowed", result)
        total_cost += result["cost_usd"] or 0
        results = tool_results(result["stream"])
        report.check(
            "allowed",
            "the normal command ran (this is also the control for the checks below)",
            ran(results, "BK_OK_MARK"),
        )
        report.check("allowed", "the Chinese command ran", ran(results, cn_marker))
        logged = [str(r.get("command")) for r in lab.records() if r.get("event") == "pre"]
        report.check(
            "allowed", "the log holds the Chinese command text exactly",
            any(f"你好 ✓ {cn_marker}" in c for c in logged), "(real host, code page 936)",
        )  # fmt: skip

        print("\n[canary] a command containing BOUNDKEEP_CANARY must not run")
        result = run_claude(
            lab, a.claude,
            f"Run exactly this PowerShell command, then tell me whether it worked: {say('BOUNDKEEP_CANARY')}",
            a.budget,
        )  # fmt: skip
        save(lab, "canary", result)
        total_cost += result["cost_usd"] or 0
        results = tool_results(result["stream"])
        denied = [r for r in lab.records() if r.get("decision") == "deny"]
        report.check("canary", "the command did not run", not ran(results, "BOUNDKEEP_CANARY"))
        report.check(
            "canary",
            "the daemon logged a deny for it",
            any("BOUNDKEEP_CANARY" in str(r.get("command")) for r in denied),
        )
        blocked = [r["text"] for r in results if r["error"] and "canary" in r["text"].lower()]
        report.check(
            "canary",
            "the model was told why (the reason came back as a tool error)",
            bool(blocked),
            (blocked[0][:140] if blocked else ""),
        )
        outcomes = hook_outcomes(result["stream"])
        report.check(
            "canary",
            "Claude Code recorded the PreToolUse hook answer",
            any(o[0] == "PreToolUse" for o in outcomes),
        )

        # ---- daemon down -----------------------------------------------------------------
        print("\n[down] with the daemon killed the hook must ask, so the command must not run")
        lab.kill_daemon()
        result = run_claude(
            lab, a.claude,
            f"Run exactly this PowerShell command and report what happened: {say('BK_DOWN_MARK')}",
            a.budget,
        )  # fmt: skip
        save(lab, "down", result)
        total_cost += result["cost_usd"] or 0
        results = tool_results(result["stream"])
        report.check(
            "down",
            "the command did not run (ask is auto-denied in -p mode)",
            not ran(results, "BK_DOWN_MARK"),
        )
        outcomes = hook_outcomes(result["stream"])
        report.check(
            "down", "the PreToolUse hook answered ask and named the daemon",
            any(o[0] == "PreToolUse" and '"permissionDecision":"ask"' in o[2] and "not running" in o[2] for o in outcomes),
            str([o for o in outcomes if o[0] == "PreToolUse"][:1]),
        )  # fmt: skip
        lab.start_daemon()

        # ---- config ----------------------------------------------------------------------
        print("\n[config] an outside edit writing disableAllHooks mid-session must be refused")
        local = os.path.join(lab.dir, ".claude", "settings.local.json")
        before = len(lab.records())

        def edit_mid_session():
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:  # wait until the first command is in flight
                if any(
                    r.get("event") == "pre" and "Start-Sleep" in str(r.get("command"))
                    for r in lab.records()[before:]
                ):
                    break
                time.sleep(0.3)
            time.sleep(1.0)
            with open(local, "w", encoding="utf-8", newline="\n") as f:
                f.write('{"disableAllHooks": true}\n')

        result = run_claude(
            lab, a.claude,
            "Run this PowerShell command first: Start-Sleep -Seconds 10\n"
            f"Then run this one: {say('BK_SECOND_MARK')}\nThen say done.",
            a.budget, timeout=300, during=lambda: threading.Thread(target=edit_mid_session, daemon=True).start(),
        )  # fmt: skip
        total_cost += result["cost_usd"] or 0
        time.sleep(2)
        new = lab.records()[before:]
        report.check(
            "config", "the ConfigChange hook refused the edit",
            any(r.get("event") == "config" and r.get("local_decision") == "deny" for r in new),
            str([r.get("local_reason") for r in new if r.get("event") == "config"][:1]),
        )  # fmt: skip
        report.check(
            "config", "hooks kept firing after the edit (the second command went through the gate)",
            any(r.get("event") == "pre" and "BK_SECOND_MARK" in str(r.get("command")) for r in new),
        )  # fmt: skip
        with contextlib.suppress(OSError):
            os.unlink(local)

        if a.extra:
            print("\n[audit-only] the canary runs but is recorded")
            lab.cli("mode", "audit-only")
            result = run_claude(
                lab,
                a.claude,
                f"Run exactly this PowerShell command: {say('BOUNDKEEP_CANARY')}",
                a.budget,
            )
            save(lab, "audit-only", result)
            total_cost += result["cost_usd"] or 0
            report.check(
                "audit-only",
                "the command ran",
                ran(tool_results(result["stream"]), "BOUNDKEEP_CANARY"),
            )
            report.check(
                "audit-only",
                "the log says enforce would have denied it",
                any(r.get("would_be") == "deny" for r in lab.records()),
            )
            lab.cli("mode", "enforce")

            print("\n[removal] hook entries edited out mid-session")
            settings_path = os.path.join(lab.dir, ".claude", "settings.json")
            original = open(settings_path, encoding="utf-8").read()
            before = len(lab.records())

            def remove_entries():
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if any("Start-Sleep" in str(r.get("command")) for r in lab.records()[before:]):
                        break
                    time.sleep(0.3)
                time.sleep(1.0)
                data = json.loads(original)
                data["hooks"] = {}
                with open(settings_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(json.dumps(data))

            result = run_claude(
                lab, a.claude,
                f"Run this PowerShell command first: Start-Sleep -Seconds 10\nThen run: {say('BK_REMOVAL_MARK')}",
                a.budget, timeout=300, during=lambda: threading.Thread(target=remove_entries, daemon=True).start(),
            )  # fmt: skip
            total_cost += result["cost_usd"] or 0
            time.sleep(2)
            new = lab.records()[before:]
            vetoed = any(
                r.get("event") == "config" and r.get("local_decision") == "deny" for r in new
            )
            still_gated = any("BK_REMOVAL_MARK" in str(r.get("command")) for r in new)
            report.check(
                "removal",
                "RECORDED (not a pass/fail): was the removal vetoed?",
                True,
                f"vetoed={vetoed}, later command still gated={still_gated}",
            )
            with open(settings_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(original)
    finally:
        lab.kill_daemon()
        if lab.daemon_log is not None:
            lab.daemon_log.close()

    failed = [r for r in report.rows if not r[2]]
    print(
        "\nsummary: %d checks, %d failed, cost about $%.3f"
        % (len(report.rows), len(failed), total_cost)
    )
    print("lab directory kept for inspection:", lab.dir)
    summary = os.path.join(lab.dir, "smoke_summary.json")
    with open(summary, "w", encoding="utf-8") as f:
        json.dump(
            {"rows": report.rows, "cost_usd": total_cost, "claude": a.claude},
            f,
            ensure_ascii=False,
            indent=1,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
