"""Latency of the boundkeep hook client (M0 acceptance: report p50 / p95 against the E10 baseline).

Builds a throwaway profile (init + a real daemon), then times full hook invocations as Claude Code
runs them (a new process per event, event JSON on stdin): the default style (base interpreter,
``-I -S hook_client.py``), the virtualenv interpreter, and the console-script launcher, with the
daemon up (full round trip) and down (the degrade path). Also times a bare ``python -I -S -c pass``
for each interpreter as the floor.

Usage: python scripts/bench_hook.py [--runs 60] [--out FILE]
Numbers are for this machine at this moment (background load included), not a benchmark suite.
"""

import argparse
import contextlib
import json
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

from boundkeep import hookcmd, protocol  # noqa: E402
from boundkeep.ipc import client as ipc_client  # noqa: E402
from boundkeep.ipc import endpoint as ipc_endpoint  # noqa: E402

EVENT = {
    "session_id": "00000000-0000-4000-8000-000000000001",
    "transcript_path": "C:\\Users\\testuser\\.claude\\projects\\x\\t.jsonl",
    "cwd": "E:\\bench",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "PowerShell",
    "tool_input": {"command": 'Write-Output "你好 ✓"', "description": "bench"},
    "tool_use_id": "toolu_bench",
}


def percentile(values, p):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def time_runs(argv, stdin, env, runs):
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        subprocess.run(argv, input=stdin, capture_output=True, env=env, check=True, timeout=60)
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def row(label, samples):
    return {
        "label": label,
        "n": len(samples),
        "p50_ms": round(statistics.median(samples), 1),
        "p95_ms": round(percentile(samples, 0.95), 1),
        "min_ms": round(min(samples), 1),
        "max_ms": round(max(samples), 1),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=60)
    parser.add_argument("--out")
    args = parser.parse_args()
    runs = args.runs

    base_python = hookcmd.default_hook_python()
    venv_python = os.path.abspath(sys.executable)
    script = hookcmd.hook_script_path()
    launcher = hookcmd.launcher_path()
    stdin = json.dumps(EVENT, ensure_ascii=False).encode("utf-8")

    rows = []
    with tempfile.TemporaryDirectory(prefix="bk-bench-") as root:
        user = os.path.join(root, "user")
        project = os.path.join(root, "project")
        os.makedirs(user)
        os.makedirs(project)
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.upper().startswith(("PYTHON", "CLAUDE", "BOUNDKEEP", "ANTHROPIC"))
        }
        env.update({"USERPROFILE": user, "HOME": user, "APPDATA": user})
        home = os.path.join(user, ".boundkeep")

        for label, exe in (("base interpreter", base_python), ("venv interpreter", venv_python)):
            rows.append(
                row(
                    f"floor: {label} -I -S -c pass",
                    time_runs([exe, "-I", "-S", "-c", "pass"], b"", env, runs),
                )
            )

        cli = [venv_python, "-m", "boundkeep"]
        subprocess.run(
            [*cli, "init", "--project-dir", project],
            env=env,
            check=True,
            capture_output=True,
            timeout=120,
        )
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        log = open(os.path.join(root, "daemon.out"), "wb")
        daemon = subprocess.Popen(
            [*cli, "serve"], env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=flags
        )
        endpoint = ipc_endpoint.read_endpoint(os.path.join(home, "endpoint.json"))
        deadline = time.monotonic() + 30
        while True:
            try:
                rid = protocol.new_request_id()
                ipc_client.call(endpoint, protocol.encode_request("ping", {}, rid), timeout_s=2)
                break
            except (ipc_client.IpcError, OSError):
                if time.monotonic() > deadline:
                    raise SystemExit("daemon did not start")
                time.sleep(0.1)

        styles = [
            (
                "python.exe (base) -I -S hook_client.py   [default]",
                [base_python, "-I", "-S", script, "pre"],
            ),
            ("python.exe (venv) -I -S hook_client.py", [venv_python, "-I", "-S", script, "pre"]),
        ]
        if os.path.isfile(launcher):
            styles.append(("boundkeep-hook launcher exe", [launcher, "pre"]))

        try:
            for label, argv in styles:
                rows.append(row(f"daemon up:   {label}", time_runs(argv, stdin, env, runs)))
            # the daemon's own view: time spent between receiving a request and answering it
            records = [
                json.loads(line)
                for line in open(os.path.join(home, "logs", "audit.jsonl"), encoding="utf-8")
            ]
            handled = [r["latency_ms"] for r in records if r.get("event") == "pre"]
            if handled:
                rows.append(row("daemon side: request received -> answered", handled))
        finally:
            with contextlib.suppress(OSError):
                pid = int(open(os.path.join(home, "serve.pid"), encoding="ascii").read().strip())
                os.kill(pid, signal.SIGTERM)
            daemon.wait(30)
            log.close()
        for label, argv in styles:
            rows.append(row(f"daemon down: {label}", time_runs(argv, stdin, env, runs)))

    result = {
        "machine": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "cpus": os.cpu_count(),
            "venv_python_is_launcher": os.path.abspath(sys.executable)
            != os.path.abspath(base_python),
        },
        "runs_per_row": runs,
        "rows": rows,
    }
    width = max(len(r["label"]) for r in rows)
    print("%-*s %5s %9s %9s %9s %9s" % (width, "", "n", "p50 ms", "p95 ms", "min ms", "max ms"))
    for r in rows:
        print(
            "%-*s %5d %9.1f %9.1f %9.1f %9.1f"
            % (width, r["label"], r["n"], r["p50_ms"], r["p95_ms"], r["min_ms"], r["max_ms"])
        )
    if args.out:
        with open(args.out, "w", encoding="ascii", newline="\n") as f:
            f.write(json.dumps(result, indent=1) + "\n")


if __name__ == "__main__":
    main()
