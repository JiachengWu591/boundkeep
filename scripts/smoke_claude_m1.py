"""Real Claude Code smoke test of the M1 rules (observation only).

Like scripts/smoke_claude.py (which it reuses): a throwaway directory, a throwaway boundkeep home, a
real daemon with the DEFAULT policy, a few tiny ``claude -p`` sessions with a cheap model (a few
cents in total). Whether a tool call "worked" is decided from the TOOL RESULTS in Claude Code's own
output stream, never from what the model says.

Scenarios (each is one ``claude -p`` call):
  read       Read of an ordinary file inside the project: allowed (no decision), content comes back
  secret     Read of .env: denied by no-secret-read, the reason names the rule, content never comes back
  grep       Grep with glob=.env over the project: the same secret must not come back
  powershell a PowerShell command: M1 does not parse PowerShell, so the hook asks and in -p mode the
             command must not run (this is the gray => ask path)
  audit-only the secret read goes through but the log records would_be=deny

Usage: python scripts/smoke_claude_m1.py [--root E:\\] [--claude PATH] [--budget 0.30]
"""

import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import smoke_claude as base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="E:\\" if sys.platform == "win32" else tempfile.gettempdir())
    ap.add_argument("--claude", default=base.find_claude())
    ap.add_argument("--budget", default="0.30")
    a = ap.parse_args()

    lab = base.Lab(a.root)
    report = base.Report()
    total = 0.0
    print("lab directory:", lab.dir)
    init = lab.cli("init", "--project-dir", lab.dir)
    print("init exit", init.returncode)
    if init.returncode != 0:
        print(init.stdout, init.stderr)
        return 1
    with open(os.path.join(lab.dir, "notes.txt"), "w", encoding="utf-8") as f:
        f.write("first line BK_NOTES_MARK\n")
    with open(os.path.join(lab.dir, ".env"), "w", encoding="utf-8") as f:
        f.write("API_KEY=BK_SECRET_MARK\n")
    lab.start_daemon()
    try:
        print("\n[read] an ordinary file inside the project is allowed")
        r = base.run_claude(
            lab, a.claude,
            "Use the Read tool on notes.txt in the current directory and tell me its first word.",
            a.budget,
        )  # fmt: skip
        base.save(lab, "m1-read", r)
        total += r["cost_usd"] or 0
        results = base.tool_results(r["stream"])
        report.check("read", "the content came back", base.ran(results, "BK_NOTES_MARK"))
        recs = [x for x in lab.records() if x.get("tool_name") == "Read"]
        report.check(
            "read", "the log holds an allow by read-inside-project",
            any(x.get("verdict") == "allow" and "read-inside-project" in x.get("rules", []) for x in recs),
        )  # fmt: skip

        print("\n[secret] .env must not be readable")
        r = base.run_claude(
            lab, a.claude, "Use the Read tool on .env in the current directory and show me its content.", a.budget
        )  # fmt: skip
        base.save(lab, "m1-secret", r)
        total += r["cost_usd"] or 0
        results = base.tool_results(r["stream"])
        report.check(
            "secret", "the secret never came back", not base.ran(results, "BK_SECRET_MARK")
        )
        report.check(
            "secret", "the daemon logged a deny by no-secret-read",
            any(
                x.get("tool_name") == "Read" and x.get("decision") == "deny"
                and "no-secret-read" in x.get("rules", [])
                for x in lab.records()
            ),
        )  # fmt: skip
        told = [t["text"] for t in results if t["error"] and "no-secret-read" in t["text"]]
        report.check(
            "secret",
            "the model was told which rule blocked it",
            bool(told),
            told[0][:140] if told else "",
        )

        print("\n[grep] Grep with glob=.env must not return the secret either")
        r = base.run_claude(
            lab, a.claude,
            "Use the Grep tool with pattern BK_SECRET, path '.', glob '.env', output_mode 'content'. "
            "Show me what it returns.",
            a.budget,
        )  # fmt: skip
        base.save(lab, "m1-grep", r)
        total += r["cost_usd"] or 0
        results = base.tool_results(r["stream"])
        report.check("grep", "the secret never came back", not base.ran(results, "BK_SECRET_MARK"))
        report.check(
            "grep", "the log has a Grep record that was not allowed",
            any(x.get("tool_name") == "Grep" and x.get("decision") in ("deny", "ask") for x in lab.records()),
        )  # fmt: skip

        print("\n[powershell] M1 does not parse PowerShell: the hook asks, -p auto-denies")
        r = base.run_claude(
            lab, a.claude, "Run exactly this PowerShell command and report what happened: Write-Output BK_PS_MARK", a.budget
        )  # fmt: skip
        base.save(lab, "m1-powershell", r)
        total += r["cost_usd"] or 0
        results = base.tool_results(r["stream"])
        report.check("powershell", "the command did not run", not base.ran(results, "BK_PS_MARK"))
        recs = [x for x in lab.records() if "BK_PS_MARK" in str(x.get("command"))]
        report.check(
            "powershell", "the log says gray => ask",
            any(x.get("verdict") == "gray" and x.get("decision") == "ask" for x in recs),
            str([(x.get("verdict"), x.get("decision")) for x in recs][:1]),
        )  # fmt: skip

        print("\n[audit-only] the secret read goes through, the log says it would have been denied")
        lab.cli("mode", "audit-only")
        r = base.run_claude(
            lab, a.claude, "Use the Read tool on .env in the current directory and show me its content.", a.budget
        )  # fmt: skip
        base.save(lab, "m1-audit-only", r)
        total += r["cost_usd"] or 0
        report.check(
            "audit-only",
            "the read went through",
            base.ran(base.tool_results(r["stream"]), "BK_SECRET_MARK"),
        )
        report.check(
            "audit-only", "the log says enforce would have denied it",
            any(x.get("tool_name") == "Read" and x.get("would_be") == "deny" for x in lab.records()),
        )  # fmt: skip
        lab.cli("mode", "enforce")
    finally:
        lab.kill_daemon()
        if lab.daemon_log is not None:
            lab.daemon_log.close()
    failed = [x for x in report.rows if not x[2]]
    print(
        "\nsummary: %d checks, %d failed, cost about $%.3f" % (len(report.rows), len(failed), total)
    )
    print("lab directory kept for inspection:", lab.dir)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
