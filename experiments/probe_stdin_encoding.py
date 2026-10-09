"""What does a "naive" Python hook really do with UTF-8 stdin on a Chinese-locale Windows?

Written during M0 (2026-10-07) to correct M0a's E18. M0a's BK_NAIVE hook did
``raw.decode(sys.stdin.encoding)`` (a STRICT decode), which fails on this machine; but the way
people actually write a hook, ``json.load(sys.stdin)``, goes through ``sys.stdin``'s text layer,
whose error handler is ``surrogateescape`` here: it does not crash, it silently reads the text
wrong. This script shows both, per interpreter, with a clean environment and ``-I -S`` (what a
hook launched by Claude Code sees when the dev shell's PYTHONIOENCODING is not inherited).

Usage: python experiments/probe_stdin_encoding.py [--python PATH ...] [--out FILE]
Without --python only the running interpreter is tested. Output names interpreters by version,
never by path.
"""

import argparse
import json
import locale
import os
import subprocess
import sys

DATA = {
    "ascii": b'{"command": "echo hi"}',
    "chinese": '{"prompt": "你好世界"}'.encode(),
    "check-mark": '{"command": "echo ✓ done"}'.encode(),
    "chinese+check": '{"command": "echo 你好 ✓ done"}'.encode(),
}

SETTINGS = (
    "import sys; print('%s|%s|%s|%s|%s' % (sys.version.split()[0], sys.stdin.encoding, "
    "sys.stdin.errors, sys.stdout.errors, sys.flags.utf8_mode))"
)
# the way a hook is normally written
NAIVE_LOAD = "import json, sys; d = json.load(sys.stdin); print(json.dumps(d))"
# M0a's BK_NAIVE model: decode the raw bytes strictly with the stdin encoding
M0A_MODEL = "import sys; raw = sys.stdin.buffer.read(); raw.decode(sys.stdin.encoding)"
# does the text survive? (re-encode as ASCII JSON so the comparison is unambiguous)
ROUND_TRIP = "import json, sys; print(ascii(json.load(sys.stdin)))"


def clean_env():
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}


def run(exe, code, data):
    return subprocess.run(
        [exe, "-I", "-S", "-c", code],
        input=data,
        capture_output=True,
        env=clean_env(),
        check=False,
        timeout=60,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", action="append", default=[])
    ap.add_argument("--out")
    args = ap.parse_args()
    exes = args.python or [sys.executable]
    lines = []

    def emit(text=""):
        lines.append(text)
        print(text)

    emit("ANSI code page / locale encoding of the machine: %s" % locale.getpreferredencoding(False))
    emit("environment: PYTHON* variables removed, interpreter flags -I -S, stdin is a pipe")
    for exe in exes:
        info = run(exe, SETTINGS, b"").stdout.decode().strip().split("|")
        version, enc, in_err, out_err, utf8 = info
        emit("")
        emit("== Python %s: stdin encoding %s, stdin errors %s, stdout errors %s, utf8_mode %s"
             % (version, enc, in_err, out_err, utf8))
        for name, data in DATA.items():
            m0a = run(exe, M0A_MODEL, data)
            naive = run(exe, NAIVE_LOAD, data)
            trip = run(exe, ROUND_TRIP, data)
            original = json.loads(data)
            got = trip.stdout.decode("utf-8", "replace").strip()
            same = got == ascii(original)
            emit(
                "  %-14s M0a model (strict decode): %-7s | json.load(sys.stdin): exit %d | text unchanged: %s%s"
                % (
                    name,
                    "FAILS" if m0a.returncode else "ok",
                    naive.returncode,
                    same,
                    "" if same else "   read as: %s" % got,
                )
            )
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
