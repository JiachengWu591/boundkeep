"""boundkeep-hook entry script: the file Claude Code launches (``python -I -S hook_client.py``).

Deliberately tiny. A script run as ``__main__`` is compiled from source on every start, while an
imported module is loaded from cached bytecode; the logic therefore lives in ``hook_main.py``
(see scripts/bench_hook.py for the difference). Under ``-I -S`` neither this directory nor any
site-packages is on ``sys.path``, so the package root is added explicitly first.

Importing the package can fail (a half-finished upgrade, a corrupt cache file). An uncaught import
error would exit 1, which Claude Code treats as "no decision" and lets the tool call run, so the
import is guarded and falls back to the same answers ``hook_main`` gives when it cannot decide.
"""

import os
import sys
import time

_T0 = time.monotonic()  # the hook's time budget counts from here

_SRC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_ROOT not in sys.path:
    sys.path.insert(0, _SRC_ROOT)

try:
    from boundkeep import hook_main
except BaseException:  # noqa: BLE001 - any failure to load must still end in a safe answer
    hook_main = None  # type: ignore[assignment]

# Same bytes as hook_main._FALLBACK_ASK (a test compares them): hook_main could not be imported.
_ASK = (
    b'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask",'
    b'"permissionDecisionReason":"boundkeep: internal error in the hook client"}}\n'
)


def _fail_safe() -> None:
    """Answer without the package: ask for PreToolUse, block ConfigChange, stay quiet otherwise."""
    sub = sys.argv[1] if len(sys.argv) > 1 else "pre"
    try:
        if sub == "config":
            os.write(2, b"boundkeep: settings change blocked: the hook client could not start\n")
            os._exit(2)
        if sub not in ("post", "prompt"):
            os.write(1, _ASK)
    except BaseException:  # noqa: BLE001
        os._exit(2)  # the answer could not be delivered: blocking is the only safe outcome
    os._exit(0)


def entry() -> None:
    if hook_main is None:
        _fail_safe()
    try:
        hook_main.entry(_T0)
    except BaseException:  # noqa: BLE001 - entry() normally ends in os._exit; this is the net
        _fail_safe()


if __name__ == "__main__":
    entry()
