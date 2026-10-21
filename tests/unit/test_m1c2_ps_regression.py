"""M1c-2 regression guard: no adversarial PowerShell corpus entry may get milder.

The changes of this milestone (dev tools, pipeline heads, data-shaping cmdlets) only ever add
information to the digest and the Actions. Every ``adv: true`` PowerShell entry of every
``tests/corpus/pipeline*.yaml`` must still come out at least as strict as its expectation, and
never as ``allow`` (``test_pipeline_corpus`` checks the same through its exact-verdict test; this
file keeps the guarantee visible next to the M1c-2 tests and also covers entries added later).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from boundkeep import policycli
from boundkeep.policy import default_policy_text, parse_policy_text

CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
STRICT = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="PowerShell entries need the real parser helper"
)


def _adv_ps_entries() -> list[Any]:
    out = []
    for path in sorted(CORPUS_DIR.glob("pipeline*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            if entry.get("tool") == "PowerShell" and entry.get("adv"):
                out.append(pytest.param(entry, id=f"{path.stem}:{entry['id']}"))
    return out


@pytest.fixture(scope="module")
def policy() -> Any:
    return parse_policy_text(default_policy_text(), home=policycli._FAKE["windows"]["home"])


ENTRIES = _adv_ps_entries()


def test_there_are_many_adversarial_powershell_entries() -> None:
    assert len(ENTRIES) >= 400


@pytest.mark.parametrize("entry", ENTRIES)
def test_no_adversarial_entry_got_milder(entry: dict[str, Any], policy: Any) -> None:
    only = entry.get("platform")
    if only not in (None, "windows"):
        pytest.skip("not a Windows entry")
    expect = entry["expect"]
    if entry.get("trusted"):
        # tests/corpus/pipeline_m1c2_trusted.yaml: `expect` is for a trusted project (the policy
        # here trusts none): the untrusted verdict, or `expect` for the entries that run with an
        # empty trusted list; tests/unit/test_m1c2_trusted_policy.py runs the trusted side
        expect = entry.get("expect_untrusted", expect if entry.get("trust") == "empty" else None)
        if expect is None:
            pytest.skip("an entry for the trusted policy only")
    result = policycli._run_one(
        policy,
        "windows",
        "PowerShell",
        entry["input"],
        entry.get("cwd"),
        entry.get("project_dir"),  # type: ignore[arg-type]
    )
    got = result.verdict.decision
    assert got != "allow", f"{entry['id']}: {entry['input']['command']!r} is allowed"
    assert STRICT[got] >= STRICT[expect], (
        f"{entry['id']}: expected at least {expect}, got {got}; reasons: {result.verdict.reasons}"
    )
