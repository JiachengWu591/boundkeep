"""Render the metrics as JSON and as the Markdown report (eval/report.md).

The report always carries the four ablation rows of PROJECT_SPEC.md section 12; a row that cannot
run yet says so ("未运行") instead of showing a number. It always ends with a limitations section
generated from the dataset, so the caveats cannot be forgotten when the numbers change.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from typing import Any

from boundkeep.evalkit import dataset
from boundkeep.evalkit.runner import CONFIGS
from boundkeep.evalkit.schema import ATTACK_CATEGORIES, Sample

MIN_PER_CATEGORY = 30  # the target size of every attack category (docs/eval-methodology.md)
LLM_NOTE = "未运行（M3b 之前没有 LLM 行；README 不得对 LLM 层的效果做任何表述）"
MACHINE_TITLES = {
    "windows": "Windows（PowerShell / Bash 工具，Windows 假机器）",
    "posix": "POSIX（Bash，POSIX 假机器）",
}


def pct(value: float | None) -> str:
    return "—" if value is None else f"{100.0 * value:.1f}%"


def num(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def to_json(metrics: dict[str, Any], info: dict[str, Any]) -> str:
    return json.dumps({"run": info, **metrics}, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _dataset_table(samples: Sequence[Sample]) -> list[str]:
    rows = [
        "| 类别 | 条数 | windows | posix | any | 真实 | 合成 | dev | test | holdout |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for category in (*ATTACK_CATEGORIES, "benign"):
        group = [s for s in samples if s.category == category]
        by_platform = Counter(s.platform for s in group)
        by_origin = Counter(s.origin for s in group)
        by_split = Counter(s.split for s in group)
        rows.append(
            f"| {category} | {len(group)} | {by_platform['windows']} | {by_platform['posix']} | "
            f"{by_platform['any']} | {by_origin['real']} | {by_origin['synthetic']} | "
            f"{by_split['dev']} | {by_split['test']} | {by_split['holdout']} |"
        )
    return rows


def _headline_split(metrics: dict[str, Any]) -> str:
    """The split whose numbers stand for the rules: the holdout once opened, else test."""
    return "holdout" if "holdout" in metrics["cells"]["windows"] else "test"


def _flag(block: dict[str, Any]) -> str:
    return f"{pct(block['rate'])}（{block['flagged']} / {block['n']}）"


def _trusted_reference(metrics: dict[str, Any]) -> list[str]:
    ref = metrics.get("trusted_reference")
    if ref is None:
        return []
    out = [
        "## 参考：假机器的项目列入 trusted_projects",
        "",
        "不是消融行，也不是头条数字：同一批样本，只把假机器的项目设为受信任，用来看开发工具的询问"
        "有多少来自“项目没有被信任”。`trusted_projects` 默认关闭、不作为推荐设置。",
        "",
        "| 机器 / 切分 | 攻击拦截（ask + deny） | 达到要求 | 正常误报率 | 每 100 个正常动作的 ask |",
        "|---|---:|---:|---:|---:|",
    ]
    for machine in ("windows", "posix"):
        for split in ref[machine]:
            a, b = ref[machine][split]["attacks"], ref[machine][split]["benign"]
            out.append(
                f"| {machine} / {split} | {pct(a['block_rate'])} | {pct(a['meets_expected_rate'])} | "
                f"{pct(b['false_positive_rate'])} | {num(b['asks_per_100'])} |"
            )
    return [*out, ""]


def _machine_split(machine: str, split: str, cell: dict[str, Any]) -> list[str]:
    a, b = cell["attacks"], cell["benign"]
    out = [
        f"#### {machine} / {split}",
        "",
        "| 指标 | 值 |",
        "|---|---:|",
        f"| 攻击样本数 | {a['n']} |",
        f"| 攻击拦截率：ask | {pct(a['ask_rate'])}（{a['ask']}） |",
        f"| 　其中由规则命中的 ask | {pct(a['ask_by_rule_rate'])}（{a['ask_by_rule']}） |",
        f"| 　其中由灰色兜底转成的 ask（规则不认识，不确定就问） | {pct(a['ask_by_gray_rate'])}（{a['ask_by_gray']}） |",
        f"| 攻击拦截率：deny | {pct(a['deny_rate'])}（{a['deny']}） |",
        f"| 攻击拦截率：合计（ask + deny） | {pct(a['block_rate'])}（{a['ask'] + a['deny']}） |",
        f"| 达到样本要求的最低裁决（expected_min_verdict） | {pct(a['meets_expected_rate'])}（{a['meets_expected']}） |",
        f"| 　其中由规则裁决达到要求（不含灰色兜底） | {pct(a['meets_expected_by_rule_rate'])}（{a['meets_expected_by_rule']}） |",
        f"| 正常样本数 | {b['n']} |",
        f"| 正常操作误报率（ask 或 deny） | {pct(b['false_positive_rate'])}（ask {b['ask']}，deny {b['deny']}） |",
        f"| 其中：运行项目自身代码的命令（默认策略对未受信任项目有意地问） | {_flag(b['repo_code'])} |",
        f"| 其中：其余正常样本 | {_flag(b['other'])} |",
        f"| 其中灰色（规则判不了）转成的 ask | {b['of_which_gray']} |",
        f"| 打扰率：每 100 个正常动作的 ask 数 | {num(b['asks_per_100'])} |",
        f"| 规则路径延迟 p50 / p95（毫秒，进程内） | {num(cell['latency_rules']['p50_ms'], 2)} / {num(cell['latency_rules']['p95_ms'], 2)} |",
        "| LLM 路径延迟 p50 / p95 | 未运行 |",
        "",
    ]
    for kind, title in (("attacks", "攻击样本的裁决分布"), ("benign", "正常样本的裁决分布")):
        table = cell["by_category"][kind]
        if not table:
            continue
        out += [f"{title}：", "", "| 类别 | allow | ask | deny |", "|---|---:|---:|---:|"]
        out += [f"| {cat} | {v['allow']} | {v['ask']} | {v['deny']} |" for cat, v in table.items()]
        out.append("")
    for key, title in (
        ("misses", "漏报（前 10 条，按 id 排序）"),
        ("false_positives", "误报（前 10 条，按 id 排序）"),
    ):
        total = cell[f"{key}_total"]
        out.append(f"{title}，共 {total} 条：")
        out.append("")
        if not cell[key]:
            out += ["（无）", ""]
            continue
        out += ["| id | 类别 | 要求 | 实际 | 规则 | 原因 |", "|---|---|---|---|---|---|"]
        for row in cell[key]:
            rules = ", ".join(row["rule_ids"]) or "—"
            reasons = "; ".join(row["reasons"]).replace("|", "\\|") or "—"
            out.append(
                f"| {row['id']} | {row['category']} | {row['expected'] or 'allow'} | {row['verdict']} | {rules} | {reasons} |"
            )
        out.append("")
    return out


def _ablation(metrics: dict[str, Any]) -> list[str]:
    """The four rows; every configuration measured in this run gets numbers (``ablation``: the
    blocks of each, from the same samples, policy and date)."""
    split = _headline_split(metrics)
    measured: dict[str, Any] = dict(metrics.get("ablation") or {})
    if metrics["config"] not in measured:
        measured[metrics["config"]] = {
            m: {split: metrics["cells"][m][split]} for m in ("windows", "posix")
        }
    machines = ("windows", "posix")
    out = [
        "| 配置 | 状态 | "
        + " | ".join(f"{m} 拦截（{split}）" for m in machines)
        + " | "
        + " | ".join(f"{m} 达到要求（{split}）" for m in machines)
        + " | "
        + " | ".join(f"{m} 误报（{split}）" for m in machines)
        + " |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, available in CONFIGS.items():
        if available and name in measured:
            cells = [measured[name][m][split] for m in machines]
            row = (
                [pct(c["attacks"]["block_rate"]) for c in cells]
                + [pct(c["attacks"]["meets_expected_rate"]) for c in cells]
                + [pct(c["benign"]["false_positive_rate"]) for c in cells]
            )
            out.append(f"| {name} | 已运行 | " + " | ".join(row) + " |")
        elif available:
            out.append(f"| {name} | 这次运行没有测 | — | — | — | — | — | — |")
        else:
            out.append(f"| {name} | 未运行（M3b） | — | — | — | — | — | — |")
    return out


def _delta_rows(rows: list[dict[str, Any]]) -> list[str]:
    out = [
        "| id | 类别 | 之前（rules-only） | 之后（rules+taint） | 规则 |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        before = f"{row['before']}（{row['raw_before']}）"
        after = f"{row['after']}（{row['raw_after']}）"
        rules = ", ".join(row["rule_ids"]) or "—"
        out.append(f"| {row['id']} | {row['category']} | {before} | {after} | {rules} |")
    return out


def _taint_delta(metrics: dict[str, Any]) -> list[str]:
    changes = metrics.get("taint_delta")
    if changes is None:
        return []
    out = [
        "## rules+taint 相对 rules-only 的变化",
        "",
        "同一批样本、同一份策略、同一次运行。`rules+taint` 给每个样本一个自己的会话（真实的 "
        "`SessionStore`，内存库）：标了 `tainted` 的样本先收到一次污染来源的 PostToolUse，再判它"
        "自己的调用；其余样本在干净的会话里判。括号里是策略自己的结论（`gray` = 规则判不了）。",
        "",
        "| 机器 / 切分 | 在污染会话里判的样本 | 有效裁决改变 | 只有规则结论改变（有效裁决相同） |",
        "|---|---:|---:|---:|",
    ]
    for machine in ("windows", "posix"):
        for split, cell in changes[machine].items():
            out.append(
                f"| {machine} / {split} | {cell['tainted_samples']} | {cell['effective_changed']} | "
                f"{cell['raw_changed']} |"
            )
    out.append("")
    for machine in ("windows", "posix"):
        for split, cell in changes[machine].items():
            rows = cell["effective_rows"] + cell["raw_rows"]
            if not rows:
                continue
            out += [f"{machine} / {split} 里变化的样本（前 10 条）：", "", *_delta_rows(rows), ""]
    return out


def _taint_sensitivity(metrics: dict[str, Any]) -> list[str]:
    ref = metrics.get("taint_sensitivity")
    if ref is None:
        return []
    benign_tainted = _benign_tainted(metrics)
    if benign_tainted == 0:
        why = (
            "数据集里的正常样本没有一条标了 `tainted`，所以上面的 `rules+taint` 量不出污染层对正常"
            "操作的代价。"
        )
    else:
        why = (
            f"数据集里只有 {benign_tainted} 条正常样本标了 `tainted`，上面的 `rules+taint` 只量到"
            "它们。"
        )
    out = [
        "## 参考：每个样本都在刚读过不可信内容的会话里",
        "",
        f"不是消融行，也不是头条数字：{why}这里把全部样本（正常的也算）都放进刚调用过污染来源的"
        "会话里再判一次，给出这个代价的上限；“会话干净”两列取自 `rules-only`（没有一个样本在"
        "污染会话里）；“受信任”两列是假机器的项目列入 `trusted_projects` 时的同一组数字（开发"
        "工具的放行只在那里出现）。",
        "",
        "| 机器 / 切分 | 正常误报率：会话干净 | 正常误报率：全部污染 | 受信任：会话干净 | 受信任：全部污染 |",
        "|---|---:|---:|---:|---:|",
    ]
    for machine in ("windows", "posix"):
        for split in ref["clean"][machine]:
            values = [
                ref[key][machine][split]["benign"]["false_positive_rate"]
                for key in ("clean", "tainted", "trusted_clean", "trusted_tainted")
            ]
            out.append(f"| {machine} / {split} | " + " | ".join(pct(v) for v in values) + " |")
    return [*out, ""]


def _benign_tainted(metrics: dict[str, Any]) -> int | None:
    """How many benign samples are marked ``tainted`` (None: the run did not say)."""
    ref = metrics.get("taint_sensitivity")
    value = ref.get("benign_tainted") if isinstance(ref, dict) else None
    return value if isinstance(value, int) else None


def limitations(
    samples: Sequence[Sample], metrics: dict[str, Any], info: dict[str, Any]
) -> list[str]:
    counts = dataset.counts(samples)
    real = counts["origin"]["real"]
    synthetic = counts["origin"]["synthetic"]
    lines = [
        f"- 样本来源：真实会话导入 {real} 条（脱敏后经人逐条确认），合成样本 {synthetic} 条。"
        f"合成样本里 {counts['provenance']['llm-assisted']} 条由 LLM 助手起草、经人逐条确认"
        f"（不是作者独立手写），{counts['provenance']['handwritten']} 条由作者手写。"
        "攻击样本全部是合成的、惰性的（保留域名、金丝雀字符串），不是真实攻击流量的抽样。",
        "- 样本的分布由作者选定，不代表任何真实的攻击或使用分布；比例（拦截率、误报率）只在这份样本集内有意义，不能当作对真实世界的估计。",
        "- 规模：每个类别的条数见上表；条数少的单元格上，一条样本的变化就是几个百分点。",
        "- 正常样本主要来自作者一个人的工作流（Windows / PowerShell 为主），POSIX 的正常样本以合成为主。",
        "- 评测在假机器上进程内运行，不经过 Claude Code，也不访问真实磁盘；真实目录里的硬链接、符号链接、联接点不在评测范围内。",
        "- 延迟是进程内的规则管线耗时，不含 hook 客户端启动与守护进程往返（那部分见 scripts/bench_hook.py）。",
        "- test 集一经冻结就不再用于调规则；若规则在看过 test 结果之后又改了，必须在报告里声明 test 集已被污染。",
    ]
    short = [
        f"{cat} {counts['category'][cat]} 条"
        for cat in ATTACK_CATEGORIES
        if counts["category"][cat] < MIN_PER_CATEGORY
    ]
    if short:
        lines.append(
            f"- 以下攻击类别不足 {MIN_PER_CATEGORY} 条，这些类别的比例只能当作粗略的提示："
            + "、".join(short)
            + "。"
        )
    if metrics.get("taint_delta") is not None:
        benign_tainted = _benign_tainted(metrics)
        cost = (
            "数据集里没有一条正常样本标了 `tainted`，污染层对正常操作的代价只能看“全部污染”的参考表。"
            if benign_tainted == 0
            else f"数据集里标了 `tainted` 的正常样本有 {benign_tainted} 条，"
            "污染层对其余正常操作的代价看“全部污染”的参考表。"
            if benign_tainted is not None
            else "污染层对正常操作的代价看“全部污染”的参考表。"
        )
        lines.append(
            "- `rules+taint` 的会话是模拟的：每个样本是单独一次调用，污染只是它之前的一次来源调用；"
            "跨多步的链（例如先写测试文件、再运行 pytest）不在样本集里，只有单元测试覆盖。" + cost
        )
    if info.get("test_contaminated"):
        lines.append(
            "- **test 切分已被污染**：规则是在看过 test 切分的结果之后改的（动机来自 dev 的原因统计和规则自身的理由，但严格说，test 不再能给改后的规则一个无偏的估计）。这份报告里 test 列只能和 dev 列一起当作参考，需要换一个新的留出集才能做无偏比较。"
        )
    lines += _holdout_lines(info)
    if info.get("include_unconfirmed"):
        lines.append(
            "- 本报告包含未经人工确认的样本（--include-unconfirmed）：只能用于调试，不能发布。"
        )
    elif info.get("left_out_unconfirmed"):
        lines.append(
            f"- 有 {info['left_out_unconfirmed']} 个样本尚未经人工确认，没有计入任何数字。"
        )
    if metrics["skipped"]:
        lines.append(
            f"- 有 {len(metrics['skipped'])} 个样本因本机没有 PowerShell 解析器而跳过，没有计入任何数字。"
        )
    return lines


def _holdout_lines(info: dict[str, Any]) -> list[str]:
    return [_batch_line(batch) for batch in info.get("holdout_batches", [])]


def _batch_line(batch: dict[str, Any]) -> str:
    name, earlier = batch["batch"], batch["earlier_openings"]
    head = f"- 留出集 {name}（{batch['samples']} 条，指纹 `{str(batch['hash'])[:16]}…`）"
    if not batch["opened"]:
        if not earlier:
            return head + "已封存，这次运行没有打开，上面的数字里没有它。"
        line = (
            head + f"已经打开过 {earlier} 次（`eval/holdout-ledger.jsonl`），这次运行没有打开，"
            "上面的数字里没有它。"
        )
        if batch["contaminated"]:
            line += (
                f"**它已被污染**：{batch['contamination_why']}；"
                "再打开得到的数字不是无偏估计，需要一个新的留出批次。"
            )
        return line
    if batch["contaminated"]:
        return (
            f"- **留出集 {name} 已被污染**：{batch['contamination_why']}。这次的留出集数字"
            "只能当作参考，不能作为无偏估计；需要一个新的留出批次。"
        )
    if earlier:
        return head + f"在同一份策略下已经打开过 {earlier} 次，策略与样本都没有变，数字仍然有效。"
    return (
        head + "第一次打开，记在 `eval/holdout-ledger.jsonl`。从现在起，只要规则或这一批样本"
        "再变，之后打开的结果就会被自动声明为已污染。"
    )


def _batch_state(batch: dict[str, Any]) -> str:
    if batch["opened"]:
        return "这次打开，已污染" if batch["contaminated"] else "这次打开"
    if batch["earlier_openings"]:
        return "以前打开过，" + ("已污染，" if batch["contaminated"] else "") + "这次未打开"
    return "封存，未打开"


def to_markdown(metrics: dict[str, Any], samples: Sequence[Sample], info: dict[str, Any]) -> str:
    holdout_note = "".join(
        f"；留出集 {b['batch']} 指纹 `{str(b['hash'])[:16]}…`（{_batch_state(b)}）"
        for b in info.get("holdout_batches", [])
    )
    lines = [
        "# 评测报告（生成物，不要手改）",
        "",
        f"- 配置：`{metrics['config']}`；指标口径版本：{metrics['metrics_version']}（见 docs/eval-methodology.md）",
        f"- 策略：{metrics['policy']}（sha256 `{metrics['policy_sha256'][:16]}…`）",
        f"- 运行日期：{info['date']}；boundkeep {info['version']}；Python {info['python']}；主机 {info['host']}",
        f"- 数据集：dev 指纹 `{info['dev_hash'][:16]}…`，test 指纹 `{info['test_hash'][:16]}…`（冻结的 test 集，改动会改变指纹）{holdout_note}",
        "",
        "## 数据集",
        "",
        *_dataset_table(samples),
        "",
        "## 消融（四行）",
        "",
        *_ablation(metrics),
        "",
        f"LLM 行：{LLM_NOTE}。",
        "",
        *_taint_delta(metrics),
        f"## 结果（`{metrics['config']}`，按平台与切分分别报告，不合并）",
        "",
    ]
    for machine in ("windows", "posix"):
        lines += [f"### {MACHINE_TITLES[machine]}", ""]
        for split, cell in metrics["cells"][machine].items():
            lines += _machine_split(machine, split, cell)
    lines += [
        *_trusted_reference(metrics),
        *_taint_sensitivity(metrics),
        "## 局限性",
        "",
        *limitations(samples, metrics, info),
        "",
    ]
    return "\n".join(lines)
