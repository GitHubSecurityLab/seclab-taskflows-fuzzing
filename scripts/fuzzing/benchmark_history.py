#!/usr/bin/env python3
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Render the recorded benchmark history.

Reads the runs in ``benchmark/results/*.json`` (written by
``run_benchmark.py --record``) and regenerates:

    benchmark/history-light.svg, benchmark/history-dark.svg
        best line coverage per project across runs; the marker colour is the
        code_analysis model and its shape the model's reasoning effort
    the section of README.md between the benchmark-history markers
        the chart plus the latest run's results table

Usage:
    python scripts/fuzzing/benchmark_history.py

The SVGs need matplotlib (``pip install '.[benchmark]'``).
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
REPO_URL = "https://github.com/GitHubSecurityLab/seclab-taskflows-fuzzing"
START_MARKER = "<!-- benchmark-history:start -->"
END_MARKER = "<!-- benchmark-history:end -->"
# Reasoning efforts a recorded run may use, with their chart markers.
EFFORT_MARKERS = {"low": "o", "medium": "s", "high": "^", "xhigh": "D", "max": "*"}
EFFORTS = tuple(EFFORT_MARKERS)
THEMES = {
    "light": {
        "text": "#1f2328",
        "muted": "#59636e",
        "grid": "#d1d9e0",
        "line": "#9198a1",
        "palette": ("#0969da", "#bc4c00", "#8250df", "#1a7f37", "#cf222e", "#bf3989", "#9a6700"),
    },
    "dark": {
        "text": "#f0f6fc",
        "muted": "#9198a1",
        "grid": "#3d444d",
        "line": "#656c76",
        "palette": ("#4493f8", "#f0883e", "#ab7df8", "#3fb950", "#f85149", "#db61a2", "#d29922"),
    },
}


def results_dir(root: Path) -> Path:
    return root / "benchmark" / "results"


def svg_path(root: Path, theme: str) -> Path:
    return root / "benchmark" / f"history-{theme}.svg"


def reasoning_effort(model_settings: dict | None, role: str) -> str | None:
    """The reasoning effort model_config.yaml sets for *role*, if any.

    ``reasoning: {effort: ...}`` is the openai_agents / anthropic_sdk form,
    ``reasoning_effort`` the copilot_sdk one.
    """
    settings = (model_settings or {}).get(role) or {}
    reasoning = settings.get("reasoning")
    if isinstance(reasoning, dict) and reasoning.get("effort"):
        return reasoning["effort"]
    return settings.get("reasoning_effort")


def fmt_verdicts(verdicts: dict[str, int]) -> str:
    if not verdicts:
        return "—"
    return ", ".join(f"`{v}`" + (f" (×{n})" if n > 1 else "") for v, n in verdicts.items())


def load_runs(directory: Path) -> list[dict]:
    """Recorded runs, oldest first."""
    runs = [json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))]
    return sorted(runs, key=lambda r: r["started_at"])


def _started(run: dict) -> datetime.datetime:
    return datetime.datetime.strptime(run["started_at"], "%Y-%m-%dT%H:%M:%SZ")


def _coverage(run: dict, repo: str) -> float | None:
    return next((p["best_line_pct"] for p in run["projects"] if p["repo"] == repo), None)


def _model_label(run: dict, role: str) -> str:
    model = run["models"].get(role, "unknown")
    effort = reasoning_effort(run.get("model_settings"), role)
    return f"{model} ({effort or 'default'} effort)"


def render_svg(runs: list[dict], theme_name: str) -> str:
    """One panel per project in the latest run, plus a legend panel."""
    import matplotlib
    import matplotlib.dates as mdates
    from matplotlib.figure import Figure
    from matplotlib.lines import Line2D
    from matplotlib.ticker import MaxNLocator

    theme = THEMES[theme_name]
    repos = [p["repo"] for p in runs[-1]["projects"]]
    models: list[str] = []
    for run in runs:
        model = run["models"].get("code_analysis", "unknown")
        if model not in models:
            models.append(model)
    colours = {m: theme["palette"][i % len(theme["palette"])] for i, m in enumerate(models)}
    efforts = {reasoning_effort(r.get("model_settings"), "code_analysis") for r in runs}

    ncols = 3
    nrows = math.ceil((len(repos) + 1) / ncols)
    rc = {"svg.hashsalt": "benchmark-history", "svg.fonttype": "none", "font.size": 10}
    with matplotlib.rc_context(rc):
        fig = Figure(figsize=(10.5, 2.8 * nrows))
        axes = fig.subplots(nrows, ncols, sharex=True, squeeze=False).ravel()
        times = [_started(r) for r in runs]
        for ax, repo in zip(axes, repos):
            pts = [(t, _coverage(r, repo), r) for t, r in zip(times, runs)]
            pts = [(t, v, r) for t, v, r in pts if v is not None]
            ax.set_title(repo, loc="left", fontsize=10, color=theme["text"], fontweight="bold")
            ax.grid(axis="y", color=theme["grid"], lw=0.8)
            ax.set_axisbelow(True)
            ax.tick_params(colors=theme["muted"], labelsize=9, labelbottom=True)
            for side in ("top", "right"):
                ax.spines[side].set_visible(False)
            for side in ("left", "bottom"):
                ax.spines[side].set_color(theme["grid"])
            if not pts:
                continue
            values = [v for _, v, _ in pts]
            ax.plot([t for t, _, _ in pts], values, color=theme["line"], lw=1, zorder=1)
            for t, v, run in pts:
                effort = reasoning_effort(run.get("model_settings"), "code_analysis")
                ax.scatter(
                    t,
                    v,
                    color=colours[run["models"].get("code_analysis", "unknown")],
                    marker=EFFORT_MARKERS.get(effort, "X"),
                    s=38,
                    zorder=2,
                )
            ax.annotate(
                f"{values[-1]:.1f}%",
                (pts[-1][0], values[-1]),
                xytext=(6, 0),
                textcoords="offset points",
                va="center",
                fontsize=9,
                color=theme["text"],
            )
            lo, hi = min(values), max(values)
            pad = max(3.0, (hi - lo) * 0.15)
            ax.set_ylim(max(0.0, lo - pad), min(100.0, hi + pad))
            ax.yaxis.set_major_locator(MaxNLocator(nbins=5, steps=[1, 2, 5, 10], integer=True))
            ax.yaxis.set_major_formatter(lambda x, _: f"{x:.0f}%")
        locator = mdates.AutoDateLocator(minticks=2, maxticks=6)
        axes[0].xaxis.set_major_locator(locator)
        axes[0].xaxis.set_major_formatter(mdates.ConciseDateFormatter(locator))
        span = max(times) - min(times)
        margin = max(span * 0.08, datetime.timedelta(days=2))
        axes[0].set_xlim(min(times) - margin, max(times) + margin)

        legend_ax = axes[len(repos)]
        for ax in axes[len(repos) :]:
            ax.axis("off")
        model_handles = [Line2D([], [], ls="", marker="o", ms=7, color=colours[m], label=m) for m in models]
        effort_handles = [
            Line2D([], [], ls="", marker=EFFORT_MARKERS[e], ms=7, color=theme["muted"], label=e)
            for e in EFFORTS
            if e in efforts
        ]
        if efforts - set(EFFORTS):
            effort_handles.append(Line2D([], [], ls="", marker="X", ms=7, color=theme["muted"], label="other"))
        common = {"frameon": False, "labelcolor": theme["text"], "alignment": "left", "fontsize": 9}
        first = legend_ax.legend(handles=model_handles, title="code_analysis model", loc="upper left", **common)
        first.get_title().set_color(theme["text"])
        legend_ax.add_artist(first)

        fig.suptitle("Best line coverage per recorded run", x=0.01, ha="left", fontsize=12, color=theme["text"])
        fig.tight_layout()
        # Stack the effort legend right below the model legend, whose height depends on the number of models.
        fig.draw_without_rendering()
        below = legend_ax.transAxes.inverted().transform(first.get_window_extent())[0][1]
        second = legend_ax.legend(
            handles=effort_handles,
            title="Reasoning effort",
            loc="upper left",
            bbox_to_anchor=(0, below - 0.04),
            **common,
        )
        second.get_title().set_color(theme["text"])
        buf = io.StringIO()
        fig.savefig(
            buf,
            format="svg",
            metadata={"Date": None, "Creator": None},
            transparent=True,
            bbox_inches="tight",
            pad_inches=0.1,
        )
    return buf.getvalue()


def render_section(runs: list[dict]) -> str:
    """README section (including the markers) for *runs*."""
    lines = [
        START_MARKER,
        "<!-- Generated by scripts/fuzzing/benchmark_history.py from benchmark/results/; don't edit by hand. -->",
        "",
    ]
    if not runs:
        lines += ["No recorded runs yet; see [Recording a run](benchmark/README.md#recording-a-run).", ""]
        return "\n".join([*lines, END_MARKER])
    latest, previous = runs[-1], runs[:-1]
    sha = latest["commit"]
    lines += [
        "<picture>",
        '  <source media="(prefers-color-scheme: dark)" srcset="benchmark/history-dark.svg">',
        '  <img alt="Best line coverage per benchmark project across recorded runs" src="benchmark/history-light.svg">',
        "</picture>",
        "",
        (
            f"Latest run: {_started(latest):%Y-%m-%d} · commit [`{sha[:7]}`]({REPO_URL}/commit/{sha}) · "
            f"code_analysis: {_model_label(latest, 'code_analysis')} · "
            f"general_tasks: {_model_label(latest, 'general_tasks')}"
        ),
        "",
        "| Repo | Best line cov | Δ vs previous run | Targets | Harnesses built | AFL runs | Crashes | Verdicts seen |",
        "|------|---------------|-------------------|---------|-----------------|----------|---------|---------------|",
    ]
    for p in latest["projects"]:
        cur = p["best_line_pct"]
        prev = next((v for r in reversed(previous) if (v := _coverage(r, p["repo"])) is not None), None)
        cov = "—" if cur is None else f"{cur:.1f}%"
        delta = "—" if cur is None or prev is None else f"{cur - prev:+.1f} pp"
        lines.append(
            f"| `{p['repo']}` | {cov} | {delta} | {p['targets']} | {p['harnesses_built']}/{p['harnesses_total']} "
            f"| {p['afl_runs']} | {p['crashes']} | {fmt_verdicts(p['verdicts'])} |"
        )
    return "\n".join([*lines, "", END_MARKER])


def update_readme(readme: Path, section: str) -> None:
    text = readme.read_text()
    start, end = text.find(START_MARKER), text.find(END_MARKER)
    if start < 0 or end < start:
        raise ValueError(f"{readme} has no {START_MARKER} ... {END_MARKER} section")
    readme.write_text(text[:start] + section + text[end + len(END_MARKER) :])


def regenerate(root: Path = ROOT) -> None:
    """Rewrite the SVGs and the README section of *root* from its recorded runs."""
    runs = load_runs(results_dir(root))
    for theme in THEMES:
        path = svg_path(root, theme)
        if runs:
            path.write_text(render_svg(runs, theme))
        else:
            path.unlink(missing_ok=True)
    update_readme(root / "README.md", render_section(runs))


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__.split("\n\n")[0]).parse_args(argv)
    regenerate()
    print("[benchmark_history] regenerated benchmark/history-*.svg and the README.md section")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
