# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the benchmark history chart and README section."""

import importlib.util
import json
from pathlib import Path

import pytest


def _load_history():
    spec = importlib.util.spec_from_file_location(
        "fuzz_benchmark_history",
        Path(__file__).parent.parent / "scripts" / "fuzzing" / "benchmark_history.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def history():
    return _load_history()


def _run(started, commit, coverage, model="claude-sonnet-5", effort="high"):
    return {
        "started_at": started,
        "finished_at": started,
        "commit": commit * 40,
        "versions": {},
        "models": {"code_analysis": model, "general_tasks": "small-model"},
        "model_settings": {"code_analysis": {"reasoning": {"effort": effort}}},
        "settings": {},
        "projects": [
            {
                "repo": repo,
                "duration_seconds": 60,
                "targets": 3,
                "harnesses_built": 2,
                "harnesses_total": 3,
                "afl_runs": 12,
                "crashes": 1 if pct else 0,
                "best_line_pct": pct,
                "verdicts": {"vulnerability": 2, "oom": 1} if pct else {},
            }
            for repo, pct in coverage.items()
        ],
    }


RUNS = [
    _run("2026-09-01T10:00:00Z", "a", {"demo/xz": 40.0, "demo/json": 70.0}, model="old-model", effort="low"),
    _run("2026-09-20T10:00:00Z", "b", {"demo/xz": 42.5, "demo/json": None}, effort="medium"),
    _run("2026-10-16T09:30:00Z", "c", {"demo/xz": 43.0, "demo/json": 71.2, "demo/new": 10.0}),
]


def _write_runs(directory, runs):
    directory.mkdir(parents=True, exist_ok=True)
    for run in runs:
        stamp = run["started_at"].replace("-", "").replace(":", "")
        (directory / f"{stamp}_{run['commit'][:7]}.json").write_text(json.dumps(run))


def _root(tmp_path):
    root = tmp_path / "root"
    (root / "benchmark").mkdir(parents=True)
    (root / "README.md").write_text(
        "# Demo\n\nBefore\n\n<!-- benchmark-history:start -->\nold\n<!-- benchmark-history:end -->\n\nAfter\n"
    )
    return root


def test_reasoning_effort_reads_both_config_forms(history):
    settings = {"a": {"reasoning": {"effort": "high"}}, "b": {"reasoning_effort": "xhigh"}, "c": {"temperature": 0}}
    assert history.reasoning_effort(settings, "a") == "high"
    assert history.reasoning_effort(settings, "b") == "xhigh"
    assert history.reasoning_effort(settings, "c") is None
    assert history.reasoning_effort(settings, "missing") is None
    assert history.reasoning_effort(None, "a") is None


def test_load_runs_oldest_first(history, tmp_path):
    _write_runs(tmp_path, reversed(RUNS))
    assert [r["commit"][0] for r in history.load_runs(tmp_path)] == ["a", "b", "c"]


def test_render_section_shows_latest_run_with_deltas(history):
    section = history.render_section(RUNS)

    assert section.startswith(history.START_MARKER + "\n")
    assert section.endswith("\n" + history.END_MARKER)
    assert 'srcset="benchmark/history-dark.svg"' in section
    assert 'src="benchmark/history-light.svg"' in section
    assert (
        f"Latest run: 2026-10-16 · commit [`ccccccc`]({history.REPO_URL}/commit/{'c' * 40}) · "
        "code_analysis: claude-sonnet-5 (high effort) · general_tasks: small-model (default effort)"
    ) in section
    # demo/xz compares with run b; demo/json skips run b (no coverage) and compares with run a.
    assert "| `demo/xz` | 43.0% | +0.5 pp | 3 | 2/3 | 12 | 1 | `vulnerability` (×2), `oom` |" in section
    assert "| `demo/json` | 71.2% | +1.2 pp |" in section
    assert "| `demo/new` | 10.0% | — |" in section


def test_render_section_without_runs(history):
    section = history.render_section([])
    assert "No recorded runs yet" in section
    assert "<picture>" not in section


def test_update_readme_replaces_only_the_marked_section(history, tmp_path):
    readme = _root(tmp_path) / "README.md"
    history.update_readme(readme, history.render_section(RUNS))
    text = readme.read_text()
    assert text.startswith("# Demo\n\nBefore\n\n" + history.START_MARKER)
    assert text.endswith(history.END_MARKER + "\n\nAfter\n")
    assert "\nold\n" not in text
    assert text.count(history.START_MARKER) == text.count(history.END_MARKER) == 1


def test_update_readme_without_markers(history, tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# No markers\n")
    with pytest.raises(ValueError, match="benchmark-history"):
        history.update_readme(readme, history.render_section([]))


def test_regenerate_without_runs_removes_stale_svgs(history, tmp_path):
    root = _root(tmp_path)
    stale = history.svg_path(root, "light")
    stale.write_text("<svg/>")
    history.regenerate(root)
    assert not stale.exists()
    assert "No recorded runs yet" in (root / "README.md").read_text()


def test_regenerate_writes_svgs_and_readme(history, tmp_path):
    pytest.importorskip("matplotlib")
    root = _root(tmp_path)
    _write_runs(history.results_dir(root), RUNS)
    history.regenerate(root)
    for theme in history.THEMES:
        svg = history.svg_path(root, theme).read_text()
        assert svg.startswith("<?xml")
        for text in ("demo/xz", "demo/json", "demo/new", "claude-sonnet-5", "old-model", "low", "medium", "high"):
            assert text in svg
    assert "Latest run: 2026-10-16" in (root / "README.md").read_text()


def test_render_svg_is_deterministic(history):
    pytest.importorskip("matplotlib")
    svg = history.render_svg(RUNS, "dark")
    assert svg == history.render_svg(RUNS, "dark")
    assert "<dc:date>" not in svg
    assert "Matplotlib v" not in svg
    assert history.THEMES["dark"]["palette"][0] in svg
