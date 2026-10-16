#!/usr/bin/env python3
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Run the fuzzing benchmark end-to-end and write a results summary.

Runs ``run_fuzzing.sh`` once per project in ``benchmark/projects.yaml`` (or
once per ``owner/repo`` given on the command line), keeps going when a project
fails, and writes ``summary.md`` / ``summary.json`` with per-project results.

Usage:
    python scripts/fuzzing/run_benchmark.py                    # every project
    python scripts/fuzzing/run_benchmark.py DaveGamble/cJSON   # a subset
    python scripts/fuzzing/run_benchmark.py --out DIR          # pick the results dir
    python scripts/fuzzing/run_benchmark.py --record           # add the run to the benchmark history

Each benchmark run gets its own results directory (default
``~/.local/share/seclab-taskflow-agent/benchmarks/<UTC timestamp>/``), so its
numbers don't mix with earlier runs:

    data/          DATA_DIR: fuzz_context.db, fuzz_runner workspace, sources
    logs/          LOG_DIR: MCP server logs and one <owner>__<repo>.log per project
    summary.md     results table
    summary.json   the same numbers plus run metadata

The summary is rewritten after every project, so an interrupted run still
leaves results for the projects that finished. The dashboard serves this run's
database on ``FUZZ_DASHBOARD_PORT`` (default 8765) unless ``FUZZ_NO_DASHBOARD=1``.

With ``--record``, a full run from a clean checkout in which every project
finishes is also saved to ``benchmark/results/<UTC timestamp>_<commit>.json``,
and ``benchmark_history.py`` regenerates the history chart and the results
section of README.md from those files.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import yaml

import benchmark_history as history  # sibling script; this script's directory is on sys.path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
RUN_FUZZING = SCRIPT_DIR / "run_fuzzing.sh"
PROJECTS_FILE = ROOT / "benchmark" / "projects.yaml"
MODEL_CONFIG = ROOT / "src" / "seclab_taskflows_fuzzing" / "configs" / "model_config.yaml"
# Under the agent's data root so the dashboard's /file endpoint can serve
# coverage HTML and reports produced by benchmark runs.
DEFAULT_OUT_ROOT = Path.home() / ".local/share/seclab-taskflow-agent/benchmarks"
# run_fuzzing.sh knobs; their defaults are read from the script.
FUZZ_SETTINGS = ("HARNESS_CANDIDATES", "QUALIFIER_SECONDS", "FUZZ_PLATEAU_THRESHOLD_PCT")
PACKAGES = ("seclab-taskflows-fuzzing", "seclab-taskflows", "seclab-taskflow-agent")
RECORDED_FIELDS = (
    "repo",
    "duration_seconds",
    "targets",
    "harnesses_built",
    "harnesses_total",
    "afl_runs",
    "crashes",
    "best_line_pct",
    "verdicts",
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(ts: datetime.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_projects(path: Path = PROJECTS_FILE) -> list[str]:
    data = yaml.safe_load(path.read_text()) or {}
    return [p["repo"] for p in data.get("projects", [])]


def repo_stats(db_path: Path, repo: str) -> dict:
    """Per-repo numbers from fuzz_context.db (zeros if the DB isn't populated yet)."""
    stats = {
        "targets": 0,
        "harnesses_built": 0,
        "harnesses_total": 0,
        "afl_runs": 0,
        "crashes": 0,
        "best_line_pct": None,
        "verdicts": {},
    }
    if not db_path.is_file():
        return stats
    harness = "harness h WHERE lower(h.repo) = lower(?)"
    runs = "fuzz_run fr JOIN harness h ON fr.harness_id = h.id WHERE lower(h.repo) = lower(?)"
    crashes = (
        "crash c JOIN fuzz_run fr ON c.run_id = fr.id JOIN harness h ON fr.harness_id = h.id "
        "WHERE lower(h.repo) = lower(?)"
    )
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:

        def one(sql: str):
            return conn.execute(sql, (repo,)).fetchone()[0]

        stats["targets"] = one("SELECT COUNT(*) FROM fuzz_target WHERE lower(repo) = lower(?)")
        stats["harnesses_total"] = one(f"SELECT COUNT(*) FROM {harness}")
        # 'superseded' harnesses built fine but lost the qualifier round.
        stats["harnesses_built"] = one(f"SELECT COUNT(*) FROM {harness} AND h.build_status IN ('ok', 'superseded')")
        stats["afl_runs"] = one(f"SELECT COUNT(*) FROM {runs}")
        stats["crashes"] = one(f"SELECT COUNT(*) FROM {crashes}")
        stats["best_line_pct"] = one(
            "SELECT MAX(cr.line_pct) FROM coverage_report cr "
            "JOIN fuzz_run fr ON cr.run_id = fr.id JOIN harness h ON fr.harness_id = h.id "
            "WHERE lower(h.repo) = lower(?)"
        )
        stats["verdicts"] = dict(
            conn.execute(
                f"SELECT COALESCE(c.verdict, 'unclassified'), COUNT(*) FROM {crashes} GROUP BY 1 ORDER BY 2 DESC, 1",
                (repo,),
            ).fetchall()
        )
    except sqlite3.OperationalError:
        pass  # schema not created yet
    finally:
        conn.close()
    return stats


def git_state() -> tuple[str | None, bool]:
    """HEAD's full commit SHA (None outside a git checkout) and whether the tree has changes."""

    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
        except OSError:
            return None
        return proc.stdout if proc.returncode == 0 else None

    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain")
    return (head.strip() if head else None), bool(status and status.strip())


def fuzz_settings() -> dict[str, str | None]:
    """The run_fuzzing.sh knobs this run uses: the environment, else the script's defaults."""
    script = RUN_FUZZING.read_text()
    settings = {}
    for name in FUZZ_SETTINGS:
        default = re.search(r"\$\{" + name + r":-([^}]*)\}", script)
        settings[name] = os.environ.get(name) or (default.group(1) if default else None)
    return settings


def ai_endpoint() -> str | None:
    try:
        from seclab_taskflow_agent.capi import get_AI_endpoint
    except ImportError:
        return os.environ.get("AI_API_ENDPOINT")
    return get_AI_endpoint()


def run_metadata() -> dict:
    """What produced these numbers: commit, package versions, models, settings."""
    versions = {}
    for pkg in PACKAGES:
        try:
            versions[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            versions[pkg] = None
    commit, dirty = git_state()
    try:
        config = yaml.safe_load(MODEL_CONFIG.read_text()) or {}
    except OSError:
        config = {}
    model_settings = {
        role: {k: v for k, v in (settings or {}).items() if k != "token"}
        for role, settings in (config.get("model_settings") or {}).items()
    }
    return {
        "commit": commit,
        "dirty": dirty,
        "versions": versions,
        "models": config.get("models") or {},
        "model_settings": model_settings,
        "settings": {"AI_API_ENDPOINT": ai_endpoint(), **fuzz_settings()},
    }


def _has_matplotlib() -> bool:
    return importlib.util.find_spec("matplotlib") is not None


def record_problems(repos_given: bool, meta: dict) -> list[str]:
    """Why this run can't be recorded (checked before it starts)."""
    problems = []
    if repos_given:
        problems.append("--record needs a full run of benchmark/projects.yaml; drop the owner/repo arguments")
    if meta["commit"] is None:
        problems.append(f"{ROOT} is not a git checkout")
    elif meta["dirty"]:
        problems.append("the checkout has uncommitted or untracked changes (see `git status`)")
    effort = history.reasoning_effort(meta["model_settings"], "code_analysis")
    if effort not in history.EFFORTS:
        current = "doesn't set" if effort is None else f"sets {effort!r} as"
        problems.append(
            f"model_config.yaml {current} the code_analysis reasoning effort; "
            f"set it to one of {', '.join(history.EFFORTS)}"
        )
    if not _has_matplotlib():
        problems.append("matplotlib is missing; install it with `pip install '.[benchmark]'`")
    return problems


def record_run(summary: dict, root: Path) -> Path:
    """Save a finished run to <root>/benchmark/results/ and return the file."""
    meta = summary["meta"]
    record = {
        "started_at": summary["started_at"],
        "finished_at": _iso(_now()),
        "commit": meta["commit"],
        "versions": meta["versions"],
        "models": meta["models"],
        "model_settings": meta["model_settings"],
        "settings": meta["settings"],
        "projects": [{k: p[k] for k in RECORDED_FIELDS} for p in summary["projects"]],
    }
    stamp = summary["started_at"].replace("-", "").replace(":", "")
    path = history.results_dir(root) / f"{stamp}_{meta['commit'][:7]}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    return path


def _fmt_duration(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _models_line(meta: dict) -> str:
    parts = []
    for role, model in meta["models"].items():
        effort = history.reasoning_effort(meta["model_settings"], role)
        parts.append(f"{role}={model}" + (f" ({effort} effort)" if effort else ""))
    return ", ".join(parts) or "unknown"


def render_markdown(summary: dict) -> str:
    meta = summary["meta"]
    versions = ", ".join(f"{k} {v or 'not installed'}" for k, v in meta["versions"].items())
    commit = f"`{meta['commit'][:12]}`" if meta["commit"] else "unknown"
    if meta["dirty"]:
        commit += " with uncommitted changes"
    settings = ", ".join(f"{k}={v}" for k, v in meta["settings"].items())
    lines = [
        "# Fuzzing benchmark results",
        "",
        f"- Started {summary['started_at']}, last updated {summary['updated_at']}",
        f"- Commit {commit}; {versions}",
        f"- Models: {_models_line(meta)}",
        f"- Settings: {settings}",
        "",
        "| Repo | Status | Duration | Targets | Harnesses built | AFL runs | Crashes | Best line cov | Verdicts seen |",
        "|------|--------|----------|---------|-----------------|----------|---------|---------------|---------------|",
    ]
    for p in summary["projects"]:
        status = p["status"] if p["exit_code"] in (0, None) else f"{p['status']} (exit {p['exit_code']})"
        cov = "—" if p["best_line_pct"] is None else f"{p['best_line_pct']:.1f}%"
        lines.append(
            f"| `{p['repo']}` | [{status}]({p['log']}) | {_fmt_duration(p['duration_seconds'])} "
            f"| {p['targets']} | {p['harnesses_built']}/{p['harnesses_total']} | {p['afl_runs']} "
            f"| {p['crashes']} | {cov} | {history.fmt_verdicts(p['verdicts'])} |"
        )
    return "\n".join(lines) + "\n"


def write_summary(out: Path, summary: dict) -> None:
    summary["updated_at"] = _iso(_now())
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    (out / "summary.md").write_text(render_markdown(summary))


def run_project(repo: str, env: dict[str, str], log_path: Path) -> int:
    """Run run_fuzzing.sh for one repo, copying its output to the console and log_path."""
    with (
        log_path.open("w", encoding="utf-8") as log,
        subprocess.Popen(
            [str(RUN_FUZZING), repo],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as proc,
    ):
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
            log.flush()
        return proc.wait()


def start_dashboard(db_path: Path, log_path: Path) -> subprocess.Popen | None:
    if os.environ.get("FUZZ_NO_DASHBOARD") == "1":
        return None
    port = os.environ.get("FUZZ_DASHBOARD_PORT", "8765")
    with log_path.open("w") as log:
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT_DIR / "dashboard.py"), "--port", port, "--db", str(db_path)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    time.sleep(1)
    if proc.poll() is not None:
        print(f"[run_benchmark] WARNING: dashboard failed to start (port {port} in use?); see {log_path}")
        return None
    print(f"[run_benchmark] dashboard on http://127.0.0.1:{port}")
    return proc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fuzzing benchmark and summarise the results.")
    parser.add_argument(
        "repos",
        nargs="*",
        metavar="owner/repo",
        help="projects to run (default: every entry in benchmark/projects.yaml)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="results directory (default: ~/.local/share/seclab-taskflow-agent/benchmarks/<UTC timestamp>)",
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help="add the run to benchmark/results/ and regenerate the history chart and README section "
        "(needs a full run from a clean checkout; only recorded if every project finishes)",
    )
    args = parser.parse_args(argv)

    meta = run_metadata()
    if args.record and (problems := record_problems(bool(args.repos), meta)):
        for problem in problems:
            print(f"[run_benchmark] can't record: {problem}", file=sys.stderr)
        return 2

    repos = args.repos or load_projects()
    started = _now()
    out = (args.out or DEFAULT_OUT_ROOT / started.strftime("%Y%m%dT%H%M%SZ")).resolve()
    data, logs = out / "data", out / "logs"
    # fuzz_context silently falls back to an in-memory DB if its directory is missing.
    data.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    db = data / "fuzz_context.db"

    env = os.environ.copy()
    # The toolboxes derive their data dirs from DATA_DIR, but run_fuzzing.sh's
    # plateau check imports fuzz_context directly and reads FUZZ_CONTEXT_DIR.
    env.update(DATA_DIR=str(data), FUZZ_CONTEXT_DIR=str(data), LOG_DIR=str(logs), FUZZ_NO_DASHBOARD="1")

    summary = {
        "started_at": _iso(started),
        "updated_at": None,
        "out_dir": str(out),
        "meta": meta,
        "projects": [],
    }
    print(f"[run_benchmark] {len(repos)} project(s); results in {out}")
    dashboard = start_dashboard(db, logs / "dashboard.log")
    try:
        for i, repo in enumerate(repos, 1):
            print(f"[run_benchmark] === {i}/{len(repos)}: {repo} ===", flush=True)
            log = logs / f"{repo.replace('/', '__')}.log"
            entry = {"repo": repo, "status": "interrupted", "exit_code": None, "duration_seconds": None}
            entry["log"] = str(log.relative_to(out))
            summary["projects"].append(entry)
            t0 = time.monotonic()
            try:
                rc = run_project(repo, env, log)
                entry["status"] = "ok" if rc == 0 else "failed"
                entry["exit_code"] = rc
            finally:
                entry["duration_seconds"] = round(time.monotonic() - t0)
                entry.update(repo_stats(db, repo))
                write_summary(out, summary)
    except KeyboardInterrupt:
        print(f"[run_benchmark] interrupted; partial summary in {out / 'summary.md'}")
        return 130
    finally:
        if dashboard is not None:
            dashboard.terminate()

    print(f"[run_benchmark] done; summary in {out / 'summary.md'}")
    failed = [p["repo"] for p in summary["projects"] if p["status"] != "ok"]
    if not args.record:
        return 1 if failed else 0
    if failed:
        print(f"[run_benchmark] not recorded: {', '.join(failed)} didn't finish", file=sys.stderr)
        return 1
    if git_state() != (meta["commit"], False):
        print("[run_benchmark] not recorded: the checkout changed during the run", file=sys.stderr)
        return 1
    path = record_run(summary, ROOT)
    history.regenerate(ROOT)
    print(f"[run_benchmark] recorded {path.relative_to(ROOT)}; commit it with benchmark/history-*.svg and README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
