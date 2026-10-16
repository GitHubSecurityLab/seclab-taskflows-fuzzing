# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the benchmark runner (with a fake run_fuzzing.sh; no fuzzing here)."""

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from seclab_taskflows_fuzzing.mcp_servers.fuzz_context_models import Base

SCRIPTS = Path(__file__).parent.parent / "scripts" / "fuzzing"
SHA = "0123456789abcdef0123456789abcdef01234567"
MODEL_CONFIG = """\
models:
  code_analysis: m1
  general_tasks: m2
model_settings:
  code_analysis:
    reasoning:
      effort: high
  general_tasks:
    reasoning_effort: low
"""


def _load_runner():
    spec = importlib.util.spec_from_file_location("fuzz_run_benchmark", SCRIPTS / "run_benchmark.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def runner(monkeypatch, tmp_path):
    # run_benchmark.py imports its sibling benchmark_history.py.
    monkeypatch.syspath_prepend(str(SCRIPTS))
    mod = _load_runner()
    config = tmp_path / "model_config.yaml"
    config.write_text(MODEL_CONFIG)
    monkeypatch.setattr(mod, "MODEL_CONFIG", config)
    return mod


def _populate(db: Path) -> None:
    engine = create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    engine.dispose()
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        INSERT INTO fuzz_target (id, repo, file, function, signature, input_kind)
            VALUES (1, 'demo/lib', 'a.c', 'parse', '', 'bytes'),
                   (2, 'demo/lib', 'b.c', 'decode', '', 'bytes'),
                   (3, 'other/lib', 'c.c', 'load', '', 'bytes');
        INSERT INTO harness (id, target_id, repo, harness_path, version, build_status)
            VALUES (1, 1, 'demo/lib', '/h1.c', 1, 'ok'),
                   (2, 1, 'demo/lib', '/h2.c', 1, 'superseded'),
                   (3, 2, 'demo/lib', '/h3.c', 1, 'undefined reference to foo'),
                   (4, 3, 'other/lib', '/h4.c', 1, 'ok');
        INSERT INTO fuzz_run (id, harness_id, iteration_number, time_budget_seconds,
                paths_total, crashes_count, hangs_count, status)
            VALUES (1, 1, 1, 30, 5, 1, 0, 'completed'), (2, 1, 2, 60, 9, 3, 0, 'completed'),
                   (3, 4, 1, 30, 4, 1, 0, 'completed');
        INSERT INTO coverage_report (run_id, lines_total, lines_hit, line_pct, fns_total,
                fns_hit, fn_pct, branches_total, branches_hit, branch_pct)
            VALUES (1, 200, 60, 30.0, 10, 3, 30.0, 50, 10, 20.0),
                   (2, 200, 85, 42.5, 10, 4, 40.0, 50, 12, 24.0),
                   (3, 100, 90, 90.0, 10, 9, 90.0, 50, 40, 80.0);
        INSERT INTO crash (run_id, input_blob_path, verdict)
            VALUES (1, '/c1', 'vulnerability'), (2, '/c2', 'vulnerability'),
                   (2, '/c3', 'harness_bug'), (2, '/c4', NULL), (3, '/c5', 'oom');
        """
    )
    conn.commit()
    conn.close()


def test_load_projects_reads_benchmark_file(runner):
    repos = runner.load_projects()
    assert "DaveGamble/cJSON" in repos
    assert len(repos) == len(set(repos)) >= 5


def test_repo_stats(runner, tmp_path):
    db = tmp_path / "fuzz_context.db"
    _populate(db)
    stats = runner.repo_stats(db, "Demo/Lib")
    assert stats == {
        "targets": 2,
        "harnesses_built": 2,
        "harnesses_total": 3,
        "afl_runs": 2,
        "crashes": 4,
        "best_line_pct": 42.5,
        "verdicts": {"vulnerability": 2, "harness_bug": 1, "unclassified": 1},
    }


def test_repo_stats_without_db(runner, tmp_path):
    stats = runner.repo_stats(tmp_path / "missing.db", "demo/lib")
    assert stats["targets"] == 0
    assert stats["best_line_pct"] is None
    assert stats["verdicts"] == {}


def test_main_runs_every_repo_and_writes_summary(runner, tmp_path, monkeypatch):
    fake = tmp_path / "run_fuzzing.sh"
    fake.write_text(
        "#!/bin/sh\n"
        'echo "repo=$1 data=$DATA_DIR ctx=$FUZZ_CONTEXT_DIR logs=$LOG_DIR nodash=$FUZZ_NO_DASHBOARD"\n'
        '[ "$1" = "bad/repo" ] && exit 3\n'
        "exit 0\n"
    )
    fake.chmod(0o755)
    monkeypatch.setattr(runner, "RUN_FUZZING", fake)
    monkeypatch.setenv("FUZZ_NO_DASHBOARD", "1")
    monkeypatch.setenv("HARNESS_CANDIDATES", "2")
    out = (tmp_path / "out").resolve()
    (out / "data").mkdir(parents=True)
    _populate(out / "data" / "fuzz_context.db")

    rc = runner.main(["demo/lib", "bad/repo", "--out", str(out)])

    assert rc == 1
    data, logs = out / "data", out / "logs"
    log = (logs / "demo__lib.log").read_text()
    assert f"repo=demo/lib data={data} ctx={data} logs={logs} nodash=1" in log
    assert (logs / "bad__repo.log").is_file()

    summary = json.loads((out / "summary.json").read_text())
    assert summary["meta"]["settings"]["HARNESS_CANDIDATES"] == "2"
    assert summary["meta"]["model_settings"]["code_analysis"]["reasoning"]["effort"] == "high"
    demo, bad = summary["projects"]
    assert (demo["repo"], demo["status"], demo["exit_code"]) == ("demo/lib", "ok", 0)
    assert (demo["afl_runs"], demo["crashes"]) == (2, 4)
    assert (bad["status"], bad["exit_code"], bad["targets"]) == ("failed", 3, 0)

    md = (out / "summary.md").read_text()
    assert "code_analysis=m1 (high effort), general_tasks=m2 (low effort)" in md
    assert "HARNESS_CANDIDATES=2" in md
    assert "| `demo/lib` | [ok](logs/demo__lib.log) |" in md
    assert "| 2 | 2/3 | 2 | 4 | 42.5% | `vulnerability` (×2), `harness_bug`, `unclassified` |" in md
    assert "[failed (exit 3)](logs/bad__repo.log)" in md


def test_fuzz_settings_fall_back_to_script_defaults(runner, monkeypatch):
    for name in runner.FUZZ_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    assert runner.fuzz_settings() == {
        "HARNESS_CANDIDATES": "1",
        "QUALIFIER_SECONDS": "60",
        "FUZZ_PLATEAU_THRESHOLD_PCT": "1.0",
    }
    monkeypatch.setenv("QUALIFIER_SECONDS", "90")
    assert runner.fuzz_settings()["QUALIFIER_SECONDS"] == "90"


def test_run_metadata_drops_tokens(runner, tmp_path, monkeypatch):
    config = tmp_path / "model_config.yaml"
    config.write_text(
        "models:\n  code_analysis: m1\n  general_tasks: m2\n"
        "model_settings:\n  code_analysis:\n    token: SECRET_ENV\n    reasoning:\n      effort: max\n"
    )
    monkeypatch.setattr(runner, "MODEL_CONFIG", config)
    monkeypatch.setattr(runner, "git_state", lambda: (SHA, True))
    meta = runner.run_metadata()
    assert (meta["commit"], meta["dirty"]) == (SHA, True)
    assert meta["models"] == {"code_analysis": "m1", "general_tasks": "m2"}
    assert meta["model_settings"] == {"code_analysis": {"reasoning": {"effort": "max"}}}
    assert set(meta["settings"]) == {"AI_API_ENDPOINT", *runner.FUZZ_SETTINGS}


@pytest.fixture
def recording(runner, tmp_path, monkeypatch):
    """A fake benchmark checkout under tmp_path/root plus a fake run_fuzzing.sh."""
    root = tmp_path / "root"
    root.mkdir()
    readme = root / "README.md"
    readme.write_text("# Demo\n\n<!-- benchmark-history:start -->\n<!-- benchmark-history:end -->\n\nTail\n")
    fake = tmp_path / "run_fuzzing.sh"
    fake.write_text('#!/bin/sh\n[ "$1" = "bad/repo" ] && exit 3\nexit 0\n')
    fake.chmod(0o755)
    monkeypatch.setattr(runner, "ROOT", root)
    monkeypatch.setattr(runner, "RUN_FUZZING", fake)
    monkeypatch.setattr(runner, "git_state", lambda: (SHA, False))
    monkeypatch.setattr(runner, "load_projects", lambda: ["demo/lib", "other/lib"])
    monkeypatch.setattr(runner, "_has_matplotlib", lambda: True)
    monkeypatch.setenv("FUZZ_NO_DASHBOARD", "1")
    out = (tmp_path / "out").resolve()
    (out / "data").mkdir(parents=True)
    _populate(out / "data" / "fuzz_context.db")
    return root, out


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("subset", "needs a full run"),
        ("dirty", "uncommitted or untracked changes"),
        ("no_effort", "doesn't set the code_analysis reasoning effort"),
        ("bad_effort", "sets 'minimal' as the code_analysis reasoning effort"),
        ("no_matplotlib", "matplotlib is missing"),
    ],
)
def test_record_refuses_before_running(runner, recording, tmp_path, monkeypatch, capsys, case, message):
    root, out = recording
    args = ["--record", "--out", str(out)]
    if case == "subset":
        args.insert(0, "demo/lib")
    elif case == "dirty":
        monkeypatch.setattr(runner, "git_state", lambda: (SHA, True))
    elif case in ("no_effort", "bad_effort"):
        config = tmp_path / "model_config.yaml"
        effort = "\nmodel_settings:\n  code_analysis:\n    reasoning_effort: minimal\n" if case == "bad_effort" else ""
        config.write_text("models:\n  code_analysis: m1\n" + effort)
        monkeypatch.setattr(runner, "MODEL_CONFIG", config)
    elif case == "no_matplotlib":
        monkeypatch.setattr(runner, "_has_matplotlib", lambda: False)

    assert runner.main(args) == 2
    assert message in capsys.readouterr().err
    assert not (out / "logs").exists()
    assert not (root / "benchmark").exists()


def test_record_writes_result_and_history(runner, recording):
    pytest.importorskip("matplotlib")
    root, out = recording

    assert runner.main(["--record", "--out", str(out)]) == 0

    (path,) = (root / "benchmark" / "results").iterdir()
    assert path.name.endswith(f"Z_{SHA[:7]}.json")
    record = json.loads(path.read_text())
    assert record["commit"] == SHA
    assert record["model_settings"]["code_analysis"] == {"reasoning": {"effort": "high"}}
    assert set(record["settings"]) == {"AI_API_ENDPOINT", *runner.FUZZ_SETTINGS}
    assert "out_dir" not in record
    demo, other = record["projects"]
    assert set(demo) == set(runner.RECORDED_FIELDS)
    assert (demo["repo"], demo["best_line_pct"], demo["crashes"]) == ("demo/lib", 42.5, 4)
    assert (other["repo"], other["best_line_pct"]) == ("other/lib", 90.0)

    readme = (root / "README.md").read_text()
    assert readme.startswith("# Demo\n") and readme.endswith("\n\nTail\n")
    assert f"commit [`{SHA[:7]}`]" in readme
    assert "| `demo/lib` | 42.5% | — | 2 | 2/3 | 2 | 4 |" in readme
    assert (root / "benchmark" / "history-light.svg").is_file()
    assert (root / "benchmark" / "history-dark.svg").is_file()


def test_record_skips_runs_with_a_failed_project(runner, recording, monkeypatch, capsys):
    root, out = recording
    monkeypatch.setattr(runner, "load_projects", lambda: ["demo/lib", "bad/repo"])
    before = (root / "README.md").read_text()

    assert runner.main(["--record", "--out", str(out)]) == 1

    assert "not recorded: bad/repo didn't finish" in capsys.readouterr().err
    assert not (root / "benchmark").exists()
    assert (root / "README.md").read_text() == before


def test_record_skips_runs_when_the_checkout_changes(runner, recording, monkeypatch, capsys):
    root, out = recording
    states = iter([(SHA, False), ("f" * 40, False)])
    monkeypatch.setattr(runner, "git_state", lambda: next(states))

    assert runner.main(["--record", "--out", str(out)]) == 1

    assert "checkout changed during the run" in capsys.readouterr().err
    assert not (root / "benchmark").exists()
