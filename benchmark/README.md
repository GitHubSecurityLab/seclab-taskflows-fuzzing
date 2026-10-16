# Fuzzing benchmark

Reference projects we use to validate the fuzzing taskflow end-to-end. Each
entry is a small or well-known C/C++ project where AFL++ instrumentation works
out of the box.

Run the whole benchmark with:

```bash
python scripts/fuzzing/run_benchmark.py                                   # every project below
python scripts/fuzzing/run_benchmark.py DaveGamble/cJSON akheron/jansson  # a subset
```

It runs `run_fuzzing.sh` once per project in `projects.yaml`, keeps going when a
project fails, and writes `summary.md` (a table with status, duration, targets,
harnesses, AFL runs, crashes, best line coverage and verdicts per project) and
`summary.json` to a fresh results directory:
`~/.local/share/seclab-taskflow-agent/benchmarks/<UTC timestamp>/` (override
with `--out`). Each benchmark run uses its own `DATA_DIR`, so its numbers don't
mix with earlier runs. The summary also records the commit, package versions,
models, reasoning efforts and `run_fuzzing.sh` settings used.

To run a single project without the wrapper:

```bash
./scripts/fuzzing/run_fuzzing.sh <owner/repo>
```

## Projects

| # | Repo | Why it's interesting | Notes |
|---|------|----------------------|-------|
| 1 | `tukaani-project/xz` | Real-world parser-heavy library (`liblzma`); rich filter chain + integer/VLI parsing surface | Our baseline |
| 2 | `DaveGamble/cJSON` | Small single-file C JSON parser; trivial CMake; classic fuzz target | Quick smoke for the pipeline |
| 3 | `akheron/jansson` | Compact C JSON library with documented `json_loadb()` byte-buffer entry point | CMake; very fast exec/sec |
| 4 | `libexpat/libexpat` | Mature streaming XML parser; large attack surface; many historical CVEs | CMake or autotools; classic fuzz target |
| 5 | `kkos/oniguruma` | Regex engine with state-machine compiler; takes attacker pattern + subject | Autotools; pattern compilation is the hot path |

## Results

The history of recorded runs and the latest run's numbers are in the
[root README](../README.md#benchmark-projects-and-results).

## Recording a run

```bash
pip install '.[benchmark]'   # matplotlib, for the chart (the devcontainer already installs it)
python scripts/fuzzing/run_benchmark.py --record
```

`--record` checks before it starts that:
- it's a full run (no `owner/repo` arguments),
- the checkout is clean (`git status` shows nothing),
- `src/seclab_taskflows_fuzzing/configs/model_config.yaml` sets the
  `code_analysis` reasoning effort to `low`, `medium`, `high`, `xhigh` or `max`,
- matplotlib is installed.

The run is recorded only if every project finishes and the checkout is still at
the same commit with no uncommitted changes. Then it writes
`results/<UTC timestamp>_<commit>.json` (commit, package versions, models and
their settings, the `AI_API_ENDPOINT` and `run_fuzzing.sh` settings used, and
per-project numbers) and regenerates `history-light.svg`, `history-dark.svg`
and the results section of the root README. Commit those files in a pull
request.

The chart has one panel per project with the best line coverage of each
recorded run. Marker colour is the `code_analysis` model and marker shape its
reasoning effort (● low, ■ medium, ▲ high, ◆ xhigh, ★ max).

To regenerate the chart and README section from `results/` (for example after
removing a result file):

```bash
python scripts/fuzzing/benchmark_history.py
```

## Adding a project

Add an entry to `projects.yaml` and (optionally) document why in this README.
Anything that the existing `analyze_build_system` stage can build with `clang`
+ AFL++ flags is a reasonable candidate. Pure-C parsers, decoders, and
serialisers tend to work best.

## Reading results

`run_benchmark.py` puts everything for a benchmark run under its results
directory:
- `summary.md`, `summary.json`
- `logs/`: one `<owner>__<repo>.log` per project, plus the MCP server logs
- `data/fuzz_context.db`, and per project `data/repo/<owner>__<repo>/REPORT.md` and `vuln_<id>.md`

The dashboard below serves that run's database for the whole benchmark.

A single `run_fuzzing.sh` run writes:
- SQLite DB: `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_context/fuzz_context.db`
- Per-repo report: `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/repo/<owner>__<repo>/REPORT.md`
- Per-crash vuln reports: same directory, `vuln_<id>.md`
- Live dashboard during the run: <http://127.0.0.1:8765>
- Programmatic JSON snapshot: <http://127.0.0.1:8765/api/json> (or with `?repo=...`)
