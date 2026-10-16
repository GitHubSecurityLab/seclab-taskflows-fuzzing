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

## Most-recent benchmark results

These numbers come from end-to-end runs through the full v4 pipeline on the
codespace dev image. Coverage and crash counts depend on the underlying LLM and
the time budget cap (≈32 min/target).

| Repo | Targets | Harnesses built | AFL runs | Crashes | Verdicts seen |
|------|---------|-----------------|----------|---------|---------------|
| `tukaani-project/xz` | 8 | 8 | 48 | 0 | — |
| `DaveGamble/cJSON` | 6 | 6 | 36 | 0 | — |
| `akheron/jansson` | 7 | 7 | 35 | 10 | `harness_bug`, `library_hardening`, `duplicate`, `needs_investigation` |
| `libexpat/libexpat` | 3 | 3 | 18 | 0 | — |
| `kkos/oniguruma` | 10 | 10 | 60 | 13 | `vulnerability` (×2, OOB read in `regerror.c`), `library_hardening`, `harness_bug`, `non_reproducible` |

The xz / cJSON / libexpat zero-crash results are expected: those projects are
heavily fuzzed upstream. The two `vulnerability`-classified findings in
oniguruma are real out-of-bounds reads in the warning-formatting code path of
`onig_snprintf_with_pattern` (one-byte read past `pat_end` when the pattern
ends with a backslash); the per-crash markdown reports include suggested
patches.

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
