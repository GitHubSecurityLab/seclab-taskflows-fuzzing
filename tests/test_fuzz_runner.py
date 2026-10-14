# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import seclab_taskflows_fuzzing.mcp_servers.fuzz_runner as fr


def _make_proc(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


_DRIVER_OK = {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "", "cmd": "clang -c driver"}


# ---------------------------------------------------------------------------
# stack_top_hash
# ---------------------------------------------------------------------------

class TestStackTopHash:
    def test_extracts_frames(self):
        asan = """
==1234==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x4001ab in foo /src/foo.c:42
    #1 0x4002cd in bar /src/bar.c:10
    #2 0x4003ef in baz /src/baz.c:5
"""
        h1 = fr._stack_top_hash(asan)
        assert h1 != ""
        # Same trace → same hash
        h2 = fr._stack_top_hash(asan)
        assert h1 == h2
        # Different top frame → different hash
        asan2 = asan.replace("foo /src/foo.c", "qux /src/foo.c")
        assert fr._stack_top_hash(asan2) != h1

    def test_no_frames(self):
        assert fr._stack_top_hash("just some random text") == ""


# ---------------------------------------------------------------------------
# check_tooling
# ---------------------------------------------------------------------------

class TestCheckTooling:
    def test_returns_dict_of_paths(self):
        with patch.object(fr.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n != "afl-clang-fast" else None):
            out = fr.check_tooling.fn()
        assert out["afl_clang_lto"] == "/usr/bin/afl-clang-lto"
        assert out["afl_clang_fast"] is None
        assert out["llvm_cov"] == "/usr/bin/llvm-cov"


# ---------------------------------------------------------------------------
# AFL stats parser
# ---------------------------------------------------------------------------

class TestAflStatsParser:
    def test_reads_default_subdir(self, tmp_path):
        out_dir = tmp_path
        (out_dir / "default").mkdir()
        (out_dir / "default" / "fuzzer_stats").write_text(
            "execs_per_sec : 123.4\n"
            "corpus_count  : 42\n"
            "saved_crashes : 2\n"
            "saved_hangs   : 0\n"
        )
        stats = fr._read_afl_stats(out_dir)
        assert stats["execs_per_sec"] == "123.4"
        assert stats["corpus_count"] == "42"

    def test_falls_back_to_top_level(self, tmp_path):
        (tmp_path / "fuzzer_stats").write_text("execs_per_sec : 50\n")
        stats = fr._read_afl_stats(tmp_path)
        assert stats["execs_per_sec"] == "50"


# ---------------------------------------------------------------------------
# compile_harness
# ---------------------------------------------------------------------------

class TestCompileHarness:
    def test_missing_source_short_circuits(self, tmp_path):
        out = fr.compile_harness.fn(
            harness_source=str(tmp_path / "nope.c"),
            output_basename="x",
        )
        assert out["ok"] is False
        assert "harness source not found" in out["error"]

    def test_missing_clang_short_circuits(self, tmp_path):
        src = tmp_path / "h.c"
        src.write_text("int main(){return 0;}")
        with patch.object(fr.shutil, "which", side_effect=lambda n: "/usr/bin/afl-clang-lto" if n.startswith("afl-") else None):
            out = fr.compile_harness.fn(harness_source=str(src), output_basename="x")
        assert out["ok"] is False
        assert "clang not found" in out["error"]

    def test_invokes_both_compilers(self, tmp_path):
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){(void)d;(void)n;return 0;}")
        # Fake the AFL driver archive so compile_harness gets past its lookup.
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")

        def which_mock(name):
            if name in ("afl-clang-lto", "afl-clang-fast"):
                return "/usr/bin/afl-clang-lto"
            if name in ("clang", "clang++"):
                return "/usr/bin/clang"
            return None

        calls = []
        def run_mock(cmd, cwd=None, timeout=None, env=None, unset_env=None):
            calls.append(cmd)
            return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "",
                    "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which", side_effect=which_mock), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_build_standalone_driver", return_value=_DRIVER_OK), \
             patch.object(fr, "_run", side_effect=run_mock):
            out = fr.compile_harness.fn(
                harness_source=str(src), output_basename="my_harness",
                extra_cflags=["-I/include"], extra_libs=["pthread"],
            )

        assert out["ok"] is True
        assert len(calls) == 3
        afl_cmd, cov_cmd, _cmplog_cmd = calls
        assert "/usr/bin/afl-clang-lto" in afl_cmd
        assert "-fsanitize=address,undefined" in afl_cmd
        assert str(fake_driver) in afl_cmd
        assert "/usr/bin/clang" in cov_cmd
        assert "-fprofile-instr-generate" in cov_cmd
        assert "-fcoverage-mapping" in cov_cmd
        assert "-lpthread" in afl_cmd
        assert "-I/include" in afl_cmd

    @pytest.mark.parametrize(("sanitizers", "expected"), [
        ("address,undefined", {"AFL_USE_ASAN", "AFL_USE_UBSAN"}),
        ("undefined", {"AFL_USE_UBSAN"}),
        ("", set()),
    ])
    def test_sets_afl_use_only_for_requested_sanitizers(self, tmp_path, sanitizers, expected):
        # afl-cc enables a sanitizer if its AFL_USE_* variable exists at all.
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){return 0;}")
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")

        def which_mock(name):
            return f"/usr/bin/{name}" if name.startswith(("afl-", "clang")) else None

        calls = []
        def run_mock(cmd, env=None, **kwargs):
            calls.append({"cmd": cmd, "env": env or {}})
            return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "",
                    "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which", side_effect=which_mock), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_run", side_effect=run_mock):
            fr.compile_harness.fn(harness_source=str(src), output_basename="h",
                                  sanitizers=sanitizers)

        afl_env = next(c["env"] for c in calls if c["cmd"][-1].endswith(".afl"))
        assert {k for k in afl_env if k.startswith("AFL_USE_")} == expected
        assert all(afl_env[k] == "1" for k in expected)


class TestCmplogBuild:
    def _compile(self, tmp_path, exit_codes=(0, 0, 0), **kwargs):
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){(void)d;(void)n;return 0;}")
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")
        calls = []
        codes = iter(exit_codes)

        def run_mock(cmd, **kw):
            calls.append({"cmd": cmd, "env": kw.get("env") or {}, "unset_env": kw.get("unset_env") or []})
            return {"exit_code": next(codes), "timed_out": False, "stdout": "", "stderr": "log",
                    "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_build_standalone_driver", return_value=_DRIVER_OK), \
             patch.object(fr, "_run", side_effect=run_mock), \
             patch.object(fr, "FUZZ_BUILDS", tmp_path / "builds"):
            out = fr.compile_harness.fn(harness_source=str(src), output_basename="h", **kwargs)
        return out, calls, fake_driver

    def test_builds_sanitizer_free_cmplog_binary(self, tmp_path):
        mutator = tmp_path / "mut.c"
        mutator.write_text("/* mutator */")
        out, calls, driver = self._compile(tmp_path, custom_mutator_source=str(mutator))
        assert out["ok"] is True
        assert len(calls) == 3
        cmplog = calls[2]
        assert cmplog["cmd"][0] == "/usr/bin/afl-clang-lto"
        assert cmplog["cmd"][-1].endswith("h.cmplog")
        assert str(driver) in cmplog["cmd"]
        assert not any(a.startswith("-fsanitize") for a in cmplog["cmd"])
        assert str(mutator) not in cmplog["cmd"]
        assert cmplog["env"]["AFL_LLVM_CMPLOG"] == "1"
        assert "AFL_USE_ASAN" not in cmplog["env"]
        assert {"AFL_USE_ASAN", "AFL_USE_UBSAN"} <= set(cmplog["unset_env"])
        assert out["cmplog_binary_path"].endswith("h.cmplog")
        assert out["cmplog_build_cmd"]

    def test_cmplog_failure_fails_build(self, tmp_path):
        out, _, _ = self._compile(tmp_path, exit_codes=(0, 0, 1))
        assert out["ok"] is False
        assert out["cmplog_binary_path"] == ""
        assert "log" in out["cmplog_build_log"]

    def test_cmplog_skipped_when_afl_build_fails(self, tmp_path):
        out, calls, _ = self._compile(tmp_path, exit_codes=(1, 0))
        assert out["ok"] is False
        assert len(calls) == 2
        assert out["cmplog_binary_path"] == ""

    def test_stale_cmplog_binary_removed(self, tmp_path):
        stale = tmp_path / "builds" / "h.cmplog"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"old")
        out, _, _ = self._compile(tmp_path, exit_codes=(0, 0, 1))
        assert not stale.exists()
        assert out["cmplog_binary_path"] == ""


class TestLtoAndVariants:
    def _compile(self, tmp_path, **kwargs):
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){(void)d;(void)n;return 0;}")
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")
        calls = []

        def run_mock(cmd, **kw):
            calls.append(cmd)
            return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "", "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_build_standalone_driver", return_value=_DRIVER_OK), \
             patch.object(fr, "_run", side_effect=run_mock), \
             patch.object(fr, "FUZZ_BUILDS", tmp_path / "builds"):
            out = fr.compile_harness.fn(harness_source=str(src), output_basename="h", **kwargs)
        return out, calls

    def test_variant_placeholder_resolved_per_build(self, tmp_path):
        out, calls = self._compile(
            tmp_path,
            extra_sources=["/src/build-{variant}/libfoo.a"],
            extra_cflags=["-I/src/include", "-I/src/build-{variant}/include"],
            extra_ldflags=["-L/src/build-{variant}"],
            extra_libs=["z"],
        )
        assert out["ok"] is True
        for cmd, variant in zip(calls, ("afl", "cov", "cmplog")):
            assert not any("{variant}" in a for a in cmd)
            assert f"/src/build-{variant}/libfoo.a" in cmd
            assert f"-I/src/build-{variant}/include" in cmd
            assert f"-L/src/build-{variant}" in cmd
            assert "-I/src/include" in cmd
            assert "-lz" in cmd


class TestStandaloneDriver:
    def _compile(self, tmp_path, driver_exit=0, language="c"):
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long n){(void)d;(void)n;return 0;}")
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")
        calls = []

        def run_mock(cmd, **kw):
            calls.append(cmd)
            code = driver_exit if "-c" in cmd else 0
            return {"exit_code": code, "timed_out": False, "stdout": "", "stderr": "boom" if code else "",
                    "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_run", side_effect=run_mock), \
             patch.object(fr, "WORKSPACE", tmp_path), \
             patch.object(fr, "FUZZ_BUILDS", tmp_path / "builds"):
            out = fr.compile_harness.fn(harness_source=str(src), output_basename="h", language=language)
        return out, calls

    @pytest.mark.parametrize(("language", "cov_compiler"), [("c", "clang"), ("c++", "clang++")])
    def test_driver_compiled_as_plain_c_and_linked_as_object(self, tmp_path, language, cov_compiler):
        out, calls = self._compile(tmp_path, language=language)
        assert out["ok"] is True
        driver_cmd, _afl_cmd, cov_cmd, _cmplog_cmd = calls
        driver_c = str(tmp_path / "_aflpp_standalone_driver.c")
        driver_o = str(tmp_path / "builds" / "h.driver.o")
        assert driver_cmd == ["/usr/bin/clang", "-g", "-O1", "-c", driver_c, "-o", driver_o]
        assert cov_cmd[0] == f"/usr/bin/{cov_compiler}"
        assert "-fprofile-instr-generate" in cov_cmd
        assert driver_o in cov_cmd
        assert driver_c not in cov_cmd

    def test_driver_failure_fails_build(self, tmp_path):
        out, calls = self._compile(tmp_path, driver_exit=1)
        assert out["ok"] is False
        assert "standalone driver failed to compile" in out["error"]
        assert "boom" in out["error"]
        assert len(calls) == 1


def test_run_unset_env_removes_inherited_vars(monkeypatch):
    monkeypatch.setenv("AFL_USE_ASAN", "1")
    captured = {}

    def fake_subprocess_run(cmd, **kw):
        captured["env"] = kw["env"]
        return _make_proc()

    with patch.object(fr.subprocess, "run", side_effect=fake_subprocess_run):
        fr._run(["true"], env={"AFL_LLVM_CMPLOG": "1"}, unset_env=["AFL_USE_ASAN"])
    assert "AFL_USE_ASAN" not in captured["env"]
    assert captured["env"]["AFL_LLVM_CMPLOG"] == "1"

# ---------------------------------------------------------------------------
# run_afl_for: error paths only (real AFL runs are out of scope)
# ---------------------------------------------------------------------------

class TestRunAflFor:
    def test_missing_afl_binary(self, tmp_path):
        with patch.object(fr.shutil, "which", return_value="/usr/bin/afl-fuzz"):
            out = fr.run_afl_for.fn(
                afl_binary_path=str(tmp_path / "no_such"),
                cmplog_binary_path=str(tmp_path / "no_such.cmplog"),
                seed_dir=str(tmp_path / "seeds"),
                output_dir=str(tmp_path / "out"),
                seconds=1,
            )
        assert out["ok"] is False
        assert "binary not found" in out["error"]

    def test_missing_afl_fuzz(self, tmp_path):
        bin_path = tmp_path / "h.afl"
        bin_path.write_bytes(b"\x7fELF")
        with patch.object(fr.shutil, "which", return_value=None):
            out = fr.run_afl_for.fn(
                afl_binary_path=str(bin_path),
                cmplog_binary_path=str(bin_path),
                seed_dir=str(tmp_path / "seeds"),
                output_dir=str(tmp_path / "out"),
                seconds=1,
            )
        assert out["ok"] is False
        assert "afl-fuzz not on PATH" in out["error"]

    def _setup(self, tmp_path):
        bin_path = tmp_path / "h.afl"
        bin_path.write_bytes(b"\x7fELF")
        cmplog = tmp_path / "h.cmplog"
        cmplog.write_bytes(b"\x7fELF")
        return bin_path, cmplog

    def test_single_instance_passes_cmplog(self, tmp_path):
        bin_path, cmplog = self._setup(tmp_path)
        calls = []

        def run_mock(cmd, **kw):
            calls.append(cmd)
            return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": "", "cmd": ""}

        with patch.object(fr.shutil, "which", return_value="/usr/bin/afl-fuzz"), \
             patch.object(fr, "_run", side_effect=run_mock):
            out = fr.run_afl_for.fn(
                afl_binary_path=str(bin_path), cmplog_binary_path=str(cmplog),
                seed_dir=str(tmp_path / "seeds"), output_dir=str(tmp_path / "out"), seconds=1,
            )
        cmd = calls[0]
        sep = cmd.index("--")
        assert cmd[cmd.index("-c") + 1] == str(cmplog)
        assert cmd.index("-c") < sep
        assert "-l" not in cmd
        assert cmd[sep + 1] == str(bin_path)
        assert out["cmplog_workers"] == ["default"]

    def test_parallel_cmplog_on_master_and_first_secondary(self, tmp_path):
        bin_path, cmplog = self._setup(tmp_path)
        cmds = []

        def popen_mock(cmd, **kw):
            cmds.append(cmd)
            p = MagicMock()
            p.communicate.return_value = (b"", b"")
            p.returncode = 0
            return p

        with patch.object(fr.shutil, "which", return_value="/usr/bin/afl-fuzz"), \
             patch.object(fr.subprocess, "Popen", side_effect=popen_mock):
            out = fr.run_afl_for.fn(
                afl_binary_path=str(bin_path), cmplog_binary_path=str(cmplog),
                seed_dir=str(tmp_path / "seeds"), output_dir=str(tmp_path / "out"),
                seconds=1, parallel_workers=3,
            )
        master, sec1, sec2 = cmds
        assert "-M" in master and "-c" in master and "-l" not in master
        assert "-S" in sec1 and sec1[sec1.index("-c") + 1] == str(cmplog)
        assert sec1[sec1.index("-l") + 1] == "2AT"
        assert "-c" not in sec2
        assert out["cmplog_workers"] == ["default", "secondary_1"]

    @pytest.mark.parametrize("cmplog_path", ["", "gone.cmplog"])
    def test_missing_cmplog_binary_fails(self, tmp_path, cmplog_path):
        bin_path, _ = self._setup(tmp_path)
        cmplog_arg = str(tmp_path / cmplog_path) if cmplog_path else ""

        with patch.object(fr.shutil, "which", return_value="/usr/bin/afl-fuzz"), \
             patch.object(fr, "_run") as run_mock:
            out = fr.run_afl_for.fn(
                afl_binary_path=str(bin_path), cmplog_binary_path=cmplog_arg,
                seed_dir=str(tmp_path / "seeds"), output_dir=str(tmp_path / "out"), seconds=1,
            )
        assert out["ok"] is False
        assert "cmplog binary not found" in out["error"]
        run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# v8 — persistent corpus + reproduce_crash + smart mutator with corpus splice
# ---------------------------------------------------------------------------

class TestPersistentCorpus:
    def test_get_persistent_corpus_dir_creates_and_seeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fr, "PERSISTENT_CORPUS", tmp_path / "corpus")
        out = fr.get_persistent_corpus_dir.fn(harness_id=42)
        cd = Path(out["corpus_dir"])
        assert cd.exists()
        assert cd.is_dir()
        assert "harness_42" in str(cd)
        assert out["input_count"] >= 1
        assert (cd / "seed_0").exists()

    def test_get_persistent_corpus_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fr, "PERSISTENT_CORPUS", tmp_path / "corpus")
        out1 = fr.get_persistent_corpus_dir.fn(harness_id=1)
        cd = Path(out1["corpus_dir"])
        (cd / "custom").write_bytes(b"x")
        out2 = fr.get_persistent_corpus_dir.fn(harness_id=1)
        assert out2["corpus_dir"] == out1["corpus_dir"]
        assert (cd / "custom").exists()

    def test_fold_queue_copies_new_files_when_cmin_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fr, "PERSISTENT_CORPUS", tmp_path / "corpus")
        afl = tmp_path / "harness.afl"
        afl.write_bytes(b"")
        cd = Path(fr.get_persistent_corpus_dir.fn(harness_id=7)["corpus_dir"])
        queue = tmp_path / "queue"
        queue.mkdir()
        (queue / "id:000000,orig:seed").write_bytes(b"x")
        (queue / "id:000001,src:000000,op:flip").write_bytes(b"y")
        monkeypatch.setattr(
            fr, "cmin",
            MagicMock(fn=MagicMock(return_value={"ok": False, "minimised_count": 0})),
        )
        out = fr.fold_queue_into_persistent_corpus.fn(
            afl_binary_path=str(afl), queue_dir=str(queue),
            persistent_corpus_dir=str(cd),
        )
        assert out["ok"] is True
        assert out["merged_in"] == 2
        names = sorted(p.name for p in cd.iterdir())
        assert "id:000000,orig:seed" in names
        assert "id:000001,src:000000,op:flip" in names

    def test_fold_queue_skips_dotfiles_and_stats(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fr, "PERSISTENT_CORPUS", tmp_path / "corpus")
        afl = tmp_path / "h.afl"
        afl.write_bytes(b"")
        cd = Path(fr.get_persistent_corpus_dir.fn(harness_id=1)["corpus_dir"])
        queue = tmp_path / "queue"
        queue.mkdir()
        (queue / ".state").write_bytes(b"x")
        (queue / "fuzzer_stats").write_bytes(b"x")
        monkeypatch.setattr(
            fr, "cmin",
            MagicMock(fn=MagicMock(return_value={"ok": False, "minimised_count": 0})),
        )
        out = fr.fold_queue_into_persistent_corpus.fn(
            afl_binary_path=str(afl), queue_dir=str(queue),
            persistent_corpus_dir=str(cd),
        )
        assert out["merged_in"] == 0

    def test_fold_queue_errors_when_binary_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fr, "PERSISTENT_CORPUS", tmp_path / "corpus")
        cd = Path(fr.get_persistent_corpus_dir.fn(harness_id=1)["corpus_dir"])
        out = fr.fold_queue_into_persistent_corpus.fn(
            afl_binary_path=str(tmp_path / "missing.afl"),
            queue_dir=str(cd), persistent_corpus_dir=str(cd),
        )
        assert out["ok"] is False
        assert "not found" in out["error"]


class TestReproduceCrash:
    def test_returns_error_when_binary_missing(self, tmp_path):
        inp = tmp_path / "x"
        inp.write_bytes(b"x")
        out = fr.reproduce_crash.fn(
            afl_binary_path=str(tmp_path / "missing.afl"), input_path=str(inp),
        )
        assert out["ok"] is False
        assert "not found" in out["error"]

    def test_returns_error_when_input_missing(self, tmp_path):
        afl = tmp_path / "h.afl"
        afl.write_bytes(b"")
        out = fr.reproduce_crash.fn(
            afl_binary_path=str(afl),
            input_path=str(tmp_path / "missing"),
        )
        assert out["ok"] is False
        assert "not found" in out["error"]

    def test_delegates_to_replay_under_asan_in_argv_mode(self, tmp_path, monkeypatch):
        afl = tmp_path / "h.afl"
        afl.write_bytes(b"")
        inp = tmp_path / "x"
        inp.write_bytes(b"x")
        called = {}
        def fake_replay(**kw):
            called.update(kw)
            return {"ok": True, "crashed": False, "stack_top_hash": ""}
        monkeypatch.setattr(fr, "replay_under_asan", MagicMock(fn=fake_replay))
        out = fr.reproduce_crash.fn(afl_binary_path=str(afl), input_path=str(inp))
        assert called["stdin_input"] is False
        assert out["crashed"] is False


class TestSmartMutatorWithCorpus:
    def test_corpus_dir_propagates_to_generated_c(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text('int parse(const char *s){return s[0];}')
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "seed_0").write_bytes(b"hi")
        out = fr.generate_smart_mutator.fn(
            source_root=str(src), output_path=str(tmp_path / "m.c"),
            focus="combined", corpus_dir=str(corpus),
        )
        assert out["ok"] is True
        text = (tmp_path / "m.c").read_text()
        assert "SMART_MUTATOR_CORPUS_DIR" in text
        assert str(corpus) in text
        assert "kCorpus.n_files" in text


# ---------------------------------------------------------------------------
# Recovered v3-v7 tests (re-derived after accidental git-checkout in v8)
# ---------------------------------------------------------------------------

class TestStackTopHashNormalisation:
    """Normalisation lets semantically-equivalent stacks hash to the same key."""

    def _hash_with(self, fn1, fn2):
        asan = "    #0 0x4001ab in {f1} /src/foo.c:42\n    #1 0x4002cd in {f2} /src/bar.c:10\n"
        return (
            fr._stack_top_hash(asan.format(f1=fn1, f2="bar")),
            fr._stack_top_hash(asan.format(f1=fn2, f2="bar")),
        )

    def test_normalises_template_instantiations(self):
        a, b = self._hash_with(
            "std::sort<std::vector<int>::iterator>",
            "std::sort<std::vector<long>::iterator>",
        )
        assert a == b
        assert a != ""

    def test_normalises_libcxx_inline_namespace(self):
        a, b = self._hash_with("std::__1::vector<int>::push_back", "std::vector<int>::push_back")
        assert a == b

    def test_normalises_anonymous_namespace(self):
        a, b = self._hash_with("(anonymous namespace)::helper", "helper")
        assert a == b

    def test_normalises_lto_numeric_suffix(self):
        # foo.123 (LTO clone) and foo (original) hash to the same key.
        a, b = self._hash_with("foo.123", "foo")
        assert a == b
        # Multi-segment numeric suffixes too.
        a, b = self._hash_with("foo.42.7", "foo")
        assert a == b


# ---------------------------------------------------------------------------
# extract_dictionary (binary-string mining)
# ---------------------------------------------------------------------------

class TestExtractDictionary:
    def test_writes_dictionary(self, tmp_path):
        binp = tmp_path / "bin"
        # Some real-looking ASCII strings the extractor should keep.
        binp.write_bytes(b"\x00\x00MAGIC_TOKEN\x00protocol_v1\x00short\x00BLOB_KEY_HERE\x00")
        out = tmp_path / "out.dict"
        result = fr.extract_dictionary.fn(
            binary_path=str(binp), output_path=str(out),
            min_length=4, max_length=32, max_entries=64,
        )
        assert result["ok"] is True
        assert result["entries"] >= 3
        text = out.read_text()
        assert "MAGIC_TOKEN" in text
        assert "protocol_v1" in text
        assert "BLOB_KEY_HERE" in text

    def test_skips_known_noise(self, tmp_path):
        binp = tmp_path / "bin"
        # Things we explicitly skip: file paths, mangled symbols, GCC banners.
        binp.write_bytes(
            b"\x00GCC: (Ubuntu) 11.4.0\x00/usr/lib/foo.so\x00_ZN3std3foo\x00"
            b"AddressSanitizer: heap\x00.text\x00",
        )
        out = tmp_path / "out.dict"
        result = fr.extract_dictionary.fn(
            binary_path=str(binp), output_path=str(out),
        )
        text = out.read_text()
        assert "GCC:" not in text
        assert "AddressSanitizer" not in text
        assert "/usr/lib" not in text
        assert "_ZN3std" not in text


# ---------------------------------------------------------------------------
# package_reproducer
# ---------------------------------------------------------------------------

class TestPackageReproducer:
    def test_creates_tgz(self, tmp_path):
        import tarfile  # noqa: PLC0415
        crash = tmp_path / "crash.bin"
        crash.write_bytes(b"BAD\x00BYTES")
        harness = tmp_path / "h.c"
        harness.write_text("int LLVMFuzzerTestOneInput(const uint8_t*, size_t){return 0;}")
        out = tmp_path / "repro.tgz"
        result = fr.package_reproducer.fn(
            output_path=str(out), minimised_input=str(crash),
            harness_source=str(harness),
            afl_binary_path=str(tmp_path / "h.afl"),
            build_cmd_afl="afl-clang-lto -o h.afl h.c",
            sanitizer_output="==1==ERROR: AddressSanitizer: heap-use-after-free",
            classification="heap-use-after-free in foo",
        )
        assert result["ok"] is True
        assert out.exists()
        with tarfile.open(out, "r:gz") as tar:
            names = sorted(tar.getnames())
        assert "input.bin" in names
        assert "h.c" in names
        assert "README.md" in names


# ---------------------------------------------------------------------------
# Format assets (json/xml/regex/png/binary_tlv)
# ---------------------------------------------------------------------------

class TestFormatAssets:
    def test_list_format_assets_includes_expected(self):
        out = fr.list_format_assets.fn()
        assert "json" in out
        assert "xml" in out
        assert "regex" in out
        assert "png" in out
        assert "binary_tlv" in out
        # Each entry has a description.
        for v in out.values():
            assert v["description"]

    def test_get_format_dictionary_returns_path(self):
        out = fr.get_format_dictionary.fn(format_name="json")
        assert out["ok"] is True
        assert out["dictionary_path"].endswith("json.dict")
        assert out["entries_estimated"] > 0

    def test_get_format_dictionary_copies(self, tmp_path):
        dst = tmp_path / "copied.dict"
        out = fr.get_format_dictionary.fn(
            format_name="json", output_path=str(dst),
        )
        assert out["ok"] is True
        assert dst.exists()
        assert dst.stat().st_size > 0

    def test_get_format_dictionary_unknown_format(self):
        out = fr.get_format_dictionary.fn(format_name="madeup")
        assert out["ok"] is False
        assert "no dictionary" in out["error"]

    def test_write_format_mutator(self, tmp_path):
        dst = tmp_path / "mut.c"
        out = fr.write_format_mutator.fn(format_name="json", output_path=str(dst))
        assert out["ok"] is True
        assert dst.exists()
        text = dst.read_text()
        assert "LLVMFuzzerCustomMutator" in text

    def test_write_format_mutator_unknown_format(self, tmp_path):
        out = fr.write_format_mutator.fn(
            format_name="madeup", output_path=str(tmp_path / "x.c"),
        )
        assert out["ok"] is False

    def test_compile_harness_links_custom_mutator(self, tmp_path):
        # We don't actually want to invoke clang here; mock subprocess and
        # the driver archive lookup, then assert the custom mutator path
        # appears in the AFL build command but NOT the coverage build.
        src = tmp_path / "h.c"
        src.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long){return 0;}")
        mutator = tmp_path / "mut.c"
        mutator.write_text("/* mutator */")
        fake_driver = tmp_path / "libAFLDriver.a"
        fake_driver.write_bytes(b"")
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return {"exit_code": 0, "stdout": "", "stderr": "", "cmd": " ".join(cmd)}

        with patch.object(fr.shutil, "which",
                          side_effect=lambda n: f"/usr/bin/{n}"), \
             patch.object(fr, "_afl_driver_archive", return_value=fake_driver), \
             patch.object(fr, "_build_standalone_driver", return_value=_DRIVER_OK), \
             patch.object(fr, "_run", side_effect=fake_run):
            out = fr.compile_harness.fn(
                harness_source=str(src),
                output_basename="h",
                custom_mutator_source=str(mutator),
            )
        assert out["ok"] is True
        # Custom mutator must appear in the AFL build command (first call),
        # but NOT the coverage build (second call).
        assert any(str(mutator) in arg for arg in captured[0])
        assert not any(str(mutator) in arg for arg in captured[1])
        assert out["custom_mutator"] == str(mutator)


# ---------------------------------------------------------------------------
# Source-aware (project-specific) smart mutator
# ---------------------------------------------------------------------------

class TestSourceAwareMutator:
    def test_c_string_escape_handles_specials(self):
        assert fr._c_string_escape("hello") == "hello"
        # Backslash and quote get escaped.
        assert "\\\\" in fr._c_string_escape("a\\b")
        assert '\\"' in fr._c_string_escape('a"b')
        # Common whitespace gets named escapes.
        assert "\\t" in fr._c_string_escape("\t")
        assert "\\n" in fr._c_string_escape("\n")
        # Other non-printable bytes get a 3-digit octal escape.
        out = fr._c_string_escape("\x01")
        assert "\\001" in out

    def test_extract_tokens_from_synthetic(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text(
            'static const char *kFOO = "MAGIC_TOKEN";\n'
            '#define WIDGET_VERSION 0xDEADBEEF\n'
            'switch (x) {\n'
            '    case 0xCAFEBABE: break;\n'
            '    case 0x12345678: break;\n'
            '}\n'
        )
        tokens = fr._extract_project_tokens(src)
        assert "MAGIC_TOKEN" in tokens["strings"]
        assert 0xDEADBEEF in tokens["constants"]
        assert 0xCAFEBABE in tokens["constants"]

    def test_extract_filters_noise(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text(
            '/* SPDX-License-Identifier: MIT */\n'
            'static const char *kLicense = "Licensed under the Apache License";\n'
            'static const char *kPath = "/usr/lib/libc.so";\n'
            'static const char *kHdr = "stdio.h";\n'
            'static const char *kAsm = "=r";\n'
            'static const char *kFlag = "-Wformat";\n'
            'static const char *kReal = "DEFINITELY_REAL_TOKEN";\n'
        )
        tokens = fr._extract_project_tokens(src)
        # All the noise should be dropped.
        assert not any("License" in s for s in tokens["strings"])
        assert "/usr/lib/libc.so" not in tokens["strings"]
        assert "stdio.h" not in tokens["strings"]
        assert "=r" not in tokens["strings"]
        assert "-Wformat" not in tokens["strings"]
        # The real one survives.
        assert "DEFINITELY_REAL_TOKEN" in tokens["strings"]

    def test_emit_mutator_strings_focus(self, tmp_path):
        src = tmp_path / "src"
        text = fr._emit_smart_mutator_c(src, "strings", ["TOK"], [0xDEADBEEF])
        # Only strings array present; no constants.
        assert "kSmartStrings" in text
        assert "kSmartConstants" not in text

    def test_emit_mutator_constants_focus(self, tmp_path):
        src = tmp_path / "src"
        text = fr._emit_smart_mutator_c(src, "constants", ["TOK"], [0xDEADBEEF])
        assert "kSmartStrings" not in text
        assert "kSmartConstants" in text
        assert "0xdeadbeef" in text

    def test_emit_mutator_combined_focus(self, tmp_path):
        src = tmp_path / "src"
        text = fr._emit_smart_mutator_c(src, "combined", ["TOK"], [0xDEADBEEF])
        assert "kSmartStrings" in text
        assert "kSmartConstants" in text

    def test_emit_mutator_empty_falls_back_to_passthrough(self, tmp_path):
        # No strings, no constants, no corpus → degenerate; should still
        # produce compilable C with a single pass-through case arm.
        src = tmp_path / "src"
        text = fr._emit_smart_mutator_c(src, "strings", [], [])
        # The fallback uses LLVMFuzzerMutate as the single op.
        assert "LLVMFuzzerMutate" in text

    def test_generate_smart_mutator_writes_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text('static const char *k = "TOK";\n')
        out = tmp_path / "m.c"
        result = fr.generate_smart_mutator.fn(
            source_root=str(src), output_path=str(out), focus="combined",
        )
        assert result["ok"] is True
        assert out.exists()
        assert "LLVMFuzzerCustomMutator" in out.read_text()

    def test_generate_smart_mutator_unknown_focus(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        out = fr.generate_smart_mutator.fn(
            source_root=str(src), output_path=str(tmp_path / "m.c"),
            focus="bogus",
        )
        assert out["ok"] is False
        assert "focus must be one of" in out["error"]

    def test_generate_smart_mutator_compiles_with_werror(self, tmp_path):
        import shutil as _shutil  # noqa: PLC0415
        import subprocess as _subprocess  # noqa: PLC0415
        if not _shutil.which("clang"):
            pytest.skip("clang not on PATH")
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text('static const char *k = "TOK";\n#define MAGIC 0xDEADBEEF\n')
        out = tmp_path / "m.c"
        fr.generate_smart_mutator.fn(
            source_root=str(src), output_path=str(out), focus="combined",
        )
        r = _subprocess.run(
            ["clang", "-c", "-O1", "-Wall", "-Wextra", "-Werror",
             str(out), "-o", str(tmp_path / "m.o")],
            capture_output=True, text=True, timeout=60,
        )
        assert r.returncode == 0, r.stderr

    def test_generate_smart_mutators_emits_three_variants(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text('static const char *k = "TOK";\n#define MAGIC 0xDEADBEEF\n')
        out_dir = tmp_path / "out"
        result = fr.generate_smart_mutators.fn(
            source_root=str(src), output_dir=str(out_dir), basename="smart",
        )
        assert result["ok"] is True
        assert "strings" in result["variants"]
        assert "constants" in result["variants"]
        assert "combined" in result["variants"]
        for path in result["variants"].values():
            assert Path(path).exists()


# ---------------------------------------------------------------------------
# Project-aware AFL dictionary
# ---------------------------------------------------------------------------

class TestProjectDictionary:
    def test_afl_dict_escape(self):
        assert fr._afl_dict_escape("hello") == "hello"
        # Quotes / backslashes get escaped.
        assert fr._afl_dict_escape('a"b') == 'a\\"b'
        assert fr._afl_dict_escape("a\\b") == "a\\\\b"
        # Non-printable bytes get \xNN.
        assert "\\x01" in fr._afl_dict_escape("\x01")
        assert "\\x89" in fr._afl_dict_escape("\x89")

    def test_read_afl_dict_keys_strips_comments(self, tmp_path):
        d = tmp_path / "x.dict"
        d.write_text(
            '# header comment\n'
            'kw0="MAGIC"\n'
            'kw1="\\xde\\xad\\xbe\\xef"  # 0xdeadbeef le\n'
            '\n'
            'kw2="POST"\n'
        )
        keys = fr._read_afl_dict_keys(d)
        assert "MAGIC" in keys
        assert "POST" in keys
        assert "\\xde\\xad\\xbe\\xef" in keys

    def test_append_to_afl_dict_idempotent(self, tmp_path):
        d = tmp_path / "x.dict"
        # First pass: should add 1 string + 2 constant entries (LE+BE).
        out1 = fr._append_to_afl_dict(d, ["MAGIC"], [0xDEADBEEF])
        assert out1["added_strings"] == 1
        assert out1["added_constants"] == 2
        # Re-running with the same input adds nothing.
        out2 = fr._append_to_afl_dict(d, ["MAGIC"], [0xDEADBEEF])
        assert out2["added_strings"] == 0
        assert out2["added_constants"] == 0
        assert out2["skipped_existing"] >= 3

    def test_generate_project_dictionary(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "p.c").write_text(
            'static const char *k = "PROTOCOL_TOKEN";\n'
            '#define MAGIC 0xCAFEBABE\n'
        )
        out = tmp_path / "auto.dict"
        result = fr.generate_project_dictionary.fn(
            source_root=str(src), output_path=str(out),
        )
        assert result["ok"] is True
        text = out.read_text()
        assert "PROTOCOL_TOKEN" in text
        # 0xCAFEBABE little-endian = \xbe\xba\xfe\xca, big-endian reverse.
        assert "\\xbe\\xba\\xfe\\xca" in text or "\\xca\\xfe\\xba\\xbe" in text

    def test_enrich_dictionary_extracts_strncmp_token(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = src / "p.c"
        target.write_text(
            'void parse(const char *p) {\n'
            '    if (strncmp(p, "BEGIN", 5) == 0) {\n'
            '        do_thing();\n'  # ← uncovered line we'll point at
            '    }\n'
            '}\n'
        )
        out = tmp_path / "auto.dict"
        result = fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": str(target), "line": 3}],
        )
        assert result["ok"] is True
        text = out.read_text()
        assert "BEGIN" in text

    def test_enrich_dictionary_extracts_memcmp_magic(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = src / "p.c"
        target.write_text(
            'void parse(const char *p) {\n'
            '    if (memcmp(p, "\\x89PNG", 4) == 0) {\n'
            '        decode_png();\n'  # ← uncovered
            '    }\n'
            '}\n'
        )
        out = tmp_path / "auto.dict"
        fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": str(target), "line": 3}],
        )
        text = out.read_text()
        assert "\\x89" in text
        assert "PNG" in text

    def test_enrich_dictionary_extracts_case_constants(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = src / "p.c"
        target.write_text(
            'void dispatch(int op) {\n'
            '    switch (op) {\n'
            '    case 0xDEADBEEF:\n'
            '        do_thing();\n'  # uncovered
            '        break;\n'
            '    }\n'
            '}\n'
        )
        out = tmp_path / "auto.dict"
        fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": str(target), "line": 4}],
        )
        text = out.read_text()
        # Either endianness is fine.
        assert "\\xde\\xad\\xbe\\xef" in text or "\\xef\\xbe\\xad\\xde" in text

    def test_enrich_dictionary_idempotent(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = src / "p.c"
        target.write_text(
            'void f(const char *p){ if (strncmp(p,"TOK",3)==0){ x(); } }\n'
        )
        out = tmp_path / "auto.dict"
        r1 = fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": str(target), "line": 1}],
        )
        r2 = fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": str(target), "line": 1}],
        )
        assert r1["added_strings"] >= 1
        assert r2["added_strings"] == 0

    def test_enrich_dictionary_no_uncovered_is_noop(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "auto.dict"
        result = fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[],
        )
        assert result["ok"] is True
        assert result["added_strings"] == 0
        assert result["added_constants"] == 0
        # No file should have been created when there's nothing to write.
        assert not out.exists()

    def test_enrich_dictionary_handles_relative_paths(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = src / "p.c"
        target.write_text(
            'void f(const char *p){ if (strncmp(p,"TOK",3)==0){ x(); } }\n'
        )
        out = tmp_path / "auto.dict"
        # Pass a relative path that's resolvable under source_root.
        result = fr.enrich_dictionary_from_uncovered.fn(
            source_root=str(src), dictionary_path=str(out),
            uncovered_locations=[{"file": "p.c", "line": 1}],
        )
        assert result["ok"] is True
        assert result["added_strings"] >= 1
