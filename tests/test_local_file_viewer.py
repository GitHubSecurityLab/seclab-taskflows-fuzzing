# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import os
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

import seclab_taskflows_fuzzing.mcp_servers.local_file_viewer as lfv_mod
from seclab_taskflows_fuzzing.mcp_servers.local_file_viewer import get_file, search_zipfile

# The zip entries use a root directory prefix, like a GitHub zipball, which
# local_file_viewer strips via remove_root_dir().
ROOT = "owner-repo-abc1234"

SAMPLE = 'import os\nprint("héllo wörld")\n'


def _make_zip_on_disk(tmp_dir, owner, repo, files):
    """Write a zipball-style archive to {tmp_dir}/{owner}/{repo}.zip."""
    owner_dir = Path(tmp_dir) / owner
    owner_dir.mkdir(parents=True, exist_ok=True)
    zip_path = owner_dir / f"{repo}.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for path, content in files.items():
            zf.writestr(f"{ROOT}/{path}", content)
    return zip_path


class TestGetFileDecodesBytes:
    def test_get_file_returns_decoded_str_lines(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = _make_zip_on_disk(tmp_dir, "owner", "repo", {"foo.py": SAMPLE})
            lines = get_file(zip_path, "foo.py")
            # Lines must be decoded str, not bytes, and free of b'...' reprs.
            assert lines == ["import os", 'print("héllo wörld")']
            assert all(isinstance(line, str) for line in lines)

    def test_get_file_handles_invalid_utf8_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            owner_dir = Path(tmp_dir) / "owner"
            owner_dir.mkdir(parents=True)
            zip_path = owner_dir / "repo.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(f"{ROOT}/bin.dat", b"good\n\xff\xfe\n")
            lines = get_file(zip_path, "bin.dat")
            assert lines[0] == "good"
            assert all(isinstance(line, str) for line in lines)


class TestSearchZipfileDecodesBytes:
    def test_search_matches_non_ascii_term(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = _make_zip_on_disk(tmp_dir, "owner", "repo", {"foo.py": SAMPLE})
            results = search_zipfile(zip_path, "héllo")
            assert results == {"foo.py": [2]}

    def test_search_handles_invalid_utf8_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            owner_dir = Path(tmp_dir) / "owner"
            owner_dir.mkdir(parents=True)
            zip_path = owner_dir / "repo.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(f"{ROOT}/bin.dat", b"good\n\xff\xfe match\n")
            # errors="replace" means the invalid bytes must not raise and the
            # searchable term on the same line is still matched.
            results = search_zipfile(zip_path, "match")
            assert results == {"bin.dat": [2]}


class TestFetchFileContentTool:
    @pytest.mark.asyncio
    async def test_fetch_file_content_returns_decoded_numbered_lines(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _make_zip_on_disk(tmp_dir, "owner", "repo", {"foo.py": SAMPLE})
            # Resolve symlinks (e.g. macOS /var -> /private/var) so the patched
            # dir matches sanitize_file_path's os.path.realpath comparison.
            with patch.object(lfv_mod, "LOCAL_GH_DIR", os.path.realpath(tmp_dir)):
                result = await lfv_mod.fetch_file_content(owner="Owner", repo="Repo", path="foo.py")
            assert "1: import os" in result
            assert '2: print("héllo wörld")' in result
            # Ensure no Python bytes reprs leak into the output.
            assert "b'" not in result

    @pytest.mark.asyncio
    async def test_get_file_lines_returns_decoded_range(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _make_zip_on_disk(tmp_dir, "owner", "repo", {"foo.py": SAMPLE})
            # Resolve symlinks (e.g. macOS /var -> /private/var) so the patched
            # dir matches sanitize_file_path's os.path.realpath comparison.
            with patch.object(lfv_mod, "LOCAL_GH_DIR", os.path.realpath(tmp_dir)):
                result = await lfv_mod.get_file_lines(
                    owner="owner", repo="repo", path="foo.py", start_line=2, length=1
                )
            assert result == '2: print("héllo wörld")'
            assert "b'" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
