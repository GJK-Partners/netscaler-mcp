"""The helpers the readers use on top of `localpath.open_local`: one read with
its size checked on the handle, an exclusive create, a rename by handle in a
held parent, the directory flush on the held parent, the hand-over of a leaf
to a child process, and the text helpers that build a path below a root from
the SAME text. Windows proofs on real junctions, like
tests/test_localpath_windows.py; the text helpers run everywhere."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from nsmcp import localpath
from nsmcp.localpath import PathRefused

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="de wandeling over NtCreateFile bestaat alleen op Windows"
)


@pytest.fixture
def seam(monkeypatch):
    native = localpath._Native(record=True) if sys.platform == "win32" else localpath._PosixNative(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    return native


def _junction(link: Path, target: Path) -> None:
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def test_a_refusal_is_an_os_error_so_every_existing_fail_closed_route_catches_it():
    refused = PathRefused("koppeling", path="C:\\x")
    assert isinstance(refused, OSError)
    assert str(refused) == refused.reason == localpath.REASONS["koppeling"]
    assert localpath.describe(refused) == localpath.REASONS["koppeling"]
    assert localpath.describe(PermissionError(13, "geweigerd", "C:\\geheim")) == "PermissionError"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-spelling")
@pytest.mark.parametrize(
    ("root", "parts", "expected"),
    [
        ("C:\\export", ("objects", "x.json"), "C:\\export\\objects\\x.json"),
        ("C:\\export\\", ("objects/x.json",), "C:\\export\\objects\\x.json"),
        ("C:\\", ("x.json",), "C:\\x.json"),
        ("C:\\export", ("..", "x"), "C:\\export\\..\\x"),
    ],
)
def test_under_joins_as_text_and_normalizes_nothing(root, parts, expected):
    assert localpath.under(root, *parts) == expected


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-spelling")
@pytest.mark.parametrize(
    ("text", "expected"),
    [("C:\\a\\b.txt", "C:\\a"), ("C:\\b.txt", "C:\\"), ("\\\\?\\C:\\b.txt", "\\\\?\\C:\\")],
)
def test_parent_text_is_the_directory_part_of_the_same_text(text, expected):
    assert localpath.parent_text(text) == expected


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-spelling")
def test_absolute_text_keeps_an_absolute_text_and_checks_the_spelling_first(tmp_path, monkeypatch):
    assert localpath.absolute_text("C:\\Export\\x") == "C:\\Export\\x"
    assert localpath.absolute_text(Path("C:/Export/x")) == "C:\\Export\\x"
    monkeypatch.chdir(tmp_path)
    assert localpath.absolute_text("rel") == str(tmp_path / "rel")
    with pytest.raises(PathRefused) as refused:
        localpath.absolute_text("map.")
    assert refused.value.soort == "onleesbaar"
    with pytest.raises(PathRefused) as refused:
        localpath.absolute_text("\\\\server\\share\\x")
    assert refused.value.soort == "netwerkpad"


@windows_only
def test_read_local_reads_the_size_on_the_handle_before_a_byte(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    (root / "a.txt").write_bytes(b"0123456789")
    got = localpath.read_local(str(root / "a.txt"), root=str(root), max_bytes=10)
    assert got == localpath.LocalRead(True, b"0123456789", 10, False)
    reads_before = seam.calls["ReadFile"]
    over = localpath.read_local(str(root / "a.txt"), root=str(root), max_bytes=9)
    assert over == localpath.LocalRead(True, b"", 10, True)
    assert seam.calls["ReadFile"] == reads_before, "boven het plafond is niets gelezen"
    missing = localpath.read_local(str(root / "b.txt"), root=str(root), max_bytes=9, allow_missing=True)
    assert missing == localpath.LocalRead(False, b"", 0, False)


@windows_only
def test_create_local_is_exclusive_and_names_a_link_in_its_place(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    localpath.create_local(str(root / "slot"), b"123", root=str(root))
    assert (root / "slot").read_bytes() == b"123"
    with pytest.raises(FileExistsError):
        localpath.create_local(str(root / "slot"), b"456", root=str(root))
    assert (root / "slot").read_bytes() == b"123"
    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(root / "koppeling", outside)
    with pytest.raises(PathRefused) as refused:
        localpath.create_local(str(root / "koppeling"), b"789", root=str(root))
    assert refused.value.soort == "koppeling"
    assert list(outside.iterdir()) == []
    assert seam.calls["WriteFile"] == 1, "alleen het eerste slot is geschreven"


@windows_only
def test_rename_local_renames_by_handle_and_never_replaces(tmp_path, seam):
    root = tmp_path / "wortel"
    (root / "export.nieuw").mkdir(parents=True)
    (root / "export.nieuw" / "m.json").write_text("{}", encoding="ascii")
    localpath.rename_local(str(root / "export.nieuw"), "export", root=str(root))
    assert (root / "export" / "m.json").exists() and not (root / "export.nieuw").exists()
    (root / "ander").mkdir()
    with pytest.raises(FileExistsError):
        localpath.rename_local(str(root / "ander"), "export", root=str(root))
    assert (root / "ander").is_dir() and (root / "export" / "m.json").exists()
    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(root / "link", outside)
    with pytest.raises(PathRefused) as refused:
        localpath.rename_local(str(root / "link"), "export.vorig", root=str(root))
    assert refused.value.soort == "koppeling"
    assert (root / "link").exists() and not (root / "export.vorig").exists()
    with pytest.raises(PathRefused) as refused:
        localpath.rename_local(str(root / "ander"), "..", root=str(root))
    assert refused.value.soort == "onleesbaar"


@windows_only
def test_rename_local_refuses_a_parent_that_became_a_link_before_anything_is_renamed(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    real = tmp_path / "echt"
    (real / "a").mkdir(parents=True)
    _junction(root / "p", real)
    with pytest.raises(PathRefused) as refused:
        localpath.rename_local(str(root / "p" / "a"), "b", root=str(root))
    assert refused.value.soort == "koppeling"
    assert (real / "a").is_dir() and not (real / "b").exists()
    assert seam.calls["NtSetInformationFile"] == 0


@windows_only
def test_the_directory_flush_uses_the_held_parent_and_opens_nothing_by_name(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    with localpath.open_local_for_append(str(root / "x.jsonl"), root=str(root), shared_writers=True) as handle:
        handle.write(b"regel\n")
        opens_before = seam.calls["NtCreateFile"]
        result = handle.flush_directory()
        assert seam.calls["NtCreateFile"] == opens_before, "geen tweede open op naam"
    assert isinstance(result, bool)
    assert (root / "x.jsonl").read_bytes() == b"regel\n"


@windows_only
def test_a_leaf_handed_to_a_child_process_takes_its_output(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    log = root / "runner.log"
    log.write_bytes(b"eerder\n")
    with localpath.open_local_for_append(str(log), root=str(root), shared_writers=True) as handle:
        fd = handle.detach_leaf_fd()
        try:
            subprocess.run([sys.executable, "-c", "print('kind')"], stdout=fd, stderr=subprocess.STDOUT, check=True)
        finally:
            os.close(fd)
    assert log.read_bytes().replace(b"\r\n", b"\n") == b"eerder\nkind\n"
    closed_leaf = [record for record in seam.opens if record["name"] == "runner.log"][0]["handle"]
    assert seam.closes.count(closed_leaf) == 0, "het blad is door de descriptor gesloten, niet tweemaal"
