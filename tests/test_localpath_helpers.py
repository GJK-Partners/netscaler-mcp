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
    """The held parent (traverse right only) is opened once more relative to
    ITSELF - an empty name, `FILE_WRITE_DATA` - and that handle is flushed:
    no open by name, no other component, and the flush really happens."""
    root = tmp_path / "wortel"
    root.mkdir()
    with localpath.open_local_for_append(str(root / "x.jsonl"), root=str(root), shared_writers=True) as handle:
        handle.write(b"regel\n")
        opens_before = len(seam.opens)
        parent = handle._chain[-1]
        result = handle.flush_directory()
        new_opens = seam.opens[opens_before:]
    assert result is True, "de map is geflusht (1.0.3 en de eerste bouw deden op Windows niets)"
    assert len(new_opens) == 1, new_opens
    assert new_opens[0]["name"] == "" and new_opens[0]["parent"] == parent, "heropening van de vastgehouden ouder zelf"
    assert new_opens[0]["access"] & localpath.FILE_WRITE_DATA
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


# ---------------------------------------------------------------------------
# Herstelronde 1: metadata and listings through the walk, the hardlink kind,
# the write routes off Windows.
# ---------------------------------------------------------------------------

_SHARE = "\\\\192.0.2.10\\x"


def _share_link(link: Path) -> None:
    try:
        os.symlink(_SHARE, link, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")


def _no_share_contact(native, started: float) -> None:
    """The proof that a call never reached the network: no open names the
    share, the share's target never passed the volume step, and the call
    took less than 100 ms (a contact with the documentation address takes
    about 21 s, measured in the review)."""
    import time

    for record in native.opens:
        assert "192.0.2.10" not in record["name"] and "mup" not in record["name"].lower(), record
    assert time.perf_counter() - started < 0.1, "de aanroep duurde zo lang als een netwerkcontact"


@windows_only
def test_exists_local_tells_file_dir_and_absent_and_never_follows_a_link_inside_the_root(tmp_path, seam):
    root = tmp_path / "wortel"
    (root / "map").mkdir(parents=True)
    (root / "a.txt").write_text("a", encoding="ascii")
    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(root / "link", outside)

    assert localpath.exists_local(str(root / "a.txt"), root=str(root)) == "file"
    assert localpath.exists_local(str(root / "map"), root=str(root)) == "dir"
    assert localpath.exists_local(str(root / "weg.txt"), root=str(root)) is None
    assert localpath.exists_local(str(root / "map" / "weg" / "x"), root=str(root)) is None
    with pytest.raises(PathRefused) as refused:
        localpath.exists_local(str(root / "link"), root=str(root))
    assert refused.value.soort == "koppeling"
    with pytest.raises(PathRefused) as refused:
        localpath.exists_local(str(root / "map"), root=str(root), expect="file")
    assert refused.value.soort == "geen_gewoon_bestand"
    assert seam.calls["ReadFile"] == 0


@windows_only
def test_exists_local_on_a_share_link_never_contacts_the_share(tmp_path, seam):
    import time

    _share_link(tmp_path / "voorouder")
    started = time.perf_counter()
    with pytest.raises(PathRefused) as refused:
        localpath.exists_local(str(tmp_path / "voorouder" / "x"), root=None)
    assert refused.value.soort == "netwerkpad"
    _no_share_contact(seam, started)


@windows_only
def test_list_local_reads_the_names_on_the_held_handle_and_opens_none_of_them(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    for name in ("b.jsonl", "a.jsonl", "c.txt"):
        (root / name).write_text("x", encoding="ascii")
    (root / "sub").mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(root / "link", outside)
    for index in range(300):  # more than one buffer of names
        (root / f"veel-{index:04d}-{'x' * 120}.txt").write_bytes(b"")

    names = localpath.list_local(str(root), root=str(root))

    assert {"a.jsonl", "b.jsonl", "c.txt", "sub", "link"} <= set(names)
    assert len(names) == 305 and "." not in names and ".." not in names
    opened = {record["name"] for record in seam.opens}
    assert not opened & {"a.jsonl", "b.jsonl", "c.txt", "sub", "link"}, "geen naam in de map is geopend"
    assert seam.calls["NtQueryDirectoryFile"] >= 2


@windows_only
def test_list_local_refuses_a_root_that_is_a_link_and_a_share_link_without_contact(tmp_path, seam):
    import time

    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(tmp_path / "link", outside)
    with pytest.raises(PathRefused) as refused:
        localpath.list_local(str(tmp_path / "link"), root=str(tmp_path / "link"))
    assert refused.value.soort == "koppeling"
    _share_link(tmp_path / "share")
    started = time.perf_counter()
    with pytest.raises(PathRefused) as refused:
        localpath.list_local(str(tmp_path / "share"), root=None)
    assert refused.value.soort == "netwerkpad"
    _no_share_contact(seam, started)


@windows_only
def test_mkdir_local_creates_every_missing_directory_relative_to_the_held_parent(tmp_path, seam):
    target = tmp_path / "a" / "b" / "c"
    localpath.mkdir_local(str(target), root=None)
    assert target.is_dir()
    localpath.mkdir_local(str(target), root=None)  # existing: left as it is
    creates = [record for record in seam.opens if record["disposition"] == localpath.FILE_CREATE]
    assert [record["name"] for record in creates] == ["a", "b", "c"]
    assert all(record["parent"] is not None for record in creates), "elke map relatief aan de vastgehouden ouder"


@windows_only
def test_mkdir_local_refuses_a_link_inside_the_root_and_creates_nothing_behind_it(tmp_path, seam):
    import time

    root = tmp_path / "wortel"
    root.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    _junction(root / "link", outside)
    with pytest.raises(PathRefused) as refused:
        localpath.mkdir_local(str(root / "link" / "nieuw"), root=str(root))
    assert refused.value.soort == "koppeling"
    assert list(outside.iterdir()) == []
    _share_link(tmp_path / "share")
    started = time.perf_counter()
    with pytest.raises(PathRefused) as refused:
        localpath.mkdir_local(str(tmp_path / "share" / "herkomst"), root=None)
    assert refused.value.soort == "netwerkpad"
    _no_share_contact(seam, started)


@windows_only
def test_a_hardlink_inside_the_root_is_refused(tmp_path, seam):
    """B.2 step 6 (revision 3): a file outside the root with a second name
    inside it is refused - reading and appending - before a byte is read or
    written; the same file without a root (a configured path) is read."""
    root = tmp_path / "wortel"
    root.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    (outside / "geheim.txt").write_bytes(b"GEHEIM")
    os.link(outside / "geheim.txt", root / "tweede-naam.txt")

    with pytest.raises(PathRefused) as refused:
        localpath.read_local(str(root / "tweede-naam.txt"), root=str(root), max_bytes=100)
    assert refused.value.soort == "hardlink" and str(refused.value) == localpath.REASONS["hardlink"]
    with pytest.raises(PathRefused) as refused:
        with localpath.open_local_for_append(str(root / "tweede-naam.txt"), root=str(root)) as handle:
            handle.write(b"erbij")
    assert refused.value.soort == "hardlink"
    assert seam.calls["ReadFile"] == 0 and seam.calls["WriteFile"] == 0
    assert (outside / "geheim.txt").read_bytes() == b"GEHEIM"
    assert localpath.read_configured(str(root / "tweede-naam.txt"), max_bytes=100).data == b"GEHEIM"


def test_every_write_route_refuses_off_windows_before_anything_opens(tmp_path, monkeypatch):
    """Revision 3: off Windows every write route of `localpath` raises
    `NotImplementedError` before anything is opened - also the routes this
    part added (create, rename, mkdir). Runs on Windows through the seam of
    the POSIX branch."""
    native = localpath._PosixNative(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    for call in (
        lambda: localpath.create_local(str(tmp_path / "x"), b"x", root=str(tmp_path)),
        lambda: localpath.rename_local(str(tmp_path / "x"), "y", root=str(tmp_path)),
        lambda: localpath.mkdir_local(str(tmp_path / "nieuw"), root=str(tmp_path)),
        lambda: localpath.replace_local(str(tmp_path / "x"), b"x", root=str(tmp_path)),
    ):
        with pytest.raises(NotImplementedError):
            call()
    assert native.opens == [] and native.calls == {}


@windows_only
def test_an_existing_leaf_that_cannot_be_opened_as_itself_is_unreadable_not_already_there(tmp_path, seam, monkeypatch):
    """F-8 of the red review of part 2: an exclusive create meets a name that
    exists but cannot be opened as itself (an ACL): that is `onleesbaar`,
    never `FileExistsError` - which a scan lock would read as another scan."""
    root = tmp_path / "wortel"
    root.mkdir()
    (root / "slot").write_bytes(b"1")
    real_open = seam.NtCreateFile

    def no_reopen(parent, name, access, share, disposition, options):
        if name == "slot" and disposition == localpath.FILE_OPEN:
            return localpath.STATUS_ACCESS_DENIED, None
        return real_open(parent, name, access, share, disposition, options)

    monkeypatch.setattr(seam, "NtCreateFile", no_reopen)
    with pytest.raises(PathRefused) as refused:
        localpath.create_local(str(root / "slot"), b"2", root=str(root))
    assert refused.value.soort == "onleesbaar"
    assert (root / "slot").read_bytes() == b"1"


# ---------------------------------------------------------------------------
# Herstelronde 2 (H1-M-1): deleting, a new work map and the free space on the
# walk.
# ---------------------------------------------------------------------------


@windows_only
def test_rmtree_local_deletes_a_tree_and_a_link_inside_as_itself_never_its_target(tmp_path, seam):
    root = tmp_path / "wortel"
    tree = root / "boom"
    (tree / "a" / "b").mkdir(parents=True)
    (tree / "x.txt").write_text("x", encoding="ascii")
    (tree / "a" / "b" / "y.txt").write_text("y", encoding="ascii")
    outside = tmp_path / "buiten"
    outside.mkdir()
    (outside / "behouden.txt").write_text("blijft", encoding="ascii")
    _junction(tree / "a" / "link", outside)

    localpath.rmtree_local(str(tree), root=str(root))

    assert not tree.exists()
    assert (outside / "behouden.txt").read_text(encoding="ascii") == "blijft", "het doel van de koppeling bleef"
    assert seam.calls["NtSetInformationFile"] >= 6
    deletes = [record for record in seam.opens if record["access"] == localpath._DELETE_OPEN]
    assert deletes and all(record["parent"] is not None for record in deletes), "elk object relatief geopend"


@windows_only
def test_rmtree_local_refuses_a_link_on_the_way_inside_the_root_and_deletes_nothing(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    outside = tmp_path / "buiten"
    (outside / "boom").mkdir(parents=True)
    _junction(root / "via", outside)
    with pytest.raises(PathRefused) as refused:
        localpath.rmtree_local(str(root / "via" / "boom"), root=str(root))
    assert refused.value.soort == "koppeling"
    assert (outside / "boom").is_dir()
    assert seam.calls["NtSetInformationFile"] == 0


@windows_only
def test_remove_local_deletes_a_file_by_its_handle_and_refuses_a_directory(tmp_path, seam):
    root = tmp_path / "wortel"
    (root / "map").mkdir(parents=True)
    (root / "slot").write_bytes(b"1")
    localpath.remove_local(str(root / "slot"), root=str(root))
    assert not (root / "slot").exists()
    localpath.remove_local(str(root / "slot"), root=str(root), missing_ok=True)
    with pytest.raises(FileNotFoundError):
        localpath.remove_local(str(root / "slot"), root=str(root))
    with pytest.raises(PathRefused) as refused:
        localpath.remove_local(str(root / "map"), root=str(root))
    assert refused.value.soort == "geen_gewoon_bestand" and (root / "map").is_dir()


@windows_only
def test_mkdtemp_local_creates_a_new_map_exclusively_relative_to_the_held_parent(tmp_path, seam):
    root = tmp_path / "wortel"
    root.mkdir()
    first = localpath.mkdtemp_local(str(root), "export.nieuw-", root=str(root))
    second = localpath.mkdtemp_local(str(root), "export.nieuw-", root=str(root))
    assert first != second and Path(first).is_dir() and Path(second).is_dir()
    assert Path(first).parent == root and Path(first).name.startswith("export.nieuw-")
    creates = [record for record in seam.opens if record["disposition"] == localpath.FILE_CREATE]
    assert len(creates) == 2 and all(record["parent"] is not None for record in creates)


@windows_only
def test_free_bytes_local_is_what_the_volume_reports_without_naming_a_path(tmp_path, seam):
    import shutil

    free = localpath.free_bytes_local(str(tmp_path))
    reported = shutil.disk_usage(tmp_path).free
    assert abs(free - reported) < 64 * 1024 * 1024, (free, reported)
    assert seam.calls["NtQueryVolumeInformationFile"] >= 2


def test_the_delete_and_temp_routes_refuse_off_windows_before_anything_opens(tmp_path, monkeypatch):
    native = localpath._PosixNative(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    for call in (
        lambda: localpath.rmtree_local(str(tmp_path / "x"), root=str(tmp_path)),
        lambda: localpath.remove_local(str(tmp_path / "x"), root=str(tmp_path)),
        lambda: localpath.mkdtemp_local(str(tmp_path), "w-", root=str(tmp_path)),
    ):
        with pytest.raises(NotImplementedError):
            call()
    assert native.opens == [] and native.calls == {}
