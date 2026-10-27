"""Windows proofs of `nsmcp.localpath` on real junctions and symbolic links.

Every proof that a walk does not leave the approved tree reads the seam
(`localpath._native` with `record=True`): each native open after the volume
root is relative to a handle the walk holds at that moment, with the name of
exactly one component, and nothing below a refused link has had an open
attempt. A refusal that only comes after an open of the place outside the
root does not count as a passing proof: that is why every race test asserts
on the opens, not only on the kind.

Junctions need no administrator right (`_winapi.CreateJunction`); a symbolic
link needs the right or Developer Mode, otherwise its test is skipped with
the reason."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

from nsmcp import localpath
from nsmcp.localpath import PathRefused

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="de wandeling over NtCreateFile bestaat alleen op Windows"
)

_VOLUME_ROOT = re.compile(r"\\Device\\HarddiskVolume[0-9]+\\", re.IGNORECASE)


@pytest.fixture
def seam(monkeypatch):
    native = localpath._Native(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    return native


def _junction(link: Path, target: Path) -> None:
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def _symlink(link: Path, target: str, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")


def _is_reparse_point(path: Path) -> bool:
    return bool(os.lstat(path).st_file_attributes & localpath.FILE_ATTRIBUTE_REPARSE_POINT)


def _audit(native: localpath._Native) -> list[str]:
    """Every open is the volume root by its device name, or one component
    relative to a handle that was opened earlier and is still open. Every
    handle is closed exactly once. Returns the opened names in order."""
    live: set[int] = set()
    names = []
    for kind, value in native.events:
        if kind == "close":
            assert value in live, f"handle {value} gesloten zonder open of tweemaal"
            live.discard(value)
            continue
        record = native.opens[value]
        names.append(record["name"])
        if record["parent"] is None:
            assert _VOLUME_ROOT.fullmatch(record["name"]), record["name"]
        else:
            assert record["parent"] in live, f"open relatief aan een handle die niet vastgehouden is: {record}"
            name = record["name"]
            assert name not in ("", ".", "..") and "\\" not in name and "/" not in name and ":" not in name, name
            assert record["options"] & localpath.FILE_OPEN_REPARSE_POINT, record
        if record["access"] in (localpath.DIR_ACCESS, localpath.DIR_LIST_ACCESS):
            assert record["share"] == localpath.DIR_SHARE, record
        if record["handle"] is not None:
            live.add(record["handle"])
    assert live == set(), f"handles niet gesloten: {live}"
    return names


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """`wortel\\P\\C\\leaf.txt` ("binnen") and outside the root
    `buiten\\leaf.txt` plus `buiten\\C\\leaf.txt` ("buiten")."""
    root = tmp_path / "wortel"
    (root / "P" / "C").mkdir(parents=True)
    (root / "P" / "C" / "leaf.txt").write_text("binnen", encoding="ascii")
    outside = tmp_path / "buiten"
    (outside / "C").mkdir(parents=True)
    (outside / "leaf.txt").write_text("buiten", encoding="ascii")
    (outside / "C" / "leaf.txt").write_text("buiten", encoding="ascii")
    return root, outside


def _refused(call) -> PathRefused:
    with pytest.raises(PathRefused) as refused:
        call()
    return refused.value


# ---------------------------------------------------------------------------
# The walk itself
# ---------------------------------------------------------------------------


def test_a_plain_file_is_read_component_by_component_and_every_handle_closes_once(tmp_path, seam):
    root, _ = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    assert localpath.read_local_bytes(str(leaf), root=str(root), max_bytes=100) == b"binnen"
    names = _audit(seam)
    assert names[1:] == list(leaf.parts[1:])
    opened = [record["handle"] for record in seam.opens if record["handle"] is not None]
    assert seam.closes == list(reversed(opened)), "sluiten in omgekeerde volgorde, blad eerst"
    assert seam.calls["ReadFile"] >= 1


def test_the_leaf_is_shared_for_reading_only_unless_writers_are_expected(tmp_path, seam):
    root, _ = _tree(tmp_path)
    leaf = str(root / "P" / "C" / "leaf.txt")
    localpath.read_local_bytes(leaf, root=str(root), max_bytes=100)
    localpath.read_local_bytes(leaf, root=str(root), max_bytes=100, shared_writers=True)
    leaves = [record for record in seam.opens if record["name"] == "leaf.txt"]
    assert [record["share"] for record in leaves] == [
        localpath.FILE_SHARE_READ,
        localpath.FILE_SHARE_READ | localpath.FILE_SHARE_WRITE,
    ]
    directories = [record for record in seam.opens if record["name"] in ("P", "C")]
    assert {record["share"] for record in directories} == {localpath.FILE_SHARE_READ | localpath.FILE_SHARE_WRITE}


def test_a_read_returns_at_most_one_byte_over_the_cap(tmp_path, seam):
    big = tmp_path / "groot.bin"
    big.write_bytes(b"x" * 5000)
    assert len(localpath.read_local_bytes(str(big), root=str(tmp_path), max_bytes=1000)) == 1001
    assert len(localpath.read_local_bytes(str(big), root=str(tmp_path), max_bytes=5000)) == 5000


def test_a_missing_file_is_unreadable_unless_absence_is_allowed(tmp_path, seam):
    missing = tmp_path / "ontbreekt" / "x.json"
    refused = _refused(lambda: localpath.read_local_bytes(str(missing), root=str(tmp_path), max_bytes=10))
    assert refused.soort == "onleesbaar"
    assert refused.status == localpath.STATUS_OBJECT_NAME_NOT_FOUND
    with localpath.open_local(str(missing), root=str(tmp_path), allow_missing=True) as handle:
        assert handle.exists is False
    _audit(seam)


def test_a_directory_where_a_file_is_expected_and_the_reverse_are_no_regular_file(tmp_path, seam):
    root, _ = _tree(tmp_path)
    assert _refused(lambda: localpath.read_local_bytes(str(root / "P"), root=str(root), max_bytes=10)).soort == (
        "geen_gewoon_bestand"
    )
    file_as_dir = root / "P" / "C" / "leaf.txt" / "x"
    assert _refused(lambda: localpath.read_local_bytes(str(file_as_dir), root=str(root), max_bytes=10)).soort == (
        "geen_gewoon_bestand"
    )
    with localpath.open_local(str(root / "P"), root=str(root), expect="dir") as handle:
        assert handle.directory_handle is not None
    _audit(seam)


def test_the_volume_guid_spelling_reads_the_same_file(tmp_path, seam):
    import ctypes

    leaf = tmp_path / "x.txt"
    leaf.write_text("guid", encoding="ascii")
    name = ctypes.create_unicode_buffer(64)
    assert ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(leaf.drive + "\\", name, len(name))
    spelled = name.value + str(leaf)[3:]
    assert localpath.read_local_bytes(spelled, max_bytes=10) == b"guid"


# ---------------------------------------------------------------------------
# Links and reparse points
# ---------------------------------------------------------------------------


def test_junction_inside_the_root_is_a_link_and_nothing_below_it_is_opened(tmp_path, seam):
    root, outside = _tree(tmp_path)
    _junction(root / "J", outside)
    refused = _refused(lambda: localpath.read_local_bytes(str(root / "J" / "leaf.txt"), root=str(root), max_bytes=10))
    assert refused.soort == "koppeling"
    names = _audit(seam)
    assert names[-1] == "J" and "leaf.txt" not in names
    assert seam.calls["DeviceIoControl"] == 0, "binnen de wortel wordt een koppeling niet gelezen of gevolgd"


def test_the_root_itself_being_a_junction_is_refused(tmp_path, seam):
    _, outside = _tree(tmp_path)
    linked_root = tmp_path / "wortel-koppeling"
    _junction(linked_root, outside)
    refused = _refused(
        lambda: localpath.read_local_bytes(str(linked_root / "leaf.txt"), root=str(linked_root), max_bytes=10)
    )
    assert refused.soort == "koppeling"
    names = _audit(seam)
    assert names[-1] == "wortel-koppeling"


def test_a_junction_in_the_place_of_a_file_is_a_link_not_a_wrong_type(tmp_path, seam):
    root, outside = _tree(tmp_path)
    _junction(root / "P" / "plek.json", outside)
    refused = _refused(lambda: localpath.read_local_bytes(str(root / "P" / "plek.json"), root=str(root), max_bytes=10))
    assert refused.soort == "koppeling"
    leaf_open = [record for record in seam.opens if record["name"] == "plek.json"][0]
    assert leaf_open["options"] & (localpath.FILE_DIRECTORY_FILE | localpath.FILE_NON_DIRECTORY_FILE) == 0
    _audit(seam)


def test_a_junction_above_the_root_is_followed_to_its_local_target(tmp_path, seam):
    root, _ = _tree(tmp_path)
    above = tmp_path / "boven"
    _junction(above, root.parent)
    via = above / "wortel" / "P" / "C" / "leaf.txt"
    assert localpath.read_local_bytes(str(via), root=str(above / "wortel"), max_bytes=10) == b"binnen"
    assert localpath.read_local_bytes(str(via), max_bytes=10) == b"binnen"
    _audit(seam)
    assert seam.calls["DeviceIoControl"] == 2
    assert localpath.check_where_it_leads(str(via), expect="file") == root / "P" / "C" / "leaf.txt"


def test_a_file_symlink_inside_the_root_is_a_link(tmp_path, seam):
    root, outside = _tree(tmp_path)
    _symlink(root / "P" / "s.txt", str(outside / "leaf.txt"), directory=False)
    refused = _refused(lambda: localpath.read_local_bytes(str(root / "P" / "s.txt"), root=str(root), max_bytes=10))
    assert refused.soort == "koppeling"
    assert "tag 0xA000000C" in refused.detail
    _audit(seam)


def test_a_symlink_above_the_root_to_a_share_is_refused_before_anything_of_it_opens(tmp_path, seam):
    above = tmp_path / "gedeeld"
    _symlink(above, r"\\192.0.2.10\x", directory=True)
    refused = _refused(lambda: localpath.read_local_bytes(str(above / "export" / "x.json"), max_bytes=10))
    assert refused.soort == "netwerkpad"
    assert refused.followed is True
    names = _audit(seam)
    assert names[-1] == "gedeeld"
    assert not any("192.0.2.10" in name for name in names)
    assert seam.calls["GetDriveTypeW"] == 1, "het doel kwam niet verder dan de spellingstap"


def test_a_relative_symlink_above_the_root_is_composed_against_its_parent(tmp_path, seam):
    root, _ = _tree(tmp_path)
    (tmp_path / "a").mkdir()
    _symlink(tmp_path / "a" / "terug", r"..\wortel", directory=True)
    via = tmp_path / "a" / "terug" / "P" / "C" / "leaf.txt"
    assert localpath.read_local_bytes(str(via), max_bytes=10) == b"binnen"
    _audit(seam)


def test_more_links_than_the_limit_is_refused(tmp_path, seam):
    target = tmp_path / "doel"
    target.mkdir()
    previous = target
    for index in range(localpath.LINK_LIMIT + 1):
        link = tmp_path / f"j{index}"
        _junction(link, previous)
        previous = link
    within = previous
    refused = _refused(lambda: localpath.check_where_it_leads(str(within), expect="dir"))
    assert refused.soort == "te_veel_koppelingen"
    just_enough = tmp_path / f"j{localpath.LINK_LIMIT - 1}"
    assert localpath.check_where_it_leads(str(just_enough), expect="dir") == target
    _audit(seam)


def test_a_cloud_placeholder_is_a_reparse_point_inside_and_above_the_root(tmp_path, seam, monkeypatch):
    root, _ = _tree(tmp_path)
    real = seam.query_attribute_tag
    names = {}

    def tagged_open(parent, name, *args):
        status, handle = type(seam).NtCreateFile(seam, parent, name, *args)
        if handle is not None:
            names[handle] = name
        return status, handle

    def cloud_tag(handle):
        status, attributes, tag = real(handle)
        if names.get(handle) == "P":
            return status, attributes | localpath.FILE_ATTRIBUTE_REPARSE_POINT, 0x9000601A
        return status, attributes, tag

    monkeypatch.setattr(seam, "NtCreateFile", tagged_open)
    monkeypatch.setattr(seam, "query_attribute_tag", cloud_tag)
    leaf = str(root / "P" / "C" / "leaf.txt")
    assert _refused(lambda: localpath.read_local_bytes(leaf, root=str(root), max_bytes=10)).soort == "herparseerpunt"
    assert _refused(lambda: localpath.read_local_bytes(leaf, max_bytes=10)).soort == "herparseerpunt"
    assert seam.calls["DeviceIoControl"] == 0


def test_an_alternate_data_stream_is_refused_before_any_open(tmp_path, seam):
    (tmp_path / "objects").mkdir()
    (tmp_path / "objects" / "x.json").write_text("{}", encoding="ascii")
    stream = str(tmp_path / "objects" / "x.json") + ":zijstroom"
    refused = _refused(lambda: localpath.read_local_bytes(stream, root=str(tmp_path), max_bytes=10))
    assert refused.soort == "stroom"
    assert seam.calls["NtCreateFile"] == 0
    with pytest.raises(PathRefused):
        with localpath.open_local_for_append(stream, root=str(tmp_path)):
            pass
    assert seam.calls["NtCreateFile"] == 0, "een relatieve open op naam:stroom maakt anders de stroom aan"


# ---------------------------------------------------------------------------
# The volume: network drive, device targets
# ---------------------------------------------------------------------------


def test_a_network_drive_letter_is_refused_without_any_open(tmp_path, seam, monkeypatch):
    monkeypatch.setattr(seam, "GetDriveTypeW", lambda root: localpath.DRIVE_REMOTE)
    refused = _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x.json"), max_bytes=10))
    assert refused.soort == "netwerkstation"
    assert seam.calls["NtCreateFile"] == 0
    assert localpath.drive_is_remote(tmp_path.drive) is True


@pytest.mark.parametrize(
    ("targets", "soort"),
    [
        (["\\Device\\Mup\\;LanmanRedirector\\server\\share"], "netwerkstation"),
        (["\\Device\\LanmanRedirector\\;Z:0\\server\\share"], "netwerkstation"),
        (["\\??\\UNC\\server\\share"], "netwerkstation"),
        (["\\??\\C:\\subst-doel"], "apparaatpad"),
        (["\\Device\\HarddiskVolumeShadowCopy3"], "apparaatpad"),
        (["\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume4"], "apparaatpad"),
        (None, "apparaatpad"),
    ],
)
def test_a_drive_letter_that_is_not_one_local_volume_is_refused_without_any_open(
    tmp_path, seam, monkeypatch, targets, soort
):
    monkeypatch.setattr(seam, "QueryDosDeviceW", lambda name: targets)
    refused = _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x.json"), max_bytes=10))
    assert refused.soort == soort
    assert seam.calls["NtCreateFile"] == 0


@pytest.mark.parametrize("drive_type", [0, 1, 2, 5, 6])
def test_a_drive_that_is_not_a_fixed_disk_is_a_device(tmp_path, seam, monkeypatch, drive_type):
    monkeypatch.setattr(seam, "GetDriveTypeW", lambda root: drive_type)
    assert _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x"), max_bytes=1)).soort == "apparaatpad"
    assert seam.calls["NtCreateFile"] == 0


def test_a_volume_root_that_is_not_a_local_disk_device_is_a_network_path(tmp_path, seam, monkeypatch):
    monkeypatch.setattr(seam, "query_fs_device", lambda handle: (0, localpath.FILE_DEVICE_DISK, 0x10))
    assert _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x"), max_bytes=1)).soort == "netwerkpad"
    _audit(seam)


# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------


def test_a_network_status_mid_walk_is_a_network_path_with_a_defect_line(tmp_path, seam, monkeypatch, capsys):
    real = seam.NtCreateFile

    def network(parent, name, *args):
        if name == "x.json":
            return 0xC00000CC, None
        return real(parent, name, *args)

    monkeypatch.setattr(seam, "NtCreateFile", network)
    refused = _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x.json"), root=str(tmp_path), max_bytes=1))
    assert refused.soort == "netwerkpad"
    assert localpath.DEFECT_LINE in capsys.readouterr().err
    _audit(seam)


def test_a_status_nobody_named_is_unreadable_and_closes_the_chain(tmp_path, seam, monkeypatch):
    real = seam.NtCreateFile

    def strange(parent, name, *args):
        if name == "x.json":
            return 0xC0000001, None
        return real(parent, name, *args)

    monkeypatch.setattr(seam, "NtCreateFile", strange)
    assert _refused(lambda: localpath.read_local_bytes(str(tmp_path / "x.json"), max_bytes=1)).soort == "onleesbaar"
    _audit(seam)


def test_a_file_held_without_read_sharing_is_unreadable(tmp_path, seam):
    import _winapi

    leaf = tmp_path / "bezet.txt"
    leaf.write_text("x", encoding="ascii")
    holder = _winapi.CreateFile(str(leaf), _winapi.GENERIC_READ, 0, 0, _winapi.OPEN_EXISTING, 0, 0)
    try:
        refused = _refused(lambda: localpath.read_local_bytes(str(leaf), root=str(tmp_path), max_bytes=10))
    finally:
        _winapi.CloseHandle(holder)
    assert refused.soort == "onleesbaar"
    assert refused.status == localpath.STATUS_SHARING_VIOLATION
    _audit(seam)


def test_a_running_append_blocks_a_reader_that_does_not_share_writing(tmp_path, seam):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b'{"a": 1}\n')
    with open(ledger, "ab") as appender:
        appender.write(b'{"b": 2}\n')
        appender.flush()
        refused = _refused(lambda: localpath.read_local_bytes(str(ledger), root=str(tmp_path), max_bytes=100))
        assert refused.status == localpath.STATUS_SHARING_VIOLATION
        content = localpath.read_local_bytes(str(ledger), root=str(tmp_path), max_bytes=100, shared_writers=True)
        assert content == b'{"a": 1}\n{"b": 2}\n'
    _audit(seam)


def test_no_status_and_no_path_in_the_refusal_only_in_the_debug_log(tmp_path, seam, monkeypatch, capsys):
    root, outside = _tree(tmp_path)
    _junction(root / "J", outside)
    target = str(root / "J" / "leaf.txt")
    monkeypatch.delenv("NSMCP_DEBUG", raising=False)
    refused = _refused(lambda: localpath.read_local_bytes(target, root=str(root), max_bytes=1))
    assert str(refused) == localpath.REASONS["koppeling"]
    assert capsys.readouterr().err == ""
    monkeypatch.setenv("NSMCP_DEBUG", "1")
    missing = str(root / "geen.txt")
    _refused(lambda: localpath.read_local_bytes(missing, root=str(root), max_bytes=1))
    err = capsys.readouterr().err
    assert "0xC0000034" in err and repr(missing) in err and err.count("\n") == 1


# ---------------------------------------------------------------------------
# Races, through the seam, with real junctions
# ---------------------------------------------------------------------------


def _swap_for_junction(directory: Path, outside: Path) -> None:
    directory.rename(directory.with_name(directory.name + "-weg"))
    _junction(directory, outside)


def _swap_before(native, component: str, swap) -> None:
    done = []

    def between(index, name):
        if name == component and not done:
            done.append(index)
            swap()

    native.between = between


def test_ancestor_swap_never_opens_outside_the_root(tmp_path, seam):
    """Race (a): while the walk holds `P`, a second actor replaces the
    ancestor `C` (inside the root, not yet opened) by a junction to a
    directory outside the root that holds a plain `leaf.txt`."""
    root, outside = _tree(tmp_path)
    _swap_before(seam, "C", lambda: _swap_for_junction(root / "P" / "C", outside))
    refused = _refused(
        lambda: localpath.read_local_bytes(str(root / "P" / "C" / "leaf.txt"), root=str(root), max_bytes=100)
    )
    assert refused.soort == "koppeling"
    assert "tag 0xA0000003" in refused.detail, "de geopende C is de koppeling zelf, niet haar doel"
    names = _audit(seam)
    assert names[-1] == "C"
    assert "leaf.txt" not in names, "het bestand buiten de wortel had geen open-poging"
    assert _is_reparse_point(root / "P" / "C")


def test_root_swap_never_opens_outside_the_root(tmp_path, seam):
    """Race (b): the root itself is replaced by a junction just before the walk opens it."""
    root, outside = _tree(tmp_path)
    _swap_before(seam, "wortel", lambda: _swap_for_junction(root, outside))
    refused = _refused(
        lambda: localpath.read_local_bytes(str(root / "P" / "C" / "leaf.txt"), root=str(root), max_bytes=100)
    )
    assert refused.soort == "koppeling"
    names = _audit(seam)
    assert names[-1] == "wortel"
    assert not {"P", "C", "leaf.txt"} & set(names)


def test_leaf_swap_opens_the_link_itself_and_never_its_target(tmp_path, seam):
    """Race (c): the leaf is replaced by a junction to a directory outside the root."""
    root, outside = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"

    def swap():
        leaf.rename(leaf.with_name("leaf-weg.txt"))
        _junction(leaf, outside)

    _swap_before(seam, "leaf.txt", swap)
    refused = _refused(lambda: localpath.read_local_bytes(str(leaf), root=str(root), max_bytes=100))
    assert refused.soort == "koppeling"
    assert "tag 0xA0000003" in refused.detail
    names = _audit(seam)
    assert names[-1] == "leaf.txt"
    assert seam.calls["ReadFile"] == 0, "er is niets gelezen"


def test_leaf_swap_for_a_file_symlink_opens_the_link_itself(tmp_path, seam):
    root, outside = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"

    def swap():
        leaf.rename(leaf.with_name("leaf-weg.txt"))
        _symlink(leaf, str(outside / "leaf.txt"), directory=False)

    _swap_before(seam, "leaf.txt", swap)
    refused = _refused(lambda: localpath.read_local_bytes(str(leaf), root=str(root), max_bytes=100))
    assert refused.soort == "koppeling"
    assert "tag 0xA000000C" in refused.detail
    assert seam.calls["ReadFile"] == 0
    _audit(seam)


def test_a_held_ancestor_cannot_be_renamed_or_deleted_during_a_read(tmp_path, seam):
    root, _ = _tree(tmp_path)
    (root / "leeg").mkdir()
    with localpath.open_local(str(root / "P" / "C" / "leaf.txt"), root=str(root)) as handle:
        for held in (root / "P", root / "P" / "C", root):
            with pytest.raises(PermissionError):
                held.rename(held.with_name(held.name + "-x"))
        assert handle.read(100) == b"binnen"
    with localpath.open_local(str(root / "leeg"), root=str(root), expect="dir"):
        with pytest.raises(PermissionError):
            (root / "leeg").rmdir()
    (root / "P").rename(root / "P-x")
    (root / "leeg").rmdir()
    _audit(seam)


def test_a_held_directory_still_takes_other_writers(tmp_path, seam):
    root, _ = _tree(tmp_path)
    work = root / "P"
    (work / "ander.txt").write_text("a", encoding="ascii")
    with localpath.open_local(str(work / "C" / "leaf.txt"), root=str(root)):
        (work / "nieuw.txt").write_text("n", encoding="ascii")
        (work / "tmp.txt").write_text("t", encoding="ascii")
        os.replace(work / "tmp.txt", work / "ander.txt")
        (work / "submap").mkdir()
    assert (work / "ander.txt").read_text(encoding="ascii") == "t"


# ---------------------------------------------------------------------------
# Append and replace
# ---------------------------------------------------------------------------


def test_append_creates_then_appends_and_flushes(tmp_path, seam):
    ledger = str(tmp_path / "ledger.jsonl")
    for line in (b"een\n", b"twee\n"):
        with localpath.open_local_for_append(ledger, root=str(tmp_path), shared_writers=True) as handle:
            handle.write(line)
    assert Path(ledger).read_bytes() == b"een\ntwee\n"
    assert seam.calls["FlushFileBuffers"] == 2
    _audit(seam)


def test_append_on_a_junction_in_the_place_of_the_file_writes_nothing(tmp_path, seam):
    _, outside = _tree(tmp_path)
    _junction(tmp_path / "ledger.jsonl", outside)
    with pytest.raises(PathRefused) as refused:
        with localpath.open_local_for_append(str(tmp_path / "ledger.jsonl"), root=str(tmp_path)):
            pass
    assert refused.value.soort == "koppeling"
    assert seam.calls["WriteFile"] == 0
    assert sorted(p.name for p in outside.iterdir()) == ["C", "leaf.txt"]
    _audit(seam)


def test_replace_writes_a_new_file_and_replaces_an_existing_one(tmp_path, seam):
    target = tmp_path / "tabel.json"
    localpath.replace_local(str(target), b"een", root=str(tmp_path))
    localpath.replace_local(str(target), b"twee", root=str(tmp_path))
    assert target.read_bytes() == b"twee"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tabel.json"]
    assert seam.calls["NtSetInformationFile"] == 2
    _audit(seam)


def test_replace_refuses_a_link_in_the_place_of_the_target_before_anything_is_written(tmp_path, seam):
    _, outside = _tree(tmp_path)
    _junction(tmp_path / "tabel.json", outside)
    refused = _refused(lambda: localpath.replace_local(str(tmp_path / "tabel.json"), b"x", root=str(tmp_path)))
    assert refused.soort == "koppeling"
    assert seam.calls["WriteFile"] == 0
    assert _is_reparse_point(tmp_path / "tabel.json")
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".nsmcp-tmp")]
    _audit(seam)


def test_a_failed_replace_removes_only_its_own_temporary_file(tmp_path, seam, monkeypatch):
    target = tmp_path / "tabel.json"
    target.write_bytes(b"oud")
    monkeypatch.setattr(seam, "set_rename", lambda handle, parent, name: localpath.STATUS_ACCESS_DENIED)
    refused = _refused(lambda: localpath.replace_local(str(target), b"nieuw", root=str(tmp_path)))
    assert refused.soort == "onleesbaar"
    assert target.read_bytes() == b"oud"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tabel.json"]
    _audit(seam)


def test_check_where_it_leads_opens_and_closes_the_chain(tmp_path, seam):
    root, _ = _tree(tmp_path)
    assert localpath.check_where_it_leads(str(root / "P"), root=str(root), expect="dir") == root / "P"
    assert localpath.check_where_it_leads(str(root / "nog-niet"), expect="any", allow_missing=True) == (
        root / "nog-niet"
    )
    _audit(seam)


# ---------------------------------------------------------------------------
# Containment is structural: the root is walked on its own text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("root_name", "sibling_name"),
    [
        ("staging", "\ufb06aging"),  # LATIN SMALL LIGATURE ST: Python folds it to "ST", NTFS does not
        ("SS", "\u00df"),  # SHARP S: Python upper() is "SS"
        ("\u017f", "S"),  # LONG S as the root (it does not even exist): Python upper() is "S"
    ],
    ids=["ligatuur", "ringel-s", "lange-s"],
)
def test_a_case_folding_sibling_of_the_root_is_outside_it(tmp_path, seam, root_name, sibling_name):
    sibling = tmp_path / sibling_name
    sibling.mkdir()
    (sibling / "x.txt").write_text("ZUSJE", encoding="ascii")
    if root_name != "\u017f":
        (tmp_path / root_name).mkdir()
    refused = _refused(
        lambda: localpath.read_local_bytes(str(sibling / "x.txt"), root=str(tmp_path / root_name), max_bytes=10)
    )
    assert refused.soort == "buiten_wortel"
    assert seam.calls["NtCreateFile"] == 0, "niets geopend: de wortel is niet het zusje"


def test_a_different_case_of_the_root_text_is_outside_it(tmp_path, seam):
    root, _ = _tree(tmp_path)
    other_case = tmp_path / "WORTEL" / "P" / "C" / "leaf.txt"
    refused = _refused(lambda: localpath.read_local_bytes(str(other_case), root=str(root), max_bytes=10))
    assert refused.soort == "buiten_wortel"
    assert seam.calls["NtCreateFile"] == 0


def test_a_dot_dot_out_of_the_root_is_refused_before_any_open(tmp_path, seam):
    root, outside = _tree(tmp_path)
    escape = str(root) + "\\..\\buiten\\leaf.txt"
    refused = _refused(lambda: localpath.read_local_bytes(escape, root=str(root), max_bytes=10))
    assert refused.soort in ("onleesbaar", "buiten_wortel")
    assert seam.calls["NtCreateFile"] == 0
    assert (outside / "leaf.txt").read_text(encoding="ascii") == "buiten"


def test_the_root_is_walked_on_its_own_text_and_the_rest_relative_to_it(tmp_path, seam):
    root, _ = _tree(tmp_path)
    assert localpath.read_local_bytes(str(root / "P" / "C" / "leaf.txt"), root=str(root), max_bytes=10) == b"binnen"
    names = _audit(seam)
    root_parts = list(root.parts[1:])
    assert names[1 : 1 + len(root_parts)] == root_parts
    assert names[1 + len(root_parts) :] == ["P", "C", "leaf.txt"]


# ---------------------------------------------------------------------------
# A directory on the way needs the traverse right only
# ---------------------------------------------------------------------------


def test_an_ancestor_with_only_the_traverse_right_is_walked_and_still_held(tmp_path, seam):
    import subprocess

    root, _ = _tree(tmp_path)
    user = os.environ["USERNAME"]
    hardened = root / "P"
    denied = subprocess.run(["icacls", str(hardened), "/deny", f"{user}:(RD)"], capture_output=True, text=True)
    assert denied.returncode == 0, denied.stdout + denied.stderr
    try:
        with pytest.raises(PermissionError):
            os.listdir(hardened)
        with localpath.open_local(str(root / "P" / "C" / "leaf.txt"), root=str(root)) as handle:
            assert handle.read(10) == b"binnen"
            with pytest.raises(PermissionError):
                hardened.rename(hardened.with_name("P-x"))
    finally:
        restored = subprocess.run(["icacls", str(hardened), "/remove:d", user], capture_output=True, text=True)
        assert restored.returncode == 0, restored.stdout + restored.stderr
    chain = [record for record in seam.opens if record["name"] in ("P", "C")]
    assert {record["access"] for record in chain} == {localpath.DIR_ACCESS}
    assert not localpath.DIR_ACCESS & localpath.FILE_LIST_DIRECTORY
    _audit(seam)


def test_a_directory_asked_for_itself_is_opened_for_listing(tmp_path, seam):
    root, _ = _tree(tmp_path)
    with localpath.open_local(str(root / "P"), root=str(root), expect="dir"):
        pass
    assert [record["access"] for record in seam.opens if record["name"] == "P"] == [localpath.DIR_LIST_ACCESS]
    _audit(seam)


# ---------------------------------------------------------------------------
# Off Windows nothing is written through this module
# ---------------------------------------------------------------------------


def test_the_write_routes_refuse_off_windows_before_anything_opens(tmp_path, monkeypatch):
    native = localpath._PosixNative(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    with pytest.raises(NotImplementedError):
        with localpath.open_local_for_append(str(tmp_path / "x"), root=str(tmp_path)):
            pass
    with pytest.raises(NotImplementedError):
        with localpath.open_local(str(tmp_path / "x"), root=str(tmp_path), mode="create"):
            pass
    with pytest.raises(NotImplementedError):
        localpath.replace_local(str(tmp_path / "x"), b"x", root=str(tmp_path))
    assert native.opens == []


# ---------------------------------------------------------------------------
# B.5, the network provider (M-4 of the red review of part 2): an open
# measurement. With a packet capture (pktmon, elevated right) a symbolic link
# in the place of an ancestor to the documentation address must give ZERO
# packets to it on 445/139 while the walk refuses it. Without the elevated
# right and the explicit switch this test is skipped by name and the
# measurement stays open in docs/klant/OPENSTAANDE-METINGEN.md.
# ---------------------------------------------------------------------------


def _elevated() -> bool:
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


@pytest.mark.skipif(
    not (os.environ.get("NSMCP_NETWERKPROEF") == "1" and _elevated()),
    reason=(
        "netwerkproef B.5: vraagt verhoogde rechten en NSMCP_NETWERKPROEF=1 voor een pakketopname met pktmon;"
        " de meting staat open in docs/klant/OPENSTAANDE-METINGEN.md"
    ),
)
def test_the_network_provider_sees_no_packet(tmp_path, seam):
    import subprocess
    import time

    address = "192.0.2.10"
    capture = tmp_path / "opname.etl"
    link = tmp_path / "voorouder"
    os.symlink("\\\\" + address + "\\x", link, target_is_directory=True)
    subprocess.run(["pktmon", "filter", "remove"], check=True, capture_output=True)
    for port in ("445", "139"):
        subprocess.run(["pktmon", "filter", "add", "-i", address, "-p", port], check=True, capture_output=True)
    subprocess.run(["pktmon", "start", "--capture", "--file-name", str(capture)], check=True, capture_output=True)
    try:
        started = time.perf_counter()
        refused = _refused(lambda: localpath.read_local_bytes(str(link / "x.txt"), max_bytes=10))
        elapsed = time.perf_counter() - started
        time.sleep(2)
    finally:
        subprocess.run(["pktmon", "stop"], check=True, capture_output=True)
        subprocess.run(["pktmon", "filter", "remove"], check=False, capture_output=True)
    counters = subprocess.run(["pktmon", "counters"], capture_output=True, text=True, check=False).stdout
    assert refused.soort == "netwerkpad"
    assert elapsed < 0.1
    assert all("192.0.2.10" not in record["name"] for record in seam.opens)
    assert "All counters are zero" in counters or "Alle tellers zijn nul" in counters, counters
