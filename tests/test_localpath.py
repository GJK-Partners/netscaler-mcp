"""Logic proofs of `nsmcp.localpath`: the fixed sentences, the spelling rules,
the status table and the link-target text. Pure Python, no file is opened;
they run on every platform. The proofs on real junctions, the races and the
seam counters are in tests/test_localpath_windows.py."""

from __future__ import annotations

import struct
import sys

import pytest

from nsmcp import localpath
from nsmcp.localpath import REASONS, SOORTEN, PathRefused, check_spelling

# ---------------------------------------------------------------------------
# Kinds and fixed sentences
# ---------------------------------------------------------------------------


def test_every_kind_has_one_fixed_sentence_and_no_other_kind_exists():
    assert (
        set(REASONS)
        == set(SOORTEN)
        == {
            "netwerkpad",
            "apparaatpad",
            "stroom",
            "netwerkstation",
            "koppeling",
            "herparseerpunt",
            "buiten_wortel",
            "geen_gewoon_bestand",
            "te_veel_koppelingen",
            "onleesbaar",
        }
    )


@pytest.mark.parametrize("soort", SOORTEN)
def test_a_reason_names_no_path_no_status_and_no_line_break(soort):
    reason = REASONS[soort]
    assert reason == reason.strip()
    for forbidden in ("\\", "/", "\n", "\r", "0x", "STATUS_", "C:"):
        assert forbidden not in reason, (soort, forbidden)


def test_a_refusal_reads_as_its_fixed_sentence_whatever_it_carries():
    refused = PathRefused("koppeling", path=r"C:\geheim\pad", status=0xC0000022, detail="tag 0xA0000003")
    assert str(refused) == REASONS["koppeling"]
    assert refused.soort == "koppeling"
    assert refused.path == r"C:\geheim\pad"
    assert refused.status == 0xC0000022


def test_an_unknown_kind_is_unreadable_never_open():
    refused = PathRefused("niet-bestaand")
    assert refused.soort == "onleesbaar"
    assert str(refused) == REASONS["onleesbaar"]


# ---------------------------------------------------------------------------
# Step 1: spelling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        r"C:\export\x.json",
        r"C:\export",
        "C:/export/x.json",
        r"relatief\pad",
        r"\\?\C:\export\x.json",
        r"\\.\C:\export",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\export\x.json",
        r"C:\a\..\b",
    ],
)
def test_check_spelling_lets_a_local_spelling_pass(text):
    check_spelling(text)


@pytest.mark.parametrize(
    ("text", "soort"),
    [
        (r"\\server\share\x.json", "netwerkpad"),
        (r"\\?\UNC\server\share\x.json", "netwerkpad"),
        (r"\\.\UNC\server\share", "netwerkpad"),
        ("//server/share/x.json", "netwerkpad"),
        (r"\\.\pipe\nsmcp", "apparaatpad"),
        (r"\\?\GLOBALROOT\Device\Mup\server\share", "apparaatpad"),
        (r"C:\export\x.json:zijstroom", "stroom"),
        (r"C:\export\x.json::$DATA", "stroom"),
        (r"C:\export.\x.json", "onleesbaar"),
        (r"C:\export\x.json ", "onleesbaar"),
    ],
)
def test_check_spelling_refuses_without_opening(text, soort):
    with pytest.raises(PathRefused) as refused:
        check_spelling(text)
    assert refused.value.soort == soort


@pytest.mark.parametrize(
    ("text", "key", "components"),
    [
        (r"C:\export\x.json", "C:", ["export", "x.json"]),
        (r"c:\export\sub\\"[:-1], "C:", ["export", "sub"]),
        ("C:\\", "C:", []),
        (r"\\?\C:\export", "C:", ["export"]),
        (
            r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\export",
            "Volume{12345678-1234-1234-1234-123456789abc}",
            ["export"],
        ),
    ],
)
def test_the_strict_form_splits_one_absolute_local_spelling(text, key, components):
    assert localpath._split(text) == (key, components)


@pytest.mark.parametrize(
    "text",
    [
        r"relatief\x.json",
        r"\zonder\schijf",
        "C:",
        "C:x.json",
        "C:/export/x.json",
        r"C:\export\\x.json",
        r"C:\export\.\x.json",
        r"C:\export\..\x.json",
        "C:\\export\\x\0.json",
        "C:\\" + "a" * 256,
    ],
)
def test_the_strict_form_refuses_every_other_spelling(text):
    with pytest.raises(PathRefused) as refused:
        localpath._split(text)
    assert refused.value.soort == "onleesbaar"


def test_a_stream_in_any_component_is_a_stream():
    with pytest.raises(PathRefused) as refused:
        localpath._split(r"C:\export\objects\x.json:zijstroom")
    assert refused.value.soort == "stroom"


@pytest.mark.parametrize(
    ("path", "root", "walked"),
    [
        (r"C:\export\x.json", r"C:\export", ["export", "x.json"]),
        (r"c:\export\x.json", r"C:\export", ["export", "x.json"]),  # only the volume key ignores case
        (r"C:\export", r"C:\export", ["export"]),
        (r"C:\export\a\b", "C:\\", ["export", "a", "b"]),
    ],
)
def test_the_root_is_walked_on_its_own_text(path, root, walked):
    key, components = localpath._split(path)
    assert localpath._within(key, components, root) == walked


def test_containment_never_folds_case():
    """Python folds differently from NTFS: a mutation back to a folding comparison must fall here."""
    key, components = localpath._split(r"C:\EXPORT\x.json")
    with pytest.raises(PathRefused) as refused:
        localpath._within(key, components, r"C:\export")
    assert refused.value.soort == "buiten_wortel"


@pytest.mark.parametrize(
    ("path", "root"),
    [
        (r"C:\elders\x.json", r"C:\export"),
        (r"C:\exportx\x.json", r"C:\export"),
        (r"D:\export\x.json", r"C:\export"),
        (r"C:\export", r"C:\export\sub"),
    ],
)
def test_a_path_that_does_not_start_with_the_root_is_outside_it(path, root):
    key, components = localpath._split(path)
    with pytest.raises(PathRefused) as refused:
        localpath._within(key, components, root)
    assert refused.value.soort == "buiten_wortel"


# ---------------------------------------------------------------------------
# The status table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "soort"),
    [
        (0xC0000034, "onleesbaar"),  # OBJECT_NAME_NOT_FOUND without allow_missing
        (0xC000003A, "onleesbaar"),  # OBJECT_PATH_NOT_FOUND
        (0xC0000022, "onleesbaar"),  # ACCESS_DENIED
        (0xC0000043, "onleesbaar"),  # SHARING_VIOLATION
        (0xC0000056, "onleesbaar"),  # DELETE_PENDING
        (0xC0000033, "onleesbaar"),  # OBJECT_NAME_INVALID
        (0xC0000103, "geen_gewoon_bestand"),  # NOT_A_DIRECTORY
        (0xC00000BA, "geen_gewoon_bestand"),  # FILE_IS_A_DIRECTORY
        (0x00000104, "koppeling"),  # REPARSE
        (0x8000002D, "koppeling"),  # STOPPED_ON_SYMLINK
        (0xC0000280, "koppeling"),  # REPARSE_POINT_NOT_RESOLVED (measured)
        (0xC00000BE, "netwerkpad"),  # BAD_NETWORK_PATH
        (0xC00000CC, "netwerkpad"),  # BAD_NETWORK_NAME
        (0xC000023C, "netwerkpad"),  # NETWORK_UNREACHABLE
        (0xC0000281, "koppeling"),  # DIRECTORY_IS_A_REPARSE_POINT
        (0xC0000282, "onleesbaar"),  # every other status
        (0xC0000001, "onleesbaar"),
        (0x00000001, "onleesbaar"),
    ],
)
def test_every_status_has_one_kind_and_an_unknown_one_is_unreadable(status, soort, capsys):
    refusal = localpath._status_refusal(status, r"C:\x", allow_missing=False)
    assert isinstance(refusal, PathRefused)
    assert refusal.soort == soort
    assert refusal.status == status
    assert "0x" not in str(refusal)
    defect = localpath.DEFECT_LINE in capsys.readouterr().err
    assert defect == (soort == "netwerkpad")


@pytest.mark.parametrize("status", [0xC0000034, 0xC000003A])
def test_absence_is_only_absence_with_allow_missing(status):
    assert isinstance(localpath._status_refusal(status, r"C:\x", allow_missing=True), localpath._Absent)


# ---------------------------------------------------------------------------
# Link data: the target text, never an open
# ---------------------------------------------------------------------------


def _symlink_data(substitute: str, *, relative: bool) -> bytes:
    sub = substitute.encode("utf-16-le")
    body = struct.pack("<HHHHI", 0, len(sub), len(sub), 0, 1 if relative else 0) + sub
    return struct.pack("<IHH", localpath.IO_REPARSE_TAG_SYMLINK, len(body), 0) + body


def _mount_data(substitute: str) -> bytes:
    sub = substitute.encode("utf-16-le")
    body = struct.pack("<HHHH", 0, len(sub), len(sub) + 2, 0) + sub + b"\0\0"
    return struct.pack("<IHH", localpath.IO_REPARSE_TAG_MOUNT_POINT, len(body), 0) + body


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (_mount_data("\\??\\C:\\elders\\"), r"C:\elders\rest\x.json"),
        (_mount_data("\\??\\C:\\"), r"C:\rest\x.json"),
        (_symlink_data("\\??\\D:\\doel", relative=False), r"D:\doel\rest\x.json"),
        (_symlink_data("\\??\\UNC\\server\\share", relative=False), r"\\server\share\rest\x.json"),
        (_symlink_data("\\??\\pipe\\x", relative=False), r"\\?\pipe\x\rest\x.json"),
        (
            _mount_data("\\??\\Volume{12345678-1234-1234-1234-123456789abc}\\"),
            r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\rest\x.json",
        ),
        (_symlink_data("..\\naast", relative=True), r"C:\a\naast\rest\x.json"),
        (_symlink_data("sub\\.\\diep", relative=True), r"C:\a\b\sub\diep\rest\x.json"),
        (_symlink_data("\\top", relative=True), r"C:\top\rest\x.json"),
        (_symlink_data("\\Device\\Mup\\server", relative=False), r"\\?\GLOBALROOT\Device\Mup\server\rest\x.json"),
    ],
)
def test_a_link_above_the_root_becomes_a_new_path_text(raw, expected):
    assert localpath._link_target(raw, "C:", ["a", "b"], ["rest", "x.json"], r"C:\a\b\link\rest\x.json") == expected


@pytest.mark.parametrize(
    "target",
    [
        r"\\server\share\rest\x.json",
        r"\\?\pipe\x\rest\x.json",
        r"\\?\GLOBALROOT\Device\Mup\server\rest\x.json",
    ],
)
def test_a_link_target_on_a_share_or_a_device_is_refused_by_the_spelling_step(target):
    with pytest.raises(PathRefused) as refused:
        localpath._split(target)
    assert refused.value.soort in ("netwerkpad", "apparaatpad")


@pytest.mark.parametrize(
    "raw",
    [
        _symlink_data("..\\..\\..\\boven", relative=True),
        _symlink_data("a/b", relative=True),
        b"\x0c\x00\x00\xa0\x00\x00",
        struct.pack("<IHH", localpath.IO_REPARSE_TAG_SYMLINK, 12, 0) + struct.pack("<HHHHI", 64, 64, 0, 0, 0),
    ],
)
def test_link_data_that_cannot_be_read_as_one_target_is_unreadable(raw):
    with pytest.raises(PathRefused) as refused:
        localpath._link_target(raw, "C:", ["a", "b"], [], r"C:\a\b\link")
    assert refused.value.soort == "onleesbaar"


def test_another_tag_above_the_root_is_a_reparse_point():
    raw = struct.pack("<IHH", 0x9000601A, 0, 0)
    with pytest.raises(PathRefused) as refused:
        localpath._link_target(raw, "C:", [], [], r"C:\wolk")
    assert refused.value.soort == "herparseerpunt"


# ---------------------------------------------------------------------------
# Off Windows: the same walk over file descriptors (logic runs only)
# ---------------------------------------------------------------------------

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="os.open met dir_fd bestaat niet op Windows; daar draaien de Windows-proeven"
)


@posix_only
def test_posix_a_symlink_inside_the_root_is_a_link(tmp_path, monkeypatch):
    monkeypatch.setattr(localpath, "_native", localpath._PosixNative(record=True))
    (tmp_path / "buiten").mkdir()
    (tmp_path / "buiten" / "x.json").write_text("buiten")
    root = tmp_path / "wortel"
    root.mkdir()
    (root / "link").symlink_to(tmp_path / "buiten", target_is_directory=True)
    with pytest.raises(PathRefused) as refused:
        localpath.read_local_bytes(str(root / "link" / "x.json"), root=str(root), max_bytes=100)
    assert refused.value.soort == "koppeling"
    assert all(entry["name"] != "x.json" for entry in localpath._native.opens)


@posix_only
def test_posix_a_plain_file_is_read_and_never_written(tmp_path, monkeypatch):
    monkeypatch.setattr(localpath, "_native", localpath._PosixNative(record=True))
    (tmp_path / "x.json").write_bytes(b"oud")
    assert localpath.read_local_bytes(str(tmp_path / "x.json"), root=str(tmp_path), max_bytes=10) == b"oud"
    with pytest.raises(NotImplementedError):
        localpath.replace_local(str(tmp_path / "x.json"), b"nieuw", root=str(tmp_path))
    assert (tmp_path / "x.json").read_bytes() == b"oud"
