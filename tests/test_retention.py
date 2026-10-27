"""Previous exports are owned siblings; scan time is untrusted input."""

import hashlib
import json
from pathlib import Path

import pytest

from nsmcp.retention import Retention, keep, kept_exports, newest_kept


def export(root, name="export.vorig", moment="2026-09-01T08:00:00.0000000Z"):
    directory = root / name
    directory.mkdir()
    (directory / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": moment,
                "resources": {},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_keep_uses_scan_time_and_clears_recovery_slot(tmp_path):
    previous = export(tmp_path)
    result = keep(previous, tmp_path / "export", Retention(enabled=True))
    assert result.name == "export.bewaard-20260901T080000Z"
    assert not previous.exists()
    assert newest_kept(tmp_path / "export") == result


def test_keep_is_off_by_default(tmp_path):
    previous = export(tmp_path)
    assert keep(previous, tmp_path / "export", Retention()) is None
    assert not previous.exists()
    assert Retention().count == 5
    assert Retention().floor_mb == 2048


@pytest.mark.parametrize(
    "kwargs",
    [
        {"count": True},
        {"count": -1},
        {"floor_mb": False},
        {"floor_mb": -1},
        {"enabled": 1},
        {"count": "5"},
    ],
)
def test_direct_policy_refuses_wrong_types(kwargs):
    with pytest.raises(ValueError):
        Retention(**kwargs)


@pytest.mark.parametrize(
    "moment", [None, "", [], {}, True, 12, "../../escape", "2026-99-01T08:00:00Z", "2026-09-01T08:00:00Z/private"]
)
def test_unknown_time_is_preserved_but_not_chronological(tmp_path, moment):
    previous = export(tmp_path, moment=moment)
    result = keep(previous, tmp_path / "export", Retention(enabled=True))
    assert result.name == "export.bewaard-onbekend"
    assert kept_exports(tmp_path / "export") == (result,)
    assert newest_kept(tmp_path / "export") is None


def test_collisions_preserve_both_exports(tmp_path):
    previous = export(tmp_path)
    first = keep(previous, tmp_path / "export", Retention(enabled=True))
    (first / "evidence.txt").write_text("first", encoding="utf-8")
    second = keep(export(tmp_path), tmp_path / "export", Retention(enabled=True))
    assert first != second
    assert (first / "evidence.txt").read_text(encoding="utf-8") == "first"
    assert len(kept_exports(tmp_path / "export")) == 2


def test_unknown_time_collision_preserves_both_exports(tmp_path):
    first = keep(export(tmp_path, moment=None), tmp_path / "export", Retention(enabled=True))
    second = keep(export(tmp_path, moment=None), tmp_path / "export", Retention(enabled=True))
    assert first != second and first.exists() and second.exists()
    assert newest_kept(tmp_path / "export") is None


def test_scan_time_order_retains_seven_digit_precision_and_utc_offsets(tmp_path):
    earlier = export(tmp_path, "export.bewaard-20260901T080000Z", "2026-09-01T10:00:00.0000001+02:00")
    later = export(tmp_path, "export.bewaard-20260901T080001Z", "2026-09-01T08:00:00.0000002Z")
    assert kept_exports(tmp_path / "export") == (later, earlier)


@pytest.mark.parametrize("offset", ["+00:60", "-00:60", "+01:99", "-01:99", "+23:60", "-23:60", "+24:00", "-24:00"])
def test_invalid_offset_is_kept_as_unknown_and_never_newest(tmp_path, offset):
    previous = export(tmp_path, moment="2026-09-03T12:00:00" + offset)
    result = keep(previous, tmp_path / "export", Retention(enabled=True))
    assert result.name == "export.bewaard-onbekend"
    assert kept_exports(tmp_path / "export") == (result,)
    assert newest_kept(tmp_path / "export") is None


@pytest.mark.parametrize(
    "offset,stamp",
    [
        ("+00:59", "20260903T110100Z"),
        ("-00:59", "20260903T125900Z"),
        ("+23:59", "20260902T120100Z"),
        ("-23:59", "20260904T115900Z"),
        ("+00:00", "20260903T120000Z"),
        ("+12:30", "20260902T233000Z"),
    ],
)
def test_valid_offset_boundaries_keep_the_correct_utc_moment(tmp_path, offset, stamp):
    previous = export(tmp_path, moment="2026-09-03T12:00:00" + offset)
    result = keep(previous, tmp_path / "export", Retention(enabled=True))
    assert result.name == "export.bewaard-" + stamp
    assert newest_kept(tmp_path / "export") == result


def test_real_junction_outside_root_is_never_followed(tmp_path):
    import os

    external = export(tmp_path, "external")
    root = tmp_path / "root"
    root.mkdir()
    linked = root / "export.bewaard-20260901T080000Z"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(external), str(linked))
    else:
        linked.symlink_to(external, target_is_directory=True)
    try:
        assert kept_exports(root / "export") == ()
        assert (external / "export-manifest.json").is_file()
    finally:
        if os.name == "nt":
            linked.rmdir()
        else:
            linked.unlink()


def test_order_uses_manifest_moment_not_name_or_mtime(tmp_path):
    early = export(tmp_path, "export.bewaard-20991231T235959Z", "2026-09-01T08:00:00Z")
    late = export(tmp_path, "export.bewaard-20000101T000000Z", "2026-09-03T08:00:00Z")
    unknown = export(tmp_path, "export.bewaard-onbekend", None)
    assert kept_exports(tmp_path / "export") == (late, early, unknown)
    assert newest_kept(tmp_path / "export") == late


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "{",
        "[]",
        "{}",
        '{"manifestVersion":"1.1","resources":[],"files":{}}',
        '{"manifestVersion":"1.1","resources":{},"files":[]}',
        '{"manifestVersion":[],"resources":{},"files":{}}',
        '{"manifestVersion":"1.1","resources":{},"files":{},"extra":1e999}',
        '{"manifestVersion":"1.1","resources":{},"files":{},"files":{}}',
    ],
)
def test_invalid_or_missing_manifest_is_never_previous(tmp_path, payload):
    candidate = tmp_path / "export.bewaard-20260901T080000Z"
    candidate.mkdir()
    if payload is not None:
        (candidate / "export-manifest.json").write_text(payload, encoding="utf-8")
    assert kept_exports(tmp_path / "export") == ()
    assert newest_kept(tmp_path / "export") is None
    assert candidate.exists()


@pytest.mark.parametrize(
    "name",
    [
        "export.vorig",
        "export",
        "export-other.bewaard-onbekend",
        "export.bewaard-",
        "export.bewaard-arbitrary",
        "export.bewaard-20260901T080000Z-private",
    ],
)
def test_only_owned_name_forms_are_recognized(tmp_path, name):
    candidate = export(tmp_path, name)
    assert kept_exports(tmp_path / "export") == ()
    assert candidate.exists()


def test_keep_does_not_follow_an_arbitrary_previous_path(tmp_path):
    other = export(tmp_path, "other")
    assert keep(other, tmp_path / "export", Retention(enabled=True)) is None
    assert other.exists()


def test_manifest_read_is_bounded(tmp_path, monkeypatch):
    from nsmcp import retention

    candidate = export(tmp_path, "export.bewaard-20260901T080000Z")
    monkeypatch.setattr(retention, "MAX_MANIFEST_BYTES", 32)
    assert kept_exports(tmp_path / "export") == ()
    assert candidate.exists()


def test_manifest_depth_is_bounded(tmp_path):
    candidate = export(tmp_path, "export.bewaard-20260901T080000Z")
    (candidate / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","resources":{},"files":{},"nested":' + "[" * 102 + "0" + "]" * 102 + "}",
        encoding="utf-8",
    )
    assert kept_exports(tmp_path / "export") == ()


def test_reparse_directory_and_manifest_are_refused(tmp_path, monkeypatch):
    from conftest import reparse_at

    candidate = export(tmp_path, "export.bewaard-20260901T080000Z")
    assert kept_exports(tmp_path / "export") == (candidate,), "premisse: zonder herparseerpunt telt hij mee"
    for linked in (candidate, candidate / "export-manifest.json", tmp_path):
        with monkeypatch.context() as patched:
            reparse_at(patched, linked)
            assert kept_exports(tmp_path / "export") == ()


def test_rename_failure_is_safe_and_does_not_reveal_input(tmp_path, monkeypatch, capsys):
    from nsmcp import localpath

    previous = export(tmp_path)
    original = localpath.rename_local

    # 1.1 B: the keep rename is `localpath.rename_local`, by handle.
    def fail(path, new_name, **kwargs):
        if Path(path) == previous:
            raise OSError("PRIVATE_VALUE")
        return original(path, new_name, **kwargs)

    monkeypatch.setattr(localpath, "rename_local", fail)
    assert keep(previous, tmp_path / "export", Retention(enabled=True)) is None
    assert not previous.exists()
    # Integration point 4: the event is one prefixed JSON line on stderr, the
    # same channel and shape as the action log - never a `logging` record.
    err = capsys.readouterr().err
    assert "PRIVATE_VALUE" not in err
    assert "[nsmcp-bewaren] {" in err and "nieuwe export blijft geldig" in err


def record_target(directory, name="lab"):
    digest = hashlib.sha256((directory / "export-manifest.json").read_bytes()).hexdigest()
    (directory / "scan-doel.txt").write_text(name + "\n" + digest + "\n", encoding="utf-8")


def saved_scans(root, count=4, target="lab"):
    paths = []
    for day in range(1, count + 1):
        prior = export(root, moment=f"2026-09-{day:02d}T08:00:00Z")
        if target is not None:
            record_target(prior, target)
        paths.append(keep(prior, root / "export", Retention(enabled=True)))
    return paths


def test_prune_removes_oldest_first_and_logs_each_success(tmp_path, monkeypatch):
    from nsmcp import retention

    paths = saved_scans(tmp_path)
    removed = []
    original = retention._remove_tree  # 1.1 B: the tree is deleted on the walk

    def remove(path):
        removed.append(path)
        original(path)

    monkeypatch.setattr(retention, "_remove_tree", remove)
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=2))
    assert removed == paths[:2]
    assert kept_exports(tmp_path / "export") == tuple(reversed(paths[2:]))
    assert lines == (
        "bewaarbeleid: bewaarde export 20260901T080000Z verwijderd",
        "bewaarbeleid: bewaarde export 20260902T080000Z verwijderd",
    )


@pytest.mark.parametrize("space", [0, 10, 499, None, True, False, -1, 500.0, "500", [], {}])
def test_prune_gates_space_before_any_delete_even_over_count(tmp_path, monkeypatch, space):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 3)
    monkeypatch.setattr(retention, "free_mb", lambda _: space)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1, floor_mb=500))
    assert all(path.exists() for path in paths)
    assert len(lines) == 1 and "er wordt NIETS opgeruimd" in lines[0]
    assert "verwijderd" not in lines[0]


def test_prune_rechecks_space_before_each_delete(tmp_path, monkeypatch):
    from nsmcp import retention

    paths = saved_scans(tmp_path)
    # The value depends on real deletions, not the implementation's call count.
    monkeypatch.setattr(retention, "free_mb", lambda _: 500 if paths[0].exists() else 499)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1, floor_mb=500))
    assert not paths[0].exists() and all(p.exists() for p in paths[1:])
    assert lines[0] == "bewaarbeleid: bewaarde export 20260901T080000Z verwijderd"
    assert "geen verdere exports" in lines[1]


def test_prune_floor_zero_still_requires_known_space(tmp_path, monkeypatch):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 2)
    monkeypatch.setattr(retention, "free_mb", lambda _: None)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1, floor_mb=0))
    assert all(p.exists() for p in paths)
    assert "niet vastgesteld" in lines[0]


@pytest.mark.parametrize("policy", [Retention(), Retention(enabled=True, count=0)])
def test_prune_disabled_does_not_delete_existing_history(tmp_path, policy):
    from nsmcp.retention import prune

    paths = saved_scans(tmp_path, 3)
    assert prune(tmp_path / "export", policy) == ()
    assert all(p.exists() for p in paths)


def test_prune_counts_per_verified_target_and_separate_unknown_bucket(tmp_path, monkeypatch):
    from nsmcp import retention

    first = saved_scans(tmp_path, 3, "lab-a")
    second = saved_scans(tmp_path, 3, "lab-b")
    unknown = saved_scans(tmp_path, 3, None)
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    for group in (first, second, unknown):
        assert not group[0].exists() and not group[1].exists() and group[2].exists()
    assert sum(line.endswith(" verwijderd") for line in lines) == 6
    assert len({line for line in lines if line.endswith(" verwijderd")}) == 6
    assert "doelidentiteit niet vastgesteld" in "\n".join(lines)
    assert "lab-a" not in "\n".join(lines) and str(tmp_path) not in "\n".join(lines)


def test_prune_preserves_unknown_time_and_newest_known_even_over_limit(tmp_path, monkeypatch):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 3)
    unknown = export(tmp_path, moment=None)
    record_target(unknown)
    unknown = keep(unknown, tmp_path / "export", Retention(enabled=True))
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    assert unknown.exists() and paths[-1].exists()
    assert not paths[0].exists() and not paths[1].exists()
    assert "scanmoment niet vastgesteld" in "\n".join(lines)


@pytest.mark.parametrize(
    "name",
    ["export", "export.vorig", "_beheer", "manual", "other.bewaard-20260901T080000Z", "export.bewaard-arbitrary"],
)
def test_prune_never_deletes_foreign_names_even_if_list_is_untrusted(tmp_path, monkeypatch, name):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 2)
    candidate = export(tmp_path, name)
    monkeypatch.setattr(retention, "kept_exports", lambda _: tuple(reversed(paths)) + (candidate,))
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    assert candidate.exists()


@pytest.mark.parametrize("payload", [None, "{}", "{", '{"manifestVersion":"1.1","files":{},"resources":[]}'])
def test_prune_never_deletes_unowned_manifest_from_stale_list(tmp_path, monkeypatch, payload):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 2)
    candidate = export(tmp_path, "export.bewaard-20000101T000000Z")
    manifest = candidate / "export-manifest.json"
    if payload is None:
        manifest.unlink()
    else:
        manifest.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(retention, "kept_exports", lambda _: tuple(reversed(paths)) + (candidate,))
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    assert candidate.exists()


def test_prune_refuses_an_outside_path_even_with_the_owned_name(tmp_path, monkeypatch):
    from nsmcp import retention

    root = tmp_path / "root"
    root.mkdir()
    paths = saved_scans(root, 2)
    outside = export(tmp_path, "export.bewaard-20000101T000000Z")
    monkeypatch.setattr(retention, "kept_exports", lambda _: tuple(reversed(paths)) + (outside,))
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    retention.prune(root / "export", Retention(enabled=True, count=1))
    assert (outside / "export-manifest.json").is_file()


@pytest.mark.parametrize("change", ["invalid_manifest", "unknown_time", "other_target", "reparse"])
def test_prune_revalidates_candidate_immediately_before_delete(tmp_path, monkeypatch, change):
    from conftest import reparse_at

    from nsmcp import retention

    paths = saved_scans(tmp_path, 3)
    original_remove = retention._remove_tree  # 1.1 B: the tree is deleted on the walk

    def remove(path):
        original_remove(path)
        if path != paths[0]:
            return
        manifest = paths[1] / "export-manifest.json"
        if change == "invalid_manifest":
            manifest.write_text("{}", encoding="utf-8")
        elif change == "unknown_time":
            raw = json.loads(manifest.read_text(encoding="utf-8"))
            raw["collectedAtUtc"] = None
            manifest.write_text(json.dumps(raw), encoding="utf-8")
        elif change == "other_target":
            record_target(paths[1], "other")
        else:
            reparse_at(monkeypatch, paths[1])

    monkeypatch.setattr(retention, "_remove_tree", remove)
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    assert paths[1].exists() and paths[2].exists()
    assert sum(line.endswith(" verwijderd") for line in lines) == 1


def test_prune_delete_failure_never_claims_success_or_echoes_error(tmp_path, monkeypatch):
    from nsmcp import retention

    paths = saved_scans(tmp_path, 2)

    def fail(path):
        raise PermissionError("PRIVATE_TARGET\nPRIVATE_PATH")

    monkeypatch.setattr(retention, "_remove_tree", fail)
    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    lines = retention.prune(tmp_path / "export", Retention(enabled=True, count=1))
    assert all(p.exists() for p in paths)
    assert lines == ("bewaarbeleid: verwijderen niet gelukt; opruimen gestopt",)


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, 0),
        (1048575, 0),
        (1048576, 1),
        (2097153, 2),
        (None, None),
        (-1, None),
        (True, None),
        (5.0, None),
        ("1024", None),
    ],
)
def test_free_mb_exact_nonnegative_bytes_only(tmp_path, monkeypatch, value, expected):
    from types import SimpleNamespace

    from nsmcp import retention

    # 1.1 B: the free space is asked on the held handle (`localpath.free_bytes_local`).
    monkeypatch.setattr(retention.localpath, "free_bytes_local", lambda path, **kw: SimpleNamespace(free=value).free)
    assert retention.free_mb(tmp_path / "export") == expected


def test_free_mb_unmeasurable_returns_none(tmp_path, monkeypatch):
    from nsmcp import retention

    def fail(path):
        raise OSError("PRIVATE_PATH")

    monkeypatch.setattr(retention.localpath, "free_bytes_local", lambda path, **kw: fail(path))
    assert retention.free_mb(tmp_path / "export") is None


def test_target_identity_uses_hash_bound_shape_gated_name(tmp_path):
    from nsmcp.retention import target_identity

    directory = export(tmp_path)
    record_target(directory, "lab-a production")
    assert target_identity(directory) == "lab-a production"
    (directory / "export-manifest.json").write_text("{}", encoding="utf-8")
    assert target_identity(directory) is None


@pytest.mark.parametrize(
    "payload",
    [b"", b"lab\n", b"lab\n" + b"0" * 64, b"\xff\xfe", b"x" * 1025, b"lab\nHASH\nextra", b"[vastgesteld]\nHASH"],
)
def test_target_identity_refuses_malformed_unbounded_or_unbound_input(tmp_path, payload):
    from nsmcp.retention import target_identity

    directory = export(tmp_path)
    digest = hashlib.sha256((directory / "export-manifest.json").read_bytes()).hexdigest().encode()
    (directory / "scan-doel.txt").write_bytes(payload.replace(b"HASH", digest))
    assert target_identity(directory) is None


def test_target_identity_refuses_reparse_target_file(tmp_path, monkeypatch):
    from conftest import reparse_at

    from nsmcp.retention import target_identity

    directory = export(tmp_path)
    record_target(directory)
    assert target_identity(directory) == "lab", "premisse: zonder herparseerpunt is het doel bekend"
    reparse_at(monkeypatch, directory / "scan-doel.txt", tag=0xA000000C)
    assert target_identity(directory) is None
