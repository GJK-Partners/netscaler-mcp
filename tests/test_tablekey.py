"""1.1 C: the table slot, the anchor record, the protected key and the commit
protocol of the pseudonym table (`nsmcp.tablekey`), below the disclosure seam.

The registry is the in-memory seam here (`tablekey.MemoryRegistry`), except in
the proofs on the real HKCU store, which write only under
`HKCU\\Software\\GJK\\netscaler-mcp\\Test\\<uuid4>` and remove it afterwards.
DPAPI is the real one unless a test replaces it."""

from __future__ import annotations

import contextlib
import ctypes
import json
import sys
from pathlib import Path

import pytest

from nsmcp import localpath, tablekey
from nsmcp.tablekey import Fault

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="het tabelanker en DPAPI bestaan alleen op Windows")

CAP = 1 << 20
TEST_BASE = "Software\\GJK\\netscaler-mcp\\Test"


class Crash(Exception):
    pass


@pytest.fixture
def registry(monkeypatch):
    store = tablekey.MemoryRegistry()
    monkeypatch.setattr(tablekey, "_registry", store)
    return store


_HELD = contextlib.ExitStack()


@pytest.fixture(autouse=True)
def _release_held_chains():
    """The place keeps the held lock chain open (the directory listing is read
    on it), as the product does for its critical section; closed per test."""
    yield
    _HELD.close()


def place(table: Path) -> tablekey.Place:
    table.parent.mkdir(parents=True, exist_ok=True)
    root = localpath.absolute_text(table.parent)
    # Write sharing on the test's own lock handle: a test asks for the same
    # place under several spellings while the earlier chains stay held.
    held = _HELD.enter_context(
        localpath.open_local_for_append(localpath.under(root, table.name + ".lock"), root=root, shared_writers=True)
    )
    return tablekey.place_of(table, root, held)


def parse(data: bytes, path: Path) -> object:
    return json.loads(localpath.as_text(data))


def form_1(raw: object) -> list[tuple[str, str]]:
    assert isinstance(raw, dict)
    return list(raw.items())


def load(where: tablekey.Place) -> tablekey.Verified:
    return tablekey.load(where, parse, table_cap=CAP)


def crash_at(monkeypatch, label: str) -> None:
    def after(step: str) -> None:
        if step == label:
            raise Crash(step)

    monkeypatch.setattr(tablekey, "_after_step", after)


def no_crash(monkeypatch) -> None:
    monkeypatch.setattr(tablekey, "_after_step", tablekey._no_crash)


def say_nothing(_line: str) -> None:
    return None


def _short_name(path: Path) -> str:
    buffer = ctypes.create_unicode_buffer(1024)
    assert ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024)
    return buffer.value


# ---------------------------------------------------------------------------
# The slot
# ---------------------------------------------------------------------------


def test_the_slot_is_the_place_not_the_spelling(tmp_path):
    table = tmp_path / "Beheer Map" / "tabel.json"
    first = place(table)
    short = Path(_short_name(table.parent)) / "tabel.json"
    assert place(short).slot == first.slot
    assert place(Path(str(table).upper())).slot == first.slot
    assert place(tmp_path / "andere" / "tabel.json").slot != first.slot
    assert place(table.with_name("tabel2.json")).slot != first.slot


def test_the_slot_never_comes_from_the_file(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)
    raw = json.loads(table.read_text(encoding="utf-8"))
    raw["slot"] = "f" * 64
    table.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "slot"


# ---------------------------------------------------------------------------
# The anchor record
# ---------------------------------------------------------------------------


def _resealed(text: str, **changes) -> str:
    """The record with `changes` and a CORRECT `controle`: only the shape
    rules can refuse it."""
    record = json.loads(text)
    record.pop("controle")
    record.update(changes)
    record["tabelId"] = "b" * 32 if record.get("toestand") == "reset" else record["tabelId"]
    record["controle"] = __import__("hashlib").sha256(tablekey._canonical(record).encode("ascii")).hexdigest()
    return tablekey._canonical(record)


def _anchor(slot: str) -> tablekey.Anchor:
    return tablekey.Anchor(slot, "a" * 32, 1, 0, tablekey.ZERO_CHAIN, "vastgelegd", None, ())


def test_the_anchor_record_round_trips_and_is_canonical():
    slot = "1" * 64
    text = _anchor(slot).text()
    assert tablekey.parse_anchor(text, slot) == _anchor(slot)
    assert json.loads(text)["controle"]
    assert text.isascii() and "\n" not in text


@pytest.mark.parametrize(
    "damage",
    [
        lambda t: t[:-5],
        lambda t: t.replace('"aantal":0', '"aantal":1'),
        lambda t: t.replace('"formaat"', '"onbekend":1,"formaat"'),
        lambda t: t.replace('"toestand":"vastgelegd"', '"toestand":"klaar"'),
        lambda t: json.dumps(json.loads(t), indent=1),
        lambda t: _resealed(t, toestand="reset", nieuw={"tabelId": "a" * 32, "generatie": 2}, afgedankt=["a" * 32]),
    ],
    ids=[
        "afgekapt",
        "controle-klopt-niet",
        "onbekende-sleutel",
        "onbekende-toestand",
        "niet-canoniek",
        "nieuw-id-al-afgedankt",
    ],
)
def test_a_torn_or_edited_anchor_record_is_unreadable(damage):
    slot = "2" * 64
    with pytest.raises(Fault) as refused:
        tablekey.parse_anchor(damage(_anchor(slot).text()), slot)
    assert refused.value.soort == "anker_onleesbaar"


def test_an_anchor_record_of_another_slot_is_unreadable():
    with pytest.raises(Fault) as refused:
        tablekey.parse_anchor(_anchor("3" * 64).text(), "4" * 64)
    assert refused.value.soort == "anker_onleesbaar"


def test_a_torn_anchor_is_never_replaced_by_a_load(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)
    registry.values[where.slot] = registry.values[where.slot][:-3]
    torn = registry.values[where.slot]
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "anker_onleesbaar"
    assert registry.values[where.slot] == torn


def test_a_delayed_anchor_writer_never_moves_the_anchor_back(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    first = load(where)
    stale_raw = first.anchor_raw
    second = tablekey.append(first, [("object-01", "NAAM-A"), ("object-02", "NAAM-B")])
    assert second.anchor.aantal == 2
    # A delayed writer that read the anchor before the append and now writes
    # its own state of the SAME height (a lost update): only the re-read
    # under the lock can see that the record is no longer the one it read.
    same_height = tablekey.Anchor(where.slot, first.anchor.tabel_id, 1, 2, "f" * 64, "vastgelegd", None, ())
    with pytest.raises(Fault) as stale:
        tablekey.write_anchor(where, stale_raw, same_height, "test")
    assert stale.value.soort == "anker_onleesbaar"
    assert registry.values[where.slot] == second.anchor_raw
    behind = tablekey.Anchor(where.slot, first.anchor.tabel_id, 1, 1, second.doc.rows[0].mac, "vastgelegd", None, ())
    with pytest.raises(Fault) as lower:
        tablekey.write_anchor(where, second.anchor_raw, behind, "test")
    assert lower.value.soort == "teruggedraaid"
    assert tablekey.parse_anchor(registry.values[where.slot], where.slot).aantal == 2


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------


def test_the_key_opens_only_with_its_own_slot_id_and_generation():
    key = b"k" * 32
    wrapped = tablekey.wrap_key(key, "5" * 64, "b" * 32, 1)
    assert tablekey.unwrap_key(wrapped, "5" * 64, "b" * 32, 1) == key
    for slot, tabel_id, generatie in (("6" * 64, "b" * 32, 1), ("5" * 64, "c" * 32, 1), ("5" * 64, "b" * 32, 2)):
        with pytest.raises(Fault) as refused:
            tablekey.unwrap_key(wrapped, slot, tabel_id, generatie)
        assert refused.value.soort == "sleutel_onleesbaar"
    assert key not in wrapped


def test_a_key_of_another_account_is_unreadable(tmp_path, registry, monkeypatch):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)

    class OtherAccount(tablekey._Dpapi):
        def unprotect(self, blob, entropy):
            raise tablekey.KeyUnprotectError("ander account")

    monkeypatch.setattr(tablekey, "_dpapi", OtherAccount())
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "sleutel_onleesbaar"


# ---------------------------------------------------------------------------
# Loading: first start, missing files, rule 8
# ---------------------------------------------------------------------------


def test_a_first_start_creates_anchor_key_and_an_empty_signed_table(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    created = load(where)
    assert created.anchor.toestand == "vastgelegd" and created.anchor.generatie == 1 and created.anchor.aantal == 0
    assert table.exists() and tablekey.key_path(table).exists()
    assert load(where).anchor == created.anchor
    assert [label for label, _ in registry.writes] == [where.slot, where.slot]


@pytest.mark.parametrize(
    "leftover", ["tabel.json.afgedankt-1", "tabel.json.v1-20261027-abcdef01", "tabel.sleutel.afgedankt-2"]
)
def test_a_leftover_of_an_earlier_generation_is_never_a_first_start(tmp_path, registry, leftover):
    table = tmp_path / "b" / "tabel.json"
    table.parent.mkdir(parents=True)
    (table.parent / leftover).write_bytes(b"{}")
    with pytest.raises(Fault) as refused:
        load(place(table))
    assert refused.value.soort == "anker_ontbreekt"
    assert registry.values == {} and not table.exists()


def test_the_anchor_moves_forward_only_after_the_whole_chain_verifies(tmp_path, registry, monkeypatch):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    first = tablekey.append(load(where), [("object-01", "A")])
    crash_at(monkeypatch, "t1")
    with pytest.raises(Crash):
        tablekey.append(first, [("object-02", "B"), ("object-03", "C")])
    no_crash(monkeypatch)
    assert tablekey.parse_anchor(registry.values[where.slot], where.slot).aantal == 1
    raw = json.loads(table.read_text(encoding="utf-8"))
    raw["rijen"][2]["naam"] = "X"
    damaged = json.dumps(raw)
    table.write_text(damaged, encoding="utf-8")
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "mac" and refused.value.positie == 3
    assert tablekey.parse_anchor(registry.values[where.slot], where.slot).aantal == 1, "anker niet vooruit"


# ---------------------------------------------------------------------------
# Crash after every commit point
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", ["a1", "a2", "a3", "a4"])
def test_a_crash_during_creation_resumes_on_the_recorded_identity(tmp_path, registry, monkeypatch, label):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    crash_at(monkeypatch, label)
    with pytest.raises(Crash):
        load(where)
    no_crash(monkeypatch)
    recorded = tablekey.parse_anchor(registry.values[where.slot], where.slot)
    expected_id = recorded.nieuw["tabelId"] if recorded.nieuw else recorded.tabel_id
    resumed = load(where)
    assert resumed.anchor.toestand == "vastgelegd" and resumed.anchor.tabel_id == expected_id


def test_an_interrupted_creation_with_a_foreign_table_closes(tmp_path, registry, monkeypatch):
    other = tmp_path / "ander" / "tabel.json"
    load(place(other))
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    crash_at(monkeypatch, "a2")
    with pytest.raises(Crash):
        load(where)
    no_crash(monkeypatch)
    table.write_bytes(other.read_bytes())
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "aanmaak_onderbroken"


@pytest.mark.parametrize("label", ["t1", "t2"])
def test_a_crash_during_an_append_is_the_old_or_the_new_commit(tmp_path, registry, monkeypatch, label):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    first = load(where)
    crash_at(monkeypatch, label)
    with pytest.raises(Crash):
        tablekey.append(first, [("object-01", "A")])
    no_crash(monkeypatch)
    again = load(where)
    assert again.mapping() == {"object-01": "A"} and again.anchor.aantal == 1


def _form_1_table(tmp_path) -> tuple[Path, tablekey.Place, bytes]:
    table = tmp_path / "b" / "tabel.json"
    table.parent.mkdir(parents=True)
    data = json.dumps({"object-01": "NAAM-A", "object-02": "NAAM-B"}).encode("utf-8")
    table.write_bytes(data)
    return table, place(table), data


def migrate(where, *, confirmed=True):
    return tablekey.migrate(where, parse, form_1, confirmed=confirmed, say=say_nothing, table_cap=CAP)


@pytest.mark.parametrize("label", ["m2", "m3", "m4", "m5", "m6"])
def test_a_crash_during_migration_is_old_commit_or_named_state_and_the_cli_resumes(
    tmp_path, registry, monkeypatch, label
):
    table, where, data = _form_1_table(tmp_path)
    crash_at(monkeypatch, label)
    with pytest.raises(Crash):
        migrate(where)
    no_crash(monkeypatch)
    expected = {"m2": "formaat", "m3": "migratie_onderbroken", "m4": "migratie_onderbroken"}
    expected["m5"] = "migratie_onderbroken"
    if label in expected:
        with pytest.raises(Fault) as refused:
            load(where)
        assert refused.value.soort == expected[label]
    key_before = tablekey.key_path(table).read_bytes() if tablekey.key_path(table).exists() else None
    assert migrate(where) == 0
    assert load(where).mapping() == {"object-01": "NAAM-A", "object-02": "NAAM-B"}
    if key_before is not None:
        assert tablekey.key_path(table).read_bytes() == key_before, "geen nieuwe sleutel bij hervatten"
    backups = [p for p in table.parent.iterdir() if p.name.startswith("tabel.json.v1-")]
    assert len(backups) == 1 and backups[0].read_bytes() == data


def test_a_migration_does_not_resume_on_changed_bytes(tmp_path, registry, monkeypatch):
    table, where, _data = _form_1_table(tmp_path)
    crash_at(monkeypatch, "m3")
    with pytest.raises(Crash):
        migrate(where)
    no_crash(monkeypatch)
    table.write_text(json.dumps({"object-01": "NAAM-B", "object-02": "NAAM-A"}), encoding="utf-8")
    with pytest.raises(Fault) as refused:
        migrate(where)
    assert refused.value.soort == "migratie_onderbroken"
    assert not tablekey.key_path(table).exists()


def test_a_backup_that_does_not_read_back_byte_equal_stops_before_the_anchor(tmp_path, registry, monkeypatch):
    table, where, data = _form_1_table(tmp_path)
    real = tablekey._create

    def short_write(where_, name, payload, what):
        real(where_, name, payload[:-1] if ".v1-" in name else payload, what)

    monkeypatch.setattr(tablekey, "_create", short_write)
    with pytest.raises(tablekey.Stop):
        migrate(where)
    assert registry.values == {} and table.read_bytes() == data
    assert not tablekey.key_path(table).exists()


@pytest.mark.parametrize("label", ["h2", "h3"])
def test_a_crash_during_a_restore_is_load_rule_8(tmp_path, registry, monkeypatch, label):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    verified = tablekey.append(load(where), [("object-01", "A")])
    crash_at(monkeypatch, "t1")
    with pytest.raises(Crash):
        tablekey.append(verified, [("object-02", "B")])
    no_crash(monkeypatch)
    good = tmp_path / "kopie.json"
    good.write_bytes(table.read_bytes())
    table.write_text("{}", encoding="utf-8")
    crash_at(monkeypatch, label)
    with pytest.raises(Crash):
        tablekey.restore(where, good, parse, confirmed=True, say=say_nothing, table_cap=CAP)
    no_crash(monkeypatch)
    assert load(where).mapping() == {"object-01": "A", "object-02": "B"}


def reset(where):
    return tablekey.reset(where, confirmed=True, say=say_nothing, table_cap=CAP)


@pytest.mark.parametrize("label", ["r1", "r2", "r3", "r4", "r5"])
def test_a_crash_during_a_reset_is_the_named_state_and_the_cli_resumes(tmp_path, registry, monkeypatch, label):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    old = tablekey.append(load(where), [("object-01", "A")])
    crash_at(monkeypatch, label)
    with pytest.raises(Crash):
        reset(where)
    no_crash(monkeypatch)
    if label != "r5":
        with pytest.raises(Fault) as refused:
            load(where)
        assert refused.value.soort == "reset_onderbroken"
        assert reset(where) == 0
    fresh = load(where)
    assert fresh.anchor.generatie == 2 and fresh.mapping() == {}
    assert old.anchor.tabel_id in fresh.anchor.afgedankt
    names = sorted(p.name for p in table.parent.iterdir())
    assert "tabel.json.afgedankt-1" in names and "tabel.sleutel.afgedankt-1" in names


def test_a_reset_without_a_readable_anchor_discards_and_never_deletes(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    tablekey.append(load(where), [("object-01", "A")])
    old_bytes = table.read_bytes()
    registry.values[where.slot] = "kapot"
    lines: list[str] = []
    assert tablekey.reset(where, confirmed=True, say=lines.append, table_cap=CAP) == 0
    assert lines[0] == tablekey.RESET_WARNING
    # Review M-4: the label comes from the old table's own head, never 0.
    assert (table.parent / "tabel.json.afgedankt-1").read_bytes() == old_bytes
    assert not list(table.parent.glob("*.afgedankt-0*"))
    assert load(where).anchor.generatie == 2


def test_a_reset_without_the_flag_changes_nothing(tmp_path, registry):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)
    before = dict(registry.values), table.read_bytes()
    assert tablekey.reset(where, confirmed=False, say=say_nothing, table_cap=CAP) == 2
    assert (dict(registry.values), table.read_bytes()) == before


# ---------------------------------------------------------------------------
# The real HKCU store, only under a unique test key
# ---------------------------------------------------------------------------


@pytest.fixture
def hkcu(hkcu_anchor):
    """The shared real-store fixture of conftest (unique test key, removed after)."""
    return hkcu_anchor


def test_the_real_store_writes_one_string_record_under_the_slot(tmp_path, hkcu):
    import winreg

    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    verified = load(where)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{hkcu.base}\\anker-{where.slot}") as key:
        value, kind = winreg.QueryValueEx(key, "record")
    assert kind == winreg.REG_SZ and value == verified.anchor_raw
    assert tablekey.REGISTRY_BASE == "Software\\GJK\\netscaler-mcp\\vertaaltabel"
    assert hkcu.base.startswith(TEST_BASE + "\\")


def test_a_record_of_another_value_type_is_unreadable(tmp_path, hkcu):
    import winreg

    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, f"{hkcu.base}\\anker-{where.slot}", 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "record", 0, winreg.REG_DWORD, 7)
    with pytest.raises(Fault) as refused:
        load(where)
    assert refused.value.soort == "anker_onleesbaar"


# ---------------------------------------------------------------------------
# Herstelronde 1 (review M-1, M-2, M-3, M-6)
# ---------------------------------------------------------------------------


def test_an_8_3_file_name_of_the_table_is_refused_and_another_case_is_the_same_place(tmp_path, registry):
    """Herkeuring M-2: the key and the lock are named after the spelling
    given, so an 8.3 FILE name would look for a key that is not this table's
    (`sleutel_ontbreekt`, misleading): refused with its own exception. Another
    case is the same file, key and lock, and the same slot."""
    table = tmp_path / "Beheer Map" / "openheid-vertaaltabel.json"
    load(place(table))
    short_file = Path(_short_name(table))
    assert short_file.name != table.name, "premisse: een echte 8.3-bestandsnaam"
    with pytest.raises(tablekey.NameSpelling):
        place(short_file)
    assert place(Path(str(table.parent)) / table.name.upper()).slot == place(table).slot
    short_dir = Path(_short_name(table.parent)) / table.name
    assert place(short_dir).slot == place(table).slot, "een 8.3-MAPNAAM is dezelfde plek"


def test_a_create_that_fails_is_a_file_failure_with_its_class_only(tmp_path, registry, monkeypatch):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)

    def refused(path, data, *, root):
        raise PermissionError(13, "geweigerd", str(path))

    monkeypatch.setattr(localpath, "create_local", refused)
    with pytest.raises(tablekey.FileFailed) as failed:
        load(where)
    assert isinstance(failed.value.exc, PermissionError)
    monkeypatch.undo()
    monkeypatch.setattr(tablekey, "_registry", registry)
    assert load(where).anchor.toestand == "vastgelegd", "de volgende start hervat de aanmaak"


def test_a_reset_resumption_whose_new_table_no_longer_verifies_still_ends(tmp_path, registry, monkeypatch):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    tablekey.append(load(where), [("object-01", "A")])
    crash_at(monkeypatch, "r4")
    with pytest.raises(Crash):
        reset(where)
    no_crash(monkeypatch)
    tablekey.key_path(table).write_bytes(tablekey.KEY_MAGIC + b"beschadigd")
    assert reset(where) == 0
    assert reset(where) == 0, "een tweede keer: gewoon een nieuwe reset, geen lus"
    names = sorted(p.name for p in table.parent.iterdir())
    assert any(name.startswith("tabel.json.afgedankt-2-onvoltooid") for name in names), names
    assert load(where).mapping() == {}


def test_a_reset_resumption_whose_new_table_was_tampered_still_ends(tmp_path, registry, monkeypatch):
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    load(where)
    crash_at(monkeypatch, "r4")
    with pytest.raises(Crash):
        reset(where)
    no_crash(monkeypatch)
    raw = json.loads(table.read_text(encoding="utf-8"))
    raw["kop"]["mac"] = "0" * 64
    table.write_text(json.dumps(raw), encoding="utf-8")
    assert reset(where) == 0
    assert load(where).anchor.generatie == 2


def test_the_directory_listing_is_read_on_the_held_handle(tmp_path, registry, monkeypatch):
    seam = localpath._Native(record=True)
    monkeypatch.setattr(localpath, "_native", seam)
    table = tmp_path / "b" / "tabel.json"
    where = place(table)
    (table.parent / "tabel.json.v1-20261027-00000000").write_bytes(b"{}")
    seam.opens.clear()
    names = tablekey.directory_names(where)
    assert "tabel.json.v1-20261027-00000000" in names and "." not in names and ".." not in names
    reopen = [record for record in seam.opens if record["name"] == ""]
    assert len(reopen) == 1 and reopen[0]["parent"] == where.held.directory_handle
    assert all(record["parent"] is not None for record in seam.opens), "geen open op een padtekst"
    assert seam.calls["NtQueryDirectoryFile"] >= 1
