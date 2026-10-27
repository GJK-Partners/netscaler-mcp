"""1.1 C (SR-7): the integrity of the pseudonym table at the disclosure seam.

A table in which two valid rows swap their real names is well-formed; at
`beperkt` the writing path resolves a pseudonym the human confirmed into the
object a script acts on. These proofs go through `render()` and the CLI
(`python -m nsmcp.disclosure`) - the routes a customer has - and assert the
kind (`soort`), that nothing was written, and that no message carries a real
name, a pseudonym or a table id. The anchor store is the per-test in-memory
seam (tests/conftest.py)."""

from __future__ import annotations

import ast
import json
import shutil
import sys
from pathlib import Path

import pytest
from conftest import table_place, table_rows

from nsmcp import tablekey
from nsmcp.answer import Answer, Certainty, Finding
from nsmcp.disclosure import (
    FORM_1_NEXT_TO_ANCHOR_SENTENCE,
    FORM_1_SENTENCE,
    Disclosure,
    PseudonymTableBroken,
    PseudonymTableIntegrity,
    main,
    render,
    resolve_pseudonym_bound,
)

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="het tabelanker en DPAPI bestaan alleen op Windows")

NAME_A = "SYNTH_DOEL_ALFA"
NAME_B = "SYNTH_DOEL_BETA"
NAME_C = "SYNTH_DOEL_GAMMA"


def _render(table: Path, *names: str) -> str:
    answer = Answer(
        question="v",
        findings=[Finding(subject=n, outcome="o", certainty=Certainty.ESTABLISHED, evidence="e") for n in names]
        or [Finding(subject="geen", outcome="o", certainty=Certainty.ESTABLISHED, evidence="e", subject_is_name=False)],
    )
    return render(answer, Disclosure.LIMITED, tool="x", extra_names=names, pseudonym_table_path=table)


def _table(tmp_path: Path, *names: str) -> Path:
    table = tmp_path / "beheer" / "openheid-vertaaltabel.json"
    table.parent.mkdir(parents=True, exist_ok=True)
    _render(table, *names)
    return table


def _raw(table: Path) -> dict:
    return json.loads(table.read_text(encoding="utf-8"))


def _write_raw(table: Path, raw: dict) -> None:
    table.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")


def _refusal(table: Path, *names: str) -> PseudonymTableIntegrity:
    before = table.read_bytes() if table.exists() else None
    with pytest.raises(PseudonymTableIntegrity) as refused:
        _render(table, *names)
    after = table.read_bytes() if table.exists() else None
    assert after == before, "een geweigerde tabel wordt nooit overschreven"
    return refused.value


def _assert_no_content(message: str, table_id: str | None = None) -> None:
    for needle in (NAME_A, NAME_B, NAME_C, "object-0"):
        assert needle not in message, needle
    if table_id:
        assert table_id not in message and table_id[:8] not in message


def _store() -> tablekey.MemoryRegistry:
    store = tablekey._registry
    assert isinstance(store, tablekey.MemoryRegistry)
    return store


# ---------------------------------------------------------------------------
# Rows, chain, head, watermark
# ---------------------------------------------------------------------------


def test_swapped_names_are_refused(tmp_path):
    table = _table(tmp_path, NAME_A, NAME_B)
    raw = _raw(table)
    raw["rijen"][0]["naam"], raw["rijen"][1]["naam"] = raw["rijen"][1]["naam"], raw["rijen"][0]["naam"]
    _write_raw(table, raw)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "mac" and "vermelding 1" in str(refused)
    _assert_no_content(str(refused), raw["tabelId"])


def test_swapped_pseudonyms_are_refused(tmp_path):
    """The swap of C.1 the other way round: two valid rows exchange their
    PSEUDONYM, name and MAC stay. The pseudonym is in the row MAC."""
    table = _table(tmp_path, NAME_A, NAME_B)
    raw = _raw(table)
    first, second = raw["rijen"][0], raw["rijen"][1]
    first["pseudoniem"], second["pseudoniem"] = second["pseudoniem"], first["pseudoniem"]
    _write_raw(table, raw)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "mac" and "vermelding 1" in str(refused)
    _assert_no_content(str(refused), raw["tabelId"])


def test_reordered_rows_are_refused(tmp_path):
    table = _table(tmp_path, NAME_A, NAME_B)
    raw = _raw(table)
    raw["rijen"].reverse()
    _write_raw(table, raw)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "keten"
    _assert_no_content(str(refused), raw["tabelId"])


def test_truncated_table_with_hand_made_head_is_refused(tmp_path):
    table = _table(tmp_path, NAME_A, NAME_B)
    raw = _raw(table)
    raw["rijen"].pop()
    raw["kop"]["aantal"] = 1
    raw["kop"]["keten"] = raw["rijen"][0]["mac"]
    _write_raw(table, raw)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "kop"


def test_rollback_to_an_older_valid_table_is_refused(tmp_path):
    table = _table(tmp_path, NAME_A)
    old_table, old_key = table.read_bytes(), tablekey.key_path(table).read_bytes()
    _render(table, NAME_A, NAME_B)
    assert len(table_rows(table)) == 2
    table.write_bytes(old_table)
    tablekey.key_path(table).write_bytes(old_key)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "teruggedraaid"


def test_a_table_ahead_of_its_anchor_moves_the_anchor_forward(tmp_path, monkeypatch):
    table = _table(tmp_path, NAME_A)

    def crash(label: str) -> None:
        if label == "t1":
            raise RuntimeError("crash na de tabel")

    monkeypatch.setattr(tablekey, "_after_step", crash)
    with pytest.raises(RuntimeError):
        _render(table, NAME_A, NAME_B)
    monkeypatch.setattr(tablekey, "_after_step", tablekey._no_crash)
    assert NAME_B not in _render(table, NAME_A, NAME_B)
    where = table_place(table)
    assert tablekey.parse_anchor(_store().values[where.slot], where.slot).aantal == 2


# ---------------------------------------------------------------------------
# S-5: identity of place and generation
# ---------------------------------------------------------------------------


def test_restored_previous_generation_with_its_key_is_refused(tmp_path, capsys):
    """Two legitimate generations with the same pseudonym `object-01` for
    different synthetic targets; the old table plus its own old key put
    back is `afgedankt` - also with a valid old key, chain and own old
    watermark."""
    table = _table(tmp_path, NAME_A)
    assert table_rows(table) == {"object-01": NAME_A}
    old_table, old_key = table.read_bytes(), tablekey.key_path(table).read_bytes()
    assert main(["--reset", "--pad", str(table), "--gecontroleerd"]) == 0
    _render(table, NAME_B)
    assert table_rows(table) == {"object-01": NAME_B}
    table.write_bytes(old_table)
    tablekey.key_path(table).write_bytes(old_key)
    refused = _refusal(table, NAME_A, NAME_B)
    assert refused.soort == "afgedankt"
    with pytest.raises(PseudonymTableIntegrity):
        resolve_pseudonym_bound("object-01", (NAME_A, NAME_B), table)
    _assert_no_content(str(refused), json.loads(old_table)["tabelId"])


def test_tables_swapped_between_two_places_are_refused(tmp_path):
    first = _table(tmp_path / "een", NAME_A)
    second = _table(tmp_path / "twee", NAME_B)
    for suffix in (".json", ".sleutel"):
        a, b = first.with_suffix(suffix), second.with_suffix(suffix)
        a_bytes, b_bytes = a.read_bytes(), b.read_bytes()
        a.write_bytes(b_bytes)
        b.write_bytes(a_bytes)
    assert _refusal(first, NAME_A).soort == "slot"
    assert _refusal(second, NAME_B).soort == "slot"


def test_a_table_moved_to_a_new_place_is_refused(tmp_path):
    table = _table(tmp_path / "oud", NAME_A)
    moved = tmp_path / "nieuw" / "beheer" / table.name
    moved.parent.mkdir(parents=True)
    shutil.copy2(table, moved)
    shutil.copy2(tablekey.key_path(table), tablekey.key_path(moved))
    assert _refusal(moved, NAME_A).soort == "slot"


def test_existing_anchor_with_missing_files_is_never_a_first_start(tmp_path):
    table = _table(tmp_path, NAME_A)
    table.unlink()
    tablekey.key_path(table).unlink()
    refused = _refusal(table, NAME_A)
    assert refused.soort == "bestand_ontbreekt"
    assert not table.exists() and not tablekey.key_path(table).exists()


def test_a_missing_key_next_to_a_committed_anchor_is_refused(tmp_path):
    table = _table(tmp_path, NAME_A)
    tablekey.key_path(table).unlink()
    assert _refusal(table, NAME_A).soort == "sleutel_ontbreekt"


def test_rows_without_an_anchor_are_refused(tmp_path):
    table = _table(tmp_path, NAME_A)
    _store().values.clear()
    refused = _refusal(table, NAME_A)
    assert refused.soort == "anker_ontbreekt"
    assert _store().values == {}


def test_a_torn_anchor_record_is_refused_and_kept(tmp_path):
    table = _table(tmp_path, NAME_A)
    where = table_place(table)
    _store().values[where.slot] = _store().values[where.slot][:-10]
    torn = _store().values[where.slot]
    assert _refusal(table, NAME_A).soort == "anker_onleesbaar"
    assert _store().values[where.slot] == torn


def test_an_integrity_refusal_is_a_broken_table_for_every_existing_caller(tmp_path):
    table = _table(tmp_path, NAME_A)
    _store().values.clear()
    with pytest.raises(PseudonymTableBroken):
        _render(table, NAME_A)


# ---------------------------------------------------------------------------
# Form 1 and the CLI
# ---------------------------------------------------------------------------


def _form_1(tmp_path: Path) -> Path:
    table = tmp_path / "beheer" / "openheid-vertaaltabel.json"
    table.parent.mkdir(parents=True)
    table.write_text(json.dumps({"object-01": NAME_A, "object-02": NAME_B}), encoding="utf-8")
    return table


def test_form_1_is_refused_with_the_cli_sentence(tmp_path):
    table = _form_1(tmp_path)
    refused = _refusal(table, NAME_A)
    assert refused.soort == "formaat" and FORM_1_SENTENCE in str(refused)
    assert "--onderteken <pad> --gecontroleerd" in str(refused)
    assert _store().values == {} and not tablekey.key_path(table).exists()


def test_the_cli_without_the_flag_changes_nothing(tmp_path, capsys):
    table = _form_1(tmp_path)
    before = table.read_bytes()
    assert main(["--onderteken", str(table)]) == 2
    out = capsys.readouterr().out
    assert "telt 2 rijen" in out and "[EINDSTATUS] niets gewijzigd" in out
    assert NAME_A not in out and "object-01" not in out
    assert table.read_bytes() == before and _store().values == {}
    assert sorted(p.name for p in table.parent.iterdir()) == [
        "openheid-vertaaltabel.json",
        "openheid-vertaaltabel.json.lock",
    ]


def test_the_cli_signs_once_with_a_byte_equal_backup_and_never_again(tmp_path, capsys):
    table = _form_1(tmp_path)
    before = table.read_bytes()
    assert main(["--onderteken", str(table), "--gecontroleerd"]) == 0
    backups = [p for p in table.parent.iterdir() if ".v1-" in p.name]
    assert len(backups) == 1 and backups[0].read_bytes() == before
    text = _render(table, NAME_A, NAME_B)
    assert NAME_A not in text and "object-01" in text
    assert table_rows(table) == {"object-01": NAME_A, "object-02": NAME_B}
    key, anchors = tablekey.key_path(table).read_bytes(), dict(_store().values)
    capsys.readouterr()
    assert main(["--onderteken", str(table), "--gecontroleerd"]) == 0
    assert tablekey.ALREADY_SIGNED in capsys.readouterr().out
    assert tablekey.key_path(table).read_bytes() == key and _store().values == anchors


def test_a_1_0_x_rewrite_next_to_an_anchor_is_never_migrated_again(tmp_path, capsys):
    """Revision 3: one table belongs to one engine version. A 1.0.x server
    that rewrites the table in form 1 next to an existing anchor is refused
    at the seam AND by `--onderteken`: no new key, no new anchor."""
    table = _form_1(tmp_path)
    assert main(["--onderteken", str(table), "--gecontroleerd"]) == 0
    table.write_text(json.dumps({"object-01": NAME_B, "object-02": NAME_A}), encoding="utf-8")
    refused = _refusal(table, NAME_A)
    assert refused.soort == "formaat" and FORM_1_NEXT_TO_ANCHOR_SENTENCE in str(refused)
    key, anchors, rewritten = tablekey.key_path(table).read_bytes(), dict(_store().values), table.read_bytes()
    listing = sorted(p.name for p in table.parent.iterdir())
    assert main(["--onderteken", str(table), "--gecontroleerd"]) == 1
    assert sorted(p.name for p in table.parent.iterdir()) == listing, "geen nieuwe backup, sleutel of tabel"
    assert FORM_1_NEXT_TO_ANCHOR_SENTENCE in capsys.readouterr().err
    assert tablekey.key_path(table).read_bytes() == key and _store().values == anchors
    assert table.read_bytes() == rewritten


def test_the_cli_restores_a_copy_of_the_active_generation_only(tmp_path, capsys):
    table = _table(tmp_path, NAME_A, NAME_B)
    good = tmp_path / "kopie.json"
    good.write_bytes(table.read_bytes())
    raw = _raw(table)
    raw["rijen"][0]["naam"] = NAME_C
    _write_raw(table, raw)
    assert _refusal(table, NAME_A).soort == "mac"
    assert main(["--herstel", str(good), "--pad", str(table)]) == 2
    assert main(["--herstel", str(good), "--pad", str(table), "--gecontroleerd"]) == 0
    assert table_rows(table) == {"object-01": NAME_A, "object-02": NAME_B}
    older = tmp_path / "ouder.json"
    raw = _raw(table)
    raw["rijen"].pop()
    _write_raw(older, raw)
    assert main(["--herstel", str(older), "--pad", str(table), "--gecontroleerd"]) == 1
    assert table_rows(table) == {"object-01": NAME_A, "object-02": NAME_B}


def test_the_cli_reset_warns_renames_and_never_deletes(tmp_path, capsys):
    table = _table(tmp_path, NAME_A)
    old = table.read_bytes()
    assert main(["--reset", "--pad", str(table)]) == 2
    assert tablekey.RESET_WARNING in capsys.readouterr().out
    assert table.read_bytes() == old
    assert main(["--reset", "--pad", str(table), "--gecontroleerd"]) == 0
    assert (table.parent / (table.name + ".afgedankt-1")).read_bytes() == old
    assert (table.parent / "openheid-vertaaltabel.sleutel.afgedankt-1").exists()
    assert table_rows(table) == {}


def test_the_cli_names_no_table_content(tmp_path, capsys):
    table = _table(tmp_path, NAME_A, NAME_B)
    raw = _raw(table)
    raw["rijen"][0]["naam"] = NAME_C
    _write_raw(table, raw)
    assert main(["--onderteken", str(table), "--gecontroleerd"]) == 1
    captured = capsys.readouterr()
    _assert_no_content(captured.out + captured.err, raw["tabelId"])


# ---------------------------------------------------------------------------
# No content in any refusal; compare_digest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("soort", tablekey.SOORTEN)
def test_no_integrity_sentence_carries_content(tmp_path, soort):
    from nsmcp.disclosure import _integrity

    for vorm in ("", "1", "1-naast-anker", "2"):
        message = str(_integrity(tmp_path / "t.json", tablekey.Fault(soort, 3, vorm=vorm)))
        _assert_no_content(message)
        assert "\n" not in message and message.startswith("de vertaaltabel op ")


def test_every_mac_comparison_uses_compare_digest():
    source = (Path(__file__).resolve().parent.parent / "src" / "nsmcp" / "tablekey.py").read_text(encoding="utf-8")
    assert source.count("hmac.compare_digest(") >= 6
    secret_like = {"mac", "keten", "kop_mac", "controle", "expected", "expected_head", "at"}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            sides = (node.left, *node.comparators)
            # A comparison with a module constant (`ZERO_CHAIN`) is a shape
            # check of the record, not a comparison of a secret value.
            if any(isinstance(side, ast.Name) and side.id.isupper() for side in sides):
                continue
            for side in sides:
                name = side.attr if isinstance(side, ast.Attribute) else side.id if isinstance(side, ast.Name) else ""
                assert name not in secret_like, ast.unparse(node)


def test_a_file_failure_reaches_the_cli_as_a_fixed_sentence_without_traceback(tmp_path, capsys, monkeypatch):
    """Review M-1: an OS refusal while a file is created (here the new key of
    a reset) is the fixed sentence with the class name only, exit 1 and the
    end line - never a traceback, never the OS text with its path."""
    from nsmcp import localpath

    table = _table(tmp_path, NAME_A)

    def refused(path, data, *, root):
        raise PermissionError(13, "toegang geweigerd", str(path))

    monkeypatch.setattr(localpath, "create_local", refused)
    assert main(["--reset", "--pad", str(table), "--gecontroleerd"]) == 1
    err = capsys.readouterr().err
    assert (
        "[FOUT] het sleutelbestand van de vertaaltabel kon niet gelezen of geschreven worden (PermissionError)" in err
    )
    assert "[EINDSTATUS] niet uitgevoerd" in err
    assert "Traceback" not in err and "toegang geweigerd" not in err and str(tmp_path) not in err


def test_a_file_failure_at_the_seam_is_a_broken_table_without_the_os_text(tmp_path, monkeypatch):
    from nsmcp import localpath

    table = tmp_path / "beheer" / "openheid-vertaaltabel.json"
    table.parent.mkdir(parents=True)

    def refused(path, data, *, root):
        raise PermissionError(13, "toegang geweigerd", str(path))

    monkeypatch.setattr(localpath, "create_local", refused)
    with pytest.raises(PseudonymTableBroken) as broken:
        _render(table, NAME_A)
    message = str(broken.value)
    assert "(PermissionError)" in message and "toegang geweigerd" not in message and str(tmp_path) not in message


def test_an_8_3_file_name_is_refused_with_its_own_sentence_and_nothing_is_written(tmp_path):
    import ctypes

    table = _table(tmp_path, NAME_A)
    buffer = ctypes.create_unicode_buffer(1024)
    assert ctypes.windll.kernel32.GetShortPathNameW(str(table), buffer, 1024)
    short = Path(buffer.value)
    if short.name == table.name:
        pytest.skip(
            f"8.3-namen worden op het volume van {str(table)[:2]!r} niet gegenereerd; de M-2-weigering is niet te meten"
        )
    before = sorted(p.name for p in table.parent.iterdir()), dict(_store().values)
    with pytest.raises(PseudonymTableBroken) as refused:
        _render(short, NAME_A)
    message = str(refused.value)
    assert "andere spelling van haar bestandsnaam" in message and "sleutel_ontbreekt" not in message
    _assert_no_content(message)

    # The refusal comes under the lock, whose file is named after the spelling
    # given: that one empty lock file may appear; nothing else does.
    def unchanged() -> bool:
        names = [n for n in sorted(p.name for p in table.parent.iterdir()) if n != short.name + ".lock"]
        return (names, dict(_store().values)) == before

    assert unchanged()
    assert main(["--reset", "--pad", str(short), "--gecontroleerd"]) == 1
    assert unchanged()
