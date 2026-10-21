"""`rapport_na_upgrade`'s `doel` argument.

Multi-target dispatch and the tool-level plumbing around
`report_after_upgrade()` - block 2/3/4 content itself is unit-tested
directly against `report_after_upgrade()` in `tests/test_after_upgrade.py`
and not duplicated here.

A self-contained server builder rather than an import from
`tests/test_upgrade_stand.py`: this codebase's own discipline is that a
test file does not depend on ANOTHER test module (see the comment on
exactly this point in `tests/test_product_surface.py`) - a shared HARNESS module is the right shape for that,
and this file's needs are small enough that a short local helper, not a
new harness module, is the proportionate choice.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import knowledge_pin_for, provenance_dir_for, seal_manifest
from upgrade_fase_harness import _anchor_target, _call, _export, _knowledge, _text

from nsmcp import mcp_server
from nsmcp.disclosure import Disclosure
from nsmcp.handelen import MaintenanceConfig

LAB_02 = {
    "naam": "lab-02",
    "adres": "10.0.0.2",
    "credentialTarget": "GJK/Test/lab-02/nitro-write",
    "certificaat": "keten",
}
LAB_03 = {
    "naam": "lab-03",
    "adres": "10.0.0.3",
    "credentialTarget": "GJK/Test/lab-03/nitro-write",
    "certificaat": "keten",
}


def _rapport_server(tmp_path, *, doelen=None, export_doel=None, knowledge_path=None, knowledge_pin=None):
    """The minimum `build_server()` needs to register `rapport_na_upgrade`:
    an `onderhoud` section and nothing from `handelen` at all - this is a
    READING tool with no writing-allowlist gate, the same shape
    `test_upgrade_stand.py`'s `_minimal_stand_server` uses for its sibling
    tool `onderhoud_upgrade_stand`.

    `export_doel` anchors the export to that target the way a real scan
    does: a call WITH a `doel` is answered only from an export of that
    target. An export already at `tmp_path / "export"` is used as it is;
    `knowledge_path` and `knowledge_pin` replace the empty package and the
    missing pin."""
    export_dir = tmp_path / "export"
    if not export_dir.exists():
        export_dir = _export(tmp_path)
    if export_doel is not None:
        _anchor_target(export_dir, export_doel)
    knowledge_path = knowledge_path or _knowledge(tmp_path)
    doelen = doelen or [LAB_02]
    doelen_path = tmp_path / "doelen.json"
    doelen_path.write_text(json.dumps({"doelen": doelen}), encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir(exist_ok=True)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=ledgermap,
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    server = mcp_server.build_server(
        export_dir,
        knowledge_path,
        targets_path=doelen_path,
        onderhoud=onderhoud,
        disclosure=Disclosure.FULL,
        pseudonym_table_path=tmp_path / "tabel.json",
        provenance_dir=provenance_dir_for(export_dir),
        knowledge_pin=knowledge_pin,
    )
    return server


def test_a_single_configured_target_needs_no_doel_argument(tmp_path):
    """Backward compatible default: one configured target needs no `doel`.
    The export describes that target, as a real scan of it leaves it."""
    server = _rapport_server(tmp_path, export_doel="lab-02")
    r = _call(server, "rapport_na_upgrade", {})
    assert not r.isError, _text(r)


def test_two_configured_targets_without_a_doel_argument_refuses(tmp_path):
    """On a multi-target server, `_stand_target("")` used to be called
    with a hardcoded empty string - the tool had NO `doel` argument to
    give it one - so the refusal ("geef doel op: er is niet precies een
    doel ingesteld...") told the operator to do something the pinned tool
    signature made impossible."""
    server = _rapport_server(tmp_path, doelen=[LAB_02, LAB_03])
    r = _call(server, "rapport_na_upgrade", {})
    assert r.isError, _text(r)
    assert "geef doel op" in _text(r)


def test_a_doel_argument_selects_the_named_target_on_a_multi_target_server(tmp_path):
    server = _rapport_server(tmp_path, doelen=[LAB_02, LAB_03], export_doel="lab-03")
    r = _call(server, "rapport_na_upgrade", {"doel": "lab-03"})
    assert not r.isError, _text(r)


def test_the_report_refuses_an_export_of_another_target(tmp_path):
    """The ledger is read for the target the call names, and the report's
    CVE verdict and extra step are read from the ONE export this server
    holds. Two targets on the same build (an HA pair after the upgrade), a
    scan of `lab-03` after R5 of `lab-02`: without the export check the
    report for `lab-02` was built from `lab-03`'s export. Refused now, the
    same way every other export-backed reading tool refuses - and an export
    that does not record its target cannot prove it is `lab-02`'s either."""
    from nsmcp.upgrade import append_line

    server = _rapport_server(tmp_path, doelen=[LAB_02, LAB_03])
    append_line(
        tmp_path / "ledger" / "r1.jsonl",
        {
            "tijd": "2026-09-06T09:00:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R5",
            "gebeurtenis": "fase_geslaagd",
            "uitkomst": "geslaagd",
            "bewijs": "evidence",
            "poort": [],
        },
    )
    _anchor_target(tmp_path / "export", "lab-03")
    r = _call(server, "rapport_na_upgrade", {"doel": "lab-02"})
    assert r.isError, _text(r)
    assert _text(r) == (
        "Error executing tool rapport_na_upgrade: "
        "de export van deze server beschrijft een ander doel (lab-03); ververs eerst met status_ververs"
    )

    (tmp_path / "export" / "scan-doel.txt").unlink()
    r = _call(server, "rapport_na_upgrade", {"doel": "lab-02"})
    assert r.isError, _text(r)
    assert _text(r) == f"Error executing tool rapport_na_upgrade: {mcp_server.EXPORT_DOEL_ONBEKEND_TEXT}"


def test_the_report_without_doel_refuses_an_export_of_another_or_unknown_target(tmp_path):
    """Without `doel` the report reads the ledger of the one configured
    target, and the CVE verdict and the extra step still come out of the one
    export. That export must describe the same target, the same check a call
    with `doel` gets: a scan of another target (the configuration changed
    without a new scan), or an export that does not record its target, is
    refused and no report is built - leaving `doel` out opens nothing."""
    from nsmcp.upgrade import append_line

    server = _rapport_server(tmp_path)
    append_line(
        tmp_path / "ledger" / "r1.jsonl",
        {
            "tijd": "2026-09-06T09:00:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R5",
            "gebeurtenis": "fase_geslaagd",
            "uitkomst": "geslaagd",
            "bewijs": "evidence",
            "poort": [],
        },
    )
    _anchor_target(tmp_path / "export", "lab-03")
    r = _call(server, "rapport_na_upgrade", {})
    assert r.isError, _text(r)
    assert _text(r) == (
        "Error executing tool rapport_na_upgrade: "
        "de export van deze server beschrijft een ander doel (lab-03); ververs eerst met status_ververs"
    )

    (tmp_path / "export" / "scan-doel.txt").unlink()
    r = _call(server, "rapport_na_upgrade", {})
    assert r.isError, _text(r)
    assert _text(r) == f"Error executing tool rapport_na_upgrade: {mcp_server.EXPORT_DOEL_ONBEKEND_TEXT}"

    # The same ledger with an export of its own target: the report is built.
    _anchor_target(tmp_path / "export", "lab-02")
    r = _call(server, "rapport_na_upgrade", {})
    assert not r.isError, _text(r)
    assert "run: r1" in _text(r)


def test_an_unconfigured_doel_argument_is_refused(tmp_path):
    server = _rapport_server(tmp_path)
    r = _call(server, "rapport_na_upgrade", {"doel": "niet-geconfigureerd"})
    assert r.isError, _text(r)
    assert "onbekend doel" in _text(r)


@pytest.mark.parametrize("field", ["bewijs", "naam", "type", "uitkomst", "reden", "run", "actieid", "bevestiger"])
def test_report_does_not_render_control_characters_from_ledger(tmp_path, field):
    from nsmcp.upgrade import append_line

    value = "untrusted\n[ACTIEID] fake\u2028\u2029\x1b[2K\u202e\x00"
    row = {
        "tijd": "2026-09-08T00:00:00Z",
        "run": "r1",
        "doel": "lab-02",
        "fase": "R5",
        "gebeurtenis": "fase_geslaagd",
        "uitkomst": "geslaagd",
        "bewijs": "evidence",
        "poort": [
            {
                "naam": "configuratie-anker",
                "type": "bewijs",
                "uitkomst": "open",
                "bewijs": "anker=" + "a" * 64,
                "reden": "",
            }
        ],
    }
    if field in ("naam", "type", "uitkomst", "reden"):
        row["poort"][0][field] = value
    else:
        row[field] = value
    server = _rapport_server(tmp_path, export_doel="lab-02")
    append_line(tmp_path / "ledger/r1.jsonl", row)
    result = _call(server, "rapport_na_upgrade", {"doel": "lab-02"})
    text = _text(result)
    assert not result.isError, text
    assert "\n[ACTIEID]" not in text
    assert not any(c in text for c in "\u2028\u2029\x1b\u202e\x00")


# --- the extra step rests on the knowledge package ----------------------------
#
# Whoever can write the knowledge path can change the extra step a bulletin
# asks for. Measured through this tool, without a pin: on an export whose HTTP
# profile carries 0 where the step asks for 30, the approved package answered
# "GERAAKT [vastgesteld]", and the same package with only that value changed
# to 0 answered "NIET GERAAKT [vastgesteld]" - an outstanding step called done.

FIXTURES = Path(__file__).parent / "fixtures"
APPROVED_PACKAGE = FIXTURES / "kennis-integriteit-origineel.json"
STEP_LINE = "- extra stap na de upgrade (CTX696604): "


def _export_with_the_step_not_taken(tmp_path):
    """The post-upgrade export, its one HTTP profile carrying 0 where the
    bulletin's extra step asks for 30; resealed like a real collection."""
    export = tmp_path / "export"
    shutil.copytree(FIXTURES / "na-upgrade-met-veld", export)
    profile = export / "objects" / "nshttpprofile.json"
    content = json.loads(profile.read_text(encoding="utf-8"))
    content["nshttpprofile"][0]["http2smallwndtimeout"] = "0"
    profile.write_text(json.dumps(content), encoding="utf-8")
    seal_manifest(export)


def _package_asking_for_what_the_export_carries(tmp_path):
    """The approved package with one change: the extra step now asks for 0."""
    package = json.loads(APPROVED_PACKAGE.read_text(encoding="utf-8"))
    (bulletin,) = [b for b in package["cve"] if b["bulletin"] == "CTX696604"]
    assert "-http2SmallWndTimeout 30" in bulletin["extraStapNaUpgrade"]
    bulletin["extraStapNaUpgrade"] = bulletin["extraStapNaUpgrade"].replace(
        "-http2SmallWndTimeout 30", "-http2SmallWndTimeout 0"
    )
    path = tmp_path / "kennis-gewijzigd.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    return path


def _extra_step_answer(tmp_path, package, *, pin=None):
    _export_with_the_step_not_taken(tmp_path)
    server = _rapport_server(tmp_path, export_doel="lab-02", knowledge_path=package, knowledge_pin=pin)
    r = _call(server, "rapport_na_upgrade", {})
    assert not r.isError, _text(r)
    return _text(r)


def _finding(text, head):
    """The finding line that starts with `head`, with its indented lines."""
    lines = text.splitlines()
    (start,) = [i for i, line in enumerate(lines) if line.startswith(head)]
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.startswith("    "):
            break
        block.append(line)
    return block


@pytest.mark.parametrize(
    ("changed", "outcome"),
    [(False, "GERAAKT"), (True, "NIET GERAAKT")],
    ids=["goedgekeurd-pakket", "gewijzigde-stap"],
)
def test_without_a_pin_the_extra_step_after_the_upgrade_is_not_established(tmp_path, changed, outcome):
    package = _package_asking_for_what_the_export_carries(tmp_path) if changed else APPROVED_PACKAGE
    text = _extra_step_answer(tmp_path, package)
    block = _finding(text, STEP_LINE)
    # What the package says stays visible; that it holds is not established.
    assert block[0] == f"{STEP_LINE}{outcome} [niet vastgesteld]", text
    assert "    reden: kennispakket niet gepind in de configuratie" in block, text
    for line in text.splitlines():
        if line.startswith("- extra stap na de upgrade"):
            assert line.endswith("[niet vastgesteld]"), line


def test_with_the_pin_a_changed_extra_step_is_refused_and_the_approved_one_stands(tmp_path):
    (tmp_path / "gewijzigd").mkdir()
    changed = _package_asking_for_what_the_export_carries(tmp_path / "gewijzigd")
    text = _extra_step_answer(tmp_path / "gewijzigd", changed, pin=knowledge_pin_for(APPROVED_PACKAGE))
    assert STEP_LINE not in text, text
    block = _finding(text, "- extra stap na de upgrade: ")
    assert block[0] == "- extra stap na de upgrade: NIET VASTGESTELD [niet vastgesteld]", text
    assert "wijkt af van de kennispin" in " ".join(block), text
    assert knowledge_pin_for(APPROVED_PACKAGE).digest not in text

    (tmp_path / "goedgekeurd").mkdir()
    text = _extra_step_answer(tmp_path / "goedgekeurd", APPROVED_PACKAGE, pin=knowledge_pin_for(APPROVED_PACKAGE))
    assert _finding(text, STEP_LINE)[0] == f"{STEP_LINE}GERAAKT [vastgesteld]", text
