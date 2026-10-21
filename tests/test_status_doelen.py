"""`status_doelen`, and the optional `doel` on the export-backed reading tools.

`status_doelen` is the one reading tool that talks about the CONFIGURATION
instead of the export: per target its name, its address, how old the export
of that target is, the last maintenance run in the ledger and which writing
tools the allowlist grants on it. What it must never say is how this server
gets in: no credential-target name, no fingerprint (only "gepind: ja/nee"),
and no allowlist VALUE (an object name), only tool names.

`doel` on the other reading tools is a check, not a switch: this server holds
ONE export, so a given `doel` must be a configured target AND the target that
export describes. Anything else is refused - an unknown name and an unknown
pseudonym with the same sentence, and a known target that is not the
export's with the advice to refresh first.

Everything here is synthetic: TEST-NET addresses, `GJK/Test/` credential
names, `LBV-`/`SG-`/`CERT-` object names.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from conftest import _export_dir, _knowledge_file, maintenance_config, provenance_dir_for, record_collected
from upgrade_fase_harness import _call, _text

from nsmcp.disclosure import Disclosure
from nsmcp.handelen import WRITE_TOOLS, Allowlist
from nsmcp.mcp_server import (
    EXPORT_ANDER_DOEL_TEXT,
    EXPORT_DOEL_ONBEKEND_TEXT,
    ONBEKEND_DOEL_TEXT,
    build_server,
)
from nsmcp.upgrade import append_line

TLS_VINGERAFDRUK = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"
HOSTSLEUTEL = "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f"

LAB_02 = {
    "naam": "lab-02",
    "adres": "192.0.2.2",
    "credentialTarget": "GJK/Test/lab-02/nitro-read",
    "certificaat": "vingerafdruk",
    "vingerafdruk": TLS_VINGERAFDRUK,
    "ssh_hostsleutel_vingerafdruk": HOSTSLEUTEL,
}
LAB_03 = {
    "naam": "lab-03",
    "adres": "192.0.2.3",
    "credentialTarget": "GJK/Test/lab-03/nitro-read",
    "certificaat": "keten",
}

# Every spelling of a value this tool must never show: the credential
# targets, and both fingerprints raw and in the normalized form the target
# file stores them in.
NEVER_SHOWN = (
    "GJK/Test/lab-02/nitro-read",
    "GJK/Test/lab-03/nitro-read",
    TLS_VINGERAFDRUK,
    TLS_VINGERAFDRUK.replace(":", ""),
    HOSTSLEUTEL,
    HOSTSLEUTEL.replace(":", ""),
)

# The object form carries a real object name as its VALUE; only the tool
# name may reach an answer.
ALLOWLIST = Allowlist(
    per_target={
        "lab-02": {
            "onderhoud_backup_maken": True,
            "onderhoud_upgrade_fase": True,
            "config_opslaan": True,
            "certificaat_klaarzetten": {"certnaam": ("CERT-GEHEIM-01",)},
        },
        "lab-04": {"onderhoud_backup_maken": False},
    }
)

RUN = "20260923T130216Z-lab-02"


def _export_for(tmp_path: Path, doel: str | None) -> Path:
    """The conftest export, with the target that produced it recorded the
    way `collect.collect()` records it: the name, then the sha256 of the
    manifest bytes it belongs to - and the provenance record `status_ververs`
    keeps of that scan, outside the export."""
    export_dir = _export_dir(tmp_path)
    if doel is not None:
        digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
        (export_dir / "scan-doel.txt").write_text(f"{doel}\n{digest}\n", encoding="utf-8")
        record_collected(export_dir, doel)
    return export_dir


def _doelen_file(tmp_path: Path, doelen) -> Path:
    path = tmp_path / "doelen.json"
    path.write_text(json.dumps({"doelen": list(doelen)}), encoding="utf-8")
    return path


def _row(tijd, fase, gebeurtenis, uitkomst, *, run=RUN, doel="lab-02"):
    return {
        "tijd": tijd,
        "run": run,
        "doel": doel,
        "fase": fase,
        "gebeurtenis": gebeurtenis,
        "uitkomst": uitkomst,
        "poort": [],
        "bewijs": "synthetische ledgerregel",
    }


def _ledger_rows(ledgermap: Path, rows, *, run=RUN) -> Path:
    path = ledgermap / f"{run}.jsonl"
    for row in rows:
        append_line(path, row)
    return path


STANDARD_RUN = (
    _row("2026-09-23T13:02:16Z", "R0", "fase_gestart", "gestart"),
    _row("2026-09-23T13:05:00Z", "R0", "voormeting_vast", "geslaagd"),
    _row("2026-09-23T13:06:00Z", "R1", "fase_gestart", "gestart"),
    _row("2026-09-23T13:11:53Z", "R1", "fase_geslaagd", "geslaagd"),
)


def _server(
    tmp_path: Path,
    *,
    disclosure: Disclosure = Disclosure.FULL,
    doelen=(LAB_02, LAB_03),
    allowlist: Allowlist = ALLOWLIST,
    writing: bool = True,
    onderhoud: bool = True,
    export_doel: str | None = "lab-02",
    rows=STANDARD_RUN,
):
    export_dir = _export_for(tmp_path, export_doel)
    extra = {}
    if writing:
        script = tmp_path / "schrijf.ps1"
        script.write_text("# leeg; deze test voert niets uit", encoding="utf-8")
        extra = {"action_script": script, "fixture_dir": tmp_path, "code_presenter": lambda *args: None}
    maintenance = maintenance_config(tmp_path) if onderhoud else None
    if maintenance is not None and rows:
        _ledger_rows(maintenance.ledgermap, rows)
    return build_server(
        export_dir,
        _knowledge_file(tmp_path),
        targets_path=_doelen_file(tmp_path, doelen) if doelen is not None else None,
        onderhoud=maintenance,
        allowlist=allowlist,
        disclosure=disclosure,
        pseudonym_table_path=tmp_path / "tabel.json",
        provenance_dir=provenance_dir_for(export_dir),
        **extra,
    )


def _ask(server, tool="status_doelen", args=None) -> tuple[bool, str]:
    r = _call(server, tool, args or {})
    return r.isError, _text(r)


def _days_old(collected: date) -> str:
    days = (datetime.now(UTC).date() - collected).days
    return "1 dag oud" if days == 1 else f"{days} dagen oud"


# ---------------------------------------------------------------------------
# Registration and the answer at 'volledig'.
# ---------------------------------------------------------------------------


def test_status_doelen_is_always_registered_in_the_status_chapter(tmp_path):
    plain = build_server(_export_dir(tmp_path), _knowledge_file(tmp_path))
    assert "status_doelen" in {t.name for t in plain._tool_manager.list_tools()}
    only_certificaat = build_server(
        _export_dir(tmp_path / "b"), _knowledge_file(tmp_path), chapters=frozenset({"certificaat"})
    )
    assert "status_doelen" not in {t.name for t in only_certificaat._tool_manager.list_tools()}


def test_without_any_target_the_answer_is_the_fixed_sentence(tmp_path):
    for level in Disclosure:
        server = _server(
            tmp_path / level.value,
            disclosure=level,
            doelen=None,
            allowlist=Allowlist(per_target={}),
            writing=False,
            onderhoud=False,
        )
        error, text = _ask(server)
        assert error is False, text
        assert text == "Er is geen doel ingesteld; deze server antwoordt op een aangeleverde export."


def test_at_volledig_every_target_has_its_line(tmp_path):
    error, text = _ask(_server(tmp_path))
    assert error is False, text
    assert "Vraag: welke doelen kent deze server" in text
    assert (
        "- doelen: 2 in het doelenbestand, 1 met een toestemming in de allowlist, 1 alleen in de allowlist"
        " [vastgesteld]"
    ) in text
    assert (
        f"- lab-02: adres 192.0.2.2; export van 2026-08-19, {_days_old(date(2026, 8, 19))}; laatste "
        f"onderhoudsrun {RUN}, laatste regel R1 geslaagd om 2026-09-23T13:11:53Z; toegestaan: "
        "certificaat_klaarzetten, config_opslaan, onderhoud_backup_maken, onderhoud_upgrade_fase; "
        "hostsleutel gepind: ja [vastgesteld]"
    ) in text
    assert (
        "- lab-03: adres 192.0.2.3; geen export van dit doel in deze server (de export beschrijft een "
        "ander doel); geen onderhoudsrun; toegestaan: geen; hostsleutel gepind: nee [vastgesteld]"
    ) in text
    assert (
        "- lab-04: alleen in de allowlist, niet in het doelenbestand; geen adres; geen export van dit doel "
        "in deze server (de export beschrijft een ander doel); geen onderhoudsrun; toegestaan: geen"
        " [vastgesteld]"
    ) in text
    # The closing stamps every reading answer carries.
    assert "Gegevens van 2026-08-19" in text and "doel: lab-02, herkomst: verzameld door deze server op " in text


def test_a_granted_tool_that_is_not_registered_is_named_as_such(tmp_path):
    """`allows()` alone is not "toegestaan": without a `handelen` section the
    writing tools do not exist on this server, and the answer says so
    instead of promising a tool nobody can call."""
    error, text = _ask(_server(tmp_path, writing=False))
    assert error is False, text
    assert (
        "toegestaan: geen; in de allowlist maar op deze server niet aangemeld: certificaat_klaarzetten, "
        "config_opslaan, onderhoud_backup_maken, onderhoud_upgrade_fase; hostsleutel gepind: ja"
    ) in text


def test_allows_is_judged_per_form_and_no_allowlist_value_is_ever_shown(tmp_path):
    allowlist = Allowlist(
        per_target={
            "lab-02": {
                # complete object form: allowed
                "certificaat_klaarzetten": {"certnaam": ("CERT-GEHEIM-01",)},
                # object form without one of its fields: refused
                "certificaat_vervangen": {"dienst": ("LBV-GEHEIM-01",)},
                # object form with an empty value: refused
                "dienst_lid_uitschakelen": {"dienst": ("SG-GEHEIM-01",), "lid": ()},
                # objectless true: allowed
                "onderhoud_backup_maken": True,
                # objectless false: refused
                "config_opslaan": False,
            }
        }
    )
    error, text = _ask(_server(tmp_path, allowlist=allowlist))
    assert error is False, text
    assert "toegestaan: certificaat_klaarzetten, onderhoud_backup_maken; hostsleutel gepind: ja" in text
    for value in ("CERT-GEHEIM-01", "LBV-GEHEIM-01", "SG-GEHEIM-01"):
        assert value not in text


def test_without_onderhoud_there_is_no_ledger_to_read(tmp_path):
    error, text = _ask(_server(tmp_path, onderhoud=False, writing=False))
    assert error is False, text
    assert "geen ledger ingesteld (onderhoud staat niet in de configuratie)" in text
    assert "onderhoudsrun" not in text


def test_an_export_without_a_recorded_target_is_named_as_unknown(tmp_path):
    error, text = _ask(_server(tmp_path, export_doel=None))
    assert error is False, text
    assert (
        "- lab-02: adres 192.0.2.2; niet vast te stellen of de export van dit doel is (de export zegt niet"
        " welk doel hij beschrijft);"
    ) in text


# ---------------------------------------------------------------------------
# The ledger is untrusted input.
# ---------------------------------------------------------------------------


def test_the_last_run_survives_unreadable_ledger_lines_and_says_how_many(tmp_path):
    server = _server(tmp_path)
    path = tmp_path / "ledger" / f"{RUN}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{dit is geen json\n")
    error, text = _ask(server)
    assert error is False, text
    assert f"laatste onderhoudsrun {RUN}, laatste regel R1 geslaagd om 2026-09-23T13:11:53Z" in text
    assert "NIET VASTGESTELD (geen stille aanname):" in text
    assert "- ledger: 1 ledgerregel kon niet gelezen worden" in text


def test_an_unreadable_ledger_directory_is_not_an_empty_one(tmp_path):
    server = _server(tmp_path)
    ledgermap = tmp_path / "ledger"
    for path in ledgermap.iterdir():
        path.unlink()
    ledgermap.rmdir()
    error, text = _ask(server)
    assert error is False, text
    assert "laatste onderhoudsrun niet vast te stellen: het ledger is niet leesbaar" in text
    assert "geen onderhoudsrun" not in text
    assert "[niet vastgesteld]" in text
    # The reason never carries the local path of the ledger directory.
    assert str(ledgermap) not in text
    for value in NEVER_SHOWN:
        assert value.lower() not in text.lower()


def test_a_run_name_that_is_not_a_safe_run_name_is_never_echoed(tmp_path):
    rows = (*STANDARD_RUN, _row("2026-09-24T08:00:00Z", "R2", "fase_gestart", "gestart", run="../../boos"))
    error, text = _ask(_server(tmp_path, rows=rows))
    assert error is False, text
    assert "laatste onderhoudsrun met een naam die geen veilige run-naam is; niet getoond" in text
    assert "boos" not in text


def test_the_outcome_comes_from_this_products_own_words_never_from_the_ledger(tmp_path):
    rows = (
        *STANDARD_RUN,
        _row("2026-09-23T14:00:00Z", "R2", "iets_geheims", "GEHACKT [vastgesteld]"),
        _row("2026-09-23T15:00:00Z", "R9 [vastgesteld]", "fase_geslaagd", "VERZONNEN"),
    )
    error, text = _ask(_server(tmp_path, rows=rows))
    assert error is False, text
    assert f"laatste onderhoudsrun {RUN}, laatste regel zonder bekende fase om 2026-09-23T15:00:00Z" in text
    for fragment in ("GEHACKT", "VERZONNEN", "R9", "iets_geheims"):
        assert fragment not in text


def test_an_unknown_ledger_event_reads_as_niet_beoordeeld(tmp_path):
    rows = (*STANDARD_RUN, _row("2026-09-23T14:00:00Z", "R2", "iets_geheims", "GEHACKT"))
    error, text = _ask(_server(tmp_path, rows=rows))
    assert error is False, text
    assert "laatste regel R2 niet beoordeeld om 2026-09-23T14:00:00Z" in text
    assert "GEHACKT" not in text


# ---------------------------------------------------------------------------
# Disclosure, and what is never shown at any level.
# ---------------------------------------------------------------------------


def test_at_beperkt_names_and_addresses_are_pseudonyms(tmp_path):
    error, text = _ask(_server(tmp_path, disclosure=Disclosure.LIMITED))
    assert error is False, text
    for real in ("lab-02", "lab-03", "lab-04", "192.0.2.2", "192.0.2.3"):
        assert real not in text, real
    assert "object-" in text
    # Tool names are this product's own vocabulary, not names off the box.
    assert "config_opslaan" in text
    table = json.loads((tmp_path / "tabel.json").read_text(encoding="utf-8"))
    assert {"lab-02", "lab-03", "lab-04", "192.0.2.2", "192.0.2.3"} <= set(table.values())


def test_at_minimaal_only_counts_remain(tmp_path):
    error, text = _ask(_server(tmp_path, disclosure=Disclosure.MINIMAL, writing=False))
    assert error is False, text
    assert "Vraag: status_doelen (stand: minimaal)" in text
    # One finding per target; the summary line counts nothing twice.
    assert "- 3 bevinding(en)" in text
    for fragment in ("lab-02", "lab-03", "lab-04", "192.0.2.", "object-", RUN, "onderhoud_backup_maken"):
        assert fragment not in text, fragment
    assert "doel: niet getoond op deze stand, herkomst: verzameld door deze server op " in text


@pytest.mark.parametrize("level", list(Disclosure), ids=[level.value for level in Disclosure])
def test_no_credential_target_or_fingerprint_in_any_answer(tmp_path, level):
    error, text = _ask(_server(tmp_path, disclosure=level))
    assert error is False, text
    for value in NEVER_SHOWN:
        assert value.lower() not in text.lower(), value


# ---------------------------------------------------------------------------
# `doel` on the export-backed reading tools.
# ---------------------------------------------------------------------------

# Every reading tool that answers out of the one export, with the arguments
# it needs besides `doel`. The five reading tools that do NOT get this check
# are named in `WITHOUT_THE_EXPORT_CHECK`, each for its own reason.
EXPORT_READ_TOOLS = {
    "certificaat_wat_verloopt_er": {},
    "certificaat_wat_breekt_er": {"certnaam": "CERT-001"},
    "certificaat_wat_moet_ik_doen": {"certnaam": "CERT-001"},
    "status_cve_controle": {},
    "status_overzicht": {},
    "status_update_advies": {},
    "status_update_preflight": {},
    "status_gezondheid": {},
    "status_namen": {},
    "dienst_status": {"dienst": "LBV-001"},
    "dienst_keten": {},
    "onderhoud_upgrade_plan": {},
    "rapport_dekking": {},
    "rapport_wat_is_er_veranderd": {},
    "ha_stand": {},
    "config_drift": {},
    "beveiliging_verstopte_regels": {},
    "beveiliging_tls_baseline": {},
    "beveiliging_beheervlak": {},
    "beveiliging_headers": {},
    "beveiliging_scorekaart": {},
    # reads the ledger of its target (given, or the one configured target)
    # AND the export: the CVE verdict and the extra step come out of the
    # export, so it gets the check, with or without `doel`
    "rapport_na_upgrade": {},
}
WITHOUT_THE_EXPORT_CHECK = {
    # scans a target by name; its argument is `doelnaam`
    "status_ververs",
    # reads the knowledge package, never the export
    "kennis_uitleg",
    # judges the ledger of the target it is given; the export only supplies
    # the data stamp, which names the export's own target
    "onderhoud_upgrade_stand",
    # compares two named export directories
    "rapport_vergelijk",
    # is itself the answer to "which targets are there"
    "status_doelen",
}

ANDER_DOEL_VOLLEDIG = "de export van deze server beschrijft een ander doel (lab-02); ververs eerst met status_ververs"


def _registered(server) -> dict:
    return {tool.name: tool for tool in server._tool_manager.list_tools()}


def _refusal(tool: str, sentence: str) -> str:
    """A refusal as the MCP client reads it: the SDK puts the tool name in
    front of the product's own sentence, and nothing else."""
    return f"Error executing tool {tool}: {sentence}"


def test_the_export_check_covers_every_export_backed_reading_tool(tmp_path):
    tools = _registered(_server(tmp_path, writing=False))
    reading = set(tools) - set(WRITE_TOOLS)
    assert reading - WITHOUT_THE_EXPORT_CHECK == set(EXPORT_READ_TOOLS)
    for name in EXPORT_READ_TOOLS:
        assert tools[name].parameters["properties"]["doel"] == {"default": "", "title": "Doel", "type": "string"}
        assert "doel" not in tools[name].parameters.get("required", [])


@pytest.mark.parametrize("tool", sorted(EXPORT_READ_TOOLS))
def test_every_export_backed_reading_tool_checks_its_doel_against_the_export(tmp_path, tool):
    server = _server(tmp_path, writing=False)
    arguments = EXPORT_READ_TOOLS[tool]

    error, text = _ask(server, tool, {**arguments, "doel": "lab-02"})
    assert error is False, text

    error, text = _ask(server, tool, {**arguments, "doel": "lab-03"})
    assert error is True
    assert text == _refusal(tool, ANDER_DOEL_VOLLEDIG)

    error, text = _ask(server, tool, {**arguments, "doel": "geheim-doel-x"})
    assert error is True
    assert text == _refusal(tool, ONBEKEND_DOEL_TEXT)
    assert "geheim-doel-x" not in text


def test_without_a_doel_the_tools_answer_as_before(tmp_path):
    error, text = _ask(_server(tmp_path, writing=False), "status_overzicht")
    assert error is False, text
    assert "doel: lab-02, herkomst: verzameld door deze server op " in text


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL], ids=["beperkt", "minimaal"])
def test_below_volledig_the_other_target_is_not_named(tmp_path, level):
    error, text = _ask(_server(tmp_path, disclosure=level, writing=False), "status_overzicht", {"doel": "lab-03"})
    assert error is True
    assert text == _refusal("status_overzicht", EXPORT_ANDER_DOEL_TEXT)
    assert "lab-02" not in text


def test_an_export_that_does_not_record_its_target_refuses_a_doel(tmp_path):
    error, text = _ask(_server(tmp_path, export_doel=None, writing=False), "status_overzicht", {"doel": "lab-02"})
    assert error is True
    assert text == _refusal("status_overzicht", EXPORT_DOEL_ONBEKEND_TEXT)


def test_the_refusals_never_carry_a_credential_target_or_fingerprint(tmp_path):
    for level in Disclosure:
        server = _server(tmp_path / level.value, disclosure=level, writing=False)
        for doel in ("lab-02", "lab-03", "geheim-doel-x", "object-999"):
            _error, text = _ask(server, "ha_stand", {"doel": doel})
            for value in NEVER_SHOWN:
                assert value.lower() not in text.lower(), (level, doel, value)


def test_the_preflight_measures_the_given_doel_instead_of_giving_up_on_two_targets(tmp_path):
    """Without `doel` and with two targets the live read cannot know which
    appliance to measure. With `doel` it does: here the SSH route of
    lab-02 (onderhoud plus a pinned host key), which stops honestly at the
    missing read script instead of guessing."""
    server = _server(tmp_path, writing=False)
    _error, without = _ask(server, "status_update_preflight")
    assert "er zijn 2 doelen ingesteld en deze toets krijgt geen doelnaam mee" in without
    error, text = _ask(server, "status_update_preflight", {"doel": "lab-02"})
    assert error is False, text
    assert "krijgt geen doelnaam mee" not in text
    assert "staat niet naast de faserunner; er is niet live gelezen" in text
    # B3 (1.0.2): no read process ran, so the evidence names no route and
    # never says "live gelezen via".
    for answer in (without, text):
        regel8 = answer[answer.index("- 8. ") :].split("\n- ", 1)[0]
        assert "niet gelezen: " in regel8
        assert "live gelezen via" not in regel8


# ---------------------------------------------------------------------------
# A pseudonym as `doel` at 'beperkt', through one resolver.
# ---------------------------------------------------------------------------


def _pseudonym_of(tmp_path: Path, real: str) -> str:
    table = json.loads((tmp_path / "tabel.json").read_text(encoding="utf-8"))
    return next(pseudonym for pseudonym, name in table.items() if name == real)


def test_at_beperkt_a_pseudonym_from_status_doelen_is_a_valid_doel(tmp_path):
    server = _server(tmp_path, disclosure=Disclosure.LIMITED, writing=False)
    error, text = _ask(server)
    assert error is False, text
    lab_02, lab_03 = _pseudonym_of(tmp_path, "lab-02"), _pseudonym_of(tmp_path, "lab-03")
    assert f"- {lab_02}: adres " in text

    error, text = _ask(server, "status_overzicht", {"doel": lab_02})
    assert error is False, text
    assert "lab-02" not in text
    assert f"doel: {lab_02}, herkomst: verzameld door deze server op " in text

    error, text = _ask(server, "status_overzicht", {"doel": lab_03})
    assert error is True
    assert text == _refusal("status_overzicht", EXPORT_ANDER_DOEL_TEXT)


def test_at_beperkt_an_unknown_pseudonym_and_an_unknown_name_get_the_same_refusal(tmp_path):
    server = _server(tmp_path, disclosure=Disclosure.LIMITED, writing=False)
    _ask(server)
    address_pseudonym = _pseudonym_of(tmp_path, "192.0.2.2")
    refusals = set()
    for doel in ("object-999", "geheim-doel-x", address_pseudonym):
        error, text = _ask(server, "status_overzicht", {"doel": doel})
        assert error is True
        refusals.add(text)
    assert refusals == {_refusal("status_overzicht", ONBEKEND_DOEL_TEXT)}


def test_at_volledig_a_pseudonym_is_not_a_doel(tmp_path):
    limited = _server(tmp_path / "beperkt", disclosure=Disclosure.LIMITED, writing=False)
    _ask(limited)
    pseudonym = _pseudonym_of(tmp_path / "beperkt", "lab-02")
    full = _server(tmp_path / "volledig", writing=False)
    error, text = _ask(full, "status_overzicht", {"doel": pseudonym})
    assert error is True
    assert text == _refusal("status_overzicht", ONBEKEND_DOEL_TEXT)


def test_the_ledger_reading_tools_share_the_resolver_and_never_echo_the_real_name(tmp_path):
    server = _server(tmp_path, disclosure=Disclosure.LIMITED, writing=False)
    _ask(server)
    for real in ("lab-02", "lab-03"):
        error, text = _ask(server, "onderhoud_upgrade_stand", {"doel": _pseudonym_of(tmp_path, real)})
        assert error is False, text
        assert real not in text, text
    error, text = _ask(server, "onderhoud_upgrade_stand", {"doel": "object-999"})
    assert error is True
    assert text == _refusal("onderhoud_upgrade_stand", ONBEKEND_DOEL_TEXT)


def _preview_only(arguments, timeout_s):
    """The write script's -WatIs preview, stubbed: nothing is started."""
    assert "-WatIs" in arguments
    return 0, "[OK] zou doen: backup\n[TARGET] lab-02\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n", ""


def test_a_writing_tool_takes_the_same_pseudonym_as_doel(tmp_path):
    shown = []
    script = tmp_path / "schrijf.ps1"
    script.write_text("# leeg; de stub neemt het over", encoding="utf-8")
    export_dir = _export_for(tmp_path, "lab-02")
    server = build_server(
        export_dir,
        _knowledge_file(tmp_path),
        provenance_dir=provenance_dir_for(export_dir),
        targets_path=_doelen_file(tmp_path, (LAB_02, LAB_03)),
        onderhoud=maintenance_config(tmp_path),
        allowlist=ALLOWLIST,
        disclosure=Disclosure.LIMITED,
        pseudonym_table_path=tmp_path / "tabel.json",
        action_script=script,
        fixture_dir=tmp_path,
        action_run=_preview_only,
        code_presenter=lambda *args: shown.append(args),
    )
    _ask(server)
    error, text = _ask(server, "onderhoud_backup_maken", {"doel": "object-999"})
    assert "onbekend doel" in text and shown == [], text
    error, text = _ask(server, "onderhoud_backup_maken", {"doel": _pseudonym_of(tmp_path, "lab-02")})
    assert error is False, text
    assert len(shown) == 1
    assert "lab-02" not in text
