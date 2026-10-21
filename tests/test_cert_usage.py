"""Certificate use outside the bindings with virtual servers.

Three sources name a certificate without binding it to a virtual server: a
SAML action (`samlidpcertname`, `samlsigningcertname`), a SAML IdP profile
(`samlidpcertname`, `samlspcertname`) and the binding of a certificate to an
SSL servicegroup (`certkeyname`, `ca`). The export of a collector that fetches
them is `tests/fixtures/certgebruik-saml`; the two lab exports were taken
before any collector fetched them and prove the other half: a source that is
not in the manifest is "niet vastgesteld", never "no use".
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

from nsmcp.action import what_to_do
from nsmcp.answer import Certainty
from nsmcp.coverage import coverage_answer
from nsmcp.disclosure import Disclosure, names_from_export, render
from nsmcp.expiry import usage_per_certificate, what_expires
from nsmcp.export import load_export
from nsmcp.impact import what_breaks
from nsmcp.knowledge import Knowledge

FIXTURES = Path(__file__).parent / "fixtures"
SAML = FIXTURES / "certgebruik-saml"
LAB = FIXTURES / "lab-export-vpx-20260826"
DOH = FIXTURES / "lab-export-vpx-doh-synthetic"
K = Knowledge(version="certgebruik", date="2026-09-25", age_days=0, missing=False)

SAML_ACTION = "config/authenticationsamlaction"
SAML_IDP = "config/authenticationsamlidpprofile"
SG_FILE = "sslservicegroup_sslcertkey_binding.by-parent.json"

ABSENT_REASONS = {
    "certificaatgebruik door SAML-acties": (
        "niet vastgesteld: bron config/authenticationsamlaction niet in de export; welke certificaten"
        " SAML-acties gebruiken, is met deze export niet vast te stellen"
    ),
    "certificaatgebruik door SAML-IdP-profielen": (
        "niet vastgesteld: bron config/authenticationsamlidpprofile niet in de export; welke certificaten"
        " SAML-IdP-profielen gebruiken, is met deze export niet vast te stellen"
    ),
    "certificaatgebruik door SSL-servicegroups": (
        "niet vastgesteld: bron sslservicegroup_sslcertkey_binding.by-parent.json niet in de export; welke"
        " certificaten SSL-servicegroups gebruiken, is met deze export niet vast te stellen"
    ),
}


def _copy(tmp_path) -> Path:
    target = tmp_path / "export"
    shutil.copytree(SAML, target)
    return target


def _manifest(directory: Path, change) -> None:
    path = directory / "export-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    change(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def _rewrite(directory: Path, relative: str, document) -> None:
    """Rewrites one file of the copied export and seals its new hash, so a
    test measures the CONTENT it wrote and not a manifest it broke."""
    raw = json.dumps(document).encode("utf-8")
    (directory / relative).write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest().upper()

    def seal(manifest):
        if relative.startswith("bindings/"):
            manifest["files"][relative] = digest
        else:
            manifest["resources"][f"config/{Path(relative).stem}"]["payloadSha256"] = digest

    _manifest(directory, seal)


def _sg_file(*parents) -> dict:
    return {
        "bindingResource": "sslservicegroup_sslcertkey_binding",
        "parentResource": "sslservicegroup",
        "parentKey": "servicegroupname",
        "shape": "list",
        "parents": list(parents),
    }


def _sg_parent(name, *rows) -> dict:
    return {"parentName": name, "outcome": "OK", "data": {"sslservicegroup_sslcertkey_binding": list(rows)}}


# ---------------------------------------------------------------------------
# certificaat_wat_breekt_er: every use named, with its object and its role
# ---------------------------------------------------------------------------


def test_the_saml_uses_of_a_certificate_are_named_with_object_and_role():
    answer = what_breaks(load_export(SAML), K, "CERT-IDP")
    text = answer.to_text()
    assert answer.is_complete() is True, answer.read_gaps
    assert (
        "- CERT-IDP: gebruikt als IdP-certificaat door SAML-actie SAML-ACTIE-01 [vastgesteld]\n"
        "    bewijs: config/authenticationsamlaction: name=SAML-ACTIE-01, samlidpcertname=CERT-IDP"
    ) in text
    assert "- CERT-IDP: gebruikt als IdP-certificaat door SAML-actie SAML-ACTIE-02 [vastgesteld]" in text
    assert (
        "- CERT-IDP: gebruikt als IdP-certificaat door IdP-profiel SAML-IDP-01 [vastgesteld]\n"
        "    bewijs: config/authenticationsamlidpprofile: name=SAML-IDP-01, samlidpcertname=CERT-IDP"
    ) in text
    assert [(u.kind, u.owner, u.role) for u in answer.other_uses] == [
        ("SAML-actie", "SAML-ACTIE-01", "IdP-certificaat"),
        ("SAML-actie", "SAML-ACTIE-02", "IdP-certificaat"),
        ("IdP-profiel", "SAML-IDP-01", "IdP-certificaat"),
    ]
    # The one statement this product may not make over a certificate with users.
    assert "geen gebonden virtuele servers" not in text
    assert "- gebruiksstand: gebonden [vastgesteld]" in text
    # All three sources are read, so none of them is a boundary of this answer.
    assert [n.subject for n in answer.not_assessed] == ["volledige certificaatketen buiten deze export"]


def test_the_signing_certificate_of_a_saml_action_is_named_next_to_its_virtual_server():
    answer = what_breaks(load_export(SAML), K, "CERT-VS")
    text = answer.to_text()
    assert answer.is_complete() is True, answer.read_gaps
    assert answer.affected_vservers == ("LBV-WEB-01",)
    assert (
        "- CERT-VS: gebruikt als signing-certificaat door SAML-actie SAML-ACTIE-01 [vastgesteld]\n"
        "    bewijs: config/authenticationsamlaction: name=SAML-ACTIE-01, samlsigningcertname=CERT-VS"
    ) in text


def test_the_sp_certificate_of_an_idp_profile_is_named():
    answer = what_breaks(load_export(SAML), K, "CERT-SP")
    assert answer.is_complete() is True, answer.read_gaps
    assert [(f.subject, f.outcome) for f in answer.findings] == [
        ("CERT-SP", "gebruikt als SP-certificaat door IdP-profiel SAML-IDP-01")
    ]


@pytest.mark.parametrize(("certname", "role", "flag"), [("CERT-SG", "CA: nee", "nee"), ("CERT-SG-CA", "CA: ja", "ja")])
def test_a_servicegroup_binding_names_the_servicegroup_and_the_ca_flag(certname, role, flag):
    answer = what_breaks(load_export(SAML), K, certname)
    text = answer.to_text()
    assert answer.is_complete() is True, answer.read_gaps
    assert (
        f"- {certname}: gebonden aan SSL-servicegroup SG-BACKEND-01 ({role}) [vastgesteld]\n"
        f"    bewijs: sslservicegroup_sslcertkey_binding.by-parent.json: servicegroupname=SG-BACKEND-01,"
        f" certkeyname={certname}, ca={flag}"
    ) in text
    assert [(u.kind, u.owner, u.role) for u in answer.other_uses] == [("SSL-servicegroup", "SG-BACKEND-01", role)]


def test_a_certificate_without_any_use_gets_the_statement_over_every_source_read():
    answer = what_breaks(load_export(SAML), K, "CERT-LOS")
    closing = answer.findings[-1]
    assert answer.is_complete() is True, answer.read_gaps
    assert closing.certainty is Certainty.ESTABLISHED
    assert closing.outcome == (
        "geen gebonden virtuele servers, geen gebonden SSL-diensten, geen uitgegeven certificaten en geen"
        " gebruik door SAML-acties, SAML-IdP-profielen of SSL-servicegroups gevonden in deze export"
    )
    assert closing.evidence.endswith(
        "; config/authenticationsamlaction, config/authenticationsamlidpprofile en"
        " sslservicegroup_sslcertkey_binding.by-parent.json: gelezen en gecontroleerd, geen verwijzing naar"
        " deze naam"
    )
    assert answer.other_uses == ()
    assert "- gebruiksstand: los [vastgesteld]" in answer.to_text()


def test_an_empty_certificate_field_is_not_set_and_no_read_gap():
    """SAML-ACTIE-02 carries `samlsigningcertname: ""`: the collector's way of
    saying the field is not set. Not a use, and not a gap either."""
    answer = what_breaks(load_export(SAML), K, "CERT-LOS")
    assert answer.read_gaps == []
    assert all("SAML-ACTIE-02" not in f.outcome for f in answer.findings)


# ---------------------------------------------------------------------------
# certificaat_wat_moet_ik_doen: the other uses are a manual step, with a warning
# ---------------------------------------------------------------------------


def test_the_advice_warns_that_the_replacement_tool_leaves_the_other_uses_behind():
    export = load_export(SAML)
    advice = what_to_do(what_breaks(export, K, "CERT-VS"), K, "CERT-VS")
    steps = advice.findings[0].outcome.splitlines()
    assert advice.read_gaps == []
    assert steps[1] == "2. Koppel het om op: LBV-WEB-01. (handmatige actie)"
    assert steps[2] == (
        "3. Let op: dit certificaat is ook buiten de virtuele servers in gebruik: SAML-actie SAML-ACTIE-01"
        " (signing-certificaat). certificaat_vervangen wisselt alleen de binding op een virtuele server om;"
        " zet deze verwijzingen zelf om, want dit product heeft daarvoor geen schrijfactie. (handmatige actie)"
    )
    assert steps[-1].endswith(
        " Lees daarnaast bij de objecten buiten de virtuele servers terug dat ze naar het nieuwe certificaat"
        " verwijzen. (handmatige actie)"
    )
    assert advice.findings[0].evidence == (
        "afgeleid uit 1 vastgesteld geraakte virtuele server(s) en 0 vastgesteld uitgegeven certificaten,"
        " plus 1 vastgesteld gebruik(en) buiten de virtuele servers"
    )


def test_a_certificate_used_only_by_saml_still_gets_the_manual_step():
    advice = what_to_do(what_breaks(load_export(SAML), K, "CERT-IDP"), K, "CERT-IDP")
    steps = advice.findings[0].outcome.splitlines()
    assert steps[1] == "2. Koppel het om op: (geen gebonden virtuele servers). (handmatige actie)"
    assert steps[2].startswith(
        "3. Let op: dit certificaat is ook buiten de virtuele servers in gebruik: SAML-actie SAML-ACTIE-01"
        " (IdP-certificaat), SAML-actie SAML-ACTIE-02 (IdP-certificaat), IdP-profiel SAML-IDP-01"
        " (IdP-certificaat). "
    )


def test_without_other_use_the_steps_do_not_mention_it():
    advice = what_to_do(what_breaks(load_export(SAML), K, "CERT-LOS"), K, "CERT-LOS")
    text = advice.findings[0].outcome
    assert "Let op" not in text
    assert "buiten de virtuele servers" not in text
    assert "plus" not in advice.findings[0].evidence


# ---------------------------------------------------------------------------
# certificaat_wat_verloopt_er: the usage state counts these families
# ---------------------------------------------------------------------------


def test_a_certificate_used_only_outside_the_bindings_is_gebonden_not_los():
    usage = {u.certkey: u for u in usage_per_certificate(load_export(SAML))}
    assert {name: u.state for name, u in usage.items()} == {
        "CERT-VS": "gebonden",
        "CERT-IDP": "gebonden",
        "CERT-SP": "gebonden",
        "CERT-SG": "gebonden",
        "CERT-SG-CA": "gebonden",
        "CERT-LOS": "los",
    }
    assert usage["CERT-VS"].used_by == ("LBV-WEB-01",)
    assert usage["CERT-VS"].used_elsewhere == ("SAML-actie SAML-ACTIE-01 (signing-certificaat)",)
    assert usage["CERT-IDP"].used_elsewhere == (
        "SAML-actie SAML-ACTIE-01 (IdP-certificaat)",
        "SAML-actie SAML-ACTIE-02 (IdP-certificaat)",
        "IdP-profiel SAML-IDP-01 (IdP-certificaat)",
    )


def test_the_expiry_list_names_the_use_outside_the_bindings():
    answer = what_expires(load_export(SAML), K, 3650)
    text = answer.to_text()
    assert answer.read_gaps == []
    assert (
        "- CERT-VS: verloopt over 20 dagen (warning) - gebonden aan LBV-WEB-01; gebruikt door SAML-actie"
        " SAML-ACTIE-01 (signing-certificaat) [vastgesteld]"
    ) in text
    assert (
        "- CERT-SG: verloopt over 10 dagen (critical) - gebonden; gebruikt door SSL-servicegroup"
        " SG-BACKEND-01 (CA: nee) [vastgesteld]"
    ) in text
    assert "- CERT-LOS: verloopt over 60 dagen (notice) - los [vastgesteld]" in text
    # Sorted on impact: every certificate in use comes before the one that is not.
    subjects = [f.subject for f in answer.findings]
    assert subjects[-1] == "CERT-LOS"
    assert [n.subject for n in answer.not_assessed] == ["gebruik buiten de appliance"]


# ---------------------------------------------------------------------------
# An export without these sources: niet vastgesteld, never "no use"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", [LAB, DOH], ids=["lab", "doh"])
def test_an_export_without_the_sources_says_niet_vastgesteld_never_no_use(fixture):
    export = load_export(fixture)
    answer = what_breaks(export, K, "ns-sftrust-certificate")
    reasons = {n.subject: n.reason for n in answer.not_assessed}
    for subject, reason in ABSENT_REASONS.items():
        assert reasons[subject] == reason
    assert answer.other_uses == ()
    # "los" is the claim that nothing uses the certificate - exactly what
    # three unread sources cannot back up.
    usage = {u.certkey: u for u in usage_per_certificate(export)}
    assert usage["ns-sftrust-certificate"].state == "onbekend"
    assert usage["ns-sftrust-certificate"].reason.endswith(
        "bron config/authenticationsamlaction, config/authenticationsamlidpprofile,"
        " sslservicegroup_sslcertkey_binding.by-parent.json niet in de export"
    )
    expiry = what_expires(export, K, 3650)
    assert [n.subject for n in expiry.not_assessed] == ["gebruik buiten de appliance", *ABSENT_REASONS]
    assert "- los" not in expiry.to_text()


def test_an_export_without_the_sources_still_gets_its_advice():
    """A boundary, not a read gap: an export of an older collector keeps its
    established answer about the virtual servers, and the advice on it."""
    export = load_export(DOH)
    answer = what_breaks(export, K, "CERT-DOH-001")
    advice = what_to_do(answer, K, "CERT-DOH-001")
    assert answer.is_complete() is True, answer.read_gaps
    assert advice.findings[0].outcome.startswith("1. Vervang CERT-DOH-001")
    assert {n.subject for n in advice.not_assessed} >= set(ABSENT_REASONS)


# ---------------------------------------------------------------------------
# Fail-closed: a source that is there but not usable is a read gap
# ---------------------------------------------------------------------------


def test_a_source_the_manifest_carries_but_could_not_read_is_a_read_gap(tmp_path):
    m = _copy(tmp_path)
    _manifest(m, lambda raw: raw["resources"][SAML_ACTION].update(status="RBAC_DENIED"))
    export = load_export(m)
    answer = what_breaks(export, K, "CERT-LOS")
    assert (SAML_ACTION, "read niet bruikbaar: RBAC_DENIED") in [(g.source, g.reason) for g in answer.read_gaps]
    assert all("gevonden in deze export" not in f.outcome for f in answer.findings)
    advice = what_to_do(answer, K, "CERT-LOS")
    assert advice.findings[0].outcome == "geen wijzigingsvoorstel zolang de impact niet vaststaat"
    assert {u.certkey: u.state for u in usage_per_certificate(export)}["CERT-LOS"] == "onbekend"


def test_a_source_key_refused_at_the_export_boundary_is_a_read_gap_not_absent(tmp_path):
    m = _copy(tmp_path)

    def respell(raw):
        raw["resources"][SAML_ACTION + " "] = raw["resources"].pop(SAML_ACTION)

    _manifest(m, respell)
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert SAML_ACTION in [g.source for g in answer.read_gaps]
    assert "certificaatgebruik door SAML-acties" not in [n.subject for n in answer.not_assessed]


def test_a_certificate_field_of_the_wrong_shape_is_a_read_gap_for_every_certificate(tmp_path):
    m = _copy(tmp_path)
    _rewrite(
        m,
        "objects/authenticationsamlaction.json",
        {"authenticationsamlaction": [{"name": "SAML-ACTIE-01", "samlidpcertname": ["CERT-IDP"]}]},
    )
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert [(g.source, g.reason) for g in answer.read_gaps] == [
        (
            "config/authenticationsamlaction (SAML-actie SAML-ACTIE-01)",
            "samlidpcertname is niet bruikbaar: een waarde van het type list; niet vast te stellen welk"
            " certificaat SAML-actie SAML-ACTIE-01 hiermee gebruikt",
        )
    ]
    assert all("gevonden in deze export" not in f.outcome for f in answer.findings)
    assert {u.certkey: u.state for u in usage_per_certificate(load_export(m))}["CERT-LOS"] == "onbekend"


def test_a_saml_action_without_a_name_that_uses_the_certificate_is_a_read_gap(tmp_path):
    m = _copy(tmp_path)
    _rewrite(
        m,
        "objects/authenticationsamlaction.json",
        {"authenticationsamlaction": [{"samlidpcertname": "CERT-IDP"}, {"name": "SAML-ACTIE-01"}]},
    )
    export = load_export(m)
    answer = what_breaks(export, K, "CERT-IDP")
    assert (
        "config/authenticationsamlaction (SAML-actie op positie 1)",
        "deze SAML-actie verwijst in samlidpcertname naar CERT-IDP, maar draagt geen bruikbare naam (de"
        " sleutel ontbreekt); welke SAML-actie dat is, is niet vast te stellen",
    ) in [(g.source, g.reason) for g in answer.read_gaps]
    # The reference itself IS established: the certificate is in use.
    assert {u.certkey: u.state for u in usage_per_certificate(export)}["CERT-IDP"] == "gebonden"
    # A nameless action that names another certificate says nothing about this one.
    assert what_breaks(export, K, "CERT-LOS").is_complete() is True


def test_a_servicegroup_binding_without_a_certkeyname_is_a_read_gap(tmp_path):
    m = _copy(tmp_path)
    _rewrite(m, f"bindings/{SG_FILE}", _sg_file(_sg_parent("SG-BACKEND-01", {"servicegroupname": "SG-BACKEND-01"})))
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert (
        f"{SG_FILE} (parent SG-BACKEND-01, binding 1)",
        "certkeyname is niet bruikbaar: de sleutel ontbreekt; niet vast te stellen welk certificaat aan"
        " SSL-servicegroup SG-BACKEND-01 hangt",
    ) in [(g.source, g.reason) for g in answer.read_gaps]


def test_a_servicegroup_binding_without_a_usable_ca_flag_blocks_the_advice(tmp_path):
    m = _copy(tmp_path)
    _rewrite(
        m,
        f"bindings/{SG_FILE}",
        _sg_file(
            _sg_parent("SG-BACKEND-01", {"servicegroupname": "SG-BACKEND-01", "certkeyname": "CERT-SG"}),
            {"parentName": "SG-LEEG-01", "outcome": "EMPTY", "data": None},
        ),
    )
    answer = what_breaks(load_export(m), K, "CERT-SG")
    finding = [f for f in answer.findings if "SG-BACKEND-01" in f.outcome][0]
    assert finding.certainty is Certainty.NOT_ESTABLISHED
    assert finding.outcome == "gebonden aan SSL-servicegroup SG-BACKEND-01; rol niet vast te stellen"
    assert finding.reason == (
        "de ca-vlag ontbreekt in de binding met SSL-servicegroup SG-BACKEND-01, dus of dit certificaat daar"
        " als CA-certificaat of als eigen certificaat hangt, is niet te onderscheiden"
    )
    assert answer.other_uses == ()
    advice = what_to_do(answer, K, "CERT-SG")
    assert advice.findings[0].outcome == "geen wijzigingsvoorstel zolang de impact niet vaststaat"


def test_a_servicegroup_missing_from_the_binding_file_is_a_read_gap(tmp_path):
    """The most dangerous read error of a by-parent file: a parent that is
    simply not there. Its certificate bindings were never read."""
    m = _copy(tmp_path)
    _rewrite(
        m,
        "objects/sslservicegroup.json",
        {"sslservicegroup": [{"servicegroupname": n} for n in ("SG-BACKEND-01", "SG-LEEG-01", "SG-EXTRA-01")]},
    )
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert (
        f"{SG_FILE} (parentlijst)",
        "config/sslservicegroup kent SG-EXTRA-01, maar dit bestand draagt daarvoor geen parent-vermelding;"
        " de bindingen van SG-EXTRA-01 zijn niet gelezen en het is dus niet vast te stellen welk certificaat"
        " daaraan hangt",
    ) in [(g.source, g.reason) for g in answer.read_gaps]
    assert all("gevonden in deze export" not in f.outcome for f in answer.findings)


def test_a_servicegroup_file_whose_parent_source_is_not_collected_is_not_cross_checked(tmp_path):
    m = _copy(tmp_path)
    _manifest(m, lambda raw: raw["resources"].pop("config/sslservicegroup"))
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert (
        f"{SG_FILE} (parentlijst)",
        "de parentlijst is niet te kruiscontroleren tegen config/sslservicegroup: resource staat niet in"
        " het manifest van deze export; of elk object daar een parent-vermelding in dit bestand heeft, is"
        " daarmee niet vast te stellen",
    ) in [(g.source, g.reason) for g in answer.read_gaps]


def test_a_servicegroup_listed_twice_is_a_read_gap_not_a_silent_overwrite(tmp_path):
    m = _copy(tmp_path)
    first = _sg_parent("SG-BACKEND-01", {"servicegroupname": "SG-BACKEND-01", "certkeyname": "CERT-SG", "ca": False})
    second = _sg_parent("SG-BACKEND-01", {"servicegroupname": "SG-BACKEND-01", "certkeyname": "CERT-SG-CA", "ca": True})
    _rewrite(m, f"bindings/{SG_FILE}", _sg_file(first, second, {"parentName": "SG-LEEG-01", "outcome": "EMPTY"}))
    answer = what_breaks(load_export(m), K, "CERT-SG")
    assert (
        SG_FILE,
        "niet elke binding in dit bestand is aan een eigen parent-vermelding toe te wijzen (een dubbele of"
        " naamloze parent); niet vast te stellen aan welke SSL-servicegroup elk certificaat hangt",
    ) in [(g.source, g.reason) for g in answer.read_gaps]


def test_a_binding_row_that_names_another_servicegroup_than_its_parent_is_a_read_gap(tmp_path):
    m = _copy(tmp_path)
    _rewrite(
        m,
        f"bindings/{SG_FILE}",
        _sg_file(
            _sg_parent("SG-BACKEND-01", {"servicegroupname": "SG-ANDERS-01", "certkeyname": "CERT-SG", "ca": False}),
            {"parentName": "SG-LEEG-01", "outcome": "EMPTY"},
        ),
    )
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    assert (
        f"{SG_FILE} (parent SG-BACKEND-01, binding 1)",
        "de binding onder SSL-servicegroup SG-BACKEND-01 noemt in servicegroupname een andere servicegroup;"
        " niet vast te stellen aan welke SSL-servicegroup dit certificaat hangt",
    ) in [(g.source, g.reason) for g in answer.read_gaps]


# ---------------------------------------------------------------------------
# rapport_dekking: the three sources, read or not in the export
# ---------------------------------------------------------------------------


def _coverage_lines(fixture) -> dict[str, tuple[str, Certainty, str]]:
    answer = coverage_answer(load_export(fixture), K)
    sources = (SAML_ACTION, SAML_IDP, SG_FILE)
    return {f.subject: (f.outcome, f.certainty, f.reason) for f in answer.findings if f.subject in sources}


def test_the_coverage_report_shows_the_three_sources_as_read():
    assert _coverage_lines(SAML) == {
        SAML_ACTION: ("gelezen (certificaatgebruik door SAML-acties)", Certainty.ESTABLISHED, ""),
        SAML_IDP: ("gelezen (certificaatgebruik door SAML-IdP-profielen)", Certainty.ESTABLISHED, ""),
        SG_FILE: ("gelezen (certificaatgebruik door SSL-servicegroups)", Certainty.ESTABLISHED, ""),
    }
    assert "- dekking: volledig [vastgesteld]" in coverage_answer(load_export(SAML), K).to_text()


def test_the_coverage_report_shows_the_three_sources_as_absent_on_an_older_export():
    lines = _coverage_lines(LAB)
    reasons = list(ABSENT_REASONS.values())
    assert lines == {
        SAML_ACTION: ("niet in de export", Certainty.NOT_ESTABLISHED, reasons[0]),
        SAML_IDP: ("niet in de export", Certainty.NOT_ESTABLISHED, reasons[1]),
        SG_FILE: ("niet in de export", Certainty.NOT_ESTABLISHED, reasons[2]),
    }
    # A collector that did not fetch them is a boundary, not a lost read: the
    # verdict of the lab export stays what it was.
    assert "- dekking: gedeeltelijk [vastgesteld]" in coverage_answer(load_export(LAB), K).to_text()


def test_a_source_that_already_has_a_status_line_gets_no_second_line(tmp_path):
    """A SAML source the manifest carries with an unusable status already
    has its line in the tally (GEWEIGERD, MISLUKT, ...). A second line with
    the same subject would say the same thing twice."""
    m = _copy(tmp_path)
    _manifest(m, lambda raw: raw["resources"][SAML_ACTION].update(status="RBAC_DENIED"))
    findings = [f for f in coverage_answer(load_export(m), K).findings if f.subject == SAML_ACTION]
    assert [(f.outcome, f.certainty) for f in findings] == [("GEWEIGERD", Certainty.ESTABLISHED)]


# ---------------------------------------------------------------------------
# The parent source config/sslservicegroup: an appliance without SSL
# servicegroups is established, a parent source that failed is a read gap
# ---------------------------------------------------------------------------


def _doh_variant(tmp_path, servicegroups) -> Path:
    """The DoH export as a collector that fetches the four sources would
    write it for an appliance whose SAML sources are read and empty, WITHOUT
    the servicegroup binding file. `servicegroups` is the manifest state of
    config/sslservicegroup: a status word, or a list of objects (status OK,
    hash sealed)."""
    m = tmp_path / "doh"
    shutil.copytree(DOH, m)

    def change(raw):
        for resource in (SAML_ACTION, SAML_IDP):
            raw["resources"][resource] = {"status": "EMPTY"}
        if isinstance(servicegroups, str):
            raw["resources"]["config/sslservicegroup"] = {"status": servicegroups}
        else:
            raw["resources"]["config/sslservicegroup"] = {"status": "OK", "payloadSha256": "0" * 64}

    _manifest(m, change)
    if not isinstance(servicegroups, str):
        _rewrite(m, "objects/sslservicegroup.json", {"sslservicegroup": servicegroups})
    return m


@pytest.mark.parametrize("servicegroups", ["EMPTY", []], ids=["leeg", "ok-zonder-objecten"])
def test_an_appliance_without_ssl_servicegroups_is_established_and_can_be_los(tmp_path, servicegroups):
    """The collector writes no binding file when there is no SSL servicegroup
    to read it for - or one without parents. Either way the parent source
    says there is none: established, not "niet in de export"."""
    export = load_export(_doh_variant(tmp_path, servicegroups))
    assert {u.certkey: u.state for u in usage_per_certificate(export)}["CERT-SPARE-001"] == "los"
    answer = what_breaks(export, K, "CERT-SPARE-001")
    assert answer.is_complete() is True, answer.read_gaps
    assert [n.subject for n in answer.not_assessed] == ["volledige certificaatketen buiten deze export"]
    assert answer.findings[-1].outcome.endswith(
        "geen gebruik door SAML-acties, SAML-IdP-profielen of SSL-servicegroups gevonden in deze export"
    )
    lines = {f.subject: (f.outcome, f.certainty) for f in coverage_answer(export, K).findings}
    assert lines[SG_FILE] == ("gelezen (certificaatgebruik door SSL-servicegroups)", Certainty.ESTABLISHED)


def test_a_parent_source_that_could_not_be_read_is_a_read_gap_not_a_boundary(tmp_path):
    export = load_export(_doh_variant(tmp_path, "RBAC_DENIED"))
    answer = what_breaks(export, K, "CERT-SPARE-001")
    assert (
        "config/sslservicegroup",
        "read niet bruikbaar: RBAC_DENIED; zonder deze parentbron is niet vast te stellen welke"
        " SSL-servicegroups er zijn, en sslservicegroup_sslcertkey_binding.by-parent.json staat niet in de"
        " export",
    ) in [(g.source, g.reason) for g in answer.read_gaps]
    assert "certificaatgebruik door SSL-servicegroups" not in [n.subject for n in answer.not_assessed]
    advice = what_to_do(answer, K, "CERT-SPARE-001")
    assert advice.findings[0].outcome == "geen wijzigingsvoorstel zolang de impact niet vaststaat"
    assert {u.certkey: u.state for u in usage_per_certificate(export)}["CERT-SPARE-001"] == "onbekend"
    lines = {f.subject: (f.outcome, f.certainty) for f in coverage_answer(export, K).findings}
    assert lines[SG_FILE] == ("niet bruikbaar gelezen", Certainty.NOT_ESTABLISHED)


def test_ssl_servicegroups_without_their_binding_file_are_a_read_gap(tmp_path):
    export = load_export(_doh_variant(tmp_path, [{"servicegroupname": "SG-A-01"}, {"servicegroupname": "SG-B-01"}]))
    answer = what_breaks(export, K, "CERT-SPARE-001")
    assert (
        SG_FILE,
        "config/sslservicegroup kent 2 SSL-servicegroup(s), maar dit bindingsbestand staat niet in de export;"
        " welke certificaten daaraan hangen, is niet gelezen",
    ) in [(g.source, g.reason) for g in answer.read_gaps]
    assert what_to_do(answer, K, "CERT-SPARE-001").findings[0].outcome == (
        "geen wijzigingsvoorstel zolang de impact niet vaststaat"
    )


def test_a_binding_file_without_parents_is_no_ssl_servicegroup(tmp_path):
    """What the collector writes when config/sslservicegroup is read and
    empty: the file with zero parents. CERT-SG, bound only to a servicegroup
    in the fixture, is then "los" - established over all four sources."""
    m = _copy(tmp_path)
    _rewrite(m, f"bindings/{SG_FILE}", _sg_file())
    _rewrite(m, "objects/sslservicegroup.json", {"sslservicegroup": []})
    export = load_export(m)
    assert {u.certkey: u.state for u in usage_per_certificate(export)}["CERT-SG"] == "los"
    answer = what_breaks(export, K, "CERT-SG")
    assert answer.is_complete() is True, answer.read_gaps
    assert answer.findings[-1].outcome.endswith("SSL-servicegroups gevonden in deze export")


def test_the_closing_statement_names_the_families_that_were_read(tmp_path):
    """Both SAML sources read, the servicegroup sources not in the export:
    the statement names the two SAML families it can back, the boundary
    names the third."""
    m = _copy(tmp_path)

    def drop(raw):
        raw["resources"].pop("config/sslservicegroup")
        raw["files"].pop(f"bindings/{SG_FILE}")

    _manifest(m, drop)
    answer = what_breaks(load_export(m), K, "CERT-LOS")
    closing = answer.findings[-1]
    assert closing.outcome == (
        "geen gebonden virtuele servers, geen gebonden SSL-diensten, geen uitgegeven certificaten en geen"
        " gebruik door SAML-acties of SAML-IdP-profielen gevonden in deze export"
    )
    assert closing.evidence.endswith(
        "; config/authenticationsamlaction en config/authenticationsamlidpprofile: gelezen en gecontroleerd,"
        " geen verwijzing naar deze naam"
    )
    assert "certificaatgebruik door SSL-servicegroups" in [n.subject for n in answer.not_assessed]


# ---------------------------------------------------------------------------
# Openheid: every new name that can reach an answer is in a name family
# ---------------------------------------------------------------------------


_REAL_NAMES = (
    "SAML-ACTIE-01",
    "SAML-ACTIE-02",
    "SAML-IDP-01",
    "SG-BACKEND-01",
    "SG-LEEG-01",
    "LBV-WEB-01",
    "CERT-VS",
    "CERT-IDP",
    "CERT-SP",
    "CERT-SG",
    "CERT-SG-CA",
    "CERT-LOS",
)


def test_the_cert_usage_family_collects_the_saml_and_servicegroup_names():
    from nsmcp.cert_usage import names_in_cert_usage_sources

    export = load_export(SAML)
    family = set(names_in_cert_usage_sources(export))
    assert {"SAML-ACTIE-01", "SAML-ACTIE-02", "SAML-IDP-01", "SG-BACKEND-01", "SG-LEEG-01"} <= family
    assert set(_REAL_NAMES) <= set(names_from_export(export))
    # Nothing it cannot trust, and nothing from an export that does not carry the sources.
    assert names_in_cert_usage_sources(load_export(LAB)) == ()


def test_the_family_reads_nothing_from_a_source_whose_hash_does_not_match(tmp_path):
    from nsmcp.cert_usage import names_in_cert_usage_sources

    m = _copy(tmp_path)
    (m / "objects" / "authenticationsamlaction.json").write_text(
        json.dumps({"authenticationsamlaction": [{"name": "SAML-VERVALST"}]}), encoding="utf-8"
    )
    assert "SAML-VERVALST" not in names_in_cert_usage_sources(load_export(m))


def test_no_real_name_reaches_a_limited_answer_of_the_certificate_tools(tmp_path):
    export = load_export(SAML)
    answers = {"certificaat_wat_verloopt_er": (what_expires(export, K, 3650), None)}
    for certname in ("CERT-VS", "CERT-IDP", "CERT-SP", "CERT-SG", "CERT-SG-CA", "CERT-LOS"):
        impact = what_breaks(export, K, certname)
        answers[f"certificaat_wat_breekt_er {certname}"] = (impact, certname)
        answers[f"certificaat_wat_moet_ik_doen {certname}"] = (what_to_do(impact, K, certname), certname)
    answers["rapport_dekking"] = (coverage_answer(export, K), None)
    for label, (answer, certname) in answers.items():
        tool = label.split(" ")[0]
        full = render(answer, Disclosure.FULL, tool=tool, extra_names=names_from_export(export), caller_name=certname)
        limited = render(
            answer,
            Disclosure.LIMITED,
            tool=tool,
            extra_names=names_from_export(export),
            caller_name=certname,
            pseudonym_table_path=tmp_path / "tabel.json",
        )
        shown = [n for n in _REAL_NAMES if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", full)]
        assert shown or tool == "rapport_dekking", f"{label}: zonder echte namen bij volledig bewijst dit niets"
        leaked = [n for n in _REAL_NAMES if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", limited)]
        assert leaked == [], f"{label} lekt bij beperkt: {leaked}"


def test_the_limited_copy_pseudonymizes_the_other_uses_field(tmp_path):
    from nsmcp.disclosure import _limit

    impact = what_breaks(load_export(SAML), K, "CERT-IDP")
    copy = _limit(impact, (), tmp_path / "tabel.json")
    assert copy.other_uses, "the limited copy lost the other-uses field"
    assert all(u.owner.startswith("object-") for u in copy.other_uses)


# ---------------------------------------------------------------------------
# The proposal of certificaat_vervangen: the old certificate's other uses
# ---------------------------------------------------------------------------

WRITE_DIENST = "LBV-WEB-01"
WRITE_NIEUWCERT = "CERT-NIEUW"
USED_ELSEWHERE_LINE = (
    "- CERT-VS: dit certificaat is ook elders in gebruik: SAML-actie SAML-ACTIE-01 (signing-certificaat);"
    " die gebruiken raakt deze vervanging niet, neem ze zelf mee [vastgesteld]"
)


def _bind_target(export_dir: Path, target: str) -> None:
    """The scan file a scan of this server writes next to the manifest: the
    target it scanned, bound to THIS manifest by its hash."""
    digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"{target}\n{digest}\n", encoding="utf-8")


def _write_server(tmp_path: Path, export_dir: Path, disclosure=Disclosure.FULL, target: str | None = "lab"):
    """A real server that offers the writing tools on `export_dir`, with the
    write script replaced by the spy of the write-path tests and the code
    channel by theirs - the only place a test can read what the operator
    was shown. The export describes `target` (the allowlist section of the
    write is "lab"); None leaves the export without a recorded target."""
    from conftest import _knowledge_file, maintenance_config, record_collected
    from test_handelen_zonder_code import CodeSpy, Spy

    from nsmcp.handelen import Allowlist
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    tmp_path.mkdir(parents=True, exist_ok=True)
    provenance = tmp_path / "config" / "herkomst"
    if target is not None:
        _bind_target(export_dir, target)
        # ... and the provenance record that same scan leaves, outside the export.
        record_collected(export_dir, target, provenance)
    script = tmp_path / "schrijf.ps1"
    script.write_text("# spy", encoding="utf-8")
    spy, presenter = Spy(), CodeSpy()
    server = build_server(
        export_dir,
        _knowledge_file(tmp_path),
        disclosure=disclosure,
        action_script=script,
        fixture_dir=tmp_path,
        action_run=spy,
        code_presenter=presenter,
        allowlist=Allowlist(
            per_target={"lab": {"certificaat_vervangen": {"dienst": (WRITE_DIENST,), "nieuwcert": (WRITE_NIEUWCERT,)}}}
        ),
        pseudonym_table_path=tmp_path / "tabel.json",
        onderhoud=maintenance_config(tmp_path),
        provenance_dir=provenance,
    )
    return server, spy, presenter


def _propose(server, bevestiging: str = "") -> str:
    import asyncio

    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    arguments = {"dienst": WRITE_DIENST, "nieuwcert": WRITE_NIEUWCERT}
    if bevestiging:
        arguments["bevestiging"] = bevestiging

    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("certificaat_vervangen", arguments)

    result = asyncio.run(go())
    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    return text + " " + json.dumps(result.structuredContent or {})


def test_the_proposal_names_the_old_certificates_other_uses(tmp_path):
    """LBV-WEB-01 carries CERT-VS, and SAML-ACTIE-01 signs with CERT-VS: a
    replacement on the virtual server leaves that action on the old
    certificate. The proposal says so, the model's copy and the operator's
    copy alike."""
    server, spy, presenter = _write_server(tmp_path, _copy(tmp_path))
    text = _propose(server)
    assert USED_ELSEWHERE_LINE in text, text
    assert "    bewijs: de export, gelezen zoals certificaat_wat_breekt_er: CERT-VS hangt aan LBV-WEB-01" in text
    assert "gebruik buiten de binding niet vastgesteld" not in text
    [shown] = presenter.calls
    assert USED_ELSEWHERE_LINE in shown["proposal_text"]
    # Only the answer moved: one preview, with the script arguments of before.
    [call] = spy.calls
    assert call[call.index("-Actie") :] == [
        "-Actie",
        "replace-cert",
        "-VirtueleServer",
        WRITE_DIENST,
        "-NieuwCert",
        WRITE_NIEUWCERT,
        "-Bundel",
        call[call.index("-Bundel") + 1],
        "-WatIs",
    ]
    assert shown["arguments"] == {"dienst": WRITE_DIENST, "nieuwcert": WRITE_NIEUWCERT}


def test_the_proposal_adds_nothing_when_the_old_certificate_has_no_other_use(tmp_path):
    m = _copy(tmp_path)
    binding = json.loads((m / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").read_text(encoding="utf-8"))
    binding["parents"][0]["data"]["sslvserver_sslcertkey_binding"][0]["certkeyname"] = "CERT-LOS"
    _rewrite(m, "bindings/sslvserver_sslcertkey_binding.by-parent.json", binding)
    server, _spy, presenter = _write_server(tmp_path, m)
    text = _propose(server)
    assert "elders in gebruik" not in text and "gebruik buiten de binding" not in text, text
    assert "elders in gebruik" not in presenter.calls[0]["proposal_text"]


def test_the_proposal_says_niet_vastgesteld_when_a_source_is_not_in_the_export(tmp_path):
    m = _copy(tmp_path)

    def drop(raw):
        raw["resources"].pop(SAML_ACTION)
        raw["resources"].pop(SAML_IDP)

    _manifest(m, drop)
    server, _spy, _presenter = _write_server(tmp_path, m)
    text = _propose(server)
    assert (
        "- CERT-VS: gebruik buiten de binding niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: de export, gelezen zoals certificaat_wat_breekt_er: CERT-VS hangt aan LBV-WEB-01\n"
        "    reden: zie certificaat_wat_breekt_er voor dit certificaat; niet gelezen of niet vast te stellen:"
        " certificaatgebruik door SAML-acties, certificaatgebruik door SAML-IdP-profielen"
    ) in text, text
    assert "elders in gebruik" not in text


def test_the_proposal_says_niet_vastgesteld_when_the_export_names_no_certificate_on_the_vserver(tmp_path):
    m = _copy(tmp_path)
    _rewrite(
        m,
        "bindings/sslvserver_sslcertkey_binding.by-parent.json",
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [{"parentName": "LBV-WEB-01", "outcome": "EMPTY", "data": None}],
        },
    )
    server, _spy, _presenter = _write_server(tmp_path, m)
    text = _propose(server)
    assert ("- te vervangen certificaat: gebruik buiten de binding niet vastgesteld [niet vastgesteld]") in text, text
    assert "reden: de export noemt geen certificaat aan LBV-WEB-01" in text, text


@pytest.mark.parametrize(
    ("disclosure", "reason"),
    [
        (
            Disclosure.FULL,
            "de export van deze server beschrijft een ander doel (ander-doel); ververs eerst met status_ververs",
        ),
        (Disclosure.LIMITED, "de export van deze server beschrijft een ander doel; ververs eerst met status_ververs"),
    ],
    ids=["volledig", "beperkt"],
)
def test_the_proposal_never_states_a_use_read_from_the_export_of_another_target(tmp_path, disclosure, reason):
    """ONE export per server: a write on "lab" while the export describes
    "ander-doel" must not warn about - or stay silent about - the
    certificate of that other appliance. The same comparison as a reading
    tool with a `doel` makes."""
    server, _spy, presenter = _write_server(tmp_path, _copy(tmp_path), disclosure, target="ander-doel")
    text = _propose(server)
    assert (
        "- te vervangen certificaat: gebruik buiten de binding niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: scan-doel.txt van de export tegenover het doel van deze handeling\n"
        f"    reden: {reason}"
    ) in text, text
    assert "elders in gebruik" not in text
    assert "elders in gebruik" not in presenter.calls[0]["proposal_text"]


def test_the_proposal_never_states_a_use_read_from_an_export_without_a_recorded_target(tmp_path):
    server, _spy, _presenter = _write_server(tmp_path, _copy(tmp_path), target=None)
    text = _propose(server)
    assert (
        "- te vervangen certificaat: gebruik buiten de binding niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: scan-doel.txt van de export tegenover het doel van deze handeling\n"
        "    reden: de export van deze server zegt niet welk doel hij beschrijft; ververs eerst met status_ververs"
    ) in text, text
    assert "elders in gebruik" not in text


def test_after_a_write_without_a_new_scan_the_proposal_does_not_state_the_old_binding(tmp_path):
    """After a replacement on LBV-WEB-01 the export still says CERT-VS hangs
    there - the certificate that would come off now is the new one. Until a
    new scan the line says what this server itself did since."""
    server, spy, presenter = _write_server(tmp_path, _copy(tmp_path))
    assert USED_ELSEWHERE_LINE in _propose(server)
    _propose(server, bevestiging=presenter.calls[0]["code"])
    assert sum(1 for call in spy.calls if "-WatIs" not in call) == 1, "premisse: de schrijfactie liep"
    text = _propose(server)
    assert "elders in gebruik" not in text, text
    assert (
        "- te vervangen certificaat: gebruik buiten de binding niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: de export tegenover de handelingen van deze server sinds de laatste scan\n"
        "    reden: sinds die scan is 1 handeling uitgevoerd - ververs voor een betrouwbare leescontrole"
    ) in text, text


def test_a_refused_saml_key_keeps_its_own_coverage_line(tmp_path):
    """A key refused at the export boundary gets its tally line under its
    SHAPE, not under the source name: without its own line the SAML source
    would vanish from the three lines this report promises."""
    m = _copy(tmp_path)

    def respell(raw):
        raw["resources"][SAML_ACTION + " "] = raw["resources"].pop(SAML_ACTION)

    _manifest(m, respell)
    findings = [f for f in coverage_answer(load_export(m), K).findings if f.subject == SAML_ACTION]
    assert [(f.outcome, f.certainty) for f in findings] == [("niet bruikbaar gelezen", Certainty.NOT_ESTABLISHED)]
