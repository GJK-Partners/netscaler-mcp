"""The 29 hidden rules, measured on the real lab export.

Vocabulary correction versus the plan (corrections A-2 and D-4 of the
independent review of this file): the confidence word for `medium` is
`gemiddeld`, never `beperkt` -
spec 2.1.1 pins exactly four rungs (`hoog` / `gemiddeld` / `laag` /
`niet vastgesteld`) and `beperkt` is only ever an INPUT spelling NSHC itself
uses for the same rung in one place.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from conftest import seal_manifest

from nsmcp.answer import stamp_data
from nsmcp.export import load_export
from nsmcp.hidden_rules import CATALOG, RULE_WORDS, evaluate, hidden_rules_answer
from nsmcp.knowledge import Knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 8, 26)
_KNOWLEDGE = Knowledge(version="verstopttest", date="2026-08-26", age_days=0, missing=False)

HIT_ON_THE_REAL_EXPORT = (
    "NSHC-HR-HA-002",
    "NSHC-HR-MGMT-001",
    "NSHC-HR-MGMT-002",
    "NSHC-HR-MGMT-003",
    "NSHC-HR-GLOB-001",
    "NSHC-HR-LOG-001",
    "NSHC-HR-SSL-005",
)
CLEAN_ON_THE_REAL_EXPORT = (
    "NSHC-HR-HA-001",
    "NSHC-HR-HA-003",
    "NSHC-HR-HA-005",
    "NSHC-HR-MGMT-004",
    "NSHC-HR-SSL-001",
    "NSHC-HR-SSL-002",
    "NSHC-HR-SSL-003",
    "NSHC-HR-SSL-004",
    "NSHC-HR-RBAC-001",
    "NSHC-HR-AAA-003",
    "NSHC-HR-CS-001",
    "NSHC-HR-CS-002",
    "NSHC-HR-LB-001",
    "NSHC-HR-LB-003",
    "NSHC-HR-SVC-001",
    "NSHC-HR-SVC-002",
    "NSHC-HR-AAA-001",
    "NSHC-HR-LOG-002",
    "NSHC-HR-RW-001",
    "NSHC-HR-RSP-001",
)
# The two rules that read `config/lbmonitor`. They stood `niet geraakt` on
# this branch and stand `niet beoordeeld` on the merged tree, and that is the
# TRUTH about this export, not a regression:
#
# MEASURED on tests/fixtures/lab-export-vpx-20260826/export-manifest.json -
# the real collector's own output, unedited. `config/lbmonitor` is the ONE
# resource in that manifest that stands `status: OK` with a real object file
# (31 objects, objects/lbmonitor.json, 79601 bytes) while its
# `payloadSha256` is the EMPTY string. Every other OK resource in the same
# manifest carries a real digest; the six other empty-hash rows are EMPTY or
# NOT_SUPPORTED and have no object file to read at all.
#
# Since the hash gate (`Export._object_payload`: "geen hash in het manifest;
# geen hash is geen vertrouwen") a source without a hash is a read gap, so
# these two rules can no longer be answered from this export. Inventing a
# hash here would mean this test sealed a file the collector never vouched
# for - the exact opposite of what the gate is for. The honest pin is
# therefore 7 geraakt / 20 niet geraakt / 2 niet beoordeeld, and the missing
# digest is written up as open COLLECTOR work, not as a reader defect.
NOT_ASSESSED_ON_THE_REAL_EXPORT = (
    "NSHC-HR-MON-001",
    "NSHC-HR-MON-002",
)


def test_the_catalog_has_twenty_nine_rules_with_unique_ids():
    ids = [rule.id for rule in CATALOG]
    assert len(ids) == 29
    assert len(set(ids)) == 29


def test_the_catalog_has_sixteen_high_and_thirteen_medium_severities():
    """Measured on the catalog itself: 16 hoog / 13 midden / 0 laag, not the
    14/15 an older draft of the severity table stated."""
    severities = [rule.severity for rule in CATALOG]
    assert severities.count("high") == 16
    assert severities.count("medium") == 13
    assert severities.count("low") == 0


def test_the_catalog_needs_twenty_two_config_resources_and_one_binding_file():
    """Measured correction on the plan: 22 unique config/ resources, not 21,
    plus exactly 1 binding file (sslvserver_sslcertkey_binding), not 2 -
    service_binding.by-parent.json does not exist on the real export."""
    from nsmcp.hidden_rules import BINDING_CERTKEY

    config_resources = {r for rule in CATALOG for r in rule.requires if r.startswith("config/")}
    binding_resources = {r for rule in CATALOG for r in rule.requires if r.endswith(".by-parent.json")}
    assert len(config_resources) == 22
    assert binding_resources == {BINDING_CERTKEY}


def test_every_rule_gets_exactly_one_of_the_three_words_on_the_real_export():
    words = evaluate(load_export(FIXTURE))
    assert set(words) == {rule.id for rule in CATALOG}
    for rule_id, outcome in words.items():
        assert outcome.word in RULE_WORDS, f"{rule_id} kreeg {outcome.word!r}"


def test_the_measured_hits_on_the_real_export():
    words = evaluate(load_export(FIXTURE))
    for rule_id in HIT_ON_THE_REAL_EXPORT:
        assert words[rule_id].word == "geraakt", f"{rule_id} hoorde geraakt te zijn"
    for rule_id in CLEAN_ON_THE_REAL_EXPORT:
        assert words[rule_id].word == "niet geraakt", f"{rule_id} hoorde niet geraakt te zijn"
    for rule_id in NOT_ASSESSED_ON_THE_REAL_EXPORT:
        assert words[rule_id].word == "niet beoordeeld", (
            f"{rule_id} leest config/lbmonitor, en die bron draagt in deze export geen hash"
        )
    # The counts the answer states, pinned as a whole so a rule that silently
    # changes camp is caught even when both tuples still add up.
    counts = {word: sum(1 for o in words.values() if o.word == word) for word in RULE_WORDS}
    assert counts == {"geraakt": 7, "niet geraakt": 20, "niet beoordeeld": 2}, counts


def test_only_the_hashless_source_is_unassessable_on_the_real_export():
    """21 of the catalog's 22 config sources stand OK or EMPTY in this
    manifest WITH a hash, and the one binding file is readable, so a 'niet
    beoordeeld' on any of those would mean the read layer broke - not that
    the appliance is unclear.

    The twenty-second, `config/lbmonitor`, is the exception this export
    really carries: `status: OK`, 31 objects, and an EMPTY `payloadSha256`
    written by the collector itself. The hash gate refuses it, so exactly the
    two rules that read it - and no others - come out 'niet beoordeeld'. This
    test is the fail-closed half: any THIRD unassessed rule is a defect.
    """
    words = evaluate(load_export(FIXTURE))
    unassessed = sorted(k for k, v in words.items() if v.word == "niet beoordeeld")
    assert unassessed == sorted(NOT_ASSESSED_ON_THE_REAL_EXPORT)


def test_the_answer_names_the_instances_and_the_why_sentence():
    export = load_export(FIXTURE)
    text = stamp_data(hidden_rules_answer(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()

    assert "Vraag: wat zit hier verstopt dat niemand ziet" in text
    assert "- NSHC-HR-MGMT-001: geraakt [vastgesteld]" in text
    assert (
        "    bewijs: config/nsip: 192.0.2.6 (SNIP): gui=ENABLED, ssh=ENABLED; "
        "198.51.100.5 (SNIP): gui=ENABLED, ssh=ENABLED; "
        "192.0.2.3 (SNIP): gui=ENABLED, ssh=ENABLED"
    ) in text
    assert "Wanneer GUI of SSH op een SNIP/VIP (data-plane) is aangezet" in text
    # Corrected vocabulary (spec 2.1.1): `gemiddeld`, not the plan's `beperkt`.
    assert "[ernst: hoog, zekerheid: gemiddeld]" in text
    assert "- NSHC-HR-MGMT-004: niet geraakt [vastgesteld]" in text
    assert "- verstopte regels: 29 regels - " in text


def test_the_answer_carries_its_own_ruleset_version(tmp_path):
    """MEASURED: the hidden-rules catalogue IS a
    ruleset (vendored, SHA-anchored in rulesets.VENDORED_ANCHORS, carries
    its own rulesetVersion/rulesetDate) but printed none - the Global
    Constraint "de regelsetversie staat in elk antwoord dat uit een
    regelset volgt" was broken while beveiliging_tls_baseline, reading the
    SAME kind of vendored source, already honoured it. Root cause:
    rulesets.py defined exactly one Ruleset (SSL_BASELINE) and
    hidden_rules.py never imported this module at all."""
    from nsmcp.rulesets import HIDDEN_RULES

    export = load_export(FIXTURE)
    text = stamp_data(hidden_rules_answer(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()

    assert "- regelset: nshc-hidden-rules 1.0.1 [vastgesteld]" in text
    assert "    bewijs: Regelset nshc-hidden-rules 1.0.1 (2026-09-06)." in text
    # Premise: this is really the SAME ruleset the vendored anchor names,
    # not a second, independently-typed literal.
    assert HIDDEN_RULES.name == "nshc-hidden-rules"


def test_every_ruleset_prints_its_version_somewhere():
    """The rule behind this fix: 'a gate, not a second literal' -
    so a THIRD ruleset-derived tool that forgets this cannot silently ship.
    Discovers every `Ruleset` object `rulesets.py` actually DEFINES (module
    introspection, not a hand-typed list of names) and requires each one to
    be registered below with the answer that must print its
    `ruleset_line()`; an unregistered `Ruleset` fails LOUD here, not
    silently in production."""
    import nsmcp.rulesets as rulesets_module
    from nsmcp.rulesets import Ruleset, ruleset_line
    from nsmcp.scorecard import scorecard_answer
    from nsmcp.tls_baseline import tls_baseline

    discovered = {name: value for name, value in vars(rulesets_module).items() if isinstance(value, Ruleset)}
    assert discovered, "premisse faalt: rulesets.py definieert geen Ruleset meer"

    export = load_export(FIXTURE)
    # One rendered answer per Ruleset this product actually consumes today.
    # Extend this dict when a new Ruleset is added; never remove a name from
    # it while its Ruleset still exists - the assertion below is exactly
    # what catches that omission.
    consumers = {
        "SSL_BASELINE": tls_baseline(export, _KNOWLEDGE).to_text(),
        "HIDDEN_RULES": hidden_rules_answer(export, _KNOWLEDGE).to_text(),
        "IPREP_BASELINE": scorecard_answer(export, _KNOWLEDGE).to_text(),
    }
    missing = set(discovered) - set(consumers)
    assert not missing, f"Ruleset zonder geregistreerde consument in deze test: {missing}"
    for name, ruleset in discovered.items():
        assert ruleset_line(ruleset) in consumers[name], (
            f"{name}: de regelsetregel staat niet in het antwoord dat er bewust uit volgt"
        )


def test_a_missing_source_is_niet_beoordeeld_and_never_silently_skipped(tmp_path):
    """Issue #7, the requires test: a rule whose source is missing is
    'niet beoordeeld' and appears in the answer. Silence would read as
    'not hit'."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z","resources":{},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    words = evaluate(load_export(export_dir))
    assert {v.word for v in words.values()} == {"niet beoordeeld"}
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = hidden_rules_answer(load_export(export_dir), _KNOWLEDGE).to_text()
    assert "- NSHC-HR-HA-001: niet beoordeeld [niet vastgesteld]" in text


def test_a_positive_and_a_negative_fixture_for_a_single_field_rule(tmp_path):
    """The shape NSHC uses too: one field, two fixtures, opposite outcomes."""

    def _with(strongpassword: str):
        export_dir = tmp_path / f"export-{strongpassword}"
        (export_dir / "objects").mkdir(parents=True)
        (export_dir / "objects" / "systemparameter.json").write_text(
            json.dumps({"systemparameter": {"strongpassword": strongpassword, "timeout": 900}}),
            encoding="utf-8",
        )
        (export_dir / "export-manifest.json").write_text(
            '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
            '"resources":{"config/systemparameter":{"status":"OK"}},"files":{}}',
            encoding="utf-8",
        )
        seal_manifest(export_dir)
        return evaluate(load_export(export_dir))["NSHC-HR-MGMT-002"].word

    assert _with("disabled") == "geraakt"
    assert _with("ENABLED") == "niet geraakt"


def test_a_management_address_is_masked_at_beperkt(tmp_path):
    """Step 9's requires test on the real export: hardening point 5. A name
    this tool prints (an nsip SNIP address) must be collected by
    `names_in_hidden_rule_sources` so the disclosure seam can replace it -
    first the PREMISE (the address really is in the full answer), then the
    actual gate (it is really gone at 'beperkt', and the rule ID - not a
    name - stays)."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export = load_export(FIXTURE)
    answer = hidden_rules_answer(export, _KNOWLEDGE)
    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "192.0.2.6" in full, "zonder het echte adres in het volledige antwoord bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "192.0.2.6" not in limited
    assert "198.51.100.5" not in limited
    assert "NSHC-HR-MGMT-001" in limited, "een regel-ID is geen objectnaam en hoort te blijven staan"


def test_a_synthetic_malicious_snip_name_is_masked_too(tmp_path):
    """Hardening evidence, NOT on the real export: a synthetic export whose
    SNIP address is an adversarial-looking value (it embeds the shape of a
    path and of another object's name) proves the tenth family collects
    whatever a rule can print, not just the three addresses measured on the
    real fixture. Premise first (it really reaches the FULL answer), then
    the gate (it is really gone at 'beperkt')."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    hostile = "../../etc/passwd-QQQ_DEMO"
    (export_dir / "objects" / "nsip.json").write_text(
        json.dumps({"nsip": [{"ipaddress": hostile, "type": "SNIP", "gui": "ENABLED", "ssh": "ENABLED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/nsip": {"status": "OK"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert hostile in full, "zonder de waarde in het volledige antwoord bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol-beperkt.json",
    )
    assert hostile not in limited
    assert "NSHC-HR-MGMT-001" in limited


def test_an_unrecognized_confidence_word_becomes_niet_vastgesteld_not_a_favorable_word():
    """Hardening point 6: a `.get(x, "<gunstig woord>")` default on an
    unrecognized confidence rung is a defect - unknown is a read gap, never a
    silent, more positive word. Proven by calling the module's own
    confidence-word gate directly, the one place this decision is made."""
    from nsmcp.hidden_rules import CONFIDENCE_WORDS, _confidence_word

    assert CONFIDENCE_WORDS == {
        "high": "hoog",
        "medium": "gemiddeld",
        "beperkt": "gemiddeld",
        "low": "laag",
        "none": "niet vastgesteld",
    }
    assert _confidence_word("high") == "hoog"
    assert _confidence_word("medium") == "gemiddeld"
    assert _confidence_word("beperkt") == "gemiddeld"
    assert _confidence_word("low") == "laag"
    assert _confidence_word("none") == "niet vastgesteld"
    # The gate: an unrecognized rung must land on the LEAST favorable word,
    # not a "beperkt"/"gemiddeld" default that reads as an actual assessment.
    assert _confidence_word("onbekende-waarde") == "niet vastgesteld"
    assert _confidence_word("") == "niet vastgesteld"


# ---------------------------------------------------------------------------
# Every test
# below would FAIL against the code as it stood before this hardening pass; each
# test names in its own docstring what turns RED without its fix.
# ---------------------------------------------------------------------------


def _manifest(resources: dict, files: dict | None = None) -> str:
    return json.dumps(
        {
            "manifestVersion": "1.1",
            "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
            "resources": resources,
            "files": files or {},
        }
    )


# --- C1: four classes of name/address that only ever live in a hit's
# EVIDENCE, never in `hit.instance` - each proven premise-first (the value
# really is in `volledig`), then gate (it is really gone at `beperkt`).


def test_ssl005_bound_profile_name_reaches_evidence_and_is_masked(tmp_path):
    """SSL-005 is structurally uncollectable via config/sslprofile alone in
    THIS shape: the profile name sits in the evidence string next to the
    vserver instance, not as a second object of its own."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": "VS_TLS13", "sslprofile": "CUSTOM_PROFILE_QQQ_DEMO"}]}),
        encoding="utf-8",
    )
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps({"sslprofile": [{"name": "CUSTOM_PROFILE_QQQ_DEMO", "tls13": "DISABLED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslvserver": {"status": "OK"}, "config/sslprofile": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "CUSTOM_PROFILE_QQQ_DEMO" in full, "zonder de profielnaam in volledig bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "CUSTOM_PROFILE_QQQ_DEMO" not in limited
    assert "NSHC-HR-SSL-005" in limited


def test_rw001_action_name_reaches_evidence_and_is_masked(tmp_path):
    """RW-001 fires PRECISELY because the action name is NOT in
    config/rewriteaction - it can never be collected from that source, only
    from the hit's own evidence."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "rewritepolicy.json").write_text(
        json.dumps(
            {
                "rewritepolicy": [
                    {"name": "POL_DANGLING", "isdefault": False, "action": "ACT_MISSING_QQQ_DEMO", "undefhits": "0"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "rewriteaction.json").write_text(
        json.dumps({"rewriteaction": [{"name": "ACT_UNRELATED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/rewritepolicy": {"status": "OK"}, "config/rewriteaction": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "ACT_MISSING_QQQ_DEMO" in full

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "ACT_MISSING_QQQ_DEMO" not in limited
    assert "NSHC-HR-RW-001" in limited


def test_log002_destination_address_reaches_evidence_and_is_masked(tmp_path):
    """LOG-002's syslog destination address lives only in this evidence - no
    other of the ten disclosure families reads config/auditsyslogaction's
    serverip."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "auditsyslogaction.json").write_text(
        json.dumps(
            {
                "auditsyslogaction": [
                    {"name": "SYSLOG_EXT", "serverip": "198.51.100.77", "serverport": "514", "transport": "UDP"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/auditsyslogaction": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "198.51.100.77" in full

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "198.51.100.77" not in limited
    assert "NSHC-HR-LOG-002" in limited


def test_ssl001_certkeyname_reaches_evidence_and_is_masked(tmp_path):
    """SSL-001's evidence names the CERTKEY bound to the vserver - a SECOND
    name next to the instance (the vserver name itself)."""
    import hashlib

    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "bindings").mkdir(parents=True)
    by_parent = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {
                "parentName": "VS_MGMT",
                "outcome": "OK",
                "data": {
                    "sslvserver_sslcertkey_binding": [
                        {"vservername": "VS_MGMT", "certkeyname": "ns-server-certificate-LAB-AAA"}
                    ]
                },
            }
        ],
    }
    raw = json.dumps(by_parent)
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    file_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    (export_dir / "export-manifest.json").write_text(
        _manifest({}, {"bindings/sslvserver_sslcertkey_binding.by-parent.json": file_hash}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "ns-server-certificate-LAB-AAA" in full

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "ns-server-certificate-LAB-AAA" not in limited
    assert "NSHC-HR-SSL-001" in limited


# --- C2: a not-assessable object must not vanish when the same rule ALSO
# has a real hit.


def test_a_blocked_hit_survives_alongside_a_real_hit_on_the_same_rule(tmp_path):
    """Measured scenario: one vserver with tls13=DISABLED
    (a real hit) plus one bound to a profile that was never read (a blocked,
    not-assessable hit) on the SAME rule. Both must show, with the NSHC
    sentence and a per-object ReadGap - not a silent 'geraakt' that drops
    the unresolved object."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps(
            {
                "sslvserver": [
                    {"vservername": "VS_HIT", "tls13": "DISABLED"},
                    {"vservername": "VS_ONBEKEND", "sslprofile": "PROFIEL_NIET_GELEZEN"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps({"sslprofile": []}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslvserver": {"status": "OK"}, "config/sslprofile": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-SSL-005"]
    assert outcome.word == "geraakt", "een echte hit moet de regel nog steeds doen vuren"

    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert "VS_HIT: tls13=DISABLED" in text
    assert "Let op: 1 object(en) konden niet worden beoordeeld en tellen NIET mee als in orde." in text, (
        "de NSHC-zin mag niet ontbreken zodra er ook een echte hit is"
    )
    assert "- NSHC-HR-SSL-005: VS_ONBEKEND: TLS 1.3 niet vastgesteld" in text, (
        "elk niet-vastgesteld object hoort een EIGEN leesgat te krijgen, geen verzamelgat"
    )


# --- C3: the isdefault/builtin guards must be alive on the REAL data
# shapes (JSON bool, JSON list) - not a stringified stand-in.


def test_field_token_reads_bool_and_list_like_powershell_would():
    from nsmcp.ssl_precedence import field_token

    assert field_token({"isdefault": True}, "isdefault") == "True"
    assert field_token({"isdefault": False}, "isdefault") == "False"
    assert field_token({"builtin": ["IMMUTABLE"]}, "builtin") == "IMMUTABLE"
    assert field_token({"builtin": ["IMMUTABLE", "MODIFIABLE"]}, "builtin") == "IMMUTABLE MODIFIABLE"
    assert field_token({"other": "x"}, "isdefault") == ""


def test_rw001_a_real_bool_isdefault_true_is_correctly_skipped(tmp_path):
    """Measured on the real fixture: isdefault is a JSON BOOL. Before the
    fix, field_text() == "" for a bool, so isdefault=True never skipped and
    a default policy pointing at a missing action was a FALSE POSITIVE
    'geraakt' where NSHC gives PASS."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "rewritepolicy.json").write_text(
        json.dumps({"rewritepolicy": [{"name": "POL_DEFAULT", "isdefault": True, "action": "ACT_DOES_NOT_EXIST"}]}),
        encoding="utf-8",
    )
    (export_dir / "objects" / "rewriteaction.json").write_text(
        json.dumps({"rewriteaction": [{"name": "ACT_UNRELATED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/rewritepolicy": {"status": "OK"}, "config/rewriteaction": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    outcome = evaluate(load_export(export_dir))["NSHC-HR-RW-001"]
    assert outcome.word == "niet geraakt", "isdefault=True (bool) moet overgeslagen worden, zoals NSHC"


def test_rsp001_a_real_list_builtin_is_correctly_skipped(tmp_path):
    """Measured on the real fixture: builtin is a JSON LIST (['IMMUTABLE']).
    Before the fix, field_text() == "" for a list, so the IMMUTABLE guard
    never skipped - action=RESET on rule='true' proves it, since the real
    fixture's builtins all happen to have action=NOOP and would pass either
    way."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "responderpolicy.json").write_text(
        json.dumps(
            {
                "responderpolicy": [
                    {"name": "POL_BUILTIN_RESET", "builtin": ["IMMUTABLE"], "action": "RESET", "rule": "true"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/responderpolicy": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    outcome = evaluate(load_export(export_dir))["NSHC-HR-RSP-001"]
    assert outcome.word == "niet geraakt", "builtin=['IMMUTABLE'] moet overgeslagen worden, zoals NSHC"


# --- The printed confidence must be the WEAKEST across all real hits,
# never the first row's.


def test_weakest_confidence_wins_regardless_of_row_order(tmp_path):
    def _text(rows, tag):
        export_dir = tmp_path / f"export-{tag}"
        (export_dir / "objects").mkdir(parents=True)
        (export_dir / "objects" / "nsip.json").write_text(json.dumps({"nsip": rows}), encoding="utf-8")
        (export_dir / "export-manifest.json").write_text(
            _manifest({"config/nsip": {"status": "OK"}}),
            encoding="utf-8",
        )
        seal_manifest(export_dir)
        return hidden_rules_answer(load_export(export_dir), _KNOWLEDGE).to_text()

    high_row = {"ipaddress": "10.1.1.1", "type": "SNIP", "mgmtaccess": "ENABLED", "telnet": "ENABLED"}
    medium_row = {"ipaddress": "10.1.1.2", "type": "SNIP", "mgmtaccess": "DISABLED", "telnet": "ENABLED"}

    text_high_first = _text([high_row, medium_row], "high-first")
    text_medium_first = _text([medium_row, high_row], "medium-first")

    for text in (text_high_first, text_medium_first):
        assert "NSHC-HR-MGMT-003: geraakt" in text
        assert "zekerheid: gemiddeld]" in text, "de zwakste zekerheid moet winnen, ongeacht de rijvolgorde"
        assert "zekerheid: hoog]" not in text


# --- EMPTY on any required source of a MULTI-source rule must skip the
# detect entirely, not just filter its output afterwards.


def test_an_empty_source_on_a_multi_source_rule_skips_the_detect(tmp_path):
    """config/rewritepolicy OK with a policy pointing at a nonexistent
    action, config/rewriteaction EMPTY: NSHC gives SKIPPED (-> 'niet
    geraakt' here) and never runs the detect. Invisible on the real fixture
    because RW-001 has two OK sources there."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "rewritepolicy.json").write_text(
        json.dumps({"rewritepolicy": [{"name": "POL_WOULD_FIRE", "isdefault": False, "action": "ACT_DOES_NOT_EXIST"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest(
            {
                "config/rewritepolicy": {"status": "OK"},
                "config/rewriteaction": {"status": "EMPTY"},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    outcome = evaluate(load_export(export_dir))["NSHC-HR-RW-001"]
    assert outcome.word == "niet geraakt"
    assert outcome.hits == (), "de detect mag niet gedraaid zijn - geen hit, ook geen geblokkeerde"
    assert "manifest: EMPTY (NSHC: SKIPPED)" in outcome.evidence


# --- SSL-004 confidence must be 'high', matching NSHC (severity stays
# 'medium' - a different axis).


def test_ssl004_confidence_is_high_matching_nshc(tmp_path):
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "CERT_AAA", "expirymonitor": "DISABLED", "daystoexpiration": 30, "status": "Valid"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslcertkey": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    text = hidden_rules_answer(load_export(export_dir), _KNOWLEDGE).to_text()
    assert "- NSHC-HR-SSL-004: geraakt [vastgesteld]" in text
    assert "[ernst: midden, zekerheid: hoog]" in text
    # daystoexpiration is a JSON INT here (30, not
    # "30") - field_text() returns "" for any non-string, so this used to
    # print "daystoexpiration=?" for every hit, including this one where
    # the value WAS read successfully.
    assert "daystoexpiration=30" in text
    assert "daystoexpiration=?" not in text


# --- SSL-003 must never treat an unreadable ssl3/tls1/tls11 field as
# the PASSING (DISABLED) word - the one guard in this module whose
# unreadable case used to be the good outcome.


def test_ssl003_an_unreadable_protocol_field_is_niet_beoordeeld_not_disabled(tmp_path):
    """MEASURED: `_is(field_text(r, f) or "DISABLED",
    "ENABLED")` collapsed a bool/number/absent-key `ssl3` field to "" via
    `field_text`, and the `or "DISABLED"` then silently supplied the
    PASSING value - NSHC-HR-SSL-003 never fired and left no trace. A JSON
    bool reproduces the class `field_token`'s own docstring measures on
    this exact resource family (`isdefault`/`builtin`)."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps(
            {
                "sslprofile": [
                    {
                        "name": "CUSTOM_FRONTEND",
                        "sslprofiletype": "FRONTEND",
                        "ssl3": True,
                        "tls1": "DISABLED",
                        "tls11": "DISABLED",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslprofile": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-003"]
    # PREMISE: the detect really ran and really produced exactly this one
    # not-assessable hit - not a source-level read gap or a silent pass.
    assert len(outcome.hits) == 1, outcome
    assert outcome.hits[0].not_assessable is True
    assert outcome.word == "niet beoordeeld"
    assert "CUSTOM_FRONTEND" in outcome.reason
    assert "ssl3" in outcome.reason
    assert "niet gelezen als ENABLED/DISABLED" in outcome.reason


# --- CS-002 must never echo the raw supplied policy expression, at ANY
# disclosure level (it is untrusted export input the masking seam cannot
# reach - hardening rule 1).


def test_cs002_never_echoes_the_raw_policy_expression(tmp_path):
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    hostile = 'HTTP.REQ.HOSTNAME.CONTAINS("intern.geheim.example.nl")'
    (export_dir / "objects" / "cspolicy.json").write_text(
        json.dumps({"cspolicy": [{"policyname": "POL_CS_AAA", "rule": hostile}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/cspolicy": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)
    assert "NSHC-HR-CS-002: geraakt" in answer.to_text(), "premisse: de regel moet echt vuren"

    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_verstopte_regels",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "intern.geheim.example.nl" not in full, "de ruwe expressie mag op GEEN enkel niveau doorkomen"
    assert "POL_CS_AAA" in full


def test_log001_leaks_supplied_address_to_beperkt_disclosure(tmp_path):
    """LOG-001 echoes the supplied serverip into its evidence
    OUTSIDE the masking seam. The prefix guard is `ip.startswith("127.")` which
    accepts "127.0.0.1 ZZMARK_SYSIP". Without the names= parameter in the Hit,
    the marker reaches beperkt verbatim.

    PREMISE: marker appears in full answer.
    GATE: marker is absent at beperkt and minimaal levels.
    """
    from nsmcp.disclosure import Disclosure, names_from_export, render

    # Create export with LOG-001 marker
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)

    import hashlib
    import json

    syslog_file = {
        "errorcode": 0,
        "message": "Done",
        "severity": "NONE",
        "auditsyslogparams": {
            "serverip": "127.0.0.1 ZZMARK_SYSIP",
            "serverport": 514,
        },
    }
    file_path = export_dir / "objects" / "auditsyslogparams.json"
    file_path.write_text(json.dumps(syslog_file), encoding="utf-8")
    file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
        "resources": {"config/auditsyslogparams": {"status": "OK"}},
        "files": {"objects/auditsyslogparams.json": file_hash},
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)

    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    # PREMISE: marker is in full answer
    full = render(
        answer,
        Disclosure.FULL,
        tool="test_log001",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-full.json",
    )
    assert "ZZMARK_SYSIP" in full, "Premise failed: marker not in full answer"
    assert "NSHC-HR-LOG-001" in full, "LOG-001 must hit"

    # GATE: marker absent at beperkt
    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="test_log001",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-limited.json",
    )
    assert "ZZMARK_SYSIP" not in limited, "Finding 1: marker leaked to beperkt disclosure"
    assert "NSHC-HR-LOG-001" in limited, "rule ID must stay at beperkt"

    # GATE: marker absent at minimaal
    minimal = render(
        answer,
        Disclosure.MINIMAL,
        tool="test_log001",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-minimal.json",
    )
    assert "ZZMARK_SYSIP" not in minimal, "Finding 1: marker leaked to minimaal disclosure"


def test_log002_echoes_raw_uninterpretable_transport_value(tmp_path):
    """LOG-002's not-assessable branch hides uninterpretable
    transport values without echoing them raw. For empty or unrecognized values,
    it uses either shape_of() or "heeft niet de vorm van" statement.

    Global Constraint: An unreadable value is named by its SHAPE, never by
    its raw value. PREMISE: LOG-002 fires (not-assessable). GATE: the
    evidence does not contain the raw value.
    """
    from nsmcp.disclosure import Disclosure, names_from_export, render

    # Create export with LOG-002 uninterpretable transport
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)

    import hashlib

    # auditsyslogaction is a list resource with NITRO wrapper
    actions_file = {
        "errorcode": 0,
        "message": "Done",
        "severity": "NONE",
        "auditsyslogaction": [
            {
                "name": "test-action",
                "serverip": "192.0.2.1",
                "serverport": "514",
                "transport": "UNRECOGNIZED_VALUE",  # Unrecognizable value
            }
        ],
    }
    file_path = export_dir / "objects" / "auditsyslogaction.json"
    file_path.write_text(json.dumps(actions_file), encoding="utf-8")
    file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
        "resources": {"config/auditsyslogaction": {"status": "OK"}},
        "files": {"objects/auditsyslogaction.json": file_hash},
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)

    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    # PREMISE: LOG-002 fires with not-assessable status
    full = render(
        answer,
        Disclosure.FULL,
        tool="test_log002",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-full.json",
    )
    assert "NSHC-HR-LOG-002" in full, "LOG-002 must hit (not-assessable)"
    # The evidence should NOT contain the raw unrecognized value
    assert "UNRECOGNIZED_VALUE" not in full, "Premise: unrecognized transport value should not appear in evidence"
    # But it should describe the unrecognized value (either via shape or "heeft niet de vorm van")
    assert (
        "een lege of alleen-witruimte tekstwaarde" in full
        or "waarde van het type" in full
        or "heeft niet de vorm van" in full
    ), "Premise: description of unrecognized value must appear in evidence"

    # GATE: at beperkt, the description is still there, no raw value leaks
    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="test_log002",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-limited.json",
    )
    assert "UNRECOGNIZED_VALUE" not in limited, (
        "Finding 2: raw uninterpretable value must not leak to beperkt disclosure"
    )
    assert "NSHC-HR-LOG-002" in limited, "rule ID must stay at beperkt"
    assert (
        "een lege of alleen-witruimte tekstwaarde" in limited
        or "waarde van het type" in limited
        or "heeft niet de vorm van" in limited
    ), "Description of unrecognized value should remain at beperkt, protecting the raw value"


def test_log002_unrecognized_transport_not_empty_statement(tmp_path):
    """Finding: LOG-002's not-assessable branch should not claim unrecognized
    transport values are empty when they are not.

    PREMISE: transport has a non-empty unrecognized value like "SCTP".
    GATE: the evidence must NOT contain the false claim "een lege of
    alleen-witruimte tekstwaarde"; must contain "heeft niet de vorm van" instead.
    """
    from nsmcp.disclosure import Disclosure, names_from_export, render

    # Create export with non-empty unrecognized transport value
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)

    import hashlib

    actions_file = {
        "errorcode": 0,
        "message": "Done",
        "severity": "NONE",
        "auditsyslogaction": [
            {
                "name": "test-action",
                "serverip": "192.0.2.1",
                "serverport": "514",
                "transport": "SCTP_UNIQUE_MARKER_9821",  # Non-empty unrecognized value
            }
        ],
    }
    file_path = export_dir / "objects" / "auditsyslogaction.json"
    file_path.write_text(json.dumps(actions_file), encoding="utf-8")
    file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
        "resources": {"config/auditsyslogaction": {"status": "OK"}},
        "files": {"objects/auditsyslogaction.json": file_hash},
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)

    export = load_export(export_dir)
    answer = hidden_rules_answer(export, _KNOWLEDGE)

    # PREMISE: LOG-002 fires with not-assessable status
    full = render(
        answer,
        Disclosure.FULL,
        tool="test_log002_unrecognized",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-full.json",
    )
    assert "NSHC-HR-LOG-002" in full, "LOG-002 must hit (not-assessable)"
    # GATE 1: must NOT leak the marker value
    assert "SCTP_UNIQUE_MARKER_9821" not in full, "Finding: unrecognized transport marker leaked to full disclosure"
    # GATE 2: must NOT contain the false empty-value claim
    assert "een lege of alleen-witruimte tekstwaarde" not in full, (
        "Finding: false empty-value claim appeared in full disclosure for non-empty value"
    )
    # GATE 3: must contain the proper "heeft niet de vorm van" statement
    assert "heeft niet de vorm van" in full, (
        "Finding: expected 'heeft niet de vorm van' statement missing in full disclosure"
    )

    # GATE: at beperkt, shape is still there, no raw value leaks
    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="test_log002_unrecognized",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-limited.json",
    )
    assert "SCTP_UNIQUE_MARKER_9821" not in limited, (
        "Finding: unrecognized transport marker leaked to limited disclosure"
    )
    assert "NSHC-HR-LOG-002" in limited, "rule ID must stay at limited"
    # At limited, the proper statement should still be there
    assert "heeft niet de vorm van" in limited, (
        "Finding: 'heeft niet de vorm van' statement missing at limited disclosure"
    )


def test_log002_raw_field_shape_determination(tmp_path):
    """LOG-002's absent/null/non-text branch must distinguish
    "key is absent" from "key carries JSON null". The _shape_or_missing helper
    uses the _MISSING sentinel to distinguish these two cases. This test verifies
    that each of the six transport value shapes renders its own correct phrase.

    PREMISE: transport field carries six different shapes; each absence means
    LOG-002 fires (not-assessable) with a unique shape sentence.
    GATE: each of the six cases produces the CORRECT observable shape sentence
    in the rendered answer, not a tautologically assigned constant.
    """
    import re

    from nsmcp.disclosure import Disclosure, names_from_export, render

    # Define the six test cases: (transport_value, case_id, expected_shape_phrase, skip_transport_key)
    # skip_transport_key=True means the key is not in the dict at all (absent key case)
    test_cases = [
        # (transport_value, case_id, expected_shape_phrase, skip_key)
        (None, "json_null", "een lege waarde (JSON null)", False),  # JSON null
        (123, "int_number", "een waarde van het type int", False),  # number
        (True, "boolean", "een waarde van het type bool", False),  # boolean
        (["UDP"], "list_type", "een waarde van het type list", False),  # list
        ("", "empty_string", "een lege of alleen-witruimte tekstwaarde", False),  # empty string
        (None, "absent_key", "de sleutel ontbreekt", True),  # absent key
    ]

    shape_results = {}  # Track the shapes actually rendered

    for transport_value, case_id, expected_phrase, skip_key in test_cases:
        export_dir = tmp_path / f"export_{case_id}"
        (export_dir / "objects").mkdir(parents=True)

        import hashlib

        # Build the action object; skip transport key if requested
        action = {
            "name": f"action-{case_id}",
            "serverip": "192.0.2.1",
            "serverport": "514",
        }
        if not skip_key:
            action["transport"] = transport_value

        actions_file = {"errorcode": 0, "message": "Done", "severity": "NONE", "auditsyslogaction": [action]}
        file_path = export_dir / "objects" / "auditsyslogaction.json"
        file_path.write_text(json.dumps(actions_file), encoding="utf-8")
        file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

        manifest = {
            "manifestVersion": "1.1",
            "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
            "resources": {"config/auditsyslogaction": {"status": "OK"}},
            "files": {"objects/auditsyslogaction.json": file_hash},
        }
        (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        seal_manifest(export_dir)

        export = load_export(export_dir)
        answer = hidden_rules_answer(export, _KNOWLEDGE)

        # Render at full disclosure to check the evidence
        full = render(
            answer,
            Disclosure.FULL,
            tool="test_log002_shapes",
            extra_names=names_from_export(export),
            pseudonym_table_path=export_dir / "tabel-full.json",
        )

        # GATE 1: LOG-002 must hit (not-assessable)
        assert "NSHC-HR-LOG-002" in full, f"LOG-002 must hit for transport={transport_value} (case: {case_id})"

        # GATE 2: Extract the actual shape phrase from the rendered answer.
        # Look for the pattern "gelezen waarde: <phrase>" in the evidence.
        match = re.search(r"gelezen waarde: ([^;]+);", full)
        assert match, f"Could not find 'gelezen waarde: <phrase>' in evidence for case {case_id}. Full output:\n{full}"
        rendered_phrase = match.group(1).strip()

        # GATE 3: Verify the rendered phrase is what we expect for this shape.
        assert rendered_phrase == expected_phrase, (
            f"Case {case_id}: expected '{expected_phrase}' but got '{rendered_phrase}'. Full output:\n{full}"
        )

        # Record the shape for later verification that they are distinct.
        shape_results[case_id] = rendered_phrase

    # GATE 4: Verify we got DIFFERENT phrases for absent_key vs json_null.
    # This is the critical assertion: it will fail if the bug is re-introduced
    # (i.e., if both cases are made to produce the same phrase).
    assert shape_results["json_null"] == "een lege waarde (JSON null)", "JSON null must produce JSON null shape phrase"
    assert shape_results["absent_key"] == "de sleutel ontbreekt", "absent key must produce absent key shape phrase"
    assert shape_results["json_null"] != shape_results["absent_key"], (
        "JSON null and absent key MUST render different phrases"
    )

    # GATE 5: Verify all other shapes rendered their expected phrases.
    assert shape_results["int_number"] == "een waarde van het type int", "int number must produce int type shape"
    assert shape_results["boolean"] == "een waarde van het type bool", "boolean must produce bool type shape"
    assert shape_results["list_type"] == "een waarde van het type list", "list must produce list type shape"
    assert shape_results["empty_string"] == "een lege of alleen-witruimte tekstwaarde", (
        "empty string must produce empty/whitespace shape"
    )

    # GATE 6: No raw value should reach volledig, beperkt or minimaal exposure levels.
    # These are coverage levels, not shape phrases, so they should not appear
    # in the evidence text alongside the shape phrase.
    for case_id, rendered_phrase in shape_results.items():
        assert rendered_phrase not in ("volledig", "beperkt", "minimaal"), (
            f"Case {case_id}: shape phrase '{rendered_phrase}' is a coverage level, not a shape"
        )


# ---------------------------------------------------------------------------
# Dode guards op niet-string JSON. ONE table-driven test over the
# WHOLE catalog, derived from the source itself (AST), not hand-typed - a
# thirtieth rule or a new field read by an existing rule fails this LOUDLY
# (test_field_inventory_matches_every_field_the_catalog_actually_reads)
# rather than passing silently.
# ---------------------------------------------------------------------------


# Every helper in hidden_rules.py that reads a field BY NAME. Kept honest by
# `test_every_field_reading_helper_is_in_the_extractor_set` below, which
# derives the same set from the module's own source instead of trusting this
# list.
_FIELD_READ_HELPERS = (
    "field_text",
    "field_token",
    "_num",
    "_raw_field",
    "_shape_or_missing",
    "_gate",
    "_vocab",
    "_num_gate",
    "_num_text",
    "_enum_text",
)

# The helpers that route a read through the shared three-way gate. `_vocab`
# IS `_gate` (it calls it and then completes the closed-vocabulary half);
# `test_vocab_delegates_to_the_shared_gate` proves that rather than assuming
# it, so a `_vocab`-read field counts as gate-routed for the invariant below.
_GATE_ROUTED_HELPERS = ("_gate", "_vocab")


def _scan_field_reads(tree, detect_names: set[str]):
    """The AST walk itself, factored out so it can be exercised directly
    (see `test_field_extractor_fails_loud_on_an_unclassifiable_field_argument`)
    without needing a real module to parse. Returns (calls, unrecognized).

    A field-read call whose argument this
    walker cannot classify - not a string literal, not a loop variable bound
    (in an enclosing `for` in the SAME function) to a tuple/list of string
    literals - used to just VANISH from `calls`, the same escape class as
    an earlier fix for the HELPER-name side of this, not the
    ARGUMENT side. `unrecognized` collects those sites as (function,
    helper) pairs, restricted to `detect_names` - the CATALOG detect
    functions FIELD_INVENTORY actually needs to cover. An INTERNAL helper
    like `_gate`/`_vocab` forwarding its OWN `field` parameter hits this
    same "unclassifiable" shape by construction and must NOT be flagged:
    that forwarding is not a completeness gap, so it is excluded by
    `detect_names` on purpose rather than by guessing at parameter names."""
    import ast

    calls: set[tuple[str, str, str]] = set()
    unrecognized: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        func_name = node.name
        loopvars: dict[str, list[str]] = {}
        for sub in ast.walk(node):
            if isinstance(sub, ast.For) and isinstance(sub.target, ast.Name):
                it = sub.iter
                if isinstance(it, (ast.Tuple, ast.List)) and all(isinstance(e, ast.Constant) for e in it.elts):
                    loopvars[sub.target.id] = [e.value for e in it.elts]
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                helper = sub.func.id
                if helper not in _FIELD_READ_HELPERS:
                    continue
                if len(sub.args) < 2:
                    continue
                arg = sub.args[1]
                if isinstance(arg, ast.Constant):
                    calls.add((func_name, helper, arg.value))
                elif isinstance(arg, ast.Name) and arg.id in loopvars:
                    for value in loopvars[arg.id]:
                        calls.add((func_name, helper, value))
                elif func_name in detect_names:
                    unrecognized.add((func_name, helper))
    return calls, unrecognized


def _extract_field_reads_from_source() -> set[tuple[str, str, str]]:
    """(detect-function, helper, field) triples the module's source ACTUALLY
    contains today - ground truth, not a transcription. Walks every
    top-level function body for a call to one of `_FIELD_READ_HELPERS`
    whose field argument is either a string literal, or a loop variable
    bound (in an enclosing `for` in the SAME function) to a tuple/list of
    string literals - the shape `_ssl003`'s `for f in ("ssl3", "tls1",
    "tls11")` uses. Every helper that can READ a field by name belongs in
    that set: a site that starts reaching for a field through a NEW helper
    must not disappear from this inventory just because the set was never
    widened (`_shape_or_missing` was exactly that hole,
    harmless on the day it was found and still the wrong shape of gate).

    The walk itself now FAILS LOUD (see
    `_scan_field_reads`) instead of silently skipping a field-read call in
    a CATALOG detect function whose argument it cannot classify."""
    import ast
    import inspect

    import nsmcp.hidden_rules as hr

    source = inspect.getsource(hr)
    tree = ast.parse(source)
    detect_names = {rule.detect.__name__ for rule in CATALOG}
    calls, unrecognized = _scan_field_reads(tree, detect_names)
    assert not unrecognized, (
        "field-read call(s) in a CATALOG detect function with an argument this "
        "extractor cannot classify as a literal or a literal-tuple loop variable, "
        f"so it cannot be inventoried: {sorted(unrecognized)} - name the field "
        "with a literal, or teach the extractor this shape explicitly "
        "(Minor 4, review 3 of task-2b-0b)"
    )
    return calls


def test_field_extractor_fails_loud_on_an_unclassifiable_field_argument():
    """PREMISE - a synthetic CATALOG-style
    detect function calls `field_text` with a COMPUTED (non-literal) field
    name. GATE: `_scan_field_reads` reports the site in `unrecognized`
    rather than silently dropping it from `calls`."""
    import ast

    src = (
        "def _synthetic_detect(ctx):\n"
        '    field_name = "computed_" + "field"\n'
        '    for r in ctx.rows("x"):\n'
        "        value = field_text(r, field_name)\n"
        "    return []\n"
    )
    tree = ast.parse(src)
    calls, unrecognized = _scan_field_reads(tree, {"_synthetic_detect"})
    assert ("_synthetic_detect", "field_text") in unrecognized, (
        "premisse faalt: een niet-letterlijk veldargument in een detect-functie"
        " moet gemeld worden, niet stil verdwijnen"
    )
    assert not calls, "bij een onherkenbaar argument mag er geen veldlezing geregistreerd worden"


def test_field_extractor_ignores_a_non_detect_helpers_own_forwarded_parameter():
    """The other half of the same premise: an INTERNAL helper (not a
    CATALOG detect function) forwarding its own `field` parameter - exactly
    what `_gate`/`_vocab`/etc. do for real - hits the identical
    "unclassifiable argument" shape and must NOT be flagged: that
    forwarding is not a completeness gap, only a detect function's own
    field-read is."""
    import ast

    src = "def _internal_helper(row, field):\n    return field_text(row, field)\n"
    tree = ast.parse(src)
    calls, unrecognized = _scan_field_reads(tree, {"_synthetic_detect"})
    assert not unrecognized, "een interne helper die zijn EIGEN parameter doorgeeft is geen gat"
    assert not calls


# FIELD_INVENTORY: every (detect-function, helper, field) triple the module
# reads to evaluate CATALOG - the measured inventory this module
# requires. The value is a (ROLE, reason)
# pair: `reason` records WHY that helper is the right one (see hidden_rules.py's
# own comments at each site), and `role` is the CLASSIFICATION every derived
# gate below keys on.
#
# The six-shape sweep used to derive its scope from
# `helper == "_gate"`, i.e. from the FIX. A field that was a closed-vocabulary
# gate but had NOT been routed through the shared helper then fell out of the
# sweep silently - which is exactly what happened to `_ssl004`'s expirymonitor
# and `_ssl003`'s ssl3/tls1/tls11. `role` says what the field IS,
# not how it is currently read, so the sweep now covers every gate and
# `test_every_gate_role_field_is_routed_through_the_shared_gate` fails LOUD for
# any gate that leaves the shared helper without a documented reason.
#
# The roles:
#   gate         - a closed-vocabulary / readability gate whose value can move a
#                  verdict. Must be read through `_gate`/`_vocab` (or be listed
#                  in `_NON_GATE_ROUTED_GATES` with a MEASURED reason).
#   numeric-gate - the same, for a field that is a NUMBER: `_num_gate`, which
#                  keeps 'absent' (a documented default) apart from 'present but
#                  not a whole number' (a read gap). Its own sweep, because an
#                  int is a VALID shape here and 'niet beoordeeld' is not.
#   presence     - a `_raw_field` absence check made BEFORE a gate.
#   render       - a value rendered into evidence or a label after a successful
#                  read; never gates anything on its own.
#   name         - an entity name or address (reaches the masking seam).
#   text         - free text that is never echoed.
#   shape        - a `_shape_or_missing` read that names a shape in evidence.
FIELD_INVENTORY: dict[tuple[str, str, str], tuple[str, str]] = {
    ("_ha001", "_gate", "hastatus"): (
        "gate",
        "gate: readability only - the comparison stays a substring test (NSHC parity)",
    ),
    ("_ha001", "field_text", "hastatus"): (
        "render",
        "render: the readable string, and only when it IS one of the two maintenance words (Minor J)",
    ),
    ("_ha001", "_num_text", "id"): (
        "render",
        "evidence: HA node id, a small number - _num_text, never the [string] cast (Critical B)",
    ),
    ("_ha002", "_num_text", "id"): ("render", "evidence: same as _ha001/id"),
    ("_ha002", "_gate", "syncstatusstrictmode"): ("gate", "gate: against DISABLED"),
    ("_ha002", "field_text", "syncstatusstrictmode"): ("render", "render: the matched word"),
    ("_ha003", "_gate", "haprop"): ("gate", "gate: against DISABLED"),
    ("_ha003", "field_text", "haprop"): ("render", "render: the matched word"),
    ("_ha003", "_num_text", "id"): ("render", "evidence: same as _ha001/id"),
    ("_ha005", "_gate", "failsafe"): ("gate", "gate: against OFF"),
    ("_ha005", "field_text", "failsafe"): ("render", "render: the matched word"),
    ("_ha005", "_num_text", "id"): ("render", "evidence: same as _ha001/id"),
    ("_cs001", "_gate", "stateupdate"): ("gate", "gate: against DISABLED"),
    ("_cs001", "field_text", "stateupdate"): ("render", "render: the matched word"),
    ("_cs001", "field_text", "name"): ("name", "name: always a string by the object model"),
    ("_lb001", "_raw_field", "somethod"): (
        "presence",
        "presence check BEFORE _gate: somethod is the one gated field in this module whose "
        "ABSENCE is the documented default (optional NetScaler attribute; NSHC parity reads a "
        'null soMethod as "", not a read failure) - see _gate\'s own docstring',
    ),
    ("_lb001", "_gate", "somethod"): (
        "gate",
        "gate: against NONE, only once the key is confirmed present",
    ),
    ("_lb001", "field_text", "somethod"): (
        "render",
        "render: printed only when it IS a documented spillover method (Minor J)",
    ),
    ("_lb001", "field_text", "backupvserver"): (
        "name",
        "name reference: vserver names are always strings",
    ),
    ("_lb001", "field_text", "name"): ("name", "name"),
    ("_lb003", "_gate", "sessionless"): ("gate", "gate: against ENABLED"),
    ("_lb003", "_gate", "persistencetype"): (
        "gate",
        "gate: against NONE (inverted - skip when matched)",
    ),
    ("_lb003", "field_text", "persistencetype"): (
        "render",
        "compare: the readable string, once _gate confirms it",
    ),
    ("_lb003", "_enum_text", "persistencetype"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_lb003", "_shape_or_missing", "persistencetype"): (
        "shape",
        "shape: an EMPTY persistencetype is a read gap, named by shape (Important C)",
    ),
    ("_lb003", "_enum_text", "servicetype"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_lb003", "field_text", "name"): ("name", "name"),
    ("_mgmt001", "_gate", "type"): (
        "gate",
        "gate: against NSIP - INVERTED (skip when matched), Important 3 (review of "
        "task-2b-0b): an unreadable type must never be treated as a skip. _gate, not _vocab: "
        "a readable non-NSIP string is the normal case, not a read problem",
    ),
    ("_mgmt001", "_enum_text", "type"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mgmt001", "_vocab", "gui"): (
        "gate",
        "gate: closed vocabulary ENABLED/SECUREONLY/DISABLED - MEASURED",
    ),
    ("_mgmt001", "field_text", "gui"): ("render", "render: the matched word"),
    ("_mgmt001", "_vocab", "ssh"): (
        "gate",
        "gate: closed vocabulary ENABLED/DISABLED - MEASURED",
    ),
    ("_mgmt001", "field_text", "ssh"): ("render", "render: the matched word"),
    ("_mgmt001", "field_text", "ipaddress"): ("name", "address: always a string"),
    ("_mgmt003", "_gate", "telnet"): (
        "gate",
        "gate: against ENABLED, independent fire-gate (same pattern as gui/ssh)",
    ),
    ("_mgmt003", "_gate", "ftp"): ("gate", "gate: against ENABLED, independent fire-gate"),
    ("_mgmt003", "_gate", "type"): (
        "gate",
        "gate: against NSIP, same field as _mgmt001 - here a CONFIDENCE modifier of an "
        "already-established telnet/ftp hit, not a fire-gate itself; unreadable degrades "
        "confidence to 'none' instead of blocking the real hit (see _mgmt003's own comment)",
    ),
    ("_mgmt003", "_gate", "mgmtaccess"): (
        "gate",
        "gate: against ENABLED - same confidence-modifier role as type",
    ),
    ("_mgmt003", "_enum_text", "mgmtaccess"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mgmt003", "_enum_text", "type"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mgmt003", "field_text", "ipaddress"): ("name", "address: always a string"),
    ("_rbac001", "_gate", "action"): ("gate", "gate: against ALLOW"),
    ("_rbac001", "field_text", "policyname"): ("name", "name"),
    ("_rbac001", "field_text", "cmdspec"): (
        "text",
        "text: a command-match spec, always a string, never echoed",
    ),
    ("_ssl001", "field_text", "certkeyname"): ("name", "name: certkey names are always strings"),
    ("_ssl001", "field_text", "vservername"): ("name", "name"),
    ("_cs002", "field_text", "rule"): (
        "text",
        "text: a raw policy expression, always a string, never echoed",
    ),
    ("_cs002", "field_text", "policyname"): ("name", "name"),
    ("_ssl002", "_gate", "denysslreneg"): ("gate", "gate: against NO"),
    ("_ssl002", "field_text", "denysslreneg"): ("render", "render: the matched word"),
    ("_mgmt002", "_gate", "strongpassword"): ("gate", "gate: against DISABLED"),
    ("_mgmt002", "field_text", "strongpassword"): ("render", "render: the matched word"),
    ("_mgmt004", "_num_gate", "timeout"): (
        "numeric-gate",
        "numeric gate: 0 means 'never expires'. Present-but-unreadable is a read gap; ABSENT "
        "is NetScaler's own 900-second default and stays a skip (Important C, review 2)",
    ),
    ("_aaa001", "_gate", "sectype"): ("gate", "gate: against SSL/TLS"),
    ("_aaa001", "field_text", "sectype"): ("render", "render: the matched word"),
    ("_aaa001", "_gate", "validateservercert"): (
        "gate",
        "gate: against YES (inverted) + a truthy-string presence test",
    ),
    ("_aaa001", "field_text", "validateservercert"): (
        "render",
        "compare: the readable, non-YES string",
    ),
    ("_aaa001", "_enum_text", "validateservercert"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_aaa001", "_num_text", "serverport"): (
        "render",
        "evidence: port number - _num_text, never the [string] cast (Critical B)",
    ),
    ("_aaa001", "field_text", "name"): ("name", "name"),
    ("_aaa003", "_num_gate", "maxloginattempts"): (
        "numeric-gate",
        "numeric gate: MEASURED absent on the real fixture (no lockout configured), which "
        "stays a documented skip; present-but-unreadable is a read gap (Important C, review "
        "2)",
    ),
    ("_aaa003", "_gate", "persistentloginattempts"): ("gate", "gate: against DISABLED"),
    ("_aaa003", "field_text", "persistentloginattempts"): ("render", "render: the matched word"),
    ("_svc001", "_gate", "healthmonitor"): ("gate", "gate: against NO"),
    ("_svc001", "field_text", "name"): ("name", "name"),
    ("_svc001", "_enum_text", "svrstate"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_svc001", "_enum_text", "servicetype"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_svc002", "_gate", "usip"): ("gate", "gate: against YES"),
    ("_svc002", "field_text", "servicegroupname"): ("name", "name"),
    ("_svc002", "field_text", "name"): ("name", "name (fallback)"),
    ("_svc002", "_enum_text", "servicetype"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_svc002", "_enum_text", "state"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_glob001", "_gate", "internaluserlogin"): ("gate", "gate: against ENABLED"),
    ("_glob001", "field_text", "internaluserlogin"): ("render", "render: the matched word"),
    ("_ssl003", "_gate", "sslprofiletype"): (
        "gate",
        "gate: against FRONTEND - a ROW FILTER, but the same three-way read (Critical A, "
        "review 2: the hand-written isinstance copy is gone). A readable non-FrontEnd string "
        "keeps its existing, deliberate skip; a non-string/absent value is a read gap",
    ),
    ("_ssl003", "_vocab", "ssl3"): (
        "gate",
        "gate: closed vocabulary ENABLED/DISABLED (Critical A: was field_token, which read ['ENABLED'] as the WORD)",
    ),
    ("_ssl003", "_vocab", "tls1"): ("gate", "gate: same as ssl3"),
    ("_ssl003", "_vocab", "tls11"): ("gate", "gate: same as ssl3"),
    ("_ssl003", "field_text", "name"): ("name", "name"),
    ("_log001", "field_text", "serverip"): (
        "name",
        "address: always a string, .startswith() prefix test",
    ),
    ("_log002", "field_text", "name"): ("name", "name"),
    ("_log002", "field_text", "serverip"): ("name", "address: always a string"),
    ("_log002", "_num", "serverport"): (
        "render",
        "evidence: port number - _num, never the [string] cast (Critical B)",
    ),
    ("_log002", "_gate", "transport"): (
        "gate",
        "gate: against TCP/UDP/HTTP. The two refusal SENTENCES are pinned byte-for-byte by "
        "three dedicated tests and stay as they were; the READ goes through the shared gate "
        "so the field sits inside the derived sweep instead of beside it (Critical A, review "
        "2)",
    ),
    ("_log002", "field_text", "transport"): (
        "render",
        "render/compare: the readable string, once _gate confirms it",
    ),
    ("_log002", "_shape_or_missing", "transport"): (
        "shape",
        "shape: the pinned 'gelezen waarde: <vorm>' sentence",
    ),
    ("_rw001", "field_token", "isdefault"): (
        "gate",
        "gate: _is() against TRUE - MEASURED a JSON BOOL on every one of the 71 real "
        "rewritepolicy rows, so a non-string is this field's NORMAL shape and _gate would "
        "call the whole resource unreadable. See _NON_GATE_ROUTED_GATES",
    ),
    ("_rw001", "_num_text", "undefhits"): (
        "render",
        "evidence: hit count - _num_text, never the [string] cast (Critical B)",
    ),
    ("_rw001", "field_text", "action"): (
        "name",
        "name reference: rewrite-action names are always strings",
    ),
    ("_rw001", "field_text", "name"): ("name", "name"),
    ("_rsp001", "field_token", "builtin"): (
        "gate",
        "gate: substring test - MEASURED a JSON LIST on 6 of 7 real responderpolicy rows and "
        "ABSENT on the seventh (the documented 'not a built-in policy' state), so BOTH shapes "
        "_gate would refuse are this field's normal ones. See _NON_GATE_ROUTED_GATES",
    ),
    ("_rsp001", "_gate", "action"): ("gate", "gate: against RESET/DROP"),
    ("_rsp001", "field_text", "action"): ("render", "render: the matched word"),
    ("_rsp001", "field_text", "rule"): ("text", "text: a raw policy expression, always a string"),
    ("_rsp001", "field_text", "name"): ("name", "name"),
    ("_ssl004", "_vocab", "expirymonitor"): (
        "gate",
        "gate: closed vocabulary ENABLED/DISABLED - MEASURED. Critical A "
        "(review 2): was field_token, which read ['ENABLED'] as the WORD and passed silently",
    ),
    ("_ssl004", "_num_text", "daystoexpiration"): (
        "render",
        "evidence: day count - _num_text, never the [string] cast (Critical B)",
    ),
    ("_ssl004", "field_text", "certkey"): ("name", "name"),
    ("_ssl004", "_enum_text", "status"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mon001", "_gate", "units3"): (
        "gate",
        "gate: readability only - the comparison is against units4, not a word",
    ),
    ("_mon001", "_gate", "units4"): (
        "gate",
        "gate: readability only - the comparison is against units3, not a word",
    ),
    ("_mon001", "field_text", "units3"): (
        "render",
        "render/compare: the readable string, once _gate confirms it",
    ),
    ("_mon001", "field_text", "units4"): (
        "render",
        "render/compare: the readable string, once _gate confirms it",
    ),
    ("_mon001", "_shape_or_missing", "units3"): (
        "shape",
        "shape: an EMPTY unit is a read gap, never a silent 'SEC' (Important C)",
    ),
    ("_mon001", "_shape_or_missing", "units4"): ("shape", "shape: same as units3"),
    ("_mon001", "_enum_text", "type"): (
        "render",
        "evidence-only HERE (the gate lives in _mon002) - through the shape gate (Minor J)",
    ),
    ("_mon001", "field_text", "monitorname"): ("name", "name"),
    ("_mon001", "_num_gate", "interval"): (
        "numeric-gate",
        "numeric gate: present-but-unreadable is a read gap; absent stays a skip (Important C)",
    ),
    ("_mon001", "_num_gate", "resptimeout"): ("numeric-gate", "numeric gate: same as interval"),
    ("_mon002", "_gate", "type"): ("gate", "gate: against PING/ARP (inverted - skip when matched)"),
    ("_mon002", "_enum_text", "type"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mon002", "field_text", "monitorname"): ("name", "name"),
    ("_mon002", "_enum_text", "state"): (
        "render",
        "render: display-only NITRO enumeration - through the shape gate (Minor J, review 2)",
    ),
    ("_mon002", "_num_gate", "retries"): (
        "numeric-gate",
        "numeric gate: present-but-unreadable is a read gap; ABSENT is NetScaler's own "
        "default of 3 (not 0) and stays a skip (Important C, review 2)",
    ),
}


def test_field_inventory_matches_every_field_the_catalog_actually_reads():
    """The completeness gate this module needs: the table is DERIVED from the
    catalog's own source (AST), not hand-typed. A rule added tomorrow, or an
    existing detect gaining a new field_text/field_token/_num/_raw_field call,
    changes the AST-extracted set and this assertion fails LOUDLY - it does
    not pass silently just because FIELD_INVENTORY was never updated."""
    from_source = _extract_field_reads_from_source()
    from_inventory = set(FIELD_INVENTORY)
    missing_from_inventory = from_source - from_inventory
    stale_in_inventory = from_inventory - from_source
    assert not missing_from_inventory, (
        f"veld(en) gelezen door de module maar niet in FIELD_INVENTORY: {sorted(missing_from_inventory)}"
    )
    assert not stale_in_inventory, (
        f"FIELD_INVENTORY noemt veld(en) die de module niet meer leest: {sorted(stale_in_inventory)}"
    )


# NSHC-HR-SSL-005 (_ssl005) reads `tls13` exclusively through
# `ssl_precedence.resolve()`, never through a direct `field_text`/
# `field_token` call in hidden_rules.py itself - so the AST walk above finds
# no call site to attribute to it. This is a MEASURED, DELIBERATE exclusion,
# not an oversight: `resolve()` calls `field_text(row, field)` internally
# (ssl_precedence.py:132), which means tls13 is subject to the EXACT SAME
# dead-guard class this task fixes (a JSON bool/int/list `tls13` reads as
# ""), but `ssl_precedence.py` is pinned as "niet wijzigen" (one
# resolver, shared with the SSL-baseline tool, kept it
# byte-identical on purpose) - so this call site cannot be converted here.
# It is NOT silently unsafe: `resolve()`'s caller already treats an
# unreadable `tls13` (neither "ENABLED" nor "DISABLED", "" included) as
# NOT_ASSESSABLE (see `_ssl005` below), so an unrecognized shape fails
# CLOSED (niet vastgesteld), never favorably. This is the residual risk of
# leaving this one call site unconverted.
_RESOLVER_ROUTED_FUNCTIONS = {"_ssl005"}


def test_every_rule_in_the_catalog_has_at_least_one_inventoried_field():
    """A rule whose detect reads NO field at all (impossible today, but a
    thirtieth rule with an empty/typo'd detect must not pass this silently)
    is caught here: every CATALOG rule id's detect-function name must own at
    least one FIELD_INVENTORY entry, except the one function that reads its
    field exclusively through the shared, out-of-scope ssl_precedence
    resolver (see `_RESOLVER_ROUTED_FUNCTIONS` above)."""
    functions_with_entries = {key[0] for key in FIELD_INVENTORY}
    for rule in CATALOG:
        name = rule.detect.__name__
        if name in _RESOLVER_ROUTED_FUNCTIONS:
            continue
        assert name in functions_with_entries, f"{rule.id} ({name}) heeft geen enkel veld in FIELD_INVENTORY"


# --- The derived sweep. Every field FIELD_INVENTORY classifies as a `gate`
# is offered all SEVEN shapes a NITRO field can arrive in - two real strings,
# an ABSENT key, and the five unreadable shapes (null/bool/int/list/dict) -
# and the OBSERVABLE word is checked per shape. Nothing here is keyed on how
# the field happens to be READ today: a gate that
# leaves the shared helper stays in this sweep and fails in it.

_HANODE_NEUTRAL = {
    "id": "0",
    "hastatus": "UP",
    "syncstatusstrictmode": "ENABLED",
    "haprop": "ENABLED",
    "failsafe": "ON",
}

# Fields FIELD_INVENTORY classifies as `gate` but that are DELIBERATELY not
# routed through `_gate`/`_vocab`, each with the MEASUREMENT that makes the
# shared helper wrong for it and the dedicated test that covers it instead.
# `test_every_gate_role_field_is_routed_through_the_shared_gate` fails loudly
# for any gate not listed here, so this set is the only way out - and it is a
# written, reviewable decision rather than a silent absence.
_NON_GATE_ROUTED_GATES: dict[tuple[str, str], str] = {
    ("_rw001", "isdefault"): (
        "MEASURED on the real fixture: `isdefault` is a JSON BOOL on all 71 rewritepolicy "
        "rows. A non-string is this field's NORMAL shape (NSHC compares it after PowerShell's "
        "own [string] cast), so `_gate` - which calls every non-string unreadable - would turn "
        "the entire resource into a read gap and destroy the pinned fixture verdict. Covered "
        "by test_rw001_a_real_bool_isdefault_true_is_correctly_skipped and "
        "test_rw001_isdefault_keeps_reading_the_measured_bool_shape below."
    ),
    ("_rsp001", "builtin"): (
        "MEASURED on the real fixture: `builtin` is a JSON LIST (['IMMUTABLE']) on 6 of 7 "
        "responderpolicy rows and ABSENT on the seventh - and absence there is the documented "
        "'not a built-in policy' state, not a read failure. BOTH shapes `_gate` refuses are "
        "this field's normal ones. Covered by test_rsp001_a_real_list_builtin_is_correctly_"
        "skipped and test_rsp001_builtin_keeps_reading_the_measured_list_and_absent_shapes."
    ),
}

# Gates that ARE `_gate`-routed but whose blanket "a non-string is always
# niet beoordeeld" claim does not hold, so they are proven by a dedicated
# test instead of by the sweep.
_GATE_FIELD_EXCLUSIONS: dict[tuple[str, str], str] = {
    ("_mgmt003", "type"): (
        "confidence modifier, not a fire-gate: _mgmt003's telnet/ftp alone decide whether "
        "this rule fires; an unreadable type only degrades the resulting hit's confidence to "
        "'none' (niet vastgesteld) and does NOT block the already-established real hit - "
        "the blanket 'non-string always niet beoordeeld' claim this sweep makes does not hold "
        "for a field that only ever softens a confidence word. See "
        "test_mgmt003_unreadable_type_or_mgmtaccess_degrades_confidence_not_the_verdict for "
        "the dedicated proof of that coexistence instead."
    ),
    ("_mgmt003", "mgmtaccess"): "same reason as _mgmt003/type directly above - a confidence modifier, not a gate.",
}

# The one gated field whose ABSENCE is a documented default rather than a
# read gap, with the word absence must produce. Everything else absent is
# 'niet beoordeeld' (see `_gate`'s docstring for the measurement).
_ABSENT_IS_DOCUMENTED_DEFAULT: dict[tuple[str, str], tuple[str, str]] = {
    ("_lb001", "somethod"): (
        "niet geraakt",
        "spillover is an OPTIONAL NetScaler feature: no soMethod at all is the common, "
        'healthy configuration, and NSHC\'s own PowerShell reads a null soMethod as "". '
        "_lb001 checks `_raw_field(...) is _MISSING` BEFORE calling `_gate` for exactly this.",
    ),
}


def _fields_with_role(role: str) -> set[tuple[str, str]]:
    """The (function, field) pairs FIELD_INVENTORY classifies as `role`."""
    return {(fn, field) for (fn, _helper, field), (r, _why) in FIELD_INVENTORY.items() if r == role}


def _gate_routed_fields() -> set[tuple[str, str]]:
    """The (function, field) pairs actually READ through the shared gate -
    taken from the module's own SOURCE, not from FIELD_INVENTORY's helper
    column. Deriving it from the table would make the invariant below
    satisfiable by editing the table, which is the wrong half of the pair
    to trust: `role` is a decision about what the field IS, `helper` is a
    fact about the code, and facts come from the code."""
    return {(fn, field) for (fn, helper, field) in _extract_field_reads_from_source() if helper in _GATE_ROUTED_HELPERS}


def _derived_gate_field_cases() -> set[tuple[str, str]]:
    """The sweep's scope: every `gate`-role field, minus the two motivated
    exclusion sets. DERIVED from what a field IS, never from how it is read."""
    return {
        pair
        for pair in _fields_with_role("gate")
        if pair not in _GATE_FIELD_EXCLUSIONS and pair not in _NON_GATE_ROUTED_GATES
    }


def test_every_gate_role_field_is_routed_through_the_shared_gate():
    """The structural half: a field the
    inventory calls a `gate` must be READ through `_gate`/`_vocab`. Until
    this test existed, `_ssl004`'s expirymonitor and `_ssl003`'s
    ssl3/tls1/tls11 were hand-written three-way reads standing beside the
    shared helper, disagreeing with it on the LIST shape - and nothing
    failed, because the sweep derived its own scope from `helper ==
    "_gate"` and therefore could not see them. The escape hatch is
    `_NON_GATE_ROUTED_GATES`, which costs a written, measured reason."""
    routed = _gate_routed_fields()
    for pair in sorted(_fields_with_role("gate")):
        if pair in _NON_GATE_ROUTED_GATES:
            assert pair not in routed, (
                f"{pair} staat in _NON_GATE_ROUTED_GATES maar wordt WEL via de gedeelde poort"
                " gelezen - haal hem uit de uitzonderingslijst"
            )
            continue
        assert pair in routed, (
            f"{pair} is in FIELD_INVENTORY een poort maar wordt niet via {_GATE_ROUTED_HELPERS}"
            " gelezen; zet hem om of geef hem een gemeten reden in _NON_GATE_ROUTED_GATES"
        )


def test_every_gate_routed_field_is_inventoried_with_gate_role():
    """The invariant above is ONE-WAY - it
    proves every `gate`-role field is routed through `_gate`/`_vocab`, but
    not the reverse. A field genuinely read through `_gate`/`_vocab` in the
    source could be booked in FIELD_INVENTORY under a DIFFERENT role (e.g.
    `render`) and would then escape BOTH that invariant (which only
    iterates `_fields_with_role("gate")`) and the six/seven-shape sweep
    (`_derived_gate_field_cases()`, the same filter) - the identical silent
    escape one level up the derivation. This
    closes the loop from the other side: every (function, field) pair the
    source actually routes through `_gate`/`_vocab` must be booked `gate`
    in FIELD_INVENTORY."""
    for fn, field in sorted(_gate_routed_fields()):
        role = None
        for (inv_fn, inv_helper, inv_field), (inv_role, _reason) in FIELD_INVENTORY.items():
            if inv_fn == fn and inv_field == field and inv_helper in _GATE_ROUTED_HELPERS:
                role = inv_role
                break
        assert role == "gate", (
            f"{(fn, field)} wordt via {_GATE_ROUTED_HELPERS} gelezen (gate-routed) maar staat"
            f" in FIELD_INVENTORY met rol {role!r} in plaats van 'gate' - dat veld ontsnapt"
            " aan de sweep"
        )


def test_every_numeric_gate_role_field_is_routed_through_the_numeric_gate():
    """Same invariant for the numeric gates: a `numeric-gate` field must be
    read through `_num_gate`, which is the only reader that keeps ABSENT (a
    documented default) apart from PRESENT-BUT-UNREADABLE (a read gap)."""
    routed = {(fn, field) for (fn, helper, field) in FIELD_INVENTORY if helper == "_num_gate"}
    for pair in sorted(_fields_with_role("numeric-gate")):
        assert pair in routed, f"{pair} is een numerieke poort maar wordt niet via _num_gate gelezen"


def _field_reading_helpers_from_source() -> set[str]:
    """Every function in hidden_rules.py that reads a field BY NAME - the
    four primitives, plus every function that FORWARDS its own field
    parameter into one of them (transitively). Derived, so a helper added
    tomorrow appears here whether or not anybody remembered the list."""
    import ast
    import inspect

    import nsmcp.hidden_rules as hr

    tree = ast.parse(inspect.getsource(hr))
    # The primitives: they do the case-insensitive key walk themselves.
    # `field_text`/`field_token` live in ssl_precedence and are imported.
    found = {"field_text", "field_token", "_num", "_raw_field"}
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    for _ in range(len(functions)):
        grew = False
        for node in functions:
            if node.name in found:
                continue
            params = [a.arg for a in node.args.args]
            if len(params) < 2:
                continue
            field_param = params[1]
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id in found
                    and len(sub.args) >= 2
                    and isinstance(sub.args[1], ast.Name)
                    and sub.args[1].id == field_param
                ):
                    found.add(node.name)
                    grew = True
                    break
        if not grew:
            break
    return found


def test_every_field_reading_helper_is_in_the_extractor_set():
    """`_extract_field_reads_from_source` knew four
    helpers and not `_shape_or_missing`, so a field read only through THAT
    would have slipped past FIELD_INVENTORY unseen. Naming the missing
    helper fixes today; deriving the set fixes tomorrow - a new pass-through
    reader (`_vocab`, `_num_gate` and `_num_text` were added this way) shows up
    here whether or not the constant was updated."""
    derived = _field_reading_helpers_from_source()
    listed = set(_FIELD_READ_HELPERS)
    assert derived == listed, (
        f"_FIELD_READ_HELPERS loopt uit de pas met de module: mist {sorted(derived - listed)},"
        f" noemt te veel {sorted(listed - derived)}"
    )


def test_vocab_delegates_to_the_shared_gate():
    """`_vocab` counts as gate-routed in the invariant above only because it
    IS `_gate` plus the closed-vocabulary half - proven, not assumed: for a
    non-string it must return byte-identically what `_gate` returns."""
    from nsmcp.hidden_rules import _gate, _vocab

    for value in (None, True, 7, ["X"], {"k": "v"}):
        row = {"veld": value}
        _, gate_evidence = _gate(row, "veld", "ENABLED", "DISABLED")
        word, vocab_evidence = _vocab(row, "veld", "ENABLED", "DISABLED")
        assert gate_evidence is not None
        assert vocab_evidence == gate_evidence, f"vorm {type(value).__name__}"
        assert word == ""
    # And for an absent key.
    _, gate_evidence = _gate({}, "veld", "ENABLED")
    _, vocab_evidence = _vocab({}, "veld", "ENABLED")
    assert vocab_evidence == gate_evidence


# Base row (resource, a REALISTIC row with every OTHER field of that rule
# at a value that does not itself fire, filename) per (function, field)
# pair `_derived_gate_field_cases()` names - the one piece of this sweep
# that genuinely cannot be derived from the source (which value is a
# plausible NITRO row, what the sibling fields need to be for varying just
# this ONE field to mean anything). `test_base_rows_match_the_derived_gate_field_cases`
# below is the completeness gate: a mismatch in EITHER direction fails loud.
_BASE_ROWS: dict[tuple[str, str], tuple[str, dict, str]] = {
    ("_cs001", "stateupdate"): ("config/csvserver", {"name": "CS1", "stateupdate": "ENABLED"}, "csvserver"),
    ("_ha001", "hastatus"): ("config/hanode", _HANODE_NEUTRAL, "hanode"),
    ("_ha002", "syncstatusstrictmode"): ("config/hanode", _HANODE_NEUTRAL, "hanode"),
    ("_ha003", "haprop"): ("config/hanode", _HANODE_NEUTRAL, "hanode"),
    ("_ha005", "failsafe"): ("config/hanode", _HANODE_NEUTRAL, "hanode"),
    ("_lb001", "somethod"): ("config/lbvserver", {"name": "LB1", "somethod": "NONE", "backupvserver": ""}, "lbvserver"),
    ("_mgmt001", "type"): (
        "config/nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "gui": "ENABLED", "ssh": "ENABLED"},
        "nsip",
    ),
    ("_mgmt001", "gui"): (
        "config/nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "gui": "DISABLED", "ssh": "DISABLED"},
        "nsip",
    ),
    ("_mgmt001", "ssh"): (
        "config/nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "gui": "DISABLED", "ssh": "DISABLED"},
        "nsip",
    ),
    ("_mgmt003", "telnet"): (
        "config/nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "telnet": "DISABLED", "ftp": "DISABLED", "mgmtaccess": "DISABLED"},
        "nsip",
    ),
    ("_mgmt003", "ftp"): (
        "config/nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "telnet": "DISABLED", "ftp": "DISABLED", "mgmtaccess": "DISABLED"},
        "nsip",
    ),
    ("_rbac001", "action"): (
        "config/systemcmdpolicy",
        {"policyname": "custom_shell", "action": "DENY", "cmdspec": "show shell"},
        "systemcmdpolicy",
    ),
    ("_ssl002", "denysslreneg"): ("config/sslparameter", {"denysslreneg": "YES"}, "sslparameter"),
    ("_mgmt002", "strongpassword"): (
        "config/systemparameter",
        {"strongpassword": "ENABLED", "timeout": 900},
        "systemparameter",
    ),
    # sectype/validateservercert: the SIBLING field is set to the value that
    # lets the varied one decide the verdict on its own (a
    # base row on which the field cannot flip the word proves nothing).
    ("_aaa001", "sectype"): (
        "config/authenticationldapaction",
        {"name": "LDAP1", "sectype": "PLAINTEXT", "validateservercert": "NO", "serverport": 636},
        "authenticationldapaction",
    ),
    ("_aaa001", "validateservercert"): (
        "config/authenticationldapaction",
        {"name": "LDAP1", "sectype": "SSL", "validateservercert": "YES", "serverport": 636},
        "authenticationldapaction",
    ),
    ("_aaa003", "persistentloginattempts"): (
        "config/aaaparameter",
        {"maxloginattempts": 3, "persistentloginattempts": "ENABLED"},
        "aaaparameter",
    ),
    ("_svc001", "healthmonitor"): (
        "config/service",
        {"name": "SVC1", "healthmonitor": "YES", "svrstate": "UP", "servicetype": "HTTP"},
        "service",
    ),
    ("_svc002", "usip"): (
        "config/servicegroup",
        {"servicegroupname": "SG1", "usip": "NO", "servicetype": "HTTP", "state": "ENABLED"},
        "servicegroup",
    ),
    ("_glob001", "internaluserlogin"): ("config/nsparam", {"internaluserlogin": "DISABLED"}, "nsparam"),
    ("_rsp001", "action"): (
        "config/responderpolicy",
        {"name": "RSP1", "action": "NOOP", "rule": "true", "builtin": []},
        "responderpolicy",
    ),
    ("_lb003", "sessionless"): (
        "config/lbvserver",
        {"name": "LB1", "sessionless": "DISABLED", "persistencetype": "SOURCEIP", "servicetype": "TCP"},
        "lbvserver",
    ),
    ("_lb003", "persistencetype"): (
        "config/lbvserver",
        {"name": "LB1", "sessionless": "ENABLED", "persistencetype": "NONE", "servicetype": "TCP"},
        "lbvserver",
    ),
    # resptimeout == interval, so the units comparison (and only it) decides.
    ("_mon001", "units3"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "interval": 5, "resptimeout": 5, "units3": "SEC", "units4": "SEC", "type": "TCP"},
        "lbmonitor",
    ),
    ("_mon001", "units4"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "interval": 5, "resptimeout": 5, "units3": "SEC", "units4": "SEC", "type": "TCP"},
        "lbmonitor",
    ),
    ("_mon002", "type"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "type": "TCP", "retries": 0, "state": "ENABLED"},
        "lbmonitor",
    ),
    # --- the three gates that used to stand OUTSIDE the
    # shared helper and therefore outside this sweep.
    ("_ssl003", "sslprofiletype"): (
        "config/sslprofile",
        {"name": "CUSTOM_P", "sslprofiletype": "FrontEnd", "ssl3": "ENABLED", "tls1": "DISABLED", "tls11": "DISABLED"},
        "sslprofile",
    ),
    ("_ssl003", "ssl3"): (
        "config/sslprofile",
        {"name": "CUSTOM_P", "sslprofiletype": "FrontEnd", "ssl3": "DISABLED", "tls1": "DISABLED", "tls11": "DISABLED"},
        "sslprofile",
    ),
    ("_ssl003", "tls1"): (
        "config/sslprofile",
        {"name": "CUSTOM_P", "sslprofiletype": "FrontEnd", "ssl3": "DISABLED", "tls1": "DISABLED", "tls11": "DISABLED"},
        "sslprofile",
    ),
    ("_ssl003", "tls11"): (
        "config/sslprofile",
        {"name": "CUSTOM_P", "sslprofiletype": "FrontEnd", "ssl3": "DISABLED", "tls1": "DISABLED", "tls11": "DISABLED"},
        "sslprofile",
    ),
    ("_ssl004", "expirymonitor"): (
        "config/sslcertkey",
        {"certkey": "CERT1", "expirymonitor": "ENABLED", "daystoexpiration": 100, "status": "Valid"},
        "sslcertkey",
    ),
    ("_log002", "transport"): (
        "config/auditsyslogaction",
        {"name": "SYS1", "serverip": "192.0.2.9", "serverport": 514, "transport": "TCP"},
        "auditsyslogaction",
    ),
}

# The string half of the sweep used to evaluate
# the SAME export twice and assert `X == X` - an assertion that cannot fail.
# Here every gated field gets TWO real string values with the word each one
# is EXPECTED to produce, and the sweep asserts that the two words DIFFER:
# that is the premise "this field actually decides the verdict", without
# which the five unreadable-shape assertions below prove nothing either.
_STRING_CASES: dict[tuple[str, str], dict[str, str]] = {
    ("_cs001", "stateupdate"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_ha001", "hastatus"): {"UP": "niet geraakt", "STAYSECONDARY": "geraakt"},
    ("_ha002", "syncstatusstrictmode"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_ha003", "haprop"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_ha005", "failsafe"): {"ON": "niet geraakt", "OFF": "geraakt"},
    ("_lb001", "somethod"): {"NONE": "niet geraakt", "CONNECTION": "geraakt"},
    ("_mgmt001", "type"): {"NSIP": "niet geraakt", "SNIP": "geraakt"},
    ("_mgmt001", "gui"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_mgmt001", "ssh"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_mgmt003", "telnet"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_mgmt003", "ftp"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_rbac001", "action"): {"DENY": "niet geraakt", "ALLOW": "geraakt"},
    ("_ssl002", "denysslreneg"): {"YES": "niet geraakt", "NO": "geraakt"},
    ("_mgmt002", "strongpassword"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_aaa001", "sectype"): {"PLAINTEXT": "niet geraakt", "SSL": "geraakt"},
    ("_aaa001", "validateservercert"): {"YES": "niet geraakt", "NO": "geraakt"},
    ("_aaa003", "persistentloginattempts"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_svc001", "healthmonitor"): {"YES": "niet geraakt", "NO": "geraakt"},
    ("_svc002", "usip"): {"NO": "niet geraakt", "YES": "geraakt"},
    ("_glob001", "internaluserlogin"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_rsp001", "action"): {"NOOP": "niet geraakt", "RESET": "geraakt"},
    ("_lb003", "sessionless"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_lb003", "persistencetype"): {"NONE": "niet geraakt", "SOURCEIP": "geraakt"},
    ("_mon001", "units3"): {"SEC": "geraakt", "MSEC": "niet geraakt"},
    ("_mon001", "units4"): {"SEC": "geraakt", "MSEC": "niet geraakt"},
    ("_mon002", "type"): {"TCP": "geraakt", "PING": "niet geraakt"},
    ("_ssl003", "sslprofiletype"): {"FrontEnd": "geraakt", "BackEnd": "niet geraakt"},
    ("_ssl003", "ssl3"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_ssl003", "tls1"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_ssl003", "tls11"): {"DISABLED": "niet geraakt", "ENABLED": "geraakt"},
    ("_ssl004", "expirymonitor"): {"ENABLED": "niet geraakt", "DISABLED": "geraakt"},
    ("_log002", "transport"): {"TCP": "niet geraakt", "UDP": "geraakt"},
}

_FUNCTION_TO_RULE_ID = {rule.detect.__name__: rule.id for rule in CATALOG}

# The five UNREADABLE shapes. The list and dict carry MARKERS: a
# supplied value reaching the answer verbatim through
# PowerShell's `[string]` cast, so every gated field is checked here for
# that too, not only for the word.
_LIST_MARKER = "SWEEP-RAW-LIST-MARKER"
_DICT_KEY_MARKER = "SWEEP-RAW-DICT-KEY"
_DICT_VALUE_MARKER = "SWEEP-RAW-DICT-VALUE"
_UNREADABLE_SHAPES = [
    ("null", None, ()),
    ("bool", True, ()),
    ("int", 7, ()),
    ("list", [_LIST_MARKER], (_LIST_MARKER,)),
    ("dict", {_DICT_KEY_MARKER: _DICT_VALUE_MARKER}, (_DICT_KEY_MARKER, _DICT_VALUE_MARKER)),
]


def _write_single_resource_export(tmp_path, resource_key: str, filename: str, rows: list[dict]):
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True, exist_ok=True)
    (export_dir / "objects" / f"{filename}.json").write_text(json.dumps({filename: rows}), encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        _manifest({f"config/{filename}" if not resource_key.endswith(".json") else resource_key: {"status": "OK"}}),
        encoding="utf-8",
    )
    return export_dir


import pytest as _pytest  # local import: keeps the module importable even if unused elsewhere


def test_base_rows_match_the_derived_gate_field_cases():
    """The completeness gate for the derivation itself: `_BASE_ROWS` and
    `_STRING_CASES` must name EXACTLY the pairs `_derived_gate_field_cases()`
    computes from FIELD_INVENTORY - not more (a stale fixture nobody
    exercises anymore), not fewer (a gate silently missing its sweep
    coverage, caught here instead of as a bare KeyError in the parametrize
    call below)."""
    derived = _derived_gate_field_cases()
    for name, have in (("_BASE_ROWS", set(_BASE_ROWS)), ("_STRING_CASES", set(_STRING_CASES))):
        assert not (derived - have), f"{name} mist een afgeleid paar: {sorted(derived - have)}"
        assert not (have - derived), f"{name} heeft een paar dat niet meer afgeleid wordt: {sorted(have - derived)}"


def test_every_string_case_offers_two_outcomes():
    """Premise for the whole sweep, checked once for the table as a whole:
    every gated field must have two string values with DIFFERENT expected
    words. A table entry that expects the same word twice would make its
    row of the sweep unfalsifiable - the defect found in an
    earlier string assertion that evaluated the SAME export twice."""
    for pair, cases in sorted(_STRING_CASES.items()):
        assert len(cases) >= 2, f"{pair}: minstens twee stringwaarden nodig"
        assert len(set(cases.values())) >= 2, (
            f"{pair}: alle stringwaarden leveren hetzelfde woord op - dan bewijst deze rij niets"
        )


@_pytest.mark.parametrize(
    "function,field",
    sorted(_derived_gate_field_cases()),
    ids=[f"{fn}:{fld}" for fn, fld in sorted(_derived_gate_field_cases())],
)
def test_every_gate_field_reads_all_seven_json_shapes_with_the_expected_word(tmp_path, function, field):
    """The table-driven sweep, DERIVED from FIELD_INVENTORY's `gate` role
    (see `_derived_gate_field_cases()`), asserting the EXACT expected word
    per shape - not merely "one of the three".

    Seven shapes per field, six baseline plus the ABSENT/null distinction
    explicitly required:

    - TWO real strings with the word each is expected to produce, and those
      two words must differ (an earlier version asserted the
      string case against an evaluation of the SAME export, `X == X`).
    - the five unreadable shapes (null/bool/int/list/dict) -> always
      'niet beoordeeld', and for list/dict ALSO: the supplied value never
      appears in the rendered answer.
    - an ABSENT key -> 'niet beoordeeld', unless the pair is in
      `_ABSENT_IS_DOCUMENTED_DEFAULT` with the word it must produce instead
      (absence is a read gap for a gated field, and the ONE
      documented exception is written down rather than implied).
    """
    resource, base_row, filename = _BASE_ROWS[(function, field)]
    rule_id = _FUNCTION_TO_RULE_ID[function]

    words = set()
    for index, (value, expected) in enumerate(sorted(_STRING_CASES[(function, field)].items())):
        row = dict(base_row)
        row[field] = value
        export_dir = _write_single_resource_export(tmp_path / f"string{index}", resource, filename, [row])
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        outcome = evaluate(load_export(export_dir))[rule_id]
        assert outcome.word == expected, f"{function}/{field}={value!r}: verwacht {expected!r}, kreeg {outcome.word!r}"
        words.add(outcome.word)
    assert len(words) >= 2, (
        f"premisse faalt voor {function}/{field}: beide stringwaarden leveren hetzelfde woord op,"
        " dus de vijf niet-string-asserties hieronder bewijzen niets over dit veld"
    )

    for shape_name, value, markers in _UNREADABLE_SHAPES:
        row = dict(base_row)
        row[field] = value
        export_dir = _write_single_resource_export(tmp_path / shape_name, resource, filename, [row])
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        export = load_export(export_dir)
        outcome = evaluate(export)[rule_id]
        assert outcome.word == "niet beoordeeld", (
            f"{function}/{field} vorm={shape_name}: een niet-string levert niet beoordeeld op, kreeg {outcome.word!r}"
        )
        text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
        for marker in markers:
            assert marker not in text, (
                f"{function}/{field} vorm={shape_name}: de aangeleverde waarde {marker!r} staat"
                " in het antwoord - een [string]-cast van onvertrouwde exportinvoer (Critical B)"
            )

    absent_row = {k: v for k, v in base_row.items() if k.lower() != field.lower()}
    assert field.lower() not in {k.lower() for k in absent_row}, "premisse: de sleutel is echt weg"
    export_dir = _write_single_resource_export(tmp_path / "absent", resource, filename, [absent_row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))[rule_id]
    documented = _ABSENT_IS_DOCUMENTED_DEFAULT.get((function, field))
    expected_absent = "niet beoordeeld" if documented is None else documented[0]
    assert outcome.word == expected_absent, (
        f"{function}/{field} zonder de sleutel: verwacht {expected_absent!r}, kreeg {outcome.word!r}"
    )


def _vocab_routed_fields() -> set[tuple[str, str]]:
    """The (function, field) pairs read through `_vocab` SPECIFICALLY, not
    merely `_gate` - derived from source the same way `_gate_routed_fields`
    is. This is a `_vocab`-only defect: a bare
    `_gate` call never manufactures a second evidence sentence for a
    readable, non-matching string (that is the caller's own business - an
    inverted gate's silent skip, or a row filter's deliberate other branch)
    - only `_vocab` does, and only `_vocab` could therefore claim a
    non-empty value was empty."""
    return {(fn, field) for (fn, helper, field) in _extract_field_reads_from_source() if helper == "_vocab"}


@_pytest.mark.parametrize(
    "function,field",
    sorted(_vocab_routed_fields()),
    ids=[f"{fn}:{fld}" for fn, fld in sorted(_vocab_routed_fields())],
)
def test_vocab_readable_non_vocabulary_string_is_not_claimed_empty(tmp_path, function, field):
    """`_vocab`'s "not matched" branch
    used to call `_shape_or_missing` unconditionally, and `export.shape_of`
    names EVERY string "een lege of alleen-witruimte tekstwaarde" regardless
    of its real content - so a genuinely readable value outside the closed
    vocabulary (e.g. `expirymonitor="MAYBE"`) was reported as if it had been
    empty. `_log002`'s own test for the identical defect on `transport`
    (`test_log002_unrecognized_transport_not_empty_statement`) is the
    discipline this test extends to every `_vocab`-routed field: `_ssl004`'s
    expirymonitor, `_ssl003`'s ssl3/tls1/tls11, and `_mgmt001`'s gui/ssh.

    PREMISE: the rule lands on 'niet beoordeeld' - the VERDICT does not
    change (Hardening rule 3 still applies; this fixes only what the
    refusal text CLAIMS, never the outcome). GATE: no false empty-value
    claim, the correct 'heeft niet de vorm van' wording instead, and the
    supplied marker never reaches the answer."""
    resource, base_row, filename = _BASE_ROWS[(function, field)]
    rule_id = _FUNCTION_TO_RULE_ID[function]
    marker = "SWEEP-READABLE-NON-VOCAB-MARKER"
    row = dict(base_row)
    row[field] = marker
    export_dir = _write_single_resource_export(tmp_path, resource, filename, [row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)[rule_id]
    assert outcome.word == "niet beoordeeld", (
        f"premisse: {function}/{field}={marker!r} moet 'niet beoordeeld' opleveren, kreeg {outcome.word!r}"
    )
    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert marker not in text, f"{function}/{field}: de aangeleverde waarde {marker!r} staat in het antwoord"
    assert "een lege of alleen-witruimte tekstwaarde" not in text, (
        f"{function}/{field}: ONWARE lege-waarde-claim voor een leesbare, niet-lege string"
    )
    assert "heeft niet de vorm van" in text, (
        f"{function}/{field}: verwachtte 'heeft niet de vorm van'-formulering ontbreekt"
    )


# --- The numeric sweep. A `numeric-gate` field cannot join the sweep above:
# an INT is a VALID shape for it, so "every non-string is niet beoordeeld"
# is simply false here. What IS true
# is the pair of rules `_num_gate` enforces: an absent key keeps the
# documented default, a present-but-unreadable value is a read gap.

_NUM_BASE_ROWS: dict[tuple[str, str], tuple[str, dict, str]] = {
    ("_mgmt004", "timeout"): (
        "config/systemparameter",
        {"strongpassword": "ENABLED", "timeout": 900},
        "systemparameter",
    ),
    ("_aaa003", "maxloginattempts"): (
        "config/aaaparameter",
        {"maxloginattempts": 3, "persistentloginattempts": "DISABLED"},
        "aaaparameter",
    ),
    ("_mon001", "interval"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "interval": 5, "resptimeout": 5, "units3": "SEC", "units4": "SEC", "type": "TCP"},
        "lbmonitor",
    ),
    ("_mon001", "resptimeout"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "interval": 5, "resptimeout": 5, "units3": "SEC", "units4": "SEC", "type": "TCP"},
        "lbmonitor",
    ),
    ("_mon002", "retries"): (
        "config/lbmonitor",
        {"monitorname": "custom-mon", "type": "TCP", "retries": 0, "state": "ENABLED"},
        "lbmonitor",
    ),
}

# Two whole numbers with DIFFERENT expected words, same premise as
# `_STRING_CASES`; plus the word an ABSENT key must produce.
_NUM_CASES: dict[tuple[str, str], dict[int, str]] = {
    ("_mgmt004", "timeout"): {0: "geraakt", 900: "niet geraakt"},
    ("_aaa003", "maxloginattempts"): {3: "geraakt", 0: "niet geraakt"},
    ("_mon001", "interval"): {5: "geraakt", 10: "niet geraakt"},
    ("_mon001", "resptimeout"): {5: "geraakt", 2: "niet geraakt"},
    ("_mon002", "retries"): {0: "geraakt", 2: "niet geraakt"},
}
_NUM_ABSENT_WORD: dict[tuple[str, str], str] = {
    ("_mgmt004", "timeout"): "niet geraakt",
    ("_aaa003", "maxloginattempts"): "niet geraakt",
    ("_mon001", "interval"): "niet geraakt",
    ("_mon001", "resptimeout"): "niet geraakt",
    ("_mon002", "retries"): "niet geraakt",
}
_IMPOSSIBLE_NUMBER_SHAPES = [
    ("null", None, ()),
    ("bool", True, ()),
    ("text", "NUM-SWEEP-NOT-A-NUMBER", ("NUM-SWEEP-NOT-A-NUMBER",)),
    ("list", [_LIST_MARKER], (_LIST_MARKER,)),
    ("dict", {_DICT_KEY_MARKER: _DICT_VALUE_MARKER}, (_DICT_KEY_MARKER, _DICT_VALUE_MARKER)),
]


def test_numeric_base_rows_match_the_derived_numeric_gate_cases():
    """Same completeness gate as for the string sweep, for the numeric one."""
    derived = _fields_with_role("numeric-gate")
    for name, have in (
        ("_NUM_BASE_ROWS", set(_NUM_BASE_ROWS)),
        ("_NUM_CASES", set(_NUM_CASES)),
        ("_NUM_ABSENT_WORD", set(_NUM_ABSENT_WORD)),
    ):
        assert not (derived - have), f"{name} mist een afgeleid paar: {sorted(derived - have)}"
        assert not (have - derived), f"{name} heeft een overbodig paar: {sorted(have - derived)}"
    for pair, cases in sorted(_NUM_CASES.items()):
        assert len(set(cases.values())) >= 2, f"{pair}: beide getallen leveren hetzelfde woord op"


@_pytest.mark.parametrize(
    "function,field",
    sorted(_fields_with_role("numeric-gate")),
    ids=[f"{fn}:{fld}" for fn, fld in sorted(_fields_with_role("numeric-gate"))],
)
def test_every_numeric_gate_field_separates_absence_from_an_unreadable_number(tmp_path, function, field):
    """The numeric half. Before this fix every
    numeric guard read `_num(...)`, whose single None meant BOTH "the key is
    not there" and "the key is there but is a bool/list/dict/word" - and
    every caller treated that one None as the FAVOURABLE outcome. Measured
    on a synthetic export beforehand: `timeout: ["0"]`, `retries: ["0"]`,
    `interval: ["5"]` and `maxloginattempts: ["3"]` all produced
    'niet geraakt' with no trace at all.

    Per field: two real numbers with different expected words (and the same
    numbers as NUMERIC STRINGS, which `_num` must read identically), the
    absent key with the word its documented default produces, and the five
    shapes that are not a whole number, which must all be read gaps that
    never echo what they carried."""
    resource, base_row, filename = _NUM_BASE_ROWS[(function, field)]
    rule_id = _FUNCTION_TO_RULE_ID[function]

    words = set()
    for index, (value, expected) in enumerate(sorted(_NUM_CASES[(function, field)].items())):
        for form, written in (("int", value), ("str", str(value))):
            row = dict(base_row)
            row[field] = written
            export_dir = _write_single_resource_export(tmp_path / f"num{index}{form}", resource, filename, [row])
            seal_manifest(export_dir)  # an object file without its hash is a read gap
            outcome = evaluate(load_export(export_dir))[rule_id]
            assert outcome.word == expected, (
                f"{function}/{field}={written!r} ({form}): verwacht {expected!r}, kreeg {outcome.word!r}"
            )
            words.add(outcome.word)
    assert len(words) >= 2, f"premisse faalt voor {function}/{field}: het getal stuurt het oordeel niet"

    absent_row = {k: v for k, v in base_row.items() if k.lower() != field.lower()}
    export_dir = _write_single_resource_export(tmp_path / "num_absent", resource, filename, [absent_row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))[rule_id]
    assert outcome.word == _NUM_ABSENT_WORD[(function, field)], (
        f"{function}/{field} zonder de sleutel hoort de gedocumenteerde standaard te houden"
    )

    for shape_name, value, markers in _IMPOSSIBLE_NUMBER_SHAPES:
        row = dict(base_row)
        row[field] = value
        export_dir = _write_single_resource_export(tmp_path / f"num_{shape_name}", resource, filename, [row])
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        export = load_export(export_dir)
        outcome = evaluate(export)[rule_id]
        assert outcome.word == "niet beoordeeld", (
            f"{function}/{field} vorm={shape_name}: een aanwezige, onleesbare waarde hoort een"
            f" leesgat te zijn, kreeg {outcome.word!r}"
        )
        text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
        for marker in markers:
            assert marker not in text, (
                f"{function}/{field} vorm={shape_name}: de aangeleverde waarde staat in het antwoord"
            )


# ---------------------------------------------------------------------------
# "Elke poort, niet drie", the raw-echo audit, and the inverted-gate
# correction, each proven at the rule level (not just "reads _gate now").
# ---------------------------------------------------------------------------


def test_mgmt001_unreadable_type_becomes_niet_beoordeeld_not_a_silent_evaluation(tmp_path):
    """`type` is an INVERTED gate (skip this row when it IS
    NSIP) - an unreadable type must never be silently treated as
    "confirmed not NSIP" and evaluated against gui/ssh anyway (which is
    what the pre-fix code did, and which also echoed the raw token into
    the label). A JSON-bool type with gui/ssh both ENABLED
    proves the row is NOT quietly scored as a real hit."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "nsip.json").write_text(
        json.dumps(
            {
                "nsip": [
                    {"ipaddress": "10.9.9.9", "type": True, "gui": "ENABLED", "ssh": "ENABLED"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/nsip": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-MGMT-001"]
    assert outcome.word == "niet beoordeeld", (
        "een onleesbare type mag nooit stil als 'niet-NSIP, dus beoordelen' behandeld worden"
    )
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "bool" in outcome.hits[0].evidence
    assert "True" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


def test_mon002_unreadable_type_never_causes_a_silent_skip(tmp_path):
    """NSHC-HR-MON-002's `type` is an INVERTED gate (skip this
    row when type is PING/ARP) - an unreadable type must never be silently
    treated as "confirmed not PING/ARP" and skipped past the retries=0
    check as if it were clean. A JSON-list type with retries=0 proves the
    row becomes NOT ASSESSABLE, never a silent 'niet geraakt'."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "lbmonitor.json").write_text(
        json.dumps(
            {
                "lbmonitor": [
                    {"monitorname": "custom-mon", "type": ["TCP"], "retries": 0, "state": "ENABLED"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/lbmonitor": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-MON-002"]
    assert outcome.word == "niet beoordeeld", (
        "een onleesbare type mag nooit stil als 'niet PING/ARP, dus meetellen' behandeld worden"
    )
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "list" in outcome.hits[0].evidence
    assert "TCP" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


def test_lb001_unreadable_somethod_becomes_niet_beoordeeld_not_a_silent_skip(tmp_path):
    """`somethod` is an inverted-ish gate (skip when NONE/
    empty) - a PRESENT but unreadable value must never be silently treated
    as "empty, nothing configured" (a favourable skip) OR as "set, so
    fire" (echoing the raw token). Only a genuinely ABSENT key
    is the documented no-spillover default (see _lb001's own comment)."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "lbvserver.json").write_text(
        json.dumps(
            {
                "lbvserver": [
                    {"name": "LB_WEIRD", "somethod": {"nested": "value"}, "backupvserver": ""},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/lbvserver": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-LB-001"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "dict" in outcome.hits[0].evidence
    assert "nested" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


def test_lb001_a_genuinely_absent_somethod_stays_the_documented_default(tmp_path):
    """Premise + explicit scope boundary: somethod's ABSENCE (no spillover
    configured at all - the common case) is NOT routed through `_gate` and
    stays the existing, documented 'niet geraakt' - proven here so this
    fix cannot be mistaken for having widened absence into a read
    gap for this one field."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": [{"name": "LB_PLAIN", "backupvserver": ""}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/lbvserver": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-LB-001"]
    assert outcome.word == "niet geraakt"
    assert outcome.hits == ()


def test_ha001_unreadable_hastatus_is_niet_beoordeeld_and_never_echoed(tmp_path):
    """One of the ~20 'structural' swaps: hastatus is
    read via `_gate` for readability only (the comparison itself stays the
    substring test NSHC parity already used). A JSON-bool hastatus must
    become NOT ASSESSABLE, never a silent 'niet geraakt', and its raw
    value must never reach the evidence text."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "hanode.json").write_text(
        json.dumps(
            {
                "hanode": [
                    {
                        "id": "0",
                        "hastatus": False,
                        "syncstatusstrictmode": "ENABLED",
                        "haprop": "ENABLED",
                        "failsafe": "ON",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/hanode": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-HA-001"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "bool" in outcome.hits[0].evidence
    assert "False" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


# ---------------------------------------------------------------------------
# The THREE explicitly measured cases get the fullest, rule-level
# treatment - not just "does not crash" but "the specific dead-guard class
# (unreadable value silently lands on the FAVORABLE word) is actually gone".
# ---------------------------------------------------------------------------


def test_mgmt001_an_unreadable_gui_becomes_niet_beoordeeld_not_silently_off(tmp_path):
    """MEASURED: a JSON-bool/int/list `gui`
    used to collapse to "" via field_text and silently fail to match
    ENABLED/SECUREONLY - hardening rule 6's exact defect (unreadable landing
    on the FAVORABLE "not exposed" word). A bare field_token swap alone does
    NOT fix this (see hidden_rules.py's H2 comment): `field_token(True)` is
    "True", which ALSO never equals "ENABLED"/"SECUREONLY". Only the
    three-way read (H2) surfaces it as NOT ASSESSABLE."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "nsip.json").write_text(
        json.dumps({"nsip": [{"ipaddress": "10.9.9.9", "type": "SNIP", "gui": True, "ssh": "DISABLED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/nsip": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-MGMT-001"]
    assert outcome.word == "niet beoordeeld", (
        "een JSON-bool gui hoort niet beoordeeld te zijn, niet stil 'niet geraakt'"
    )
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "bool" in outcome.hits[0].evidence, "de VORM hoort genoemd, nooit de ruwe waarde"
    assert "True" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


def test_mgmt001_a_readable_gui_still_fires_exactly_as_before(tmp_path):
    """Premise + regression guard: a real ENABLED string must still fire -
    the H2 rewrite must not have turned a genuine hit into a false negative."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "nsip.json").write_text(
        json.dumps({"nsip": [{"ipaddress": "10.9.9.9", "type": "SNIP", "gui": "ENABLED", "ssh": "DISABLED"}]}),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/nsip": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-MGMT-001"]
    assert outcome.word == "geraakt"
    assert outcome.hits[0].not_assessable is False
    assert "gui=ENABLED" in outcome.hits[0].evidence


def test_ssl004_an_unreadable_expirymonitor_becomes_niet_beoordeeld(tmp_path):
    """MEASURED. Same class as
    test_mgmt001_unreadable_type_becomes_niet_beoordeeld_not_a_silent_evaluation
    above: a JSON-int/list/bool expirymonitor used to silently
    match neither "" (field_text) nor now "True"/"7" (field_token alone)
    against "DISABLED", landing on the same FAVORABLE "nothing to flag"
    branch either way. The H2 rewrite makes it NOT ASSESSABLE instead."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {"sslcertkey": [{"certkey": "CERT_WEIRD", "expirymonitor": 1, "daystoexpiration": 30, "status": "Valid"}]}
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslcertkey": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-004"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "int" in outcome.hits[0].evidence
    assert "CERT_WEIRD" in outcome.reason


def test_ssl004_a_readable_expirymonitor_still_behaves_exactly_as_before(tmp_path):
    """Premise + regression guard for both real branches."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "CERT_ENABLED", "expirymonitor": "ENABLED", "daystoexpiration": 30, "status": "Valid"},
                    {"certkey": "CERT_DISABLED", "expirymonitor": "DISABLED", "daystoexpiration": 5, "status": "Valid"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslcertkey": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-004"]
    assert outcome.word == "geraakt"
    assert len(outcome.hits) == 1
    assert outcome.hits[0].instance == "CERT_DISABLED"
    assert outcome.hits[0].not_assessable is False


def test_ssl003_an_unreadable_sslprofiletype_is_niet_beoordeeld(tmp_path):
    """MEASURED. sslprofiletype is a ROW
    FILTER, not a simple gate: MEASURED on the real fixture it carries FOUR
    distinct string values (FrontEnd/BackEnd/QUIC-FrontEnd/QUIC-BackEnd), so
    "not FRONTEND" stays a deliberate, unchanged skip for a readable string
    that just is not FrontEnd (test right below). Only a NON-STRING value
    (this test: a JSON list) becomes NOT ASSESSABLE - it used to silently
    match neither "FRONTEND" via field_text NOR field_token, landing on the
    exact same silent skip as a genuine BackEnd profile: hardening rule 6's
    defect, since the reader could never tell "definitely not in scope"
    apart from "cannot tell if in scope"."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps(
            {
                "sslprofile": [
                    {
                        "name": "WEIRD_PROFILE",
                        "sslprofiletype": ["FrontEnd"],
                        "ssl3": "ENABLED",
                        "tls1": "DISABLED",
                        "tls11": "DISABLED",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslprofile": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-003"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "list" in outcome.hits[0].evidence
    assert "FrontEnd" not in outcome.hits[0].evidence, "de ruwe waarde mag niet geechood worden"


def test_ssl003_a_genuine_backend_profile_keeps_its_existing_silent_skip(tmp_path):
    """Premise + explicit scope boundary: a READABLE string that just is not
    "FRONTEND" (BackEnd, or an unrecognized string like QUIC-FrontEnd) is
    OUT OF SCOPE for this task (enum-vocabulary completeness, not
    non-string-JSON hardening) and keeps EXACTLY today's behaviour - proven
    here so a future change to that vocabulary decision cannot slide in
    unnoticed as a side effect of this task."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps(
            {
                "sslprofile": [
                    {"name": "REAL_BACKEND", "sslprofiletype": "BackEnd", "ssl3": "ENABLED"},
                    {"name": "REAL_QUIC", "sslprofiletype": "QUIC-FrontEnd", "ssl3": "ENABLED"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/sslprofile": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-003"]
    assert outcome.word == "niet geraakt", (
        "een leesbare, niet-FRONTEND string blijft ongewijzigd overgeslagen (buiten scope)"
    )
    assert outcome.hits == ()


# ---------------------------------------------------------------------------
# Every finding reproduced the way it was
# measured - a synthetic export whose value carries a LIST, a
# bool or an int - and asserted on the OBSERVABLE answer, never on which
# helper the code calls.
# ---------------------------------------------------------------------------


def _one_row_export(tmp_path, resource: str, filename: str, row: dict):
    return _write_single_resource_export(tmp_path, resource, filename, [row])


# --- The two gates that stood outside the shared helper gave the
# LIST shape the OPPOSITE answer to every other gate in the same module.


@_pytest.mark.parametrize("supplied", [["ENABLED"], ["DISABLED"]])
def test_ssl004_a_list_expirymonitor_is_a_read_gap_either_way(tmp_path, supplied):
    """MEASURED before this fix: `expirymonitor:
    ["ENABLED"]` produced 'niet geraakt' with 0 hits (silently on the
    favourable branch) and `["DISABLED"]` produced a `geraakt [vastgesteld]`
    finding whose evidence read `expirymonitor=DISABLED` - a word the field
    never carried, because `field_token` is PowerShell's `[string]` cast and
    joins a list. BOTH must be the same read gap now, and neither may put
    the supplied element in the answer as if it had been read."""
    export_dir = _one_row_export(
        tmp_path,
        "config/sslcertkey",
        "sslcertkey",
        {"certkey": "CERT_LIST", "expirymonitor": supplied, "daystoexpiration": 30, "status": "Valid"},
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-SSL-004"]
    assert outcome.word == "niet beoordeeld", (
        f"expirymonitor={supplied!r} hoort een leesgat te zijn, kreeg {outcome.word!r}"
    )
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "list" in outcome.hits[0].evidence, "de VORM hoort genoemd"
    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert "expirymonitor=DISABLED" not in text, (
        "een waarde die nooit een string was mag niet als vastgesteld woord worden afgedrukt"
    )


@_pytest.mark.parametrize("field", ["ssl3", "tls1", "tls11"])
@_pytest.mark.parametrize("supplied", [["ENABLED"], ["DISABLED"]])
def test_ssl003_a_list_protocol_field_is_a_read_gap_either_way(tmp_path, field, supplied):
    """The same measurement for the second gate that stood outside the
    shared helper: `ssl3: ["DISABLED"]` used to be a silent 'niet geraakt'
    and `["ENABLED"]` a `geraakt [vastgesteld]`, both on a value that was
    never a string. The LIST is exactly the shape MEASURED on real
    data for `builtin`, so this is not a hypothetical."""
    row = {
        "name": "CUSTOM_P",
        "sslprofiletype": "FrontEnd",
        "ssl3": "DISABLED",
        "tls1": "DISABLED",
        "tls11": "DISABLED",
    }
    row[field] = supplied
    export_dir = _one_row_export(tmp_path, "config/sslprofile", "sslprofile", row)
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SSL-003"]
    assert outcome.word == "niet beoordeeld", f"{field}={supplied!r} hoort een leesgat te zijn, kreeg {outcome.word!r}"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert field in outcome.hits[0].evidence
    assert "list" in outcome.hits[0].evidence, "Important F: de VORM hoort in het bewijs"


def test_one_json_shape_gets_one_answer_across_the_module(tmp_path):
    """The actual complaint: 'dezelfde
    JSON-vorm krijgt twee tegengestelde antwoorden binnen een module'.
    Measured here across four gates on four different resources at once -
    one that always went through the shared helper (`_cs001`'s stateupdate,
    the control) and the three that did not."""
    cases = [
        ("config/csvserver", "csvserver", {"name": "CS1", "stateupdate": ["DISABLED"]}, "NSHC-HR-CS-001"),
        (
            "config/sslcertkey",
            "sslcertkey",
            {"certkey": "C1", "expirymonitor": ["ENABLED"], "daystoexpiration": 30, "status": "Valid"},
            "NSHC-HR-SSL-004",
        ),
        (
            "config/sslprofile",
            "sslprofile",
            {"name": "P1", "sslprofiletype": "FrontEnd", "ssl3": ["DISABLED"], "tls1": "DISABLED", "tls11": "DISABLED"},
            "NSHC-HR-SSL-003",
        ),
        (
            "config/sslprofile",
            "sslprofile",
            {"name": "P2", "sslprofiletype": ["FrontEnd"], "ssl3": "ENABLED", "tls1": "DISABLED", "tls11": "DISABLED"},
            "NSHC-HR-SSL-003",
        ),
    ]
    words = {}
    for index, (resource, filename, row, rule_id) in enumerate(cases):
        export_dir = _one_row_export(tmp_path / f"case{index}", resource, filename, row)
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        words[f"{rule_id}#{index}"] = evaluate(load_export(export_dir))[rule_id].word
    assert set(words.values()) == {"niet beoordeeld"}, words


# --- Five render sites turned a supplied value into answer text
# through PowerShell's [string] cast.

_RAW_ECHO_SITES = [
    (
        "hanode-id",
        "config/hanode",
        "hanode",
        {
            "id": ["RAW-ID-LEAK"],
            "hastatus": "STAYSECONDARY",
            "syncstatusstrictmode": "ENABLED",
            "haprop": "ENABLED",
            "failsafe": "ON",
        },
        "NSHC-HR-HA-001",
        "RAW-ID-LEAK",
    ),
    (
        "log002-serverport",
        "config/auditsyslogaction",
        "auditsyslogaction",
        {"name": "SYS1", "serverip": "10.1.1.1", "serverport": ["RAW-PORT-LEAK"], "transport": "UDP"},
        "NSHC-HR-LOG-002",
        "RAW-PORT-LEAK",
    ),
    (
        "ssl004-daystoexpiration",
        "config/sslcertkey",
        "sslcertkey",
        {"certkey": "CERT_C", "expirymonitor": "DISABLED", "daystoexpiration": ["RAW-DAYS-LEAK"], "status": "Valid"},
        "NSHC-HR-SSL-004",
        "RAW-DAYS-LEAK",
    ),
    (
        "aaa001-serverport",
        "config/authenticationldapaction",
        "authenticationldapaction",
        {"name": "LDAP1", "sectype": "SSL", "validateservercert": "NO", "serverport": ["RAW-LDAP-PORT"]},
        "NSHC-HR-AAA-001",
        "RAW-LDAP-PORT",
    ),
]


@_pytest.mark.parametrize(
    "label,resource,filename,row,rule_id,marker",
    _RAW_ECHO_SITES,
    ids=[case[0] for case in _RAW_ECHO_SITES],
)
def test_a_numeric_render_site_never_echoes_a_supplied_list(tmp_path, label, resource, filename, row, rule_id, marker):
    """MEASURED: each of these printed the supplied text
    verbatim under `geraakt [vastgesteld]` - `node RAW-ID-LEAK`,
    `naar 10.1.1.1:RAW-PORT-LEAK`, `daystoexpiration=RAW-DAYS-LEAK`,
    `serverport=RAW-LDAP-PORT`. PREMISE first (the rule really fires, so the
    render site is really reached), then the gate."""
    export_dir = _one_row_export(tmp_path, resource, filename, row)
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)[rule_id]
    assert outcome.word == "geraakt", (
        f"premisse voor {label}: de regel moet vuren, anders wordt de rendersite niet bereikt"
    )
    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert marker not in text, f"{label}: de aangeleverde waarde staat in het antwoord"


def test_rw001_undefhits_never_echoes_a_supplied_list(tmp_path):
    """The fifth site. NSHC-HR-RW-001 needs BOTH config/rewritepolicy and
    config/rewriteaction present, or the rule stops at a source-level read
    gap and never reaches the render site at all (which is why this one
    could not be measured end to end)."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "rewritepolicy.json").write_text(
        json.dumps(
            {
                "rewritepolicy": [
                    {"name": "RW1", "isdefault": False, "action": "ghost_action", "undefhits": ["RAW-UNDEFHITS-LEAK"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "rewriteaction.json").write_text(
        json.dumps({"rewriteaction": [{"name": "some_other_action"}]}), encoding="utf-8"
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/rewritepolicy": {"status": "OK"}, "config/rewriteaction": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-RW-001"]
    assert outcome.word == "geraakt", "premisse: de regel moet vuren"
    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert "RAW-UNDEFHITS-LEAK" not in text
    assert "undefhits=?" in text, "een niet-leesbaar aantal is '?', nooit een geclaimde 0"


def test_a_real_number_still_prints_at_every_render_site(tmp_path):
    """Regression guard for the same five sites: the fix must not turn a
    successfully read number into '?'. Both JSON forms a NITRO export uses
    (a real int and a numeric string) still print."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "hanode.json").write_text(
        json.dumps(
            {
                "hanode": [
                    {
                        "id": "1",
                        "hastatus": "STAYSECONDARY",
                        "syncstatusstrictmode": "ENABLED",
                        "haprop": "ENABLED",
                        "failsafe": "ON",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "CERT_D", "expirymonitor": "DISABLED", "daystoexpiration": 817, "status": "Valid"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/hanode": {"status": "OK"}, "config/sslcertkey": {"status": "OK"}}), encoding="utf-8"
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    assert evaluate(export)["NSHC-HR-HA-001"].hits[0].instance == "node 1"
    assert "daystoexpiration=817" in evaluate(export)["NSHC-HR-SSL-004"].hits[0].evidence


# --- Absence, and the empty string the absence defaults used to
# cover.


def test_mon001_an_empty_unit_is_a_read_gap_not_a_silent_sec(tmp_path):
    """MEASURED before this round: `units3: ""` with `units4: "SEC"` made
    `(field_text(...) or "SEC")` supply the missing word on BOTH sides, the
    units compared EQUAL, and the rule fired `geraakt` on a comparison it
    could not actually make. That default was written for an ABSENT key,
    which is a read gap now - so the code said two things at once. It says
    one now: an unstated unit is a read gap."""
    export_dir = _one_row_export(
        tmp_path,
        "config/lbmonitor",
        "lbmonitor",
        {"monitorname": "custom-mon", "type": "TCP", "interval": 5, "resptimeout": 5, "units3": "", "units4": "SEC"},
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-MON-001"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "units3" in outcome.hits[0].evidence
    assert "een lege of alleen-witruimte tekstwaarde" in outcome.hits[0].evidence


def test_lb003_an_empty_persistencetype_is_a_read_gap(tmp_path):
    """Same defect, same resolution, on the other absence default that was
    left behind: `if not persistence` was written for the absent key and
    silently read an unstated persistencetype as 'no persistence
    configured' - the favourable side of a rule about two settings that
    contradict each other."""
    export_dir = _one_row_export(
        tmp_path,
        "config/lbvserver",
        "lbvserver",
        {"name": "LB1", "sessionless": "ENABLED", "persistencetype": "", "servicetype": "TCP"},
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-LB-003"]
    assert outcome.word == "niet beoordeeld"
    assert len(outcome.hits) == 1 and outcome.hits[0].not_assessable is True
    assert "persistencetype" in outcome.hits[0].evidence


def test_the_absence_rule_is_the_same_at_every_gate(tmp_path):
    """The truth change stated plainly, in one place: for a gated field an
    ABSENT key is a read gap - measured across four rules
    (SVC-001, SVC-002, LB-003, MON-001) - and the one documented
    exception (`_lb001`'s optional somethod) still is one."""
    rows = [
        (
            "config/service",
            "service",
            {"name": "SVC1", "svrstate": "UP", "servicetype": "HTTP"},
            "NSHC-HR-SVC-001",
            "niet beoordeeld",
        ),
        (
            "config/servicegroup",
            "servicegroup",
            {"servicegroupname": "SG1", "servicetype": "HTTP", "state": "ENABLED"},
            "NSHC-HR-SVC-002",
            "niet beoordeeld",
        ),
        (
            "config/lbvserver",
            "lbvserver",
            {"name": "LB1", "sessionless": "ENABLED", "servicetype": "TCP"},
            "NSHC-HR-LB-003",
            "niet beoordeeld",
        ),
        (
            "config/lbmonitor",
            "lbmonitor",
            {"monitorname": "custom-mon", "type": "TCP", "interval": 5, "resptimeout": 5},
            "NSHC-HR-MON-001",
            "niet beoordeeld",
        ),
        ("config/lbvserver", "lbvserver", {"name": "LB2", "backupvserver": ""}, "NSHC-HR-LB-001", "niet geraakt"),
    ]
    for index, (resource, filename, row, rule_id, expected) in enumerate(rows):
        export_dir = _one_row_export(tmp_path / f"absent{index}", resource, filename, row)
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        outcome = evaluate(load_export(export_dir))[rule_id]
        assert outcome.word == expected, f"{rule_id} zonder de sleutel: kreeg {outcome.word!r}"


# --- The unreadable confidence modifier must name
# WHICH field and WHICH shape, and BOTH fields must be proven, not just one.


@_pytest.mark.parametrize("field,other", [("mgmtaccess", "type"), ("type", "mgmtaccess")])
def test_mgmt003_unreadable_type_or_mgmtaccess_degrades_confidence_not_the_verdict(tmp_path, field, other):
    """The dedicated proof `_GATE_FIELD_EXCLUSIONS` promises for
    (_mgmt003, type) and (_mgmt003, mgmtaccess) - now for BOTH fields
    (an earlier version varied only `mgmtaccess` while the name,
    the docstring and both exclusion reasons promised two).

    telnet/ftp are the actual fire-gate for NSHC-HR-MGMT-003, so an
    unreadable `type`/`mgmtaccess` must NOT swallow an already-established
    telnet/ftp hit into 'niet beoordeeld' - it degrades the hit's own
    confidence to 'niet vastgesteld' (never a silent 'medium' guess,
    hardening rule 6) while the RULE still reads 'geraakt'.

    The reason must NAME the unreadable field and its SHAPE.
    `_gate` produced exactly that line and an earlier version threw it away
    for a generic sentence, so the reader could not see which of the two
    fields was unreadable, nor in what shape."""
    row = {"ipaddress": "10.9.9.9", "type": "SNIP", "telnet": "ENABLED", "ftp": "DISABLED", "mgmtaccess": "DISABLED"}
    row[field] = True
    export_dir = _one_row_export(tmp_path, "config/nsip", "nsip", row)
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-MGMT-003"]
    assert outcome.word == "geraakt", "telnet=ENABLED is zelf al vastgesteld - dit hoort niet te blokkeren"
    assert len(outcome.hits) == 1
    assert outcome.hits[0].confidence == "none"

    reason = outcome.hits[0].confidence_reason
    assert f"{field} niet gelezen" in reason, f"de reden moet het onleesbare veld {field} noemen: {reason!r}"
    assert f"{other} niet gelezen" not in reason, (
        f"alleen {field} was onleesbaar - {other} hoort geen bewijsregel te krijgen: {reason!r}"
    )
    assert "een waarde van het type bool" in reason, f"de VORM hoort in de reden: {reason!r}"

    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert "- NSHC-HR-MGMT-003: geraakt [vastgesteld]" in text
    assert "zekerheid: niet vastgesteld]" in text
    assert "True" not in text, "de ruwe waarde mag niet geechood worden"


# --- Two sites echoed an ARBITRARY supplied string (not a name, so
# the masking seam can never reach it).


def test_lb001_never_echoes_an_off_vocabulary_somethod(tmp_path):
    """`soMethod=<so>` printed whatever the export supplied. `somethod` is
    a spillover METHOD, not an entity name: `disclosure.names_from_export()`
    neither collects nor should collect it, so it cannot be masked at the
    seam and must be suppressed by shape instead - the same answer
    `_cs002` already gives for a policy expression. PREMISE: the rule still
    fires on exactly the same input."""
    marker = "EVIL-SOMETHOD-VALUE"
    export_dir = _one_row_export(
        tmp_path, "config/lbvserver", "lbvserver", {"name": "LB1", "somethod": marker, "backupvserver": ""}
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-LB-001"]
    assert outcome.word == "geraakt", "premisse: de bevinding zelf verandert niet"
    assert marker not in hidden_rules_answer(export, _KNOWLEDGE).to_text()


def test_lb001_still_prints_a_documented_spillover_method(tmp_path):
    """Regression guard for the same site: a real soMethod value is exactly
    what the reader needs and must still be printed."""
    export_dir = _one_row_export(
        tmp_path, "config/lbvserver", "lbvserver", {"name": "LB1", "somethod": "CONNECTION", "backupvserver": ""}
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-LB-001"]
    assert "soMethod=CONNECTION" in outcome.hits[0].evidence


def test_ha001_never_echoes_a_hastatus_that_only_contains_the_word(tmp_path):
    """`hastatus` is matched with a SUBSTRING test (NSHC parity), so
    `STAYSECONDARY<anything>` used to reach the answer verbatim. Same
    class, same treatment: the rule still fires, the supplied tail does not
    get printed."""
    export_dir = _one_row_export(
        tmp_path,
        "config/hanode",
        "hanode",
        {
            "id": "0",
            "hastatus": "STAYSECONDARY-EVIL-TAIL",
            "syncstatusstrictmode": "ENABLED",
            "haprop": "ENABLED",
            "failsafe": "ON",
        },
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)["NSHC-HR-HA-001"]
    assert outcome.word == "geraakt", "premisse: de substring-match blijft vuren (NSHC-pariteit)"
    assert "EVIL-TAIL" not in hidden_rules_answer(export, _KNOWLEDGE).to_text()


def test_ha001_still_prints_an_exact_maintenance_state(tmp_path):
    """Regression guard: the exact word is the finding and still prints."""
    export_dir = _one_row_export(
        tmp_path,
        "config/hanode",
        "hanode",
        {
            "id": "0",
            "hastatus": "STAYSECONDARY",
            "syncstatusstrictmode": "ENABLED",
            "haprop": "ENABLED",
            "failsafe": "ON",
        },
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-HA-001"]
    assert outcome.hits[0].evidence == "hastatus=STAYSECONDARY"


# --- The two gates that stay OUTSIDE the shared helper, each proven on the
# shape that makes the shared helper wrong for it (_NON_GATE_ROUTED_GATES).


def test_rw001_isdefault_keeps_reading_the_measured_bool_shape(tmp_path):
    """`isdefault` is a JSON BOOL on all 71 real rewritepolicy rows, so a
    non-string is its NORMAL shape and `_gate` would call every row
    unreadable. Both bool values must keep working: True skips the row (a
    built-in policy), False evaluates it."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "rewritepolicy.json").write_text(
        json.dumps(
            {
                "rewritepolicy": [
                    {"name": "BUILTIN", "isdefault": True, "action": "ghost_a", "undefhits": "0"},
                    {"name": "CUSTOM", "isdefault": False, "action": "ghost_b", "undefhits": "0"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "rewriteaction.json").write_text(
        json.dumps({"rewriteaction": [{"name": "unrelated"}]}), encoding="utf-8"
    )
    (export_dir / "export-manifest.json").write_text(
        _manifest({"config/rewritepolicy": {"status": "OK"}, "config/rewriteaction": {"status": "OK"}}),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-RW-001"]
    assert outcome.word == "geraakt"
    assert [h.instance for h in outcome.hits] == ["CUSTOM"], (
        "een JSON-bool isdefault=True hoort de rij over te slaan, niet onleesbaar te zijn"
    )


def test_rsp001_builtin_keeps_reading_the_measured_list_and_absent_shapes(tmp_path):
    """`builtin` is a JSON LIST on 6 of 7 real responderpolicy rows and
    ABSENT on the seventh - and absence there is the documented 'not a
    built-in policy' state. Both shapes `_gate` refuses are this field's
    normal ones, which is why it stays on `field_token`."""
    export_dir = _write_single_resource_export(
        tmp_path,
        "config/responderpolicy",
        "responderpolicy",
        [
            {"name": "IMMUTABLE_ONE", "builtin": ["IMMUTABLE"], "action": "RESET", "rule": "true"},
            {"name": "NO_BUILTIN_KEY", "action": "RESET", "rule": "true"},
        ],
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-RSP-001"]
    assert outcome.word == "geraakt"
    assert [h.instance for h in outcome.hits] == ["NO_BUILTIN_KEY"], (
        "de lijstvorm hoort de rij over te slaan en de ontbrekende sleutel hoort hem te evalueren"
    )


# --- As a CLASS: every display-only NITRO enumeration that reaches
# the answer WITHOUT a vocabulary match having established it. These have no
# vocabulary this product can check against (lbmonitor.type alone has dozens
# of documented values, and inventing one is out of scope
# for sslprofiletype), so they go through the product's own shape
# gate - `answer.repeatable_token`, one bare NITRO token.

_SENTENCE = "DISABLED en dan nog een hele zin met spaties erin"

_ENUM_ECHO_SITES = [
    (
        "mgmt001-type",
        "config/nsip",
        "nsip",
        {"ipaddress": "10.9.9.9", "type": _SENTENCE, "gui": "ENABLED", "ssh": "DISABLED"},
        "NSHC-HR-MGMT-001",
    ),
    (
        "mgmt003-type",
        "config/nsip",
        "nsip",
        {"ipaddress": "10.9.9.9", "type": _SENTENCE, "telnet": "ENABLED", "ftp": "DISABLED", "mgmtaccess": "DISABLED"},
        "NSHC-HR-MGMT-003",
    ),
    (
        "mgmt003-mgmtaccess",
        "config/nsip",
        "nsip",
        {"ipaddress": "10.9.9.9", "type": "SNIP", "telnet": "ENABLED", "ftp": "DISABLED", "mgmtaccess": _SENTENCE},
        "NSHC-HR-MGMT-003",
    ),
    (
        "svc001-svrstate",
        "config/service",
        "service",
        {"name": "SVC1", "healthmonitor": "NO", "svrstate": _SENTENCE, "servicetype": "HTTP"},
        "NSHC-HR-SVC-001",
    ),
    (
        "svc001-servicetype",
        "config/service",
        "service",
        {"name": "SVC1", "healthmonitor": "NO", "svrstate": "UP", "servicetype": _SENTENCE},
        "NSHC-HR-SVC-001",
    ),
    (
        "svc002-servicetype",
        "config/servicegroup",
        "servicegroup",
        {"servicegroupname": "SG1", "usip": "YES", "servicetype": _SENTENCE, "state": "ENABLED"},
        "NSHC-HR-SVC-002",
    ),
    (
        "svc002-state",
        "config/servicegroup",
        "servicegroup",
        {"servicegroupname": "SG1", "usip": "YES", "servicetype": "HTTP", "state": _SENTENCE},
        "NSHC-HR-SVC-002",
    ),
    (
        "lb003-persistencetype",
        "config/lbvserver",
        "lbvserver",
        {"name": "LB1", "sessionless": "ENABLED", "persistencetype": _SENTENCE, "servicetype": "TCP"},
        "NSHC-HR-LB-003",
    ),
    (
        "lb003-servicetype",
        "config/lbvserver",
        "lbvserver",
        {"name": "LB1", "sessionless": "ENABLED", "persistencetype": "SOURCEIP", "servicetype": _SENTENCE},
        "NSHC-HR-LB-003",
    ),
    (
        "ssl004-status",
        "config/sslcertkey",
        "sslcertkey",
        {"certkey": "CERT1", "expirymonitor": "DISABLED", "daystoexpiration": 30, "status": _SENTENCE},
        "NSHC-HR-SSL-004",
    ),
    (
        "mon001-type",
        "config/lbmonitor",
        "lbmonitor",
        {
            "monitorname": "custom-mon",
            "type": _SENTENCE,
            "interval": 5,
            "resptimeout": 5,
            "units3": "SEC",
            "units4": "SEC",
        },
        "NSHC-HR-MON-001",
    ),
    (
        "mon002-type",
        "config/lbmonitor",
        "lbmonitor",
        {"monitorname": "custom-mon", "type": _SENTENCE, "retries": 0, "state": "ENABLED"},
        "NSHC-HR-MON-002",
    ),
    (
        "mon002-state",
        "config/lbmonitor",
        "lbmonitor",
        {"monitorname": "custom-mon", "type": "TCP", "retries": 0, "state": _SENTENCE},
        "NSHC-HR-MON-002",
    ),
    (
        "aaa001-validateservercert",
        "config/authenticationldapaction",
        "authenticationldapaction",
        {"name": "LDAP1", "sectype": "SSL", "validateservercert": _SENTENCE, "serverport": 636},
        "NSHC-HR-AAA-001",
    ),
]


@_pytest.mark.parametrize(
    "label,resource,filename,row,rule_id",
    _ENUM_ECHO_SITES,
    ids=[case[0] for case in _ENUM_ECHO_SITES],
)
def test_a_display_only_enum_never_echoes_a_supplied_sentence(tmp_path, label, resource, filename, row, rule_id):
    """PREMISE first: the rule really fires on this row, so the render site
    is really reached (a test where the rule stays silent would prove
    nothing about the echo). GATE: the supplied sentence does not reach the
    answer - not at `volledig`, where the masking seam is at its most
    permissive and these fields are collected by none of its ten families."""
    export_dir = _one_row_export(tmp_path, resource, filename, row)
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    outcome = evaluate(export)[rule_id]
    assert outcome.word == "geraakt", f"premisse voor {label}: de regel moet vuren, kreeg {outcome.word!r}"
    text = hidden_rules_answer(export, _KNOWLEDGE).to_text()
    assert "hele zin met spaties" not in text, f"{label}: de aangeleverde tekst staat in het antwoord"


def test_a_real_nitro_enumeration_still_prints(tmp_path):
    """Regression guard for the same gate: every enumeration value MEASURED
    on the real fixture is one bare token and must pass through untouched -
    a gate that swallowed them would cost the reader the finding.

    This used to test "OUT_OF_SERVICE"
    (spaces replaced by underscores) instead of the real, documented
    multi-word NITRO value "OUT OF SERVICE" - so it could never have caught
    `max_words=1` swallowing a genuine multi-word state (which it did:
    MEASURED, `svrstate="OUT OF SERVICE"` printed `svrstate=?`). Uses the
    real value now."""
    export_dir = _one_row_export(
        tmp_path,
        "config/service",
        "service",
        {"name": "SVC1", "healthmonitor": "NO", "svrstate": "OUT OF SERVICE", "servicetype": "SSL_BRIDGE"},
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    outcome = evaluate(load_export(export_dir))["NSHC-HR-SVC-001"]
    assert "svrstate=OUT OF SERVICE" in outcome.hits[0].evidence
    assert "servicetype=SSL_BRIDGE" in outcome.hits[0].evidence
