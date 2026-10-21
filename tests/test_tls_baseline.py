"""TLS baseline and grade per vserver, measured on the real lab export.

Four corrections, each with its measurement stated here:

- The kenmerken literal put "ciphergroep niet uitgesplitst" LAST;
  measured on the real fixture the code's own insertion order puts it FIFTH
  (protocol flags, then the cipher-group note, then the p224 curve, then
  hsts, then ocsp). The TEST LITERAL is fixed here; grade_per_vserver()'s
  flag order is not touched.
- The `_one_vserver` fixture for
  test_the_profile_wins_over_the_vserver wrote no binding files at all, so
  the vserver always fell into the missing-binding branch (NIET BEOORDEELD,
  kenmerken=()) regardless of the profile-precedence rule under test. The
  fixture here (`_write_export`) supplies the cipher, ECC-curve and
  certificate bindings the code requires.
- The `_one_vserver` fixture for
  test_a_bound_profile_that_was_not_read_... also left cipher/cert/ECC
  bindings and the certificate resource unsupplied, so the printed reason
  named FOUR missing sources and the test kept passing with the whole
  profile-precedence rule deleted. The fixture here supplies everything a
  real letter would need, so the bound-but-unread profile is the ONLY
  reason left, and the assertion pins that exact reason text.
- A fifth, self-measured correction: earlier
  prose called the ECC-curve binding a THIRD critical source next to cipher
  and cert ("VSRV-001 ... onleesbaar op drie kritieke bronnen"), but the
  draft grade_per_vserver() only checked two. Fixed here and covered by
  test_an_unreadable_ecc_curve_binding_is_niet_beoordeeld_not_a_silent_kex_100
  below - without it an unreadable ECC binding would silently score
  keyExchange=100, the BEST possible value, instead of costing the letter.

Two more tests below are the hardening-gate evidence for the T6 field_text/
field_token lesson, applied to `daystoexpiration` and `publickeysize`: both
arrive as JSON INTEGERS on the real fixture (measured), and field_text()
returns "" for any non-string on purpose - reading them with field_text
instead of field_token is a dead guard that would never catch an expired
certificate or a weak key.

The tests below are the fix evidence for a dedicated hardening pass's
findings. Each one fails without its corresponding
fix; the mutation that turns each one RED is named in that test's
own docstring.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.answer import stamp_data
from nsmcp.disclosure import Disclosure, names_from_export, render
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.rulesets import SSL_BASELINE
from nsmcp.tls_baseline import LETTERS, NOT_ASSESSED_WORD, grade_per_vserver, tls_baseline

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 8, 26)
_KNOWLEDGE = Knowledge(version="tlstest", date="2026-08-26", age_days=0, missing=False)


def test_the_two_readable_vservers_grade_c_and_the_third_is_unassessed():
    """The letter is NSHC's, the certainty is this
    product's own.

    An earlier round stripped the cipher GROUP name out of the cipher list
    before scoring, so these two vservers fell into the 50-branch and came
    out F (score 44). Measured against NSHC on the same export, that is
    two letters BELOW the healthcheck this module mirrors: NSHC's legacy
    per-vserver path puts the binding rows straight into its cipher list
    and reaches its own 50-branch only on an EMPTY list, so a group name
    scores 100 there - protocol 20, kex 60, cipher 100 -> 64 -> C.

    Parity wins on the letter. A 44 that no healthcheck produces is as
    much an invention as a silent 100 would be. What this product adds is
    the thing NSHC leaves unsaid: the group's members were never read, so
    the letter may not carry `[vastgesteld]`. Both halves are pinned here
    - the letter AND the marker - because either one alone would go green
    on the dishonest version of this answer."""
    export = load_export(FIXTURE)
    text = stamp_data(tls_baseline(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()

    assert "Vraag: welke TLS-instellingen wijken af van de baseline" in text
    assert "- VSRV-003: C (score 64) [niet vastgesteld]" in text
    assert "- VSRV-002: C (score 64) [niet vastgesteld]" in text
    assert "- VSRV-001: NIET BEOORDEELD [niet vastgesteld]" in text
    assert "- gradeverdeling: 2x C, 1x NIET BEOORDEELD [vastgesteld]" in text
    assert "- regelset: nshc-ssl-baseline 2026.08 [vastgesteld]" in text
    assert "    bewijs: Regelset nshc-ssl-baseline 2026.08 (2026-08-12)." in text
    # The letter never stands alone: the evidence line says on the spot
    # why it reads as it does, and the read gap is listed with the others.
    assert (
        "    bewijs: config/sslvserver + bindingen (bron: vserver);"
        " ciphergroep niet uitgeklapt; letter volgens de NSHC-regel"
    ) in text
    assert (
        "- VSRV-003: de gebonden ciphergroep is in deze export niet uitgeklapt,"
        " dus de ciphers zelf zijn niet gelezen; de letter volgt de NSHC-regel"
    ) in text
    # And nothing anywhere claims the score this product used to invent.
    assert "44" not in text
    assert "F (score" not in text


def test_the_kenmerken_of_the_real_export_are_named_in_plain_dutch():
    export = load_export(FIXTURE)
    grades = {g.vserver: g for g in grade_per_vserver(export)}
    # Measured: the code appends flags in THIS order -
    # _protocol_percent (ssl3/tls1.0/tls1.1/tls1.3), then _cipher_percent
    # (the cipher-group note is FIFTH), then _kex_percent (p224), then
    # hsts, then ocsp.
    # The SIXTH flag is
    # "cipher-volgorde onbetrouwbaar" again. With the group name back in
    # the cipher list (parity with NSHC), `_cipher_percent` no longer
    # returns early through the "no names" branch, so it reaches the
    # cipher-priority check - and these binding rows really do carry
    # no `cipherpriority`, which is exactly what NSHC flags there too.
    # The FIFTH flag, "ciphergroep niet uitgesplitst", is the one that
    # says the group's members were never read; it is what the read gap
    # on this grade hangs on.
    assert grades["VSRV-003"].kenmerken == (
        "ssl3 aan",
        "tls1.0 aan",
        "tls1.1 aan",
        "tls1.3 uit",
        "ciphergroep niet uitgesplitst",
        "cipher-volgorde onbetrouwbaar",
        "p224 curve",
        "hsts uit",
        "ocsp-stapling uit",
    )
    # The kenmerk and the read gap are two halves of one statement; a
    # kenmerk without the gap would leave the letter established.
    assert grades["VSRV-003"].read_gap is not None
    assert "niet uitgeklapt" in grades["VSRV-003"].read_gap.reason


def test_the_unexpanded_group_sentence_never_names_a_group_it_did_not_read(tmp_path):
    """The evidence sentence used to read
    "ciphergroep DEFAULT niet uitgeklapt".

    That was true of the real fixture and a fabrication anywhere else. The
    LEGACY path also fires on `DEFAULT_BACKEND`, and the PROFILE path fires
    on ANY group name at all - so a vserver bound to a group called something
    else would have been told, in the one sentence whose job is to say that
    something was NOT read, that the group was called DEFAULT. This proves it
    on a custom group name: the sentence stands, the invented name is gone,
    and the real name is not printed either (that is the disclosure gate one
    test over).
    """
    export = _write_export(
        tmp_path,
        "custom-group",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "eigen_profiel",
                "tls13": "ENABLED",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
            }
        ],
        profiles=[
            {
                "name": "eigen_profiel",
                "sslprofiletype": "FrontEnd",
                "tls13": "ENABLED",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        profile_cipher_parents={"eigen_profiel": [{"name": "eigen_profiel", "cipheraliasname": "ZQX_EIGEN_GROEP"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    # PREMISE: this really is the unexpanded-group path, or the assertions
    # below would hold for a reason that has nothing to do with the sentence.
    assert grade.read_gap is not None
    assert "ciphergroep niet uitgesplitst" in grade.kenmerken

    text = stamp_data(tls_baseline(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()
    assert "ciphergroep niet uitgeklapt; letter volgens de NSHC-regel" in text
    assert "DEFAULT" not in text, "een groepsnaam die niet gelezen is, hoort er niet te staan"
    assert "ZQX_EIGEN_GROEP" not in text, "en de echte naam evenmin - die is een naam"


def _by_parent(
    binding_resource: str, parents: dict, *, parent_resource: str = "sslvserver", parent_key: str = "vservername"
) -> dict:
    """The real NSHC 1.0 by-parent shape - see export.py::_flatten_by_parent.

    `parents` maps parentName -> rows. A value of None means outcome EMPTY
    (a genuinely read, empty binding for that parent) - a key simply ABSENT
    from `parents` means no parent entry at all (measured VSRV-001: unread).

    `parent_resource`/`parent_key` default to the vserver-keyed shape (the
    three original binding files); C1's profile-cipher-group binding is
    keyed by the PROFILE object instead (`parentResource: "sslprofile"`,
    `parentKey: "name"` - measured on the real fixture, 2026-09-07).
    """
    entries = []
    for name, rows in parents.items():
        if rows is None:
            entries.append({"parentName": name, "outcome": "EMPTY", "data": None})
        else:
            entries.append({"parentName": name, "outcome": "OK", "data": {binding_resource: rows}})
    return {
        "bindingResource": binding_resource,
        "parentResource": parent_resource,
        "parentKey": parent_key,
        "shape": "list",
        "parents": entries,
    }


def _write_export(
    tmp_path,
    name,
    *,
    vservers,
    profiles=(),
    certs=(),
    cipher_parents=None,
    ecc_parents=None,
    certkey_parents=None,
    profile_cipher_parents=None,
    cipher_group_parents=None,
    vserver_status="OK",
):
    """A minimal, hand-built export with real hashed binding files.

    `cipher_parents`/`ecc_parents`/`certkey_parents`/`profile_cipher_parents`
    /`cipher_group_parents` left at the default (None) skip writing that
    binding file entirely (unhashed -> a read gap for that source, same as
    a real export missing the file outright); pass a dict (even `{}`) to
    write the file with those parents. `vserver_status` overrides
    `config/sslvserver`'s manifest status (C3: "OK" by default; a caller
    proving the read-gap path passes an unusable value such as "FAILED").
    """
    export_dir = tmp_path / f"export-{name}"
    (export_dir / "objects").mkdir(parents=True, exist_ok=True)
    (export_dir / "bindings").mkdir(exist_ok=True)
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": list(vservers)}), encoding="utf-8"
    )
    (export_dir / "objects" / "sslprofile.json").write_text(
        json.dumps({"sslprofile": list(profiles)}), encoding="utf-8"
    )
    (export_dir / "objects" / "sslcertkey.json").write_text(json.dumps({"sslcertkey": list(certs)}), encoding="utf-8")
    resources = {
        "config/sslvserver": {"status": vserver_status},
        "config/sslprofile": {"status": "OK"},
        "config/sslcertkey": {"status": "OK"},
    }
    files: dict[str, str] = {}
    for file_name, binding_resource, parent_resource, parent_key, parents in (
        (
            "sslvserver_sslciphersuite_binding.by-parent.json",
            "sslvserver_sslciphersuite_binding",
            "sslvserver",
            "vservername",
            cipher_parents,
        ),
        (
            "sslvserver_ecccurve_binding.by-parent.json",
            "sslvserver_ecccurve_binding",
            "sslvserver",
            "vservername",
            ecc_parents,
        ),
        (
            "sslvserver_sslcertkey_binding.by-parent.json",
            "sslvserver_sslcertkey_binding",
            "sslvserver",
            "vservername",
            certkey_parents,
        ),
        (
            "sslprofile_sslcipher_binding.by-parent.json",
            "sslprofile_sslcipher_binding",
            "sslprofile",
            "name",
            profile_cipher_parents,
        ),
        ("sslcipher_binding.by-parent.json", "sslcipher_binding", "sslcipher", "name", cipher_group_parents),
    ):
        if parents is None:
            continue
        content = json.dumps(
            _by_parent(binding_resource, parents, parent_resource=parent_resource, parent_key=parent_key)
        ).encode("utf-8")
        (export_dir / "bindings" / file_name).write_bytes(content)
        files[f"bindings/{file_name}"] = hashlib.sha256(content).hexdigest()
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": resources,
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    # Seal the object files the way the real collector does, so the
    # collector's `payloadSha256` gate reads them instead of refusing this test's
    # own manifest. One shared helper, never a second hashing rule.
    seal_manifest(export_dir)
    return load_export(export_dir)


def test_the_profile_wins_over_the_vserver(tmp_path):
    """The measured trap from the lab lesson: reading tls13 off the vserver
    gives a false A where the bound profile says otherwise. B-2: the fixture
    now supplies the cipher/ECC/cert bindings the code requires, so the
    grade is not swallowed by the missing-binding branch before the
    precedence rule is ever exercised."""
    export = _write_export(
        tmp_path,
        "profile-wins",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "eigen_profiel",
                "tls13": "ENABLED",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
            }
        ],
        profiles=[
            {
                "name": "eigen_profiel",
                "sslprofiletype": "FrontEnd",
                "tls13": "DISABLED",
                "ssl3": "ENABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        # With a profile bound and read, ciphers come
        # from the PROFILE's own cipher-group binding, not this legacy
        # per-vserver one - present here only to prove it is NOT the source
        # consulted (the profile carries a DIFFERENT, weaker group below).
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "DEFAULT"}]},
        profile_cipher_parents={"eigen_profiel": [{"name": "eigen_profiel", "cipheraliasname": "DEFAULT"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "ssl3 aan" in grade.kenmerken, "de profielwaarde hoort te winnen van de vserver"
    assert grade.source == "profiel eigen_profiel"
    # A later fix moved the profile-bound DEFAULT group from
    # scoring 100 to 50 (correctly unexpanded, not a silent placeholder).
    # The weighted score (protocol 20 * 0.3 + kex 100 * 0.3 + cipher 50 * 0.4)
    # = (600 + 3000 + 2000) / 100 = 56 / letter C. Pinning these now to catch
    # future silent letter movements.
    assert grade.letter == "C", (
        "N1 correctly changed profile-DEFAULT from scoring like a real cipher (100) to the"
        " flagged-but-graded unexpanded-group score (50); the weighted result is C/56"
    )
    assert grade.score == 56, "weighted (protocol 20, kex 100, cipher 50) = 56"


def test_a_bound_profile_that_was_not_read_is_niet_beoordeeld_not_a_letter(tmp_path):
    """D-2 strengthened: the fixture supplies everything ELSE a real letter
    needs (all five protocol fields directly on the vserver too, so that a
    version WITHOUT the precedence rule would compute a real letter instead
    of coincidentally landing on NIET BEOORDEELD for a different reason),
    so the bound-but-unread profile is the ONLY reason left, and the
    assertion pins that exact reason text - not just "not a letter".

    Mutation-tested: deleting the profile-precedence
    short-circuit in tls_baseline.get() turns this RED, because the
    vserver's OWN ssl3/tls1/tls11/tls12/tls13 fields (all present here) then
    compute a real score instead.
    """
    export = _write_export(
        tmp_path,
        "profile-unread",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "ontbrekend_profiel",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "DISABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        profiles=[],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "DEFAULT"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "NIET BEOORDEELD"
    assert grade.score is None
    assert grade.reason == (
        "kritieke bron niet bruikbaar gelezen: gebonden SSL-profiel ontbrekend_profiel"
        " staat niet in de gelezen profiellijst"
    ), "de reden moet UITSLUITEND het onleesbare profiel noemen, geen verzamelgat"


def test_an_unreadable_ecc_curve_binding_is_niet_beoordeeld_not_a_silent_kex_100(tmp_path):
    """Self-measured fifth correction: earlier
    prose called the ECC-curve binding a third critical source next to
    cipher and cert, but the draft code never checked it. Cipher and cert
    read fine here; the ECC-curve binding file is written but carries no
    parent entry for VS1 at all (the measured VSRV-001 shape) - so this must
    cost the letter, not silently score keyExchange=100."""
    export = _write_export(
        tmp_path,
        "no-ecc-parent",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "DEFAULT"}]},
        ecc_parents={},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "NIET BEOORDEELD"
    assert grade.score is None


def test_expired_certificate_as_a_json_number_is_caught_not_a_dead_guard(tmp_path):
    """Hardening gate: daystoexpiration is a JSON integer
    on the real fixture (measured). field_text() returns "" for any
    non-string on purpose (T6 lesson); reading it with field_text instead
    of field_token would never catch an expired certificate. Turn
    field_token back into field_text for these two fields to see this go
    RED (see the report for the exact before/after)."""
    export = _write_export(
        tmp_path,
        "expired-cert",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": -5, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "DEFAULT"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "T"
    assert "verlopen certificaat" in grade.kenmerken


def test_a_weak_key_as_a_json_number_caps_the_letter_to_c(tmp_path):
    """Same hardening gate, for publickeysize. The score itself (from
    protocol/kex/cipher) does not change - only the letter is capped."""
    export = _write_export(
        tmp_path,
        "weak-key",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "DISABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "ocspstapling": "ENABLED",
                "maxage": "31536000",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 1024}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.score == 100, "de score verandert niet door de sleutelgate - alleen de letter"
    assert grade.letter == "C"
    assert "zwakke sleutel" in grade.kenmerken


def test_the_letter_vocabulary_is_the_pinned_one():
    assert LETTERS == ("A+", "A", "B", "C", "F", "T")
    assert NOT_ASSESSED_WORD == "NIET BEOORDEELD"
    # The vendored ruleset's certGate cap values must
    # themselves be within the pinned letter vocabulary - `_cap()` already
    # raises ValueError for a weakKeyCapsTo outside LETTERS; expiredCapsTo
    # had no such check at all before this fix.
    gate = SSL_BASELINE.rules["certGate"]
    assert gate["expiredCapsTo"] in LETTERS
    assert gate["weakKeyCapsTo"] in LETTERS


def test_the_vserver_names_are_masked_at_beperkt_but_the_letters_stay(tmp_path):
    export = load_export(FIXTURE)
    answer = tls_baseline(export, _KNOWLEDGE)
    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_tls_baseline",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "VSRV-001" in full, "zonder de echte naam in het volledige antwoord bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="beveiliging_tls_baseline",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "VSRV-001" not in limited
    assert "VSRV-003" not in limited
    # C (score 64), NSHC's own letter - see
    # test_the_two_readable_vservers_grade_c_and_the_third_is_unassessed.
    assert "C (score 64)" in limited, "het oordeel zelf is geen naam en hoort te blijven staan"


# ---------------------------------------------------------------------------
# A dedicated hardening pass: 6 Critical + 6 Important findings.
# ---------------------------------------------------------------------------


def test_the_cipher_source_is_the_profile_group_not_the_legacy_vserver_binding(tmp_path):
    """With a profile bound and READ, ciphers come
    from the cipher GROUP bound to the PROFILE - never from a legacy
    per-vserver ciphersuite binding, even when one is present and strong.
    Mutation-tested: reverting the cipher-source
    selection to always read CIPHER_BINDING turns this RED - the vserver's
    strong legacy cipher wins, letter A+ instead of the correct,
    profile-driven C.

    This fixture used to name the GROUP
    itself "WEAK-RC4-SHA" and rely on the (now-fixed) bug where an
    unexpanded group's own NAME stood in as a real cipher and was scored
    by pattern-matching that name - that was fixed: an unexpanded group
    contributes NOTHING to the cipher score (matches NSHC's own empty
    $cipherEntries). The group is now genuinely EXPANDED via
    `cipher_group_parents`, so this test again proves what it claims -
    the profile's real, expanded cipher members drive the score - and not
    an implementation quirk that was closed.
    """
    export = _write_export(
        tmp_path,
        "c1-cipher-source",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        profiles=[
            {
                "name": "prof1",
                "sslprofiletype": "FrontEnd",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        # The LEGACY per-vserver binding is present and STRONG - if the code
        # ever reads from here for a profile-bound vserver, the letter would
        # be A+, not the correct, profile-driven C.
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "zwakke_groep"}]},
        cipher_group_parents={"zwakke_groep": [{"name": "zwakke_groep", "ciphername": "WEAK-RC4-SHA"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "zwakke cipher" in grade.kenmerken, (
        "de PROFIEL-ciphergroep moet de score sturen, niet de sterke legacy vserver-binding"
    )
    assert "ciphergroep niet uitgesplitst" not in grade.kenmerken, (
        "de groep IS hier genuinely geexpandeerd - geen N1-kenmerk"
    )
    assert grade.letter == "C"
    assert grade.score == 60


def test_a_profile_cipher_group_binding_with_no_parent_entry_is_niet_beoordeeld(tmp_path):
    """C1: 'add that file to the critical-source list on the profile path'
    - a profile bound and READ whose OWN cipher-group binding file carries
    no parent entry at all for it (the file exists but names nothing for
    this profile) must drop the vserver to NIET BEOORDEELD, the same as an
    absent vserver-keyed cipher binding does on the no-profile path."""
    export = _write_export(
        tmp_path,
        "c1-cipher-source-absent",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        profile_cipher_parents={},  # file exists, zero parent entries for prof1
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "P_256"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "NIET BEOORDEELD"
    assert grade.reason == ("kritieke bron niet bruikbaar gelezen: sslprofile_sslcipher_binding.by-parent.json")


def test_the_profile_cipher_group_name_is_never_printed(tmp_path):
    """Hardening: this adds sslprofile_sslcipher_binding as
    a new source. Prove its group name never reaches answer text at ANY
    disclosure level - unlike a vserver/profile name (already masked at
    beperkt/minimaal by the eleventh disclosure family), the group name
    structurally never becomes a kenmerk or a reason: it only feeds
    _cipher_percent's FIXED vocabulary when unexpanded."""
    export = _write_export(
        tmp_path,
        "c1-cipher-name-hardening",
        vservers=[
            {
                "vservername": "VS1",
                "sslprofile": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "DISABLED",
                "ocspstapling": "DISABLED",
                "maxage": "0",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "GEHEIME_GROEPNAAM_XYZ"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    answer = tls_baseline(export, _KNOWLEDGE)
    full = render(
        answer,
        Disclosure.FULL,
        tool="beveiliging_tls_baseline",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "GEHEIME_GROEPNAAM_XYZ" not in full, (
        "de ciphergroepnaam mag NOOIT in antwoordtekst belanden, ook niet bij volledig"
    )

    # The premise the "gone at beperkt/minimaal" half of the hardening-eis
    # checks against: this module CAN print the vserver/profile names (the
    # eleventh disclosure family), so those still need masking below - the
    # cipher-group name is different in KIND (never printed at all, at any
    # level), and this confirms that difference rather than assuming it.
    assert "VS1" in full and "prof1" in full, "zonder de echte namen in het volledige antwoord bewijst dit niets"

    for disclosure, path_name in ((Disclosure.LIMITED, "tabel-bep.json"), (Disclosure.MINIMAL, "tabel-min.json")):
        rendered = render(
            answer,
            disclosure,
            tool="beveiliging_tls_baseline",
            extra_names=names_from_export(export),
            pseudonym_table_path=tmp_path / path_name,
        )
        assert "GEHEIME_GROEPNAAM_XYZ" not in rendered
        assert "VS1" not in rendered
        assert "prof1" not in rendered


def test_a_certkey_absent_from_config_sslcertkey_is_niet_beoordeeld(tmp_path):
    """A bound certkey that is NOT in config/sslcertkey
    must drop the vserver to NIET BEOORDEELD - never silently grade as
    'not expired, not weak' (which is what by_certkey.get(certkey, {})
    used to do, landing an unread certificate on the BEST letter)."""
    export = _write_export(
        tmp_path,
        "c2-certkey-absent",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[],  # onbekend_cert is bound but does not exist here
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "onbekend_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "NIET BEOORDEELD"
    assert grade.score is None


def test_a_missing_daystoexpiration_field_is_niet_beoordeeld_not_a_dead_pass(tmp_path):
    """C2, the second measured scenario: the certkey object IS present, but
    `daystoexpiration` is absent from it entirely - also a read gap, not a
    silent 'not expired'."""
    export = _write_export(
        tmp_path,
        "c2-daystoexpiration-absent",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "test_cert", "publickeysize": 2048}],  # no daystoexpiration key at all
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "NIET BEOORDEELD"
    assert grade.score is None


def test_an_unreadable_sslvserver_resource_is_niet_beoordeeld_with_a_read_gap(tmp_path):
    """An unreadable config/sslvserver must never
    print '[vastgesteld]' with zero read gaps - that used to read exactly
    like the genuinely-empty case (a real export with zero vservers), which
    is a DIFFERENT, established fact."""
    export = _write_export(tmp_path, "c3-vserver-unreadable", vservers=[], vserver_status="FAILED")
    answer = tls_baseline(export, _KNOWLEDGE)
    assert any(gap.source == "config/sslvserver" for gap in answer.read_gaps), "het leesgat moet doorgegeven worden"
    text = stamp_data(answer, export.collected_at, TODAY, export.target_name).to_text()
    assert "- gradeverdeling: NIET BEOORDEELD [niet vastgesteld]" in text
    assert "geen sslvserver gelezen" not in text
    assert "geen enkele sslvserver gevonden" not in text


def test_a_genuinely_empty_sslvserver_resource_gets_its_own_wording(tmp_path):
    """C3: the genuinely-empty case (config/sslvserver reads fine, holds
    zero vservers) must use DIFFERENT wording than the read-gap case above
    - both used to share one ESTABLISHED sentence that read as 'not read'
    either way."""
    export = _write_export(tmp_path, "c3-vserver-empty", vservers=[])
    text = stamp_data(tls_baseline(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()
    assert "- gradeverdeling: geen enkele sslvserver gevonden [vastgesteld]" in text


def test_a_ca_only_binding_does_not_count_as_a_server_certificate(tmp_path):
    """A binding whose ONLY certkey has ca=true is
    client-certificate VALIDATION, not a server identity - mirrors NSHC's
    Test-NshcIsServerCertBinding. Must grade T (no-server-cert-bound), never
    a normal letter as if a server certificate were present."""
    export = _write_export(
        tmp_path,
        "c4-ca-only",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "klant_ca", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "klant_ca", "ca": True}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "T"
    assert "geen servercert gebonden" in grade.kenmerken


def test_a_confirmed_empty_cert_binding_grades_t_not_niet_beoordeeld(tmp_path):
    """A cert-binding parent that is PRESENT with a
    confirmed-empty outcome (the file WAS usably read - this vserver simply
    has no certificate bound) must grade T, not NIET BEOORDEELD. NSHC's own
    three-way distinction: 'response present + 0 bindings' is a BEVINDING,
    never a leesgat."""
    export = _write_export(
        tmp_path,
        "c5-cert-binding-empty",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": None},  # outcome EMPTY, confirmed zero bindings for VS1
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "T"
    assert "geen servercert gebonden" in grade.kenmerken


def test_a_confirmed_empty_cipher_binding_grades_default_cipher_group_not_niet_beoordeeld(tmp_path):
    """C5, the cipher-side sibling: a confirmed-empty per-vserver cipher
    binding must grade 'default-cipher-group' (cipherPct 50, NSHC's own
    scoring for a response with 0 bindings) - not NIET BEOORDEELD."""
    export = _write_export(
        tmp_path,
        "c5-cipher-binding-empty",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "test_cert", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": None},  # outcome EMPTY, confirmed zero ciphers for VS1
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "test_cert"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter != "NIET BEOORDEELD"
    assert "geen expliciete ciphers" in grade.kenmerken


def test_a_confirmed_empty_ecc_curve_binding_grades_kex_100_not_niet_beoordeeld(tmp_path):
    """A vserver that legitimately binds NO ECC curve
    (RSA-only, or curves left at the appliance default) must grade a
    letter with kexPct 100 - NSHC's own $criticalReads does not list the
    ECC-curve binding at all, and Get-NshcSslVserverFacts leaves eccCurves
    empty on a confirmed-empty response. C5's three-way _parents()
    distinction is what makes this correct (parent PRESENT, zero rows)
    rather than the over-correction the first implementation round shipped
    (parent ABSENT is still, correctly, NIET BEOORDEELD - see
    test_an_unreadable_ecc_curve_binding_is_niet_beoordeeld_not_a_silent_kex_100
    above, unaffected by this fix)."""
    export = _write_export(
        tmp_path,
        "i4-ecc-confirmed-empty",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": None},  # outcome EMPTY, confirmed zero ECC curves for VS1
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter != "NIET BEOORDEELD"
    assert "p224 curve" not in grade.kenmerken


def test_an_ecc_certificate_is_never_flagged_as_a_weak_key(tmp_path):
    """A P-256 ECDSA certificate (publickeysize 256,
    well under minRsaBits) must NOT be flagged as a weak RSA key - mirrors
    NSHC's isEcc gate. Mutation-tested: removing the ECC
    skip turns this RED - letter C (weak-key cap) instead of A."""
    export = _write_export(
        tmp_path,
        "c6-ecc-not-weak",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[
            {
                "certkey": "ecc1",
                "daystoexpiration": 400,
                "publickeysize": 256,
                "signaturealg": "ecdsa-with-SHA256",
                "publickey": "ecPublicKey",
            }
        ],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "ecc1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "zwakke sleutel" not in grade.kenmerken
    assert grade.letter == "A"


def test_hsts_and_ocsp_come_only_from_the_profile_never_the_vserver(tmp_path):
    """With NO profile bound, hsts/ocsp/maxage stay
    UNSET - even when the VSERVER's own fields say otherwise. NSHC never
    reads these three off the vserver, only off a bound-and-read profile."""
    export = _write_export(
        tmp_path,
        "i1-vserver-fields-ignored",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "ocspstapling": "ENABLED",
                "maxage": "99999999",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "hsts uit" in grade.kenmerken, "zonder profiel moet hsts als UIT gelden, ook al staat het op de vserver aan"
    assert "ocsp-stapling uit" in grade.kenmerken
    assert grade.letter == "A", "de A+->A-cap moet nog steeds gelden ondanks het (genegeerde) vserver-veld"


def test_the_nshc_hstsmaxage_field_is_read_before_the_measured_maxage_alias(tmp_path):
    """NSHC's own field name (`hstsmaxage`) is read FIRST; the measured
    alias (`maxage`) only when the NSHC name is absent. Here the profile
    carries BOTH, with DIFFERENT values - a small, non-compliant
    `hstsmaxage` and a large, compliant `maxage`. If the alias were read
    first (or instead), this would stay A+; NSHC's own field must win."""
    export = _write_export(
        tmp_path,
        "i1-field-name-precedence",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "hstsmaxage": "10",
                "maxage": "99999999",
                "ocspstapling": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        # The group is genuinely EXPANDED
        # here (not left to the unexpanded-name fallback) so this test's
        # cipher score is a real, established 100 - isolating the HSTS
        # behaviour actually under test from N1's "unexpanded group scores
        # default-cipher-group (50)" fix.
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "sterke_groep"}]},
        cipher_group_parents={"sterke_groep": [{"name": "sterke_groep", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "hsts maxage te laag" in grade.kenmerken, (
        "NSHC's hstsmaxage=10 moet winnen van de gemeten alias maxage=99999999"
    )
    assert grade.letter == "A"


def test_hsts_compliant_maxage_stays_a_plus(tmp_path):
    """A compliant HSTS configuration (ENABLED,
    max-age at the threshold) must land on A+ - the premise the sibling
    test below caps FROM."""
    export = _write_export(
        tmp_path,
        "i5-hsts-compliant",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "hstsmaxage": "31536000",
                "ocspstapling": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        # The group is genuinely EXPANDED
        # here (not left to the unexpanded-name fallback) so this test's
        # cipher score is a real, established 100 - isolating the HSTS
        # behaviour actually under test from N1's "unexpanded group scores
        # default-cipher-group (50)" fix.
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "sterke_groep"}]},
        cipher_group_parents={"sterke_groep": [{"name": "sterke_groep", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "A+"
    assert grade.score == 100
    assert "hsts uit" not in grade.kenmerken
    assert "hsts maxage te laag" not in grade.kenmerken


def test_hsts_maxage_one_below_threshold_caps_to_a(tmp_path):
    """A related check: changing ONLY the max-age to hstsMinAge - 1 (31535999)
    must cap A+ to A with kenmerk 'hsts maxage te laag' - pinning
    `hstsMinAge` itself, not just the A+ threshold. Verified by mutation:
    lowering hstsMinAge in the ruleset to 31535999
    turns this RED (the same max-age then reads as compliant)."""
    export = _write_export(
        tmp_path,
        "i5-hsts-one-below",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "hstsmaxage": "31535999",
                "ocspstapling": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        # The group is genuinely EXPANDED
        # here (not left to the unexpanded-name fallback) so this test's
        # cipher score is a real, established 100 - isolating the HSTS
        # behaviour actually under test from N1's "unexpanded group scores
        # default-cipher-group (50)" fix.
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "sterke_groep"}]},
        cipher_group_parents={"sterke_groep": [{"name": "sterke_groep", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "A"
    assert grade.score == 100
    assert "hsts maxage te laag" in grade.kenmerken


def test_hstsmaxage_as_a_json_int_still_reads_as_compliant(tmp_path):
    """MEASURED: `_profile_only()` read hstsmaxage/
    maxage with `field_text()`, which returns "" for any non-string.
    `hstsmaxage` is a plausible JSON INT on this same resource
    (`sslprofile` already mixes types on the real fixture - `cleartextport`
    is an int) - and when it is, `max_age_text` fell through the
    `_profile_only(...) or _profile_only(...) or "0"` chain to the literal
    "0", which is BELOW `hstsMinAge` - so a COMPLIANT, well-configured
    vserver was wrongly capped from A+ to A with kenmerk "hsts maxage te
    laag", with no read gap to explain why. Same fixture as
    test_hsts_compliant_maxage_stays_a_plus above, ONLY hstsmaxage
    changed from the string "31536000" to the JSON int 31536000."""
    export = _write_export(
        tmp_path,
        "i2-hstsmaxage-int",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
                "hsts": "ENABLED",
                "hstsmaxage": 31536000,
                "ocspstapling": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "sterke_groep"}]},
        cipher_group_parents={"sterke_groep": [{"name": "sterke_groep", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.letter == "A+"
    assert grade.score == 100
    assert "hsts maxage te laag" not in grade.kenmerken


def test_round_not_truncate_gives_the_same_letter_as_nshc(tmp_path):
    """PowerShell's [int] cast ROUNDS half-to-even;
    Python's int() truncates. A measured example: 22 weak
    ciphers of 25 with protocol 100 and kex 100 gives an exact weighted
    64.8. int(64.8) truncates to 64 -> letter C; round(64.8) rounds to 65 ->
    letter B, matching NSHC. Mutation-tested: reverting
    round() to int() at both call sites turns this RED (score 64, letter
    C)."""
    weak_rows = [{"vservername": "VS1", "ciphername": f"TLS1.2-RSA-AES256-CBC-SHA{i}"} for i in range(22)]
    strong_rows = [
        {"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"},
        {"vservername": "VS1", "ciphername": "TLS1.2-ECDHE-RSA-AES256-GCM-SHA256"},
        {"vservername": "VS1", "ciphername": "TLS1.2-ECDHE-ECDSA-AES256-GCM-SHA384"},
    ]
    export = _write_export(
        tmp_path,
        "i3-round-not-truncate",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": weak_rows + strong_rows},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert grade.score == 65
    assert grade.letter == "B"


def test_a_certgate_cap_value_outside_letters_raises_consistently_with_cap(tmp_path, monkeypatch):
    """A certGate cap value outside LETTERS must
    raise where the gate is read - `_cap()` already raises (ValueError, via
    _CAP_ORDER.index()) for a bad weakKeyCapsTo; expiredCapsTo had NO check
    at all before this fix and would have become a silent seventh letter."""
    export = _write_export(
        tmp_path,
        "i6-bad-certgate",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        cipher_parents={"VS1": [{"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]},
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    monkeypatch.setitem(SSL_BASELINE.rules["certGate"], "expiredCapsTo", "Z")
    with pytest.raises(ValueError):
        grade_per_vserver(export)


# ---------------------------------------------------------------------------
# A follow-up hardening pass, against the findings above.
# ---------------------------------------------------------------------------


def test_a_custom_cipher_group_name_that_cannot_be_expanded_is_flagged_and_scored_like_nshc(tmp_path):
    """First half: a profile-bound cipher GROUP
    that cannot be expanded (this export simply never carries
    sslcipher_binding.by-parent.json - the common, honest case, also true
    of the real fixture) must be flagged 'ciphergroep niet uitgesplitst'
    for ANY group name - not only DEFAULT/DEFAULT_BACKEND - and scored the
    way NSHC does: an unexpandable group contributes NO real cipher names
    at all (never the group's own NAME standing in as if it were a
    best-case cipher), landing on NSHC's own 'default-cipher-group'
    treatment (cipherPct 50, Invoke-NshcSslGrade.ps1:335), never a silent
    100.

    The measured repro: profile bound and read,
    group name 'MIJN_EIGEN_GROEP', everything else perfect. BEFORE this
    fix: 'A score 100', kenmerken ('cipher-volgorde onbetrouwbaar', 'hsts
    uit', 'ocsp-stapling uit') - no cipher-group kenmerk at all, a
    favourable score on a source that was never read.
    """
    export = _write_export(
        tmp_path,
        "n1-custom-group-not-expanded",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "MIJN_EIGEN_GROEP"}]},
        # No cipher_group_parents at all - sslcipher_binding.by-parent.json
        # is simply not carried by this export (state 1 of the three N1
        # measured: also true of the real fixture, measured 2026-09-06/07).
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    # PREMISE: this must be a real, GRADED letter, not NIET BEOORDEELD - an
    # unexpanded group is an honest finding (like a bare "DEFAULT" binding
    # already was), never a read gap that costs the letter itself. If this
    # assertion ever fails, the flag/score assertions below prove nothing
    # about the branch N1 fixes.
    assert grade.letter != NOT_ASSESSED_WORD
    assert grade.score is not None
    assert "ciphergroep niet uitgesplitst" in grade.kenmerken, (
        "elke groepsnaam moet dit kenmerk geven, niet alleen DEFAULT/DEFAULT_BACKEND"
    )
    assert "geen expliciete ciphers" in grade.kenmerken, (
        "NSHC scoort een niet-uitgesplitste groep als default-cipher-group (cipherPct 50)"
    )
    # weights protocol/keyExchange/cipher = 30/30/40 (measured); protocol
    # and kex are both perfect (100) here, cipher lands on 50:
    # round((100*30 + 100*30 + 50*40) / 100) = 80.
    assert grade.score == 80
    assert grade.letter == "A"
    # The group name itself must never leak into the grade's own reason -
    # names_in_tls_sources()/render() coverage for the rendered TEXT is
    # test_the_profile_cipher_group_name_is_never_printed above; this
    # is the same guarantee at the Grade level.
    assert "MIJN_EIGEN_GROEP" not in grade.reason


def test_a_broken_cipher_group_expansion_file_is_niet_beoordeeld_not_silently_unexpanded(tmp_path):
    """Second half: a cipher-group expansion file
    that IS declared in the manifest but cannot be trusted (hash mismatch)
    is a GENUINE ReadGap - it must drop the vserver to NIET BEOORDEELD,
    never silently collapse into the same lenient "unexpanded group name"
    fallback the file-not-carried-at-all state gets (see the test above).
    `_parents()` would have discarded this specific gap (grouped_bindings()
    returning `({}, ReadGap(...))`, collapsed to `{}`); grade_per_vserver()
    now reads export.grouped_bindings() directly for this ONE lookup to
    keep it - the same C5 mechanism (export.py::_flatten_by_parent's
    three-way result), not a second one.
    """
    export_dir = tmp_path / "export-n1-broken-group"
    export = _write_export(
        tmp_path,
        "n1-broken-group",
        vservers=[{"vservername": "VS1", "sslprofile": "prof1"}],
        profiles=[
            {
                "name": "prof1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        profile_cipher_parents={"prof1": [{"name": "prof1", "cipheraliasname": "GEHEIME_KAPOTTE_GROEP"}]},
        cipher_group_parents={
            "GEHEIME_KAPOTTE_GROEP": [{"name": "GEHEIME_KAPOTTE_GROEP", "ciphername": "TLS1.3-AES256-GCM-SHA384"}]
        },
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    # PREMISE: with the expansion file intact, this vserver grades a real
    # letter - proving the corruption below (and nothing else) causes the
    # NIET BEOORDEELD result.
    clean_grade = grade_per_vserver(export)[0]
    assert clean_grade.letter != NOT_ASSESSED_WORD
    assert clean_grade.score is not None

    # Corrupt the on-disk bytes AFTER the manifest hash was already
    # computed from the clean content - a genuine "hash wijkt af van het
    # manifest" ReadGap (state 3 of the three N1 measured), not a "file
    # not carried" absence (state 1, the test above).
    group_file = export_dir / "bindings" / "sslcipher_binding.by-parent.json"
    group_file.write_bytes(group_file.read_bytes() + b" ")
    broken_export = load_export(export_dir)

    grade = grade_per_vserver(broken_export)[0]
    assert grade.letter == NOT_ASSESSED_WORD
    assert grade.score is None
    assert "sslcipher_binding.by-parent.json" in grade.reason
    assert "GEHEIME_KAPOTTE_GROEP" not in grade.reason, "de groepsnaam mag nooit in de reden lekken"


def test_the_cipher_priority_sort_decides_which_cipher_is_first(tmp_path):
    """The cipher-priority SORT was correct in the code but
    completely ungated - the full suite stayed at 1176 passed with the
    sort removed. Here the FILE order is the REVERSE of the
    cipherpriority values: the STRONG cipher is listed FIRST in the
    binding file, the WEAK cipher SECOND - but the weak one carries the
    LOWER (higher-priority) cipherpriority value. Only sorting by
    cipherpriority puts the weak cipher first.

    Mutation-tested:
    `ordered = sorted(priority_rows, key=...)` -> `ordered = priority_rows`
    (sort removed) turns this RED - the legacy-first check then reads the
    STRONG cipher (still first in raw file order) and 'zwakke cipher
    vooraan' never fires.
    """
    export = _write_export(
        tmp_path,
        "n2-sort-decides-first",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        # File order: STRONG first, WEAK second - the REVERSE of their
        # cipherpriority values (weak=1, i.e. the HIGHEST priority).
        cipher_parents={
            "VS1": [
                {"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384", "cipherpriority": "2"},
                {"vservername": "VS1", "ciphername": "TLS1.2-RSA-AES128-CBC-SHA", "cipherpriority": "1"},
            ]
        },
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    # PREMISE: both priorities parse as integers, so the legacy-first test
    # actually RUNS here rather than being skipped (that is N2's OTHER
    # half, proven by the sibling test below) - if this were unreliable,
    # "zwakke cipher vooraan" firing below would prove nothing about the
    # SORT.
    assert "cipher-volgorde onbetrouwbaar" not in grade.kenmerken
    assert "zwakke cipher vooraan" in grade.kenmerken, (
        "de SORTERING op cipherpriority moet bepalen welke cipher als eerste telt, niet de bestandsvolgorde"
    )
    # A test that pins the kenmerken but neither
    # the letter nor the score does not see a VERDICT move - an earlier gap
    # here once let a silent B->C shift through unnoticed. MEASURED:
    # TLS1.2/1.3 only, weak cipher first by priority, no HSTS/OCSP -> B 76.
    assert grade.letter == "B"
    assert grade.score == 76


def test_an_unreliable_cipher_priority_skips_the_legacy_first_test(tmp_path):
    """N2, the other half: a WEAK cipher literally FIRST in file order,
    with a NON-INTEGER cipherpriority, must SKIP the legacy-first test
    entirely - 'cipher-volgorde onbetrouwbaar' fires, 'zwakke cipher
    vooraan' must NOT, even though the raw file order alone would suggest
    it should. Mutation-tested: the full
    suite stayed at 1176 passed with the skip removed (falling back to a
    "safe" parse instead).

    The specific mutation this test catches: falling
    back to the file's own row order (`priority_rows[0]`) as a stand-in
    for priority when unreliable, instead of skipping the test outright -
    the exact anti-pattern already warned
    against above ("rather than testing the file's own row order"). Under that
    mutation the weak cipher IS first in file order and 'zwakke cipher
    vooraan' fires; this test turns RED.
    """
    export = _write_export(
        tmp_path,
        "n2-unreliable-priority-skips",
        vservers=[
            {
                "vservername": "VS1",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": "ENABLED",
                "tls13": "ENABLED",
            }
        ],
        certs=[{"certkey": "c1", "daystoexpiration": 400, "publickeysize": 2048}],
        # WEAK cipher literally FIRST in file order; its OWN priority is
        # non-numeric ("abc") - NSHC :229: ANY non-integer priority on
        # this vserver makes the whole order unreliable. The second cipher
        # also gets a non-integer priority ("xyz") so under ANY fallback
        # ordering (safe-parse sorting unparseable last), both are unparseable
        # and the weak cipher stays first in file order, proving the SKIP is
        # what suppresses 'zwakke cipher vooraan', not a coincidence of data.
        cipher_parents={
            "VS1": [
                {"vservername": "VS1", "ciphername": "TLS1.2-RSA-AES128-CBC-SHA", "cipherpriority": "abc"},
                {"vservername": "VS1", "ciphername": "TLS1.3-AES256-GCM-SHA384", "cipherpriority": "xyz"},
            ]
        },
        ecc_parents={"VS1": [{"vservername": "VS1", "ecccurvename": "X25519"}]},
        certkey_parents={"VS1": [{"vservername": "VS1", "certkeyname": "c1"}]},
    )
    grade = grade_per_vserver(export)[0]
    assert "cipher-volgorde onbetrouwbaar" in grade.kenmerken
    assert "zwakke cipher vooraan" not in grade.kenmerken, (
        "onbetrouwbare volgorde moet de legacy-first-test SKIPPEN, niet de bestandsvolgorde als vervanger gebruiken"
    )
    # Pin the VERDICT too, not only the kenmerken
    # (same reasoning as the sibling test above). MEASURED: same weights as
    # the sibling case (skip instead of a hit still costs one weak-cipher
    # kenmerk) -> B 76.
    assert grade.letter == "B"
    assert grade.score == 76
