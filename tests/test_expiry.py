from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import add_cert_usage_sources, seal_manifest

from nsmcp.answer import Certainty
from nsmcp.expiry import CERT_BINDING, RESOURCE, VSERVER_BINDING, bucket, what_expires
from nsmcp.knowledge import Knowledge


class ExportStub:
    def __init__(self, certs, gap=None, bindings=None):
        self._certs, self._gap = certs, gap
        # {file_name: (rows, gap)} - the previous
        # version of this stub ignored `file_name` and answered ([], None)
        # for EVERY source, so it could not express "one binding file
        # parsed, the other did not" - precisely what usage_per_certificate()
        # branches on. A file name absent from this mapping still answers
        # ([], None): every pre-A8 test in this file relies on that (no
        # usage-state fixture, every certificate comes out "los").
        self._bindings = bindings or {}

    # "los" needs every source that could refute it read, the three sources
    # of the certificate use outside the bindings included
    # (`nsmcp.cert_usage`). This stub stands for a complete read, so it
    # carries them - read, and empty: `status` knows every resource, the
    # servicegroup file has a hash, and every object source other than the
    # certificates answers an empty list.
    file_hashes = {"bindings/sslservicegroup_sslcertkey_binding.by-parent.json": "stub"}

    # Collected today (UTC): the counts in these rows are the counts of
    # today, so the age correction (1.0.2) is zero. A stub without a
    # date is a different case, pinned by the 1.0.2 tests at the end.
    collected_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def status(self, resource):
        return "OK"

    def binding_parents(self, file_name):
        from nsmcp.export import ParentCoverage

        return ParentCoverage()

    def objects(self, resource):
        if resource != RESOURCE:
            return ([], None)
        return (self._certs, self._gap)

    def bindings(self, file_name):
        return self._bindings.get(file_name, ([], None))

    def binding_rows(self, file_name, *, children=None):
        # The list form with child keys, as `Export.binding_rows` returns it:
        # every row under the file's own binding resource, one parent.
        rows, gap = self._bindings.get(file_name, ([], None))
        if gap is not None:
            return {}, gap
        resource = file_name.split(".", 1)[0]
        return ({"(stub)": [(resource, row) for row in rows]} if rows else {}), None

    def binding_child_keys(self, file_name):
        rows, gap = self._bindings.get(file_name, ([], None))
        return ({}, gap) if gap is not None else ({"(stub)": ()} if rows else {}, None)


FRESH = Knowledge(version="2026.08", date="2026-08-16", age_days=3, missing=False)


def test_the_ladder_follows_nshc():
    assert bucket(-1) == "expired"
    assert bucket(0) == "critical"
    assert bucket(14) == "critical"
    assert bucket(15) == "warning"
    assert bucket(30) == "warning"
    assert bucket(60) == "notice"
    assert bucket(90) == "horizon"
    assert bucket(91) == "ok"


def test_non_numeric_days_are_unknown_not_zero():
    assert bucket(None) == "unknown"
    assert bucket("") == "unknown"
    assert bucket("binnenkort") == "unknown"


def test_float_shaped_whole_numbers_are_assessed_normally():
    """Regression: 14.0 is a number, not text. bucket() must not degrade a
    cert to "unknown" merely because the source sends a float instead of an
    int - the rule is that a NON-numeric value is unassessable, not that a
    numeric value in a different format becomes so."""
    assert bucket(14.0) == "critical"
    assert bucket(15.0) == "warning"
    assert bucket(90.0) == "horizon"
    assert bucket(-1.0) == "expired"
    assert bucket("14.0") == "critical"


def test_float_with_fractional_part_rounds_down():
    """Deliberate choice for a float with a fractional part: round down
    (math.floor), never up. The ladder is monotonic in days, so rounding
    down never yields a less urgent class than the real fractional number of
    days justifies - fail-closed, like the rest of bucket()."""
    assert bucket(14.7) == "critical"  # would be "warning" when rounding up
    assert bucket(-0.3) == "expired"  # would be "critical" when rounding up


def test_only_certificates_within_the_horizon():
    certs = [
        {"certkey": "cert_dichtbij", "daystoexpiration": 12},
        {"certkey": "cert_veraf", "daystoexpiration": 400},
    ]
    a = what_expires(ExportStub(certs), FRESH, horizon_days=90)
    subjects = [b.subject for b in a.findings]
    assert "cert_dichtbij" in subjects
    assert "cert_veraf" not in subjects


def test_certificate_without_readable_expiry_is_reported_as_not_established():
    certs = [{"certkey": "cert_raar", "daystoexpiration": "onbekend"}]
    a = what_expires(ExportStub(certs), FRESH, horizon_days=90)
    b = a.findings[0]
    assert b.certainty is Certainty.NOT_ESTABLISHED
    assert b.reason


def test_unknown_expiry_bypasses_the_horizon_filter():
    """Pinned, deliberate behavior: a certificate with an unassessable
    expiry skips the horizon filter and is always reported, even when the
    requested window is so narrow that no number would fit inside it.
    Fail-closed: an unassessable certificate must not silently drop out."""
    certs = [{"certkey": "cert_onbekend", "daystoexpiration": "onbekend"}]
    a = what_expires(ExportStub(certs), FRESH, horizon_days=1)
    subjects = [b.subject for b in a.findings]
    assert "cert_onbekend" in subjects


def test_failed_read_does_not_yield_a_reassuring_empty_answer():
    from nsmcp.answer import ReadGap

    a = what_expires(
        ExportStub([], gap=ReadGap(source="config/sslcertkey", reason="RBAC_DENIED")),
        FRESH,
        horizon_days=90,
    )
    assert a.findings == []
    assert a.is_complete() is False


def test_knowledge_age_travels_with_the_answer():
    a = what_expires(ExportStub([]), FRESH, horizon_days=90)
    assert a.knowledge_age_days == 3
    assert a.knowledge_date == "2026-08-16"


# ---------------------------------------------------------------------------
# This test deliberately uses a REAL `Export` (`load_export`), not the
# `ExportStub` above, so it exercises the element validation in export.py
# itself - the stub could never show this gap, because it always returns
# `certs` ready-made without ever reading an object file. Without the
# per-element check, the REAL `what_expires()` crashes here with a bare
# AttributeError as soon as it tries `.get("certkey")` on the non-object
# element.
# ---------------------------------------------------------------------------


def test_string_element_in_the_object_file_is_a_read_gap_not_a_crash(tmp_path):
    import json

    from nsmcp.export import load_export

    dir_ = tmp_path / "export"
    (dir_ / "objects").mkdir(parents=True)
    (dir_ / "bindings").mkdir(parents=True)
    (dir_ / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "cert_a", "daystoexpiration": 12}, "niet-een-object"]}),
        encoding="utf-8",
    )
    (dir_ / "export-manifest.json").write_text(
        json.dumps(
            {
                "collectedAtUtc": "2026-08-19T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(dir_)  # an object file without its hash is a read gap
    export = load_export(dir_)

    a = what_expires(export, FRESH, horizon_days=90)

    assert a.read_gaps, "een niet-object element moet als leesgat in het ANTWOORD landen, geen crash"
    assert a.findings == [], "geen bevinding mag uit een niet-object element voortkomen"
    assert a.is_complete() is False


# ---------------------------------------------------------------------------
# The usage state per certificate, and the impact ordering it feeds into
# `what_expires`: bound, issuer-only, unbound or unknown, in that order of
# consequence.
# ---------------------------------------------------------------------------


def test_the_usage_state_of_the_real_export():
    from pathlib import Path

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    usage = {u.certkey: u for u in usage_per_certificate(export)}
    assert usage["CERT-009"].state == "gebonden"
    assert usage["CERT-009"].used_by == ("VSRV-002", "VSRV-003")
    assert usage["CERT-004"].state == "uitgever"
    assert usage["CERT-004"].used_by == ("CERT-009",)
    # Read through the aggregate cert-side file: eight service bindings.
    assert usage["ns-server-certificate"].state == "gebonden"
    assert usage["ns-server-certificate"].used_by == ()


def test_an_issuing_certificate_is_never_called_los_or_offered_for_cleanup(tmp_path):
    """The NSHC 1.1.0 regression as a fixture: an issuing certificate with zero
    vserver bindings must never come out as 'los'."""
    import json

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "root-ca", "daystoexpiration": 3000},
                    {"certkey": "leaf", "daystoexpiration": 100, "linkcertkeyname": "root-ca"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
        '"resources":{"config/sslcertkey":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usage = {u.certkey: u for u in usage_per_certificate(load_export(export_dir))}
    assert usage["root-ca"].state == "uitgever"
    assert usage["root-ca"].state != "los"


def test_two_certificates_on_one_vserver_are_both_gebonden(tmp_path):
    """SNI: two certificates on the same vserver. Both are in use."""
    import hashlib
    import json

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "cert-a", "daystoexpiration": 10},
                    {"certkey": "cert-b", "daystoexpiration": 20},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": "VS_SNI"}]}), encoding="utf-8"
    )
    raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [
                {
                    "parentName": "VS_SNI",
                    "outcome": "OK",
                    "data": {
                        "sslvserver_sslcertkey_binding": [
                            {"certkeyname": "cert-a", "vservername": "VS_SNI", "snicert": True},
                            {"certkeyname": "cert-b", "vservername": "VS_SNI", "snicert": True},
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}, "config/sslvserver": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        raw.encode("utf-8")
                    ).hexdigest()
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usage = {u.certkey: u for u in usage_per_certificate(load_export(export_dir))}
    assert usage["cert-a"].state == "gebonden"
    assert usage["cert-b"].state == "gebonden"


def test_the_answer_sorts_on_impact_not_on_days():
    from datetime import date
    from pathlib import Path

    from nsmcp.answer import stamp_data
    from nsmcp.expiry import what_expires
    from nsmcp.export import load_export
    from nsmcp.knowledge import Knowledge

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    answer = stamp_data(
        what_expires(
            export, Knowledge(version="a8", date="2026-08-26", age_days=0, missing=False), 3650, today=date(2026, 8, 26)
        ),
        export.collected_at,
        date(2026, 8, 26),
        export.target_name,
    )
    order = [f.subject for f in answer.findings]
    # ns-server-certificate moved from "onbekend" (last) to "gebonden": the
    # cert-side file is read now, and it carries eight service bindings for
    # that certificate (the management services of the appliance itself).
    assert order == ["CERT-009", "ns-server-certificate", "CERT-004"], (
        "gebonden eerst met de kortste horizon vooraan, dan uitgevers, dan los, dan onbekend"
    )
    text = answer.to_text()
    assert "verloopt over 817 dagen (ok) - gebonden aan VSRV-002, VSRV-003" in text
    assert "verloopt over 1817 dagen (ok) - uitgever van CERT-009" in text
    assert "verloopt over 3642 dagen (ok) - gebonden" in text
    assert "sleutel 2048 bits, sha256WithRSAEncryption" in text
    # The closing "gebruiksstand" sentence is NOT a
    # Finding - it inflated disclosure._minimal()'s customer-facing count
    # and wore a [vastgesteld] tag it did not earn. It is already product
    # surface in the tool description (mcp_server.py); nothing is lost.
    assert all(f.subject != "gebruiksstand" for f in answer.findings)
    assert "Deze lijst is invoer voor certificaatbeheer" not in text
    assert answer.read_gaps == [], "sslcertkey_binding is gelezen in de aggregate-vorm"
    # A raw export value must never reach the
    # rendered evidence line - the parsed day count already sits in outcome.
    assert "daystoexpiration" not in text


def test_a_certificate_bound_nowhere_when_both_sources_read_is_los(tmp_path):
    """The fourth word - the one the whole NSHC regression is about
    (no test produced it before). Both binding
    sources parse cleanly and neither lists the certificate: only THEN is
    "los" an honest claim."""
    import hashlib
    import json

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "cert-alleen", "daystoexpiration": 30}]}),
        encoding="utf-8",
    )
    vserver_raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(vserver_raw, encoding="utf-8")
    cert_raw = json.dumps(
        {
            "bindingResource": "sslcertkey_binding",
            "parentResource": "sslcertkey",
            "parentKey": "certkey",
            "shape": "list",
            "parents": [],
        }
    )
    (export_dir / "bindings" / "sslcertkey_binding.by-parent.json").write_text(cert_raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        vserver_raw.encode("utf-8")
                    ).hexdigest(),
                    "bindings/sslcertkey_binding.by-parent.json": hashlib.sha256(cert_raw.encode("utf-8")).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    # And the three sources of the use outside the bindings, read and empty:
    # without them "los" is not an honest claim either.
    add_cert_usage_sources(export_dir)
    usage = {u.certkey: u for u in usage_per_certificate(load_export(export_dir))}
    assert usage["cert-alleen"].state == "los"


def test_a_certificate_bound_only_through_the_cert_side_binding_is_gebonden_not_los(tmp_path):
    """sslcertkey_binding.by-parent.json is
    now actually READ, not merely checked for a parse error. A certificate
    bound through THAT source (to an sslservice, which
    sslvserver_sslcertkey_binding does not list) must not come out "los".

    `used_by` no longer carries the cert-side servicename - that source/
    field combination is not one `disclosure.names_from_export()` collects,
    so it could never be masked. The membership still counts toward
    `gebonden`; the name itself does not survive into `used_by`."""
    import hashlib
    import json

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "svc-cert", "daystoexpiration": 50}]}),
        encoding="utf-8",
    )
    vserver_raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(vserver_raw, encoding="utf-8")
    cert_raw = json.dumps(
        {
            "bindingResource": "sslcertkey_binding",
            "parentResource": "sslcertkey",
            "parentKey": "certkey",
            "shape": "list",
            "parents": [
                {
                    "parentName": "svc-cert",
                    "outcome": "OK",
                    "data": {
                        "sslcertkey_binding": [
                            {"certkey": "svc-cert", "servicename": "SVC_INTERN"},
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslcertkey_binding.by-parent.json").write_text(cert_raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        vserver_raw.encode("utf-8")
                    ).hexdigest(),
                    "bindings/sslcertkey_binding.by-parent.json": hashlib.sha256(cert_raw.encode("utf-8")).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usage = {u.certkey: u for u in usage_per_certificate(load_export(export_dir))}
    assert usage["svc-cert"].state == "gebonden"
    assert usage["svc-cert"].state != "los"
    assert usage["svc-cert"].used_by == (), (
        "the cert-side name proves usage but must never be echoed - see"
        " test_used_by_never_carries_a_cert_side_service_name_at_any_disclosure_level"
    )


def test_an_unreadable_certkeyname_in_the_vserver_binding_fails_closed_to_onbekend(tmp_path):
    """A present-but-not-a-string
    certkeyname/vservername must not silently drop the row and let an
    otherwise-unbound certificate read as the favourable "los"."""
    import hashlib
    import json

    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "cert-mystery", "daystoexpiration": 40}]}),
        encoding="utf-8",
    )
    vserver_raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [
                {
                    "parentName": "VS_RAAR",
                    "outcome": "OK",
                    "data": {
                        "sslvserver_sslcertkey_binding": [
                            {"certkeyname": True, "vservername": "VS_RAAR"},
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(vserver_raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        vserver_raw.encode("utf-8")
                    ).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    from nsmcp.expiry import _usage_and_gaps

    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usages, gaps = _usage_and_gaps(load_export(export_dir))
    usage = {u.certkey: u for u in usages}
    assert usage["cert-mystery"].state == "onbekend"
    assert usage["cert-mystery"].state != "los"
    assert "sslvserver_sslcertkey_binding.by-parent.json" in usage["cert-mystery"].reason
    # The SHAPE, never the raw value: the reason names what the field held
    # ("bool"), never the value itself ("True").
    assert any("bool" in g.reason for g in gaps), gaps
    assert not any("True" in g.reason for g in gaps), gaps


def test_an_unidentifiable_issuer_row_is_a_read_gap_not_the_favourable_los(tmp_path):
    """The THIRD `_field_gap` call site
    (the certs' own issuer-relation loop) still passed `required=False` on
    the `certkey` branch. Measured exactly: a row that carries
    only `linkcertkeyname` (no certkey of its own) was silently dropped -
    the issuer relationship it names was thrown away, `complete` stayed
    True, and the named issuer fell through to the favourable "los"
    instead of the honest "onbekend" a real, unidentifiable issuer row
    demands."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [
            {"linkcertkeyname": "ca1"},
            {"certkey": "ca1", "daystoexpiration": 1817},
        ]
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["ca1"].state != "los"
    assert usage["ca1"].state == "onbekend"
    assert any(g.source == "config/sslcertkey" for g in gaps), gaps


def test_a_row_identified_only_by_name_still_registers_its_issuer_relation(tmp_path):
    """Gating the identity
    check on `certkey` alone would turn a legitimate `name`-carrying row
    into a source-wide read gap. The fix must gate on the SAME identity
    expression the result loop uses (`certkey or name`) - a row identified
    only by `name`, with a readable `linkcertkeyname`, is a real, honest
    issuer relationship, not a gap."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [
            {"name": "leaf-by-name", "linkcertkeyname": "ca2", "daystoexpiration": 100},
            {"certkey": "ca2", "daystoexpiration": 1000},
        ]
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert gaps == (), gaps
    assert usage["ca2"].state == "uitgever"
    assert usage["ca2"].used_by == ("leaf-by-name",)


def test_a_cert_side_row_naming_a_certificate_with_no_binding_target_is_not_gebonden(tmp_path):
    """A cert-side row that only NAMES a
    certificate, with no servicename/servername/vservername, is not
    evidence of use. Measured: [{"certkey": "CERT-004"}] in
    the cert-side source used to yield "gebonden" with 0 gaps - the real
    fixture's own shape for a certificate that is purely a link target,
    never bound to anything. Both sources are read and neither binds it,
    so the honest state is "los"."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [{"certkey": "CERT-004", "daystoexpiration": 30}],
        bindings={
            "sslcertkey_binding.by-parent.json": ([{"certkey": "CERT-004"}], None),
        },
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["CERT-004"].state != "gebonden"
    assert usage["CERT-004"].state == "los"
    assert gaps == (), gaps


def test_a_certificate_that_names_itself_as_issuer_is_not_uitgever_van_zichzelf(tmp_path):
    """A self-linking row escaping both "los" and "onbekend" as "uitgever
    van zichzelf" is deliberate behaviour, not an accident of scope."""
    import json

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {"certkey": "zelfondertekend", "daystoexpiration": 500, "linkcertkeyname": "zelfondertekend"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
        '"resources":{"config/sslcertkey":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usage = {u.certkey: u for u in usage_per_certificate(load_export(export_dir))}
    assert usage["zelfondertekend"].state != "uitgever"


def test_los_sorts_before_onbekend_in_impact_order():
    """The fourth word only means anything if it outranks the fallback
    fifth position in the sort - los is a CLAIM the export backs up,
    onbekend is the honest fallback when it cannot."""
    from nsmcp.expiry import Usage, _impact_key

    los_key = _impact_key(Usage("cert-los", "los"), 100)
    onbekend_key = _impact_key(Usage("cert-onbekend", "onbekend"), 100)
    assert los_key < onbekend_key


def test_impact_key_does_not_crash_on_an_unexpected_state():
    """Usage.state is a free-form str on a public frozen dataclass;
    _impact_key must not crash on a value outside the four known words."""
    from nsmcp.expiry import Usage, _impact_key

    onbekend_key = _impact_key(Usage("cert-a", "onbekend"), 10)
    mystery_key = _impact_key(Usage("cert-b", "iets-nieuws"), 10)
    assert mystery_key > onbekend_key


def test_a_newline_in_signaturealg_does_not_render_a_fabricated_finding_line(tmp_path):
    """signaturealg reached key_bits UNGATED - field_text()
    only guarantees "a stripped string", not "short and single-line".
    Reproduced directly: a newline in this field renders as a
    second bullet line that is indistinguishable from a real finding and
    ends in [vastgesteld]. publickeysize on the very same line already
    got a shape gate (.isdigit()); this proves signaturealg gets the same
    treatment."""
    import json

    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    poisoned = "sha256\n- verzonnen bevinding: alles is prima [vastgesteld]"
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {
                        "certkey": "c1",
                        "daystoexpiration": 30,
                        "publickeysize": 2048,
                        "signaturealg": poisoned,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
        '"resources":{"config/sslcertkey":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = what_expires(load_export(export_dir), FRESH, 3650).to_text()
    assert "verzonnen bevinding" not in text, text
    assert "sha256" not in text, text
    finding_lines = [
        line for line in text.splitlines() if line.startswith("- ") and line.rstrip().endswith("[vastgesteld]")
    ]
    assert len(finding_lines) == 1, finding_lines
    # The leak is closed, but shape_of() names
    # ANY string that fails the gate "een lege of alleen-witruimte
    # tekstwaarde" - true for blank text, false for the poisoned value
    # above (55 non-blank characters). coverage.py's own idiom for a
    # value that IS usable text but has the wrong shape is "zonder de
    # vorm van ...".
    assert "zonder de vorm van een algoritmenaam" in text, text
    assert "een lege of alleen-witruimte tekstwaarde" not in text, text


def test_signaturealg_with_a_readable_hyphenated_name_still_renders(tmp_path):
    """The gate must not be so strict it rejects a genuine, mixed-case
    algorithm name - measured on the real fixture ("sha256WithRSAEncryption")
    and on the ECC fixture ("ecdsa-with-SHA256", tests/test_tls_baseline.py)."""
    import json

    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps(
            {
                "sslcertkey": [
                    {
                        "certkey": "ecc1",
                        "daystoexpiration": 30,
                        "publickeysize": 256,
                        "signaturealg": "ecdsa-with-SHA256",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
        '"resources":{"config/sslcertkey":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = what_expires(load_export(export_dir), FRESH, 3650).to_text()
    assert "sleutel 256 bits, ecdsa-with-SHA256" in text, text


def test_a_binding_row_missing_certkeyname_is_a_read_gap_not_the_favourable_los():
    """Measured: {"certkeyname": "cert-gebonden"}
    with no vservername used to yield "los" with zero read gaps. An
    ABSENT gated key is a leesgat, not stil de gunstige tak.

    `len(gaps) >= 1` alone does not pin the
    SOURCE - a gap from an unrelated file would pass this test just as
    well. Pinned to the exact source and wording
    (the absence clause is its own sentence, not folded into "als <shape>
    in plaats van tekst")."""
    from nsmcp.expiry import VSERVER_BINDING, _usage_and_gaps

    export = ExportStub(
        [{"certkey": "cert-gebonden", "daystoexpiration": 30}],
        bindings={
            "sslvserver_sslcertkey_binding.by-parent.json": ([{"certkeyname": "cert-gebonden"}], None),
        },
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["cert-gebonden"].state != "los"
    assert usage["cert-gebonden"].state == "onbekend"
    matching = [g for g in gaps if g.source == VSERVER_BINDING]
    assert matching, gaps
    assert "certkeyname of vservername niet als tekst (de sleutel ontbreekt)" in matching[0].reason, matching[0].reason


def test_a_binding_row_missing_vservername_is_a_read_gap_not_the_favourable_los():
    """Mirror row: {"vservername": "VS"} with no
    certkeyname used to yield "los" with zero read gaps too.

    Same source+wording pin as the sibling
    test above."""
    from nsmcp.expiry import VSERVER_BINDING, _usage_and_gaps

    export = ExportStub(
        [{"certkey": "cert-b", "daystoexpiration": 30}],
        bindings={
            "sslvserver_sslcertkey_binding.by-parent.json": ([{"vservername": "VS"}], None),
        },
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["cert-b"].state != "los"
    assert usage["cert-b"].state == "onbekend"
    matching = [g for g in gaps if g.source == VSERVER_BINDING]
    assert matching, gaps
    assert "certkeyname of vservername niet als tekst (de sleutel ontbreekt)" in matching[0].reason, matching[0].reason


def test_a_cert_side_binding_row_without_a_certkey_field_is_a_read_gap(tmp_path):
    """The cert-side half: export._flatten_by_parent does not
    put parentName into a cert-side row, so a row that also lacks its own
    certkey field cannot be identified. That is a read gap, never a
    silently dropped row that lets every certificate in the export read as
    "los" unchallenged. export.py itself is out of scope - the row simply
    is not identifiable, and this pass says so."""
    import hashlib
    import json

    from nsmcp.expiry import _usage_and_gaps
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "cert-onbekend", "daystoexpiration": 30}]}),
        encoding="utf-8",
    )
    vserver_raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(vserver_raw, encoding="utf-8")
    cert_raw = json.dumps(
        {
            "bindingResource": "sslcertkey_binding",
            "parentResource": "sslcertkey",
            "parentKey": "certkey",
            "shape": "list",
            "parents": [
                {
                    "parentName": "cert-onbekend",
                    "outcome": "OK",
                    "data": {
                        # No "certkey" field in this row - the exact shape
                        # measured (_flatten_by_parent does not add
                        # parentName back into a cert-side row).
                        "sslcertkey_binding": [{"servicename": "SVC_X"}],
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslcertkey_binding.by-parent.json").write_text(cert_raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        vserver_raw.encode("utf-8")
                    ).hexdigest(),
                    "bindings/sslcertkey_binding.by-parent.json": hashlib.sha256(cert_raw.encode("utf-8")).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    usages, gaps = _usage_and_gaps(load_export(export_dir))
    usage = {u.certkey: u for u in usages}
    assert usage["cert-onbekend"].state == "onbekend"
    assert any("sslcertkey_binding.by-parent.json" in g.source for g in gaps), gaps


def test_used_by_never_carries_a_cert_side_service_name_at_any_disclosure_level(tmp_path):
    """used_by carries ONLY names that disclosure.names_from_export()
    demonstrably covers - the vserver family, sourced from bound
    (VSERVER_BINDING's own vservername field). A cert-side binding row
    (CERT_BINDING, field servicename) still proves the certificate is
    gebonden, but its name must never reach rendered text, at ANY
    disclosure level - names_from_export() does not collect that source/
    field combination, so _limit() cannot mask a name it never learned."""
    import hashlib
    import json

    from nsmcp.disclosure import Disclosure, names_from_export, render
    from nsmcp.expiry import usage_per_certificate
    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "svc-cert", "daystoexpiration": 50}]}),
        encoding="utf-8",
    )
    vserver_raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(vserver_raw, encoding="utf-8")
    cert_raw = json.dumps(
        {
            "bindingResource": "sslcertkey_binding",
            "parentResource": "sslcertkey",
            "parentKey": "certkey",
            "shape": "list",
            "parents": [
                {
                    "parentName": "svc-cert",
                    "outcome": "OK",
                    "data": {
                        "sslcertkey_binding": [
                            {"certkey": "svc-cert", "servicename": "SVC_INTERN"},
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslcertkey_binding.by-parent.json").write_text(cert_raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        vserver_raw.encode("utf-8")
                    ).hexdigest(),
                    "bindings/sslcertkey_binding.by-parent.json": hashlib.sha256(cert_raw.encode("utf-8")).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    usage = {u.certkey: u for u in usage_per_certificate(export)}
    assert usage["svc-cert"].state == "gebonden", "cert-side binding still proves usage"
    assert usage["svc-cert"].used_by == (), "but never names the cert-side source"

    answer = what_expires(export, FRESH, 3650)
    full_text = render(answer, Disclosure.FULL, tool="certificaat_wat_verloopt_er")
    assert "SVC_INTERN" not in full_text, full_text

    names = names_from_export(export)
    limited_text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_verloopt_er",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "SVC_INTERN" not in limited_text, limited_text

    minimal_text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    assert "SVC_INTERN" not in minimal_text, minimal_text


# ---------------------------------------------------------------------------
# Two regressions measured on this checkout - both in the dangerous
# direction ("los [vastgesteld]" with no read gap on a certificate
# demonstrably in use) - plus the systematic field x case table: every row
# field `_usage_and_gaps` (and, for signaturealg/publickeysize/
# daystoexpiration, `what_expires`) reads out of the export, each proven in
# all three shapes - absent, present-but-unreadable, present-and-readable.
# ---------------------------------------------------------------------------


def test_an_unreadable_certkey_next_to_a_readable_name_is_not_los():
    """Measured directly,
    reproduced verbatim: `child = field_text(row, "certkey") or
    field_text(row, "name")` let a readable `name` hide a present-but-
    unreadable `certkey` - the certificate archived under its `name`,
    invisible to `bound` (keyed on `certkeyname`, never `name`), read as
    "los" with zero gaps even though a binding row names its TRUE certkey
    as bound. {"certkey": ["CERT-009"], "name": "harmless"} plus a
    binding row naming "CERT-009" (not "harmless") as bound."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [{"certkey": ["CERT-009"], "name": "harmless", "daystoexpiration": 30}],
        bindings={
            VSERVER_BINDING: ([{"certkeyname": "CERT-009", "vservername": "VS"}], None),
        },
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["harmless"].state != "los", usage["harmless"]
    assert usage["harmless"].state == "onbekend", usage["harmless"]
    matching = [g for g in gaps if g.source == RESOURCE]
    assert matching, gaps
    # The SHAPE, never the raw value: the list itself must never surface.
    assert "type list" in matching[0].reason, matching[0].reason
    assert "CERT-009" not in matching[0].reason, matching[0].reason


def test_an_unreadable_target_field_on_a_referencing_row_is_not_los():
    """Measured directly: a
    cert-side binding row that PROVES the certificate is referenced (it
    carries `servicename`) but with that field unreadable used to read as
    "los" with zero gaps - "no target field at all" (the honest
    zero-binding row) and "target field present but unreadable" had
    collapsed into the same branch. {"certkey": "c1", "servicename": 123}."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [{"certkey": "c1", "daystoexpiration": 30}],
        bindings={CERT_BINDING: ([{"certkey": "c1", "servicename": 123}], None)},
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["c1"].state != "los", usage["c1"]
    assert usage["c1"].state == "onbekend", usage["c1"]
    matching = [g for g in gaps if g.source == CERT_BINDING]
    assert matching, gaps
    assert "type int" in matching[0].reason, matching[0].reason
    assert "123" not in matching[0].reason, matching[0].reason


def test_the_honest_zero_binding_cert_side_row_still_survives_the_fix_above():
    """This fix must not reopen the earlier one: a row that carries NONE
    of servicename/servername/vservername (the row that earlier fix was about) is
    still the honest "los" case, with zero gaps."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [{"certkey": "CERT-004", "daystoexpiration": 30}],
        bindings={CERT_BINDING: ([{"certkey": "CERT-004"}], None)},
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["CERT-004"].state == "los", usage["CERT-004"]
    assert gaps == (), gaps


def test_identity_shape_clause_states_the_subject_once_when_combined():
    """The repeated subject in the combined
    read-gap clause reads clumsily: when a shape failure and an absent
    key occur TOGETHER in the same binding file, the combined reason must
    not restate the full subject twice."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(
        [
            {"certkey": "cert-a", "daystoexpiration": 10},
            {"certkey": "cert-b", "daystoexpiration": 20},
        ],
        bindings={
            VSERVER_BINDING: (
                [
                    {"certkeyname": 123, "vservername": "VS"},
                    {"vservername": "VS2"},
                ],
                None,
            ),
        },
    )
    _usages, gaps = _usage_and_gaps(export)
    matching = [g for g in gaps if g.source == VSERVER_BINDING]
    assert matching, gaps
    reason = matching[0].reason
    assert reason.count("een binding draagt certkeyname of vservername") == 1, reason
    assert "type int in plaats van tekst, of niet als tekst (de sleutel ontbreekt)" in reason, reason


def _no_gap(certkey, state, used_by=()):
    """Table checker: the favourable/normal path - no gap, the named
    state, the named used_by."""

    def check(usage, gaps):
        assert gaps == (), gaps
        assert usage[certkey].state == state, (certkey, usage[certkey])
        assert usage[certkey].used_by == used_by, (certkey, usage[certkey])

    return check


def _gap(certkey, state, source, shape_substr, forbidden=()):
    """Table checker: the fail-closed path - a gap from `source` naming
    `shape_substr` (never a raw value in `forbidden`), and `certkey`
    degraded to `state` (never "los")."""

    def check(usage, gaps):
        assert usage[certkey].state == state, (certkey, usage[certkey])
        matching = [g for g in gaps if g.source == source]
        assert matching, gaps
        assert shape_substr in matching[0].reason, matching[0].reason
        for bad in forbidden:
            assert bad not in matching[0].reason, matching[0].reason

    return check


# One row per (field, case) cell. Every field `_usage_and_gaps` reads out of
# the export, in every shape the binding rules distinguish: absent,
# present-but-unreadable, present-and-readable. The outcome is pinned per
# cell below.
USAGE_FIELD_CASE_TABLE = [
    # --- VSERVER_BINDING.certkeyname ------------------------------------
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"vservername": "VS"}], None)},
        _gap("target", "onbekend", VSERVER_BINDING, "de sleutel ontbreekt"),
        id="vserverbinding-certkeyname-absent",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"certkeyname": 123, "vservername": "VS"}], None)},
        _gap("target", "onbekend", VSERVER_BINDING, "type int", forbidden=("123",)),
        id="vserverbinding-certkeyname-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"certkeyname": "target", "vservername": "VS"}], None)},
        _no_gap("target", "gebonden", used_by=("VS",)),
        id="vserverbinding-certkeyname-readable",
    ),
    # --- VSERVER_BINDING.vservername ------------------------------------
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"certkeyname": "target"}], None)},
        _gap("target", "onbekend", VSERVER_BINDING, "de sleutel ontbreekt"),
        id="vserverbinding-vservername-absent",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"certkeyname": "target", "vservername": ["VS", "VS2"]}], None)},
        _gap("target", "onbekend", VSERVER_BINDING, "type list", forbidden=("VS2",)),
        id="vserverbinding-vservername-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {VSERVER_BINDING: ([{"certkeyname": "target", "vservername": "VS"}], None)},
        _no_gap("target", "gebonden", used_by=("VS",)),
        id="vserverbinding-vservername-readable",
    ),
    # --- CERT_BINDING.certkey (the binding row's own identity) ---------
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"servicename": "SVC"}], None)},
        _gap("target", "onbekend", CERT_BINDING, "de sleutel ontbreekt"),
        id="certbinding-certkey-absent",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": True, "servicename": "SVC"}], None)},
        _gap("target", "onbekend", CERT_BINDING, "type bool"),
        id="certbinding-certkey-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "servicename": "SVC"}], None)},
        _no_gap("target", "gebonden", used_by=()),
        id="certbinding-certkey-readable",
    ),
    # --- CERT_BINDING target trio: servicename / servername / vservername --
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target"}], None)},
        _no_gap("target", "los"),
        id="certbinding-target-all-absent",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "servicename": 123}], None)},
        _gap("target", "onbekend", CERT_BINDING, "type int", forbidden=("123",)),
        id="certbinding-servicename-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "servername": True}], None)},
        _gap("target", "onbekend", CERT_BINDING, "type bool"),
        id="certbinding-servername-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "vservername": None}], None)},
        _gap("target", "onbekend", CERT_BINDING, "JSON null"),
        id="certbinding-vservername-unreadable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "servicename": "SVC"}], None)},
        _no_gap("target", "gebonden", used_by=()),
        id="certbinding-servicename-readable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "servername": "SVR"}], None)},
        _no_gap("target", "gebonden", used_by=()),
        id="certbinding-servername-readable",
    ),
    pytest.param(
        [{"certkey": "target", "daystoexpiration": 30}],
        {CERT_BINDING: ([{"certkey": "target", "vservername": "VS9"}], None)},
        _no_gap("target", "gebonden", used_by=()),
        id="certbinding-vservername-readable",
    ),
    # --- certs' own certkey (with its `name` fallback) --------------------
    pytest.param(
        [{"daystoexpiration": 10}],
        {},
        _gap("(naamloos)", "onbekend", RESOURCE, "de sleutel ontbreekt"),
        id="certs-certkey-and-name-both-absent",
    ),
    pytest.param(
        [{"certkey": ["x"], "daystoexpiration": 10}],
        {},
        _gap("(naamloos)", "onbekend", RESOURCE, "type list", forbidden=("de sleutel ontbreekt",)),
        id="certs-certkey-unreadable-name-absent",
    ),
    pytest.param(
        [{"certkey": 999, "name": "leaf-shape", "daystoexpiration": 10}],
        {},
        _gap("leaf-shape", "onbekend", RESOURCE, "type int"),
        id="certs-certkey-unreadable-name-readable",
    ),
    pytest.param(
        [{"certkey": "clean1", "daystoexpiration": 10}],
        {},
        _no_gap("clean1", "los"),
        id="certs-certkey-readable",
    ),
    # --- certs' own `name` (the fallback partner) -----------------------
    pytest.param(
        [{"certkey": "clean2", "daystoexpiration": 5}],
        {},
        _no_gap("clean2", "los"),
        id="certs-name-absent-certkey-readable",
    ),
    pytest.param(
        [{"name": 123, "daystoexpiration": 10}],
        {},
        _gap("(naamloos)", "onbekend", RESOURCE, "de sleutel ontbreekt"),
        id="certs-name-unreadable-certkey-absent",
    ),
    pytest.param(
        [
            {"name": "leaf2", "linkcertkeyname": "ca3", "daystoexpiration": 50},
            {"certkey": "ca3", "daystoexpiration": 900},
        ],
        {},
        _no_gap("ca3", "uitgever", used_by=("leaf2",)),
        id="certs-name-readable-certkey-absent",
    ),
    # --- certs' own linkcertkeyname --------------------------------------
    pytest.param(
        [{"certkey": "leafNoIssuer", "daystoexpiration": 10}],
        {},
        _no_gap("leafNoIssuer", "los"),
        id="certs-linkcertkeyname-absent",
    ),
    pytest.param(
        [{"certkey": "leafX", "linkcertkeyname": 123, "daystoexpiration": 10}],
        {},
        _gap("leafX", "onbekend", RESOURCE, "type int", forbidden=("123",)),
        id="certs-linkcertkeyname-unreadable",
    ),
    pytest.param(
        [
            {"certkey": "leafY", "linkcertkeyname": "caY", "daystoexpiration": 10},
            {"certkey": "caY", "daystoexpiration": 900},
        ],
        {},
        _no_gap("caY", "uitgever", used_by=("leafY",)),
        id="certs-linkcertkeyname-readable",
    ),
]


@pytest.mark.parametrize("certs,bindings,check", USAGE_FIELD_CASE_TABLE)
def test_usage_and_gaps_field_shape_gate_table(certs, bindings, check):
    """The systematic proof: every row field
    `_usage_and_gaps` reads, in every shape, never taking the favourable
    branch on a field that was merely unreadable, never echoing the raw
    value, never gapping a field whose absence is an honest fact."""
    from nsmcp.expiry import _usage_and_gaps

    export = ExportStub(certs, bindings=bindings)
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    check(usage, gaps)


# One row per (field, case) cell for the three fields only `what_expires`
# reads (signaturealg, publickeysize, daystoexpiration) - `_usage_and_gaps`
# never touches these.
WHAT_EXPIRES_FIELD_CASE_TABLE = [
    pytest.param(
        {"certkey": "days-absent", "publickeysize": 2048, "signaturealg": "sha256WithRSAEncryption"},
        lambda f: (
            f.certainty is Certainty.NOT_ESTABLISHED and "daystoexpiration=een lege waarde (JSON null)" in f.evidence
        ),
        id="daystoexpiration-absent",
    ),
    pytest.param(
        {
            "certkey": "days-unreadable",
            "daystoexpiration": ["binnenkort"],
            "publickeysize": 2048,
            "signaturealg": "sha256WithRSAEncryption",
        },
        lambda f: (
            f.certainty is Certainty.NOT_ESTABLISHED
            and "daystoexpiration=een waarde van het type list" in f.evidence
            and "binnenkort" not in f.evidence
        ),
        id="daystoexpiration-present-but-unreadable",
    ),
    pytest.param(
        {
            "certkey": "days-readable",
            "daystoexpiration": 45,
            "publickeysize": 2048,
            "signaturealg": "sha256WithRSAEncryption",
        },
        lambda f: f.certainty is Certainty.ESTABLISHED and "verloopt over 45 dagen" in f.outcome,
        id="daystoexpiration-present-and-readable",
    ),
    pytest.param(
        {"certkey": "pks-absent", "daystoexpiration": 30, "signaturealg": "sha256WithRSAEncryption"},
        lambda f: "sleutel onbekend bits" in f.evidence,
        id="publickeysize-absent",
    ),
    pytest.param(
        {
            "certkey": "pks-unreadable",
            "daystoexpiration": 30,
            "publickeysize": {"bits": 2048},
            "signaturealg": "sha256WithRSAEncryption",
        },
        lambda f: "sleutel onbekend bits" in f.evidence and "2048" not in f.evidence,
        id="publickeysize-present-but-unreadable",
    ),
    pytest.param(
        {
            "certkey": "pks-readable",
            "daystoexpiration": 30,
            "publickeysize": 4096,
            "signaturealg": "sha256WithRSAEncryption",
        },
        lambda f: "sleutel 4096 bits" in f.evidence,
        id="publickeysize-present-and-readable",
    ),
    pytest.param(
        {"certkey": "sig-absent", "daystoexpiration": 30, "publickeysize": 2048},
        lambda f: "sleutel 2048 bits, de sleutel ontbreekt" in f.evidence,
        id="signaturealg-absent",
    ),
    pytest.param(
        {"certkey": "sig-unreadable", "daystoexpiration": 30, "publickeysize": 2048, "signaturealg": True},
        lambda f: "sleutel 2048 bits, een waarde van het type bool" in f.evidence,
        id="signaturealg-present-but-unreadable",
    ),
    pytest.param(
        {
            "certkey": "sig-readable",
            "daystoexpiration": 30,
            "publickeysize": 2048,
            "signaturealg": "sha256WithRSAEncryption",
        },
        lambda f: "sleutel 2048 bits, sha256WithRSAEncryption" in f.evidence,
        id="signaturealg-present-and-readable",
    ),
]


@pytest.mark.parametrize("cert_row,check", WHAT_EXPIRES_FIELD_CASE_TABLE)
def test_what_expires_field_shape_gate_table(cert_row, check):
    """The same systematic proof, for the three fields only `what_expires`
    (not `_usage_and_gaps`) reads out of the export."""
    answer = what_expires(ExportStub([cert_row]), FRESH, horizon_days=3650)
    finding = next(f for f in answer.findings if f.subject == cert_row["certkey"])
    assert check(finding), finding.evidence


# ---------------------------------------------------------------------------
# The cert-side file in the aggregate shape the real collector writes
# (`sslcertkey_binding.by-parent.json`: one document per certificate, with a
# nested list per bound kind).
# ---------------------------------------------------------------------------

DOH = Path(__file__).parent / "fixtures" / "lab-export-vpx-doh-synthetic"


def test_the_cert_side_aggregate_file_is_read_on_the_doh_export():
    from nsmcp.expiry import _usage_and_gaps
    from nsmcp.export import load_export

    usages, gaps = _usage_and_gaps(load_export(DOH))
    usage = {u.certkey: u for u in usages}
    assert gaps == (), gaps
    assert usage["ns-server-certificate"].state == "gebonden", "acht service-bindingen"
    assert usage["CERT-WEB-001"].state == "gebonden"
    # Both binding sources are read and neither binds CERT-SPARE-001 - but this
    # export was taken before any collector fetched the SAML objects and the
    # SSL servicegroup bindings, so "los" is not established: "niet
    # vastgesteld", never "no use". A boundary, not a read gap (`gaps` above).
    assert usage["CERT-SPARE-001"].state == "onbekend"
    assert usage["CERT-SPARE-001"].reason == (
        "niet vast te stellen of dit certificaat ergens aan hangt: bron config/authenticationsamlaction,"
        " config/authenticationsamlidpprofile, sslservicegroup_sslcertkey_binding.by-parent.json niet in de"
        " export"
    )


def _cert_side_export(tmp_path, document: dict, certs: list[dict]):
    import hashlib
    import json

    from nsmcp.export import load_export

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "sslcertkey.json").write_text(json.dumps({"sslcertkey": certs}), encoding="utf-8")
    files = {}
    for name, body in (
        (
            "sslvserver_sslcertkey_binding.by-parent.json",
            {
                "bindingResource": "sslvserver_sslcertkey_binding",
                "parentResource": "sslvserver",
                "parentKey": "vservername",
                "shape": "list",
                "parents": [],
            },
        ),
        (
            "sslcertkey_binding.by-parent.json",
            {
                "bindingResource": "sslcertkey_binding",
                "parentResource": "sslcertkey",
                "parentKey": "certkey",
                "shape": "aggregate",
                "parents": [
                    {"parentName": key, "outcome": "OK", "data": {"sslcertkey_binding": doc}}
                    for key, doc in document.items()
                ],
            },
        ),
    ):
        raw = json.dumps(body)
        (export_dir / "bindings" / name).write_text(raw, encoding="utf-8")
        files[f"bindings/{name}"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-24T06:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    add_cert_usage_sources(export_dir)
    return load_export(export_dir)


def test_an_unknown_binding_kind_makes_that_certificate_onbekend_not_los(tmp_path):
    """Fail-closed for "los": a kind this version has no rule for could be a
    use of the certificate. Only THAT certificate turns onbekend; a
    certificate next to it with only known kinds stays los."""
    from nsmcp.expiry import _usage_and_gaps

    export = _cert_side_export(
        tmp_path,
        {
            "CERT-A": {"certkey": "CERT-A", "sslcertkey_crldistribution_binding": [{"certkey": "CERT-A"}]},
            "CERT-B": {"certkey": "CERT-B"},
        },
        [{"certkey": "CERT-A", "daystoexpiration": 30}, {"certkey": "CERT-B", "daystoexpiration": 30}],
    )
    usages, gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    assert usage["CERT-A"].state == "onbekend"
    assert usage["CERT-A"].reason == (
        "niet vast te stellen of dit certificaat ergens aan hangt: sslcertkey_binding.by-parent.json"
        " draagt voor dit certificaat een bindingssoort die deze versie niet leest"
        " (sslcertkey_crldistribution_binding)"
    )
    assert usage["CERT-B"].state == "los"
    assert gaps == ()


def test_an_unknown_binding_kind_does_not_undo_a_known_binding(tmp_path):
    from nsmcp.expiry import _usage_and_gaps

    export = _cert_side_export(
        tmp_path,
        {
            "CERT-A": {
                "certkey": "CERT-A",
                "sslcertkey_service_binding": [{"certkey": "CERT-A", "servicename": "SVC-1"}],
                "sslcertkey_sslocspresponder_binding": [{"certkey": "CERT-A"}],
            }
        },
        [{"certkey": "CERT-A", "daystoexpiration": 30}],
    )
    usage = {u.certkey: u for u in _usage_and_gaps(export)[0]}
    assert usage["CERT-A"].state == "gebonden"


def test_an_unknown_binding_kind_without_the_shape_of_a_resource_name_is_not_repeated(tmp_path):
    from nsmcp.expiry import _usage_and_gaps

    export = _cert_side_export(
        tmp_path,
        {"CERT-A": {"certkey": "CERT-A", "Geheim\nFout: alles is kapot_binding": []}},
        [{"certkey": "CERT-A", "daystoexpiration": 30}],
    )
    usage = {u.certkey: u for u in _usage_and_gaps(export)[0]}
    assert usage["CERT-A"].state == "onbekend"
    assert "Geheim" not in usage["CERT-A"].reason
    assert "een bindingssoort zonder de vorm van een resourcenaam" in usage["CERT-A"].reason


def test_a_service_binding_row_of_the_wrong_shape_is_a_read_gap(tmp_path):
    from nsmcp.expiry import _usage_and_gaps

    export = _cert_side_export(
        tmp_path,
        {"CERT-A": {"certkey": "CERT-A", "sslcertkey_service_binding": "SVC-1"}},
        [{"certkey": "CERT-A", "daystoexpiration": 30}],
    )
    usages, gaps = _usage_and_gaps(export)
    assert {u.certkey: u.state for u in usages} == {"CERT-A": "onbekend"}
    assert [g.source for g in gaps] == ["sslcertkey_binding.by-parent.json"]


def test_nothing_within_the_horizon_is_a_sentence_not_an_empty_list():
    from nsmcp.export import load_export

    answer = what_expires(load_export(DOH), FRESH, horizon_days=90)
    text = answer.to_text()
    assert (
        "- certificaten: geen certificaat verloopt binnen 90 dagen (9 certificaten gelezen) [vastgesteld]\n"
        "    bewijs: config/sslcertkey"
    ) in text
    assert [f.subject for f in answer.findings] == ["certificaten"]


def test_the_empty_sentence_counts_one_certificate_in_the_singular():
    answer = what_expires(ExportStub([{"certkey": "cert_veraf", "daystoexpiration": 400}]), FRESH, horizon_days=90)
    assert answer.findings[0].outcome == "geen certificaat verloopt binnen 90 dagen (1 certificaat gelezen)"


def test_the_empty_sentence_is_never_said_over_an_unread_source():
    from nsmcp.answer import ReadGap

    answer = what_expires(
        ExportStub([], gap=ReadGap(source="config/sslcertkey", reason="RBAC_DENIED")), FRESH, horizon_days=90
    )
    assert answer.findings == []


# --- 1.0.2: the days count from today, not from the moment of the scan ---
#
# Measured in the public test of 1.0.0: `daystoexpiration` is the appliance's
# count AT THE SCAN, and the answer repeated it unchanged - "verloopt over 817
# dagen" from an export 56 days old, while 761 days remained. The horizon
# filter then counted from the scan as well.


class _DatedStub(ExportStub):
    def __init__(self, certs, collected_at):
        super().__init__(certs)
        self.collected_at = collected_at


def test_b1_a_certificate_inside_the_horizon_from_today_is_listed():
    """Export 56 days old, a certificate at daystoexpiration=100 at the scan:
    44 days remain today, so it falls INSIDE a horizon of 90 days."""
    from datetime import date

    stub = _DatedStub([{"certkey": "cert_b1", "daystoexpiration": 100}], "2026-08-26T10:00:00.0000000Z")
    answer = what_expires(stub, FRESH, horizon_days=90, today=date(2026, 10, 21))
    text = answer.to_text()
    assert "cert_b1: verloopt over 44 dagen (notice)" in text
    assert "verloopt over 100 dagen" not in text
    assert "gerekend vanaf vandaag, export van 56 dagen oud" in text


def test_b1_the_class_follows_the_corrected_days():
    """A certificate the scan saw at 60 days is past its date 61 days later."""
    from datetime import date

    stub = _DatedStub([{"certkey": "cert_weg", "daystoexpiration": 60}], "2026-08-21T10:00:00Z")
    finding = what_expires(stub, FRESH, horizon_days=90, today=date(2026, 10, 21)).findings[0]
    assert finding.outcome.startswith("is verlopen")
    assert finding.certainty is Certainty.ESTABLISHED


def test_b1_the_lab_export_counts_from_today():
    """The shipped lab export (2026-08-26), read on 2026-10-21 (56 days):
    CERT-009 carries daystoexpiration=817, so 761 days remain."""
    from datetime import date

    from nsmcp.export import load_export

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    text = what_expires(export, FRESH, 3650, today=date(2026, 10, 21)).to_text()
    assert "CERT-009: verloopt over 761 dagen" in text
    assert "verloopt over 817 dagen" not in text


@pytest.mark.parametrize(
    "collected_at",
    [None, "", "geen datum", "2099-01-01T00:00:00Z"],
    ids=["absent", "blank", "unreadable", "future"],
)
def test_b1_an_unreadable_export_date_is_not_established_never_the_raw_field(collected_at):
    from datetime import date

    stub = _DatedStub([{"certkey": "cert_x", "daystoexpiration": 100}], collected_at)
    answer = what_expires(stub, FRESH, horizon_days=90, today=date(2026, 10, 21))
    text = answer.to_text()
    assert "verloopt over 100 dagen" not in text
    finding = next(f for f in answer.findings if f.subject == "cert_x")
    assert finding.certainty is Certainty.NOT_ESTABLISHED
    assert "niet vast te stellen" in finding.outcome
    assert "geen certificaat verloopt" not in text
