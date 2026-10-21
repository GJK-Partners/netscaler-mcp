"""Openheid of the certificate use outside the bindings, end to end.

No real name from the certificate-use fixture reaches an answer of the three
certificate tools at openness `beperkt` or `minimaal`, through the real MCP
server - the same seam a client uses, `structuredContent` included.

The real names are harvested from the fixture FILES themselves (every
identity field), never from a hand-written list. Three variants: the fixture
itself; one that drives names through every read-gap path of `cert_usage`
(an unusable certificate field, a nameless SAML action, an unknown ca flag, a
parent list in contradiction with its object source); and one with a
servicegroup parent the collector could not read, whose name only a read gap
of the shared reader carries. A premise at `volledig` proves the names DO
reach the text there, and a mutation (the sixteenth family switched off)
proves the check can fail.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
from pathlib import Path

import mcp.types as types
import pytest
from conftest import _knowledge_file
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import disclosure as disclosure_module
from nsmcp.action import what_to_do
from nsmcp.cert_usage import SERVICEGROUP_BINDING, names_in_cert_usage_sources
from nsmcp.disclosure import Disclosure, names_from_export, render
from nsmcp.expiry import what_expires
from nsmcp.export import load_export
from nsmcp.impact import what_breaks
from nsmcp.knowledge import Knowledge
from nsmcp.mcp_server import build_server, forget_identities

FIXTURE = Path(__file__).parent / "fixtures" / "certgebruik-saml"
K = Knowledge(version="certgebruik", date="2026-09-25", age_days=0, missing=False)
IDENTITY_FIELDS = (
    "name",
    "certkey",
    "certkeyname",
    "servicegroupname",
    "vservername",
    "servername",
    "parentName",
    "samlidpcertname",
    "samlsigningcertname",
    "samlspcertname",
)
_FAILED_PARENT = {"parentName": "SG-KAPOT-01", "outcome": "FAILED", "data": None}


def _harvest(value, names: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in IDENTITY_FIELDS and isinstance(item, str) and item.strip():
                names.add(item.strip())
            _harvest(item, names)
    elif isinstance(value, list):
        for item in value:
            _harvest(item, names)


def _real_names(export_dir: Path) -> set[str]:
    names: set[str] = set()
    for path in [*(export_dir / "objects").glob("*.json"), *(export_dir / "bindings").glob("*.json")]:
        _harvest(json.loads(path.read_text(encoding="utf-8")), names)
    return names


def _rewrite(directory: Path, relative: str, document) -> None:
    raw = json.dumps(document).encode("utf-8")
    (directory / relative).write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest().upper()
    manifest_path = directory / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if relative.startswith("bindings/"):
        manifest["files"][relative] = digest
    else:
        manifest["resources"][f"config/{Path(relative).stem}"]["payloadSha256"] = digest
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _sg_document(*parents) -> dict:
    return {
        "bindingResource": "sslservicegroup_sslcertkey_binding",
        "parentResource": "sslservicegroup",
        "parentKey": "servicegroupname",
        "shape": "list",
        "parents": list(parents),
    }


def _sg_rows(parent, *rows) -> dict:
    return {"parentName": parent, "outcome": "OK", "data": {"sslservicegroup_sslcertkey_binding": list(rows)}}


def _gap_variant(export_dir: Path) -> None:
    """Every read-gap path of `cert_usage` that can put an object name into a text."""
    _rewrite(
        export_dir,
        "objects/authenticationsamlaction.json",
        {
            "authenticationsamlaction": [
                {"name": "SAML-ACTIE-01", "samlidpcertname": "CERT-IDP", "samlsigningcertname": "CERT-VS"},
                {"name": "SAML-ACTIE-03", "samlidpcertname": ["CERT-IDP"]},
                {"samlidpcertname": "CERT-SP"},
            ]
        },
    )
    _rewrite(
        export_dir,
        "objects/sslservicegroup.json",
        {"sslservicegroup": [{"servicegroupname": n} for n in ("SG-BACKEND-01", "SG-LEEG-01", "SG-EXTRA-01")]},
    )
    _rewrite(
        export_dir,
        f"bindings/{SERVICEGROUP_BINDING}",
        _sg_document(
            _sg_rows(
                "SG-BACKEND-01",
                {"servicegroupname": "SG-BACKEND-01", "certkeyname": "CERT-SG", "ca": "misschien"},
                {"servicegroupname": "SG-BACKEND-01", "certkeyname": "CERT-SG-CA", "ca": True},
            ),
            {"parentName": "SG-LEEG-01", "outcome": "EMPTY", "data": None},
            _sg_rows("SG-ONBEKEND-01", {"servicegroupname": "SG-ONBEKEND-01", "certkeyname": "CERT-LOS", "ca": False}),
        ),
    )


def _failed_parent_variant(export_dir: Path) -> None:
    """A servicegroup parent the collector could not read. The whole file is
    then a read gap of the shared reader, and that gap names the parent; the
    parent cross-check yields no names at all in that case."""
    document = json.loads((export_dir / "bindings" / SERVICEGROUP_BINDING).read_text(encoding="utf-8"))
    document["parents"].append(_FAILED_PARENT)
    _rewrite(export_dir, f"bindings/{SERVICEGROUP_BINDING}", document)
    _rewrite(
        export_dir,
        "objects/sslservicegroup.json",
        {"sslservicegroup": [{"servicegroupname": n} for n in ("SG-BACKEND-01", "SG-LEEG-01", "SG-KAPOT-01")]},
    )


_VARIANTS = {"fixture": None, "leesgaten": _gap_variant, "mislukte-parent": _failed_parent_variant}
_MUST_SHOW = {
    "fixture": {"SAML-ACTIE-01", "SAML-ACTIE-02", "SAML-IDP-01", "SG-BACKEND-01"},
    "leesgaten": {"SAML-ACTIE-01", "SAML-IDP-01", "SG-BACKEND-01", "SAML-ACTIE-03", "SG-EXTRA-01", "SG-ONBEKEND-01"},
    "mislukte-parent": {"SAML-ACTIE-01", "SAML-IDP-01", "SG-KAPOT-01"},
}


def _export(tmp_path: Path, variant: str) -> Path:
    export_dir = tmp_path / "export"
    shutil.copytree(FIXTURE, export_dir)
    if _VARIANTS[variant] is not None:
        _VARIANTS[variant](export_dir)
    return export_dir


def _answers(tmp_path: Path, export_dir: Path, level: Disclosure, tag: str) -> dict[str, str]:
    forget_identities()
    server = build_server(
        export_dir,
        _knowledge_file(tmp_path),
        disclosure=level,
        pseudonym_table_path=tmp_path / f"tabel-{tag}.json",
    )
    certs = sorted(
        row["certkey"]
        for row in json.loads((export_dir / "objects" / "sslcertkey.json").read_text(encoding="utf-8"))["sslcertkey"]
    )
    calls = [("certificaat_wat_verloopt_er", {"horizon_dagen": 3650})]
    for cert in certs:
        calls.append(("certificaat_wat_breekt_er", {"certnaam": cert}))
        calls.append(("certificaat_wat_moet_ik_doen", {"certnaam": cert}))

    async def run():
        out = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for name, arguments in calls:
                result = await client.call_tool(name, arguments)
                assert result.isError is False, (name, arguments)
                text = " ".join(b.text for b in result.content if hasattr(b, "text"))
                out[f"{name} {arguments}"] = text + " " + json.dumps(result.structuredContent or {})
        return out

    return asyncio.run(run())


@pytest.mark.parametrize("variant", list(_VARIANTS))
def test_no_real_fixture_name_reaches_a_limited_or_minimal_certificate_answer(tmp_path, variant):
    export_dir = _export(tmp_path, variant)
    real = _real_names(export_dir)
    assert _MUST_SHOW[variant] <= real

    full = _answers(tmp_path, export_dir, Disclosure.FULL, "vol")
    shown = {n for n in real if any(n in text for text in full.values())}
    # PREMISE: at volledig the object names do reach the answers, so an
    # empty leak list below is a measurement, not an artefact.
    assert _MUST_SHOW[variant] <= shown, _MUST_SHOW[variant] - shown
    joined = " ".join(full.values())
    if variant == "leesgaten":
        # The gap paths are really exercised.
        assert "samlidpcertname is niet bruikbaar" in joined
        assert "draagt geen bruikbare naam" in joined
        assert "kent SG-EXTRA-01" in joined
        assert "ca-vlag heeft een vorm" in joined
    if variant == "mislukte-parent":
        assert "parent 'SG-KAPOT-01' is niet bruikbaar gelezen" in joined

    for level, tag in ((Disclosure.LIMITED, "beperkt"), (Disclosure.MINIMAL, "minimaal")):
        answers = _answers(tmp_path, export_dir, level, tag)
        leaked = {label: sorted(n for n in real if n in text) for label, text in answers.items()}
        leaked = {label: names for label, names in leaked.items() if names}
        assert leaked == {}, f"{tag}: {leaked}"


def test_the_probe_fails_without_the_certificate_use_family(tmp_path, monkeypatch):
    """Mutation: switch the sixteenth family off. The probe above must then
    see a leak at beperkt - otherwise it could not have failed."""
    export_dir = _export(tmp_path, "fixture")
    monkeypatch.setattr(disclosure_module, "names_in_cert_usage_sources", lambda export: ())
    real = _real_names(export_dir)
    answers = _answers(tmp_path, export_dir, Disclosure.LIMITED, "mutant")
    leaked = {n for text in answers.values() for n in real if n in text}
    assert leaked & {"SAML-ACTIE-01", "SAML-ACTIE-02", "SAML-IDP-01", "SG-BACKEND-01"}, leaked


def test_a_failed_servicegroup_parent_is_masked_through_the_list_shape_harvest(tmp_path):
    """The one read of the servicegroup file that knows a parent the reader
    could not use: `Export.binding_names` harvesting the LIST shape. The read
    gap names the parent, and the parent cross-check yields no name at all on
    a file the shared reader refuses - so without that harvest the name would
    leak at beperkt in all three tools."""
    export = load_export(_export(tmp_path, "mislukte-parent"))
    # Premise: the only other road to this name is closed on this export.
    assert export.binding_parents(SERVICEGROUP_BINDING).names == ()

    impact = what_breaks(export, K, "CERT-LOS")
    answers = {
        "certificaat_wat_breekt_er": impact,
        "certificaat_wat_moet_ik_doen": what_to_do(impact, K, "CERT-LOS"),
        "certificaat_wat_verloopt_er": what_expires(export, K, 3650),
    }
    for tool, answer in answers.items():
        full = render(answer, Disclosure.FULL, tool=tool, extra_names=names_from_export(export), caller_name="CERT-LOS")
        assert "SG-KAPOT-01" in full, f"{tool}: premisse - de naam staat bij volledig in het leesgat"
        limited = render(
            answer,
            Disclosure.LIMITED,
            tool=tool,
            extra_names=names_from_export(export),
            caller_name="CERT-LOS",
            pseudonym_table_path=tmp_path / "tabel.json",
        )
        assert not re.search(r"SG-KAPOT-01", limited), f"{tool} lekt SG-KAPOT-01 bij beperkt"
    # And the road that closes it.
    assert "SG-KAPOT-01" in export.binding_names((SERVICEGROUP_BINDING,))
    assert "SG-KAPOT-01" in names_in_cert_usage_sources(export)


# ---------------------------------------------------------------------------
# The proposal of certificaat_vervangen names the old certificate's other
# uses - and at beperkt not one real name in that line.
# ---------------------------------------------------------------------------


def _broad_variant(export_dir: Path) -> None:
    """CERT-VS also on a second virtual server, on an SSL service, and the
    issuer of CERT-SP: every kind of use the proposal can name."""
    _rewrite(
        export_dir,
        "objects/sslvserver.json",
        {"sslvserver": [{"vservername": "LBV-WEB-01"}, {"vservername": "LBV-WEB-02"}]},
    )
    _rewrite(
        export_dir,
        "bindings/sslvserver_sslcertkey_binding.by-parent.json",
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [
                {
                    "parentName": v,
                    "outcome": "OK",
                    "data": {
                        "sslvserver_sslcertkey_binding": [
                            {"vservername": v, "certkeyname": "CERT-VS", "ca": False, "snicert": False}
                        ]
                    },
                }
                for v in ("LBV-WEB-01", "LBV-WEB-02")
            ],
        },
    )
    side = json.loads((export_dir / "bindings" / "sslcertkey_binding.by-parent.json").read_text(encoding="utf-8"))
    for parent in side["parents"]:
        if parent["parentName"] == "CERT-VS":
            doc = parent["data"]["sslcertkey_binding"]
            doc["sslcertkey_sslvserver_binding"].append({"certkey": "CERT-VS", "servername": "LBV-WEB-02"})
            doc["sslcertkey_service_binding"] = [{"certkey": "CERT-VS", "servicename": "SVC-WEB-01"}]
    _rewrite(export_dir, "bindings/sslcertkey_binding.by-parent.json", side)
    certs = json.loads((export_dir / "objects" / "sslcertkey.json").read_text(encoding="utf-8"))
    for row in certs["sslcertkey"]:
        if row["certkey"] == "CERT-SP":
            row["linkcertkeyname"] = "CERT-VS"
    _rewrite(export_dir, "objects/sslcertkey.json", certs)


_PROPOSAL_VARIANTS = {"fixture": None, "leesgaten": _gap_variant, "breed": _broad_variant}


@pytest.mark.parametrize("variant", list(_PROPOSAL_VARIANTS))
def test_the_replacement_proposal_names_no_real_name_at_beperkt(tmp_path, variant):
    """Every kind of use the proposal can name (another virtual server, an
    SSL service, an issued certificate, a SAML object) and the reason line of
    a read gap: at volledig the names are there, at beperkt not one, in the
    text or in `structuredContent`. The operator's own copy keeps the real
    names - a human confirms what he reads there."""
    from test_cert_usage import _propose, _write_server

    export_dir = tmp_path / f"export-{variant}"
    shutil.copytree(FIXTURE, export_dir)
    if _PROPOSAL_VARIANTS[variant] is not None:
        _PROPOSAL_VARIANTS[variant](export_dir)
    real = _real_names(export_dir) | {"CERT-NIEUW", "SVC-WEB-01"}

    full_server, _spy, _presenter = _write_server(tmp_path / "vol", export_dir, Disclosure.FULL)
    full = _propose(full_server)
    must = {"SAML-ACTIE-01"} | ({"LBV-WEB-02", "SVC-WEB-01", "CERT-SP"} if variant == "breed" else set())
    assert all(n in full for n in must), full
    if variant == "leesgaten":
        assert "gebruik buiten de binding niet vastgesteld" in full and "SAML-ACTIE-03" in full, full

    server, _spy, presenter = _write_server(tmp_path / "beperkt", export_dir, Disclosure.LIMITED)
    text = _propose(server)
    assert re.search(
        r"dit certificaat is ook elders in gebruik: [^\n]*SAML-actie object-\d+ \(signing-certificaat\)", text
    )
    leaked = sorted(n for n in real if n in text)
    assert leaked == [], (leaked, text)
    assert "SAML-ACTIE-01" in presenter.calls[0]["proposal_text"]


@pytest.mark.parametrize("shape", ["bestand-nul-parents", "geen-bestand-bron-leeg"])
def test_a_collector_export_without_ssl_servicegroups_lets_a_certificate_be_los(tmp_path, shape):
    """The lab export as a collector that fetches the four sources writes it
    on an appliance without SSL servicegroups: SAML sources EMPTY,
    config/sslservicegroup EMPTY, and the binding file with zero parents -
    or without it. Established either way: "los", and no boundary."""
    from conftest import add_cert_usage_sources

    from nsmcp.expiry import usage_per_certificate

    export_dir = tmp_path / "lab"
    shutil.copytree(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826", export_dir)
    if shape == "bestand-nul-parents":
        add_cert_usage_sources(export_dir)
    else:
        manifest_path = export_dir / "export-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for resource in (
            "config/authenticationsamlaction",
            "config/authenticationsamlidpprofile",
            "config/sslservicegroup",
        ):
            manifest["resources"][resource] = {"status": "EMPTY"}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    export = load_export(export_dir)
    usage = {u.certkey: u.state for u in usage_per_certificate(export)}
    answer = what_breaks(export, K, "ns-sftrust-certificate")
    assert usage["ns-sftrust-certificate"] == "los"
    assert not any("SSL-servicegroups" in n.subject for n in answer.not_assessed)


def test_the_replacement_proposal_does_not_exist_at_minimaal(tmp_path):
    """At minimaal the writing tools are not offered at all (a proposal
    cannot survive the counting rendering), so this line cannot reach a
    minimal answer; rendered at minimaal anyway, the findings leave counts."""
    from test_cert_usage import _write_server

    from nsmcp.action import replacement_findings
    from nsmcp.answer import Answer

    export_dir = _export(tmp_path, "fixture")
    server, _spy, _presenter = _write_server(tmp_path, export_dir, Disclosure.MINIMAL)
    assert "certificaat_vervangen" not in {t.name for t in asyncio.run(server.list_tools())}
    export = load_export(export_dir)
    findings = replacement_findings(export, K, "LBV-WEB-01")
    assert findings, "premisse: er is een regel om te verbergen"
    minimal = render(
        Answer(question="voorstel certificaat_vervangen", findings=findings),
        Disclosure.MINIMAL,
        tool="certificaat_vervangen",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-min.json",
    )
    leaked = sorted(n for n in _real_names(export_dir) | {"LBV-WEB-01"} if n in minimal)
    assert leaked == [], leaked
