"""Openheid van het certificaatgebruik en de contentswitchingroute, end to end.

Op de synthetische fixtures certgebruik-saml en keten-cs, plus een samengestelde
export die beide combineert en de CS-beleidsroute via cspolicy/csaction echt
laat lopen (opgelost, geen-LB-doel met actienaam in de reden, beleid zonder
actie, onbekend LB-doel, een vserver die alleen via een GSLB-vserver routeert),
en een variant daarvan met de leesgatpaden van cert_usage. Per variant en per
stand (beperkt, minimaal) worden via de echte MCP-server alle geraakte tools
aangeroepen:

- certificaat_wat_verloopt_er, en per certificaat _wat_breekt_er en _wat_moet_ik_doen;
- het voorstel van certificaat_vervangen (bij minimaal: niet aangeboden);
- dienst_keten zonder argument en met elke ingang (en een servicegroupnaam);
- status_gezondheid en rapport_dekking.

De echte namen komen uit de fixturebestanden zelf (elk identiteitsveld plus elke
waarde met een fixturevoorvoegsel of een IPv4-adres), nooit uit een handlijst.
Premisse bij volledig: de namen staan er wel. Mutatie: families 13 en 16 uit
-> er lekt iets bij beperkt.
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
from conftest import _knowledge_file, maintenance_config, provenance_dir_for, record_collected, seal_manifest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import disclosure as disclosure_module
from nsmcp.disclosure import Disclosure

# 1.1 B.3 point 3: every test of this module runs under the runtime seam
# check (`open_audit` in tests/conftest.py): a product open by path
# outside `nsmcp.localpath` fails it.
pytestmark = pytest.mark.usefixtures("open_audit")

FIXTURES = Path(__file__).parent / "fixtures"
SAML = FIXTURES / "certgebruik-saml"
KETEN = FIXTURES / "keten-cs"

IDENTITY_FIELDS = {
    "name",
    "certkey",
    "certkeyname",
    "servicegroupname",
    "vservername",
    "servername",
    "servicename",
    "parentName",
    "samlidpcertname",
    "samlsigningcertname",
    "samlspcertname",
    "lbvserver",
    "policyname",
    "action",
    "targetlbvserver",
    "targetvserver",
    "ip",
    "ipv46",
}
NAME_SHAPE = re.compile(r"^(CERT|SAML|SG|LBV|CSV|CSPOL|CSACT|SRV|SVC|VPN|GSLB)-[A-Z0-9-]+$|^\d{1,3}(\.\d{1,3}){3}$")


def _harvest(value, names: set[str], key: str | None = None) -> None:
    if isinstance(value, dict):
        for k, item in value.items():
            _harvest(item, names, k)
    elif isinstance(value, list):
        for item in value:
            _harvest(item, names, key)
    elif isinstance(value, str):
        text = value.strip()
        if text and ((key in IDENTITY_FIELDS and len(text) >= 3) or NAME_SHAPE.match(text)):
            names.add(text)


def _real_names(export_dir: Path) -> set[str]:
    names: set[str] = set()
    for sub in ("objects", "bindings"):
        for path in (export_dir / sub).glob("*.json"):
            _harvest(json.loads(path.read_text(encoding="utf-8")), names)
    return names


def _write_json(path: Path, document) -> bytes:
    raw = json.dumps(document, indent=1).encode("utf-8")
    path.write_bytes(raw)
    return raw


def _combined(tmp_path: Path) -> Path:
    """keten-cs + certgebruik-saml in one export, with cspolicy/csaction read."""
    export_dir = tmp_path / "gecombineerd"
    shutil.copytree(KETEN, export_dir)
    manifest = json.loads((export_dir / "export-manifest.json").read_text(encoding="utf-8"))
    saml_manifest = json.loads((SAML / "export-manifest.json").read_text(encoding="utf-8"))
    for resource, entry in saml_manifest["resources"].items():
        manifest["resources"][resource] = dict(entry)
        stem = resource.split("/")[-1]
        shutil.copy(SAML / "objects" / f"{stem}.json", export_dir / "objects" / f"{stem}.json")
    for rel, digest in saml_manifest["files"].items():
        shutil.copy(SAML / rel, export_dir / rel)
        manifest["files"][rel] = digest

    csv = json.loads((export_dir / "objects" / "csvserver.json").read_text(encoding="utf-8"))
    csv["csvserver"] += [
        {"name": "CSV-KETEN-VPN", "curstate": "UP", "ipv46": "198.51.100.5", "port": 443},
        {"name": "CSV-KETEN-GEENACTIE", "curstate": "UP", "ipv46": "198.51.100.6", "port": 443},
        {"name": "CSV-KETEN-WEGDOEL", "curstate": "UP", "ipv46": "198.51.100.7", "port": 443},
        {"name": "CSV-KETEN-GSLB", "curstate": "UP", "ipv46": "198.51.100.8", "port": 443},
    ]
    _write_json(export_dir / "objects" / "csvserver.json", csv)
    manifest["resources"]["config/csvserver"]["objectCount"] = len(csv["csvserver"])

    _write_json(
        export_dir / "objects" / "cspolicy.json",
        {
            "cspolicy": [
                {"policyname": "CSPOL-KETEN-01", "action": "CSACT-KETEN-01", "rule": "true"},
                {"policyname": "CSPOL-KETEN-02", "action": "CSACT-KETEN-VPN", "rule": "true"},
                {"policyname": "CSPOL-KETEN-03", "rule": "true"},
            ]
        },
    )
    _write_json(
        export_dir / "objects" / "csaction.json",
        {
            "csaction": [
                {"name": "CSACT-KETEN-01", "targetlbvserver": "LBV-KETEN-OK"},
                {"name": "CSACT-KETEN-VPN", "targetvserver": "VPN-KETEN-01"},
            ]
        },
    )
    manifest["resources"]["config/cspolicy"] = {"status": "OK", "propertyName": "cspolicy", "objectCount": 3}
    manifest["resources"]["config/csaction"] = {"status": "OK", "propertyName": "csaction", "objectCount": 2}

    binding = json.loads((export_dir / "bindings" / "csvserver_binding.by-parent.json").read_text(encoding="utf-8"))

    def parent(name, **children):
        return {"parentName": name, "outcome": "OK", "data": {"csvserver_binding": {"name": name, **children}}}

    binding["parents"] += [
        parent(
            "CSV-KETEN-VPN",
            csvserver_lbvserver_binding=[{"name": "CSV-KETEN-VPN", "lbvserver": "LBV-KETEN-OK"}],
            csvserver_cspolicy_binding=[{"name": "CSV-KETEN-VPN", "policyname": "CSPOL-KETEN-02", "priority": "90"}],
        ),
        parent(
            "CSV-KETEN-GEENACTIE",
            csvserver_cspolicy_binding=[
                {"name": "CSV-KETEN-GEENACTIE", "policyname": "CSPOL-KETEN-03", "priority": "80"}
            ],
        ),
        parent(
            "CSV-KETEN-WEGDOEL",
            csvserver_cspolicy_binding=[
                {
                    "name": "CSV-KETEN-WEGDOEL",
                    "policyname": "CSPOL-KETEN-01",
                    "targetlbvserver": "LBV-KETEN-WEG",
                    "priority": "70",
                }
            ],
        ),
        parent(
            "CSV-KETEN-GSLB",
            csvserver_gslbvserver_binding=[{"name": "CSV-KETEN-GSLB", "vserver": "GSLB-KETEN-01"}],
        ),
    ]
    raw = _write_json(export_dir / "bindings" / "csvserver_binding.by-parent.json", binding)
    manifest["files"]["bindings/csvserver_binding.by-parent.json"] = hashlib.sha256(raw).hexdigest().upper()
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)
    return export_dir


def _combined_gaps(tmp_path: Path) -> Path:
    from test_cert_usage_openness import _gap_variant

    export_dir = _combined(tmp_path)
    _gap_variant(export_dir)
    return export_dir


def _plain(fixture: Path):
    def build(tmp_path: Path) -> Path:
        export_dir = tmp_path / fixture.name
        shutil.copytree(fixture, export_dir)
        return export_dir

    return build


VARIANTS = {
    "certgebruik-saml": _plain(SAML),
    "keten-cs": _plain(KETEN),
    "gecombineerd": _combined,
    "gecombineerd-leesgaten": _combined_gaps,
}
# Premise per variant: these names DO reach an answer at volledig.
MUST_SHOW = {
    "certgebruik-saml": {"SAML-ACTIE-01", "SAML-IDP-01", "SG-BACKEND-01", "CERT-VS", "LBV-WEB-01"},
    "keten-cs": {"CSV-KETEN-DEFLB", "CSPOL-KETEN-01", "LBV-KETEN-OK", "SRV-KETEN-OK", "198.51.100.1"},
    "gecombineerd": {
        "SAML-ACTIE-01",
        "SG-BACKEND-01",
        "CSPOL-KETEN-02",
        "CSACT-KETEN-VPN",
        "CSPOL-KETEN-03",
        "LBV-KETEN-WEG",
        "198.51.100.5",
        "CSV-KETEN-GSLB",
    },
    "gecombineerd-leesgaten": {"SAML-ACTIE-03", "SG-EXTRA-01", "SG-ONBEKEND-01", "CSACT-KETEN-VPN"},
}
DIENST_FOR_WRITE = {
    "certgebruik-saml": "LBV-WEB-01",
    "keten-cs": "LBV-KETEN-OK",
    "gecombineerd": "LBV-WEB-01",
    "gecombineerd-leesgaten": "LBV-WEB-01",
}
NIEUWCERT = "CERT-NIEUW"


def _bind_target(export_dir: Path, target: str = "lab") -> None:
    digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"{target}\n{digest}\n", encoding="utf-8")
    # The provenance record the same scan leaves, outside the export.
    record_collected(export_dir, target)


def _server(tmp_path: Path, export_dir: Path, level: Disclosure, dienst: str, tag: str):
    from test_handelen_zonder_code import CodeSpy, Spy

    from nsmcp.handelen import Allowlist
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    work = tmp_path / f"srv-{tag}"
    work.mkdir(parents=True, exist_ok=True)
    script = work / "schrijf.ps1"
    script.write_text("# spy", encoding="utf-8")
    return build_server(
        export_dir,
        _knowledge_file(work),
        disclosure=level,
        action_script=script,
        fixture_dir=work,
        action_run=Spy(),
        code_presenter=CodeSpy(),
        allowlist=Allowlist(
            per_target={"lab": {"certificaat_vervangen": {"dienst": (dienst,), "nieuwcert": (NIEUWCERT,)}}}
        ),
        pseudonym_table_path=work / "tabel.json",
        onderhoud=maintenance_config(work),
        provenance_dir=provenance_dir_for(export_dir),
    )


def _calls(export_dir: Path, dienst: str) -> list[tuple[str, dict]]:
    def rows(resource: str, key: str) -> list[str]:
        path = export_dir / "objects" / f"{resource}.json"
        if not path.is_file():
            return []
        return sorted(r[key] for r in json.loads(path.read_text(encoding="utf-8")).get(resource, []) if key in r)

    calls: list[tuple[str, dict]] = [("certificaat_wat_verloopt_er", {"horizon_dagen": 3650})]
    for cert in rows("sslcertkey", "certkey"):
        calls.append(("certificaat_wat_breekt_er", {"certnaam": cert}))
        calls.append(("certificaat_wat_moet_ik_doen", {"certnaam": cert}))
    calls.append(("dienst_keten", {}))
    for entry in [*rows("csvserver", "name"), *rows("lbvserver", "name"), "SG-KETEN-OK"]:
        calls.append(("dienst_keten", {"dienst": entry}))
    calls.append(("status_gezondheid", {}))
    calls.append(("rapport_dekking", {}))
    calls.append(("certificaat_vervangen", {"dienst": dienst, "nieuwcert": NIEUWCERT}))
    return calls


def _answers(server, calls) -> tuple[dict[str, str], set[str]]:
    async def run():
        out: dict[str, str] = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            offered = {t.name for t in (await client.list_tools()).tools}
            for name, arguments in calls:
                if name not in offered:
                    continue
                result = await client.call_tool(name, arguments)
                text = " ".join(b.text for b in result.content if hasattr(b, "text"))
                out[f"{name} {json.dumps(arguments)}"] = (
                    f"isError={result.isError} " + text + " " + json.dumps(result.structuredContent or {})
                )
        return out, offered

    return asyncio.run(run())


def _run(tmp_path: Path, variant: str, level: Disclosure, tag: str):
    export_dir = VARIANTS[variant](tmp_path / f"exp-{tag}")
    _bind_target(export_dir)
    dienst = DIENST_FOR_WRITE[variant]
    server = _server(tmp_path, export_dir, level, dienst, tag)
    answers, offered = _answers(server, _calls(export_dir, dienst))
    return export_dir, answers, offered


EXPECTED_TOOLS = {
    "certificaat_wat_verloopt_er",
    "certificaat_wat_breekt_er",
    "certificaat_wat_moet_ik_doen",
    "dienst_keten",
    "status_gezondheid",
    "rapport_dekking",
}


@pytest.mark.parametrize("variant", list(VARIANTS))
def test_no_fixture_name_leaks_at_beperkt_or_minimaal_over_every_touched_tool(tmp_path, variant):
    export_dir, full, offered = _run(tmp_path, variant, Disclosure.FULL, "vol")
    real = _real_names(export_dir)
    assert MUST_SHOW[variant] <= real, MUST_SHOW[variant] - real
    assert EXPECTED_TOOLS | {"certificaat_vervangen"} <= offered
    joined = " ".join(full.values())
    shown = {n for n in real if n in joined}
    assert MUST_SHOW[variant] <= shown, ("premisse", MUST_SHOW[variant] - shown)
    assert not any(v.startswith("isError=True") for v in full.values()), [
        k for k, v in full.items() if v.startswith("isError=True")
    ]
    if variant.startswith("gecombineerd"):
        assert "verwijst naar een vserver die geen loadbalancing-vserver is" in joined
        assert "heeft geen leesbare actie in cspolicy" in joined
        assert "die niet voorkomt in config/lbvserver" in joined
        assert "dit certificaat is ook elders in gebruik" in joined
        assert "wel een bindingssoort die deze versie niet leest (csvserver_gslbvserver_binding)" in joined

    report = {"variant": variant, "real": len(real), "shown_at_full": len(shown), "calls": len(full)}
    for level, tag in ((Disclosure.LIMITED, "beperkt"), (Disclosure.MINIMAL, "minimaal")):
        _dir, answers, offered = _run(tmp_path, variant, level, tag)
        assert EXPECTED_TOOLS <= offered, (tag, EXPECTED_TOOLS - offered)
        if level is Disclosure.MINIMAL:
            assert "certificaat_vervangen" not in offered
        else:
            assert any(k.startswith("certificaat_vervangen") for k in answers)
        leaked = {k: sorted(n for n in real if n in v) for k, v in answers.items()}
        leaked = {k: v for k, v in leaked.items() if v}
        assert leaked == {}, f"{tag}: {leaked}"
        report[tag] = len(answers)
    print("OPENHEID-PROEF", json.dumps(report))


def test_the_probe_can_fail_without_families_13_and_16(tmp_path, monkeypatch):
    """Mutation: the chain family and the certificate-use family off -> a leak at beperkt."""
    monkeypatch.setattr(disclosure_module, "names_in_chain_sources", lambda export: ())
    monkeypatch.setattr(disclosure_module, "names_in_cert_usage_sources", lambda export: ())
    export_dir, answers, _offered = _run(tmp_path, "gecombineerd", Disclosure.LIMITED, "mutant")
    real = _real_names(export_dir)
    leaked = sorted({n for v in answers.values() for n in real if n in v})
    print("OPENHEID-MUTANT", leaked)
    assert set(leaked) & {"CSACT-KETEN-VPN", "CSPOL-KETEN-03", "SAML-ACTIE-01", "SG-BACKEND-01"}, leaked
