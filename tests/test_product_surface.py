"""Product-surface parity guard for the translation round.

Everything a customer or their AI client sees must stay exactly as it is:
MCP tool names, the FULL tool descriptions and input schemas (snapshot of
the master baseline 1cdc563, byte for byte - a first-line-only pin let a
rewritten status_ververs description slip through unseen), config keys,
on-disk artifact names, enum values and the key Dutch product texts.
Rename tasks may only change code-internal names, so every task must end
with this file green - the imports below may be updated mechanically when
identifiers are renamed, the pinned STRINGS may not change. The three
getattr guards at the bottom fail loudly when a field rename forgets a
string-based lookup that would otherwise fall back silently to its
fail-closed default.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

# `_export_dir`/`_knowledge_file` used to be a second, local
# copy of the exact helpers `tests/conftest.py` already defines (byte-for-
# byte identical shape, only the local variable names differed) - a second
# version of a fixture that should be shared, not duplicated. Imported from
# conftest.py now, so the export-manifest shape lives in one place.
# `tests/test_mcp_server.py` keeps its OWN `_export_dir`: that one takes
# optional `resources`/`files` overrides conftest's fixed-shape helper does
# not support, so it differs in substance, not by accident, and stays put.
#
# This bare `from conftest import ...` works only because
# `tests/` has no `__init__.py` and pytest has no `[tool.pytest.ini_options]`
# import-mode setting - pytest's rootless (`prepend`/legacy) import puts
# `tests/` itself on `sys.path` and loads `conftest.py` as a top-level
# module before this file, which is why `conftest` resolves here at all. A
# later `[tool.pytest.ini_options]` block (an `importmode` other than the
# default, or turning `tests/` into a real package) can break this import
# silently; if that ever happens, this comment is the pointer to why.
from conftest import _export_dir, _knowledge_file, maintenance_config

from nsmcp import mcp_server as mcp_server_module, start
from nsmcp.action import what_to_do
from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.backup import backup_name
from nsmcp.collect import PHASE_NAMES, PHASE_ORDER, PHASE_WORDS
from nsmcp.disclosure import Disclosure, render
from nsmcp.handelen import WRITE_TOOLS, Allowlist, MaintenanceConfig
from nsmcp.impact import ImpactAnswer
from nsmcp.knowledge import Knowledge
from nsmcp.mcp_server import STATUS_VERVERS_DESCRIPTION, build_server, mask_error
from nsmcp.profile import Profile
from nsmcp.target import CertAgreement


def _full_handelen_server(tmp_path: Path):
    """The SAME construction as `_handelen_server`
    (conftest.py) PLUS `onderhoud` and an allowlist that grants
    `onderhoud_upgrade_fase` on one target - the 17th tool's OWN
    registration gate (design 3.1, `mcp_server.py`: `writing_allowed and
    "onderhoud" in chapters and onderhoud is not None and any(allowlist.
    allows(...))`) needs both, and `_handelen_server` deliberately
    configures neither (it is the shared baseline, shared with
    `tests/test_firmware_boundary.py`, which reads its own branch off
    whether the runner is REALLY registered on THAT fixture - unaffected by
    this one). A LOCAL helper, not a change to the shared fixture, keeps
    this task's own scope to this file. `runner`/`ledgermap`/`firmwaremap`
    need not exist: `build_server()` never touches them, only
    `start.py`'s config loader does."""
    script = tmp_path / "schrijf.ps1"
    script.write_text("# leeg; deze fixture voert niets uit", encoding="utf-8")
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    allowlist = Allowlist(per_target={"lab": {"onderhoud_upgrade_fase": True, "config_opslaan": True}})
    targets, collect_script = _scan_config(tmp_path)
    return build_server(
        _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        action_script=script,
        fixture_dir=tmp_path,
        code_presenter=lambda *args: None,
        onderhoud=onderhoud,
        allowlist=allowlist,
        targets_path=targets,
        collect_script=collect_script,
    )


# The status_ververs description, WRITTEN OUT here instead of imported.
# The old pin read `"description": STATUS_VERVERS_DESCRIPTION` - it compared
# the constant with itself, so any rewrite of that text passed unseen: exactly
# the hole a full-text pin exists to close. The literal below is the product
# surface; `test_status_ververs_description_matches_the_pinned_text` compares
# the module constant against it.
_STATUS_VERVERS_TEXT = (
    "Hoofdstuk status. Scan een ingesteld doel opnieuw. Duurt minuten - dit is geen "
    "snelle aanroep. Gebruik dit alleen als de gegevens niet van vandaag zijn.\n"
    "\n"
    "De scan draait als apart proces op een aparte thread, zodat de server tijdens de "
    "scan bereikbaar blijft voor andere aanroepen, voor een ping en voor een annulering.\n"
    "\n"
    "Annuleren wordt gehonoreerd tot de omwisselgrens: daarvoor wordt de scan afgebroken, "
    "het kindproces echt beeindigd en blijven de vorige gegevens gelden. Daarna is de "
    "omwisseling onomkeerbaar en bij die eerste annulering zegt het antwoord dat met "
    "zoveel woorden.\n"
    "\n"
    "Een scan schrijft nooit over de huidige export heen: hij gaat naar een verse map en "
    "wordt pas na controle omgewisseld. Wat er na een mislukte of afgebroken scan geldt, "
    "staat in het antwoord zelf; de gegevensleeftijd in het volgende antwoord laat zien "
    "of er werkelijk iets ververst is."
)


# The optional `doel` of the export-backed reading tools: the same schema on
# all twenty of them (and on `config_drift`, which had it first). A given
# `doel` must be a configured target and the target the export describes.
_DOEL = {"default": "", "title": "Doel", "type": "string"}


# Full snapshot of the MCP product surface as the master baseline 1cdc563
# serves it over list_tools(): name + COMPLETE description + inputSchema,
# byte for byte. Dumped from a real server built from a clean checkout of
# that commit. The whole description is product surface: an AI client reads
# all of it, so all of it is pinned - a first-line-only pin already let a
# fully rewritten status_ververs description through once.
_BASELINE_SURFACE = {
    "certificaat_wat_verloopt_er": {
        "description": (
            "Hoofdstuk certificaat. Welke certificaten verlopen binnen de horizon, "
            "gesorteerd op impact in plaats van op dagen: eerst wat aan een virtuele server "
            "hangt, dan wat andere certificaten uitgeeft, dan de rest. Met sleutellengte, "
            "handtekeningalgoritme, bewijs en leesgaten. Gebruik dit als de vraag gaat over "
            "wat er binnenkort verloopt."
        ),
        "inputSchema": {
            "properties": {
                "horizon_dagen": {"default": 90, "title": "Horizon Dagen", "type": "integer"},
                "doel": _DOEL,
            },
            "title": "certificaat_wat_verloopt_erArguments",
            "type": "object",
        },
    },
    "certificaat_wat_breekt_er": {
        "description": (
            "Hoofdstuk certificaat. Welke virtuele servers vallen uit als dit certificaat "
            "verloopt, ook via de certificaten die het uitgeeft, en waar het verder in gebruik is: "
            "SSL-diensten, SAML-acties, SAML-IdP-profielen en SSL-servicegroups. Gebruik dit als de vraag gaat "
            "over impact of keten. Kent de export de naam niet, dan noemt het antwoord bij openheid volledig "
            "de certificaten die de term bevatten; bij beperkt of minimaal blijft die lijst weg. "
            "Stel de vraag dan opnieuw met een volledige naam."
        ),
        "inputSchema": {
            "properties": {"certnaam": {"title": "Certnaam", "type": "string"}, "doel": _DOEL},
            "required": ["certnaam"],
            "title": "certificaat_wat_breekt_erArguments",
            "type": "object",
        },
    },
    "certificaat_wat_moet_ik_doen": {
        "description": (
            "Hoofdstuk certificaat. Wijziging, terugrol en terugleescontrole voor dit "
            "certificaat - alleen als de impact vaststaat. Gebruik dit als de vraag is wat er "
            "nu moet gebeuren. Kent de export de naam niet, dan noemt het antwoord bij openheid volledig "
            "de certificaten die de term bevatten; bij beperkt of minimaal blijft die lijst weg. "
            "Stel de vraag dan opnieuw met een volledige naam."
        ),
        "inputSchema": {
            "properties": {"certnaam": {"title": "Certnaam", "type": "string"}, "doel": _DOEL},
            "required": ["certnaam"],
            "title": "certificaat_wat_moet_ik_doenArguments",
            "type": "object",
        },
    },
    "status_ververs": {
        "description": _STATUS_VERVERS_TEXT,
        "inputSchema": {
            "properties": {"doelnaam": {"title": "Doelnaam", "type": "string"}},
            "required": ["doelnaam"],
            "title": "status_verversArguments",
            "type": "object",
        },
    },
    "status_cve_controle": {
        "description": (
            "Hoofdstuk status. Toetst de build van de NetScaler aan de bekende "
            "securitybulletins uit het kennispakket, in twee lagen: zit de build onder de "
            "fix-build, en is de voorwaarde uit het bulletin in de configuratie aanwezig. "
            "Gebruik dit als de vraag is of een CVE deze NetScaler raakt."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_cve_controleArguments",
            "type": "object",
        },
    },
    "dienst_status": {
        "description": (
            "Hoofdstuk dienst. De toestand van een dienst (virtuele server) en van elk lid "
            "van de gebonden servicegroup, zoals de appliance die rapporteert. Gebruik dit "
            "als de vraag is hoe een dienst of een webserver ervoor staat."
        ),
        "inputSchema": {
            "properties": {"dienst": {"title": "Dienst", "type": "string"}, "doel": _DOEL},
            "required": ["dienst"],
            "title": "dienst_statusArguments",
            "type": "object",
        },
    },
    "dienst_keten": {
        "description": (
            "Hoofdstuk dienst. De keten van een dienst, van VIP tot backend: ingang, "
            "backendgroep en leden, met per keten of hij compleet is, waar het gat zit of "
            "dat hij niet vast te stellen is. Laat het argument leeg voor alle ketens. "
            "Losse objecten staan in een apart blok. Dit bewijst niet dat het verkeer ook "
            "echt zo loopt."
        ),
        "inputSchema": {
            "properties": {"dienst": {"default": "", "title": "Dienst", "type": "string"}, "doel": _DOEL},
            "title": "dienst_ketenArguments",
            "type": "object",
        },
    },
    "status_overzicht": {
        "description": (
            "Hoofdstuk status. Een overzicht van de NetScaler: build, HA-stand, aantal "
            "virtuele servers en hoe oud de gegevens zijn. Gebruik dit als eerste vraag, of "
            "als de vraag is hoe de NetScaler ervoor staat."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_overzichtArguments",
            "type": "object",
        },
    },
    "status_update_advies": {
        "description": (
            "Hoofdstuk status. Zegt welke build op deze NetScaler hoort: de huidige build, "
            "de vloer uit het kennispakket en de aangeboden build van de vendor, drie naast "
            "elkaar met hun herkomst en leeftijd. Gebruik dit als de vraag is welke build "
            "erop moet."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_update_adviesArguments",
            "type": "object",
        },
    },
    "status_update_preflight": {
        "description": (
            "Hoofdstuk status. Loopt negen toetsen na die een upgrade binnen 14.1 kunnen "
            "tegenhouden: licentie, classic-markers, HA-stand, drift tussen running en "
            "saved, certificaathorizon, build en tak, vormfactor, vrije ruimte op /var en "
            "het terugrolpad. De vrije ruimte wordt live gelezen in een apart proces: "
            "over SSH als onderhoud is ingesteld en het doel een gepinde hostsleutel "
            "heeft, anders via hetzelfde verzamelscript als de scan; dit is geen "
            "vendor-precheck. Gebruik dit voordat een onderhoudsvenster gepland wordt."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_update_preflightArguments",
            "type": "object",
        },
    },
    "kennis_uitleg": {
        "description": (
            "Hoofdstuk kennis. Legt een NetScaler-begrip uit vanuit het geladen "
            "kennispakket, of zegt dat het er niet in staat. Gebruik dit als je een term "
            "uit een antwoord wilt begrijpen; verzin nooit zelf een uitleg."
        ),
        "inputSchema": {
            "properties": {"begrip": {"title": "Begrip", "type": "string"}},
            "required": ["begrip"],
            "title": "kennis_uitlegArguments",
            "type": "object",
        },
    },
    "onderhoud_upgrade_plan": {
        "description": (
            "Hoofdstuk onderhoud. Stelt het plan op voor een upgrade binnen 14.1: de zeven "
            "fasen, de HA-volgorde (secondary eerst), het soakvenster, het terugrolpad per "
            "fase en per fase de poort die open moet. Deze tool leest alleen en wijzigt "
            "niets. Gebruik dit als een onderhoudsvenster voorbereid moet worden."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "onderhoud_upgrade_planArguments",
            "type": "object",
        },
    },
    "status_namen": {
        "description": (
            "Hoofdstuk status. Welke namen deze NetScaler kent, per familie: "
            "loadbalancing-, contentswitching- en Gateway-vservers, servicegroups, "
            "services en certificaten. Gebruik dit als je een naam nodig hebt voor een "
            "andere vraag; verzin nooit zelf een naam."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_namenArguments",
            "type": "object",
        },
    },
    "status_doelen": {
        "description": (
            "Hoofdstuk status. Welke NetScalers deze server kent: per doel de naam, het adres, "
            "hoe oud de export van dat doel is, de laatste onderhoudsrun en welke schrijvende "
            "gereedschappen voor dat doel zijn toegestaan. Credential-namen staan er nooit in. "
            "Gebruik dit als eerste vraag als niet duidelijk is welke doelen er zijn."
        ),
        "inputSchema": {
            "properties": {},
            "title": "status_doelenArguments",
            "type": "object",
        },
    },
    "status_gezondheid": {
        "description": (
            "Hoofdstuk status. Wat er DOWN stond op het moment van de scan: tellingen en "
            "namen per familie, met storing en dekkingsuitspraak strikt gescheiden. Dit is "
            "een momentopname uit de export met een gegevensleeftijd, geen bewaking."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "status_gezondheidArguments",
            "type": "object",
        },
    },
    "rapport_dekking": {
        "description": (
            "Hoofdstuk rapport. Hoe compleet dit antwoord is: per bron of hij gelezen is, "
            "welke bronnen mislukten, geweigerd werden of ontbraken, en of de kruiscontrole "
            "op de bindingen rondkwam. Gebruik dit als je wilt weten wat dit product NIET "
            "heeft kunnen lezen."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "rapport_dekkingArguments",
            "type": "object",
        },
    },
    "rapport_vergelijk": {
        "description": (
            "Hoofdstuk rapport. Vergelijkt twee exportmappen in een van vier modi: "
            "HA-parity (HA-pariteit: primary tegenover secondary), drift (nu tegenover "
            "een goedgekeurde baseline), run-diff (dezelfde doos op twee momenten) of "
            "pre/post (rond een wijziging). Configuratieverschillen, standverschillen en "
            "dekkingsverschillen staan in drie gescheiden blokken. Welke van de twee "
            "standen goed is, zegt dit antwoord niet - dat is een menselijk oordeel."
        ),
        "inputSchema": {
            "properties": {
                "mapA": {"title": "Mapa", "type": "string"},
                "mapB": {"title": "Mapb", "type": "string"},
                "modus": {"default": "run-diff", "title": "Modus", "type": "string"},
            },
            "required": ["mapA", "mapB"],
            "title": "rapport_vergelijkArguments",
            "type": "object",
        },
    },
    "rapport_wat_is_er_veranderd": {
        "description": (
            "Hoofdstuk rapport. Wat er veranderd is sinds de vorige scan van dit doel: "
            "dezelfde vergelijking als rapport_vergelijk in de modus run-diff, met de twee "
            "mappen zelf gekozen. Is er geen bewaarde vorige export, dan zegt het antwoord "
            "dat er niets te vergelijken is - niet dat er geen verschillen zijn."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "rapport_wat_is_er_veranderdArguments",
            "type": "object",
        },
    },
    "ha_stand": {
        "description": (
            "Hoofdstuk ha. De HA-stand voor een wijziging: rolverdeling, sync en "
            "propagatie, geforceerde stand en het verschil tussen de running en de saved "
            "config, elk aan, uit of onbevestigd - en niet van toepassing op de twee "
            "standen die een paar beschrijven als er geen HA-paar is. Gebruik dit voordat "
            "je iets op de primary "
            "wijzigt. Het antwoord bewijst geen werkende failover en zegt niets over de "
            "configuratie van de partner."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "ha_standArguments",
            "type": "object",
        },
    },
    "config_drift": {
        "description": (
            "Hoofdstuk config. Welke regels alleen in de draaiende configuratie staan en welke alleen in de "
            "opgeslagen configuratie, uit de export. Kopregels en de afsluitende 'Done' tellen niet mee. De "
            "regels zelf staan er alleen bij openheid volledig, en een regel met een herkend geheim of een "
            "geredigeerde waarde nooit. Gebruik dit voordat je configuratie opslaat of een onderhoudsvenster "
            "plant."
        ),
        "inputSchema": {
            "properties": {"doel": {"default": "", "title": "Doel", "type": "string"}},
            "title": "config_driftArguments",
            "type": "object",
        },
    },
    "beveiliging_verstopte_regels": {
        "description": (
            "Hoofdstuk beveiliging. De negenentwintig verstopte regels waar geen alarm op "
            "staat: per regel of hij geraakt is, op welke objecten, en waarom dat niet "
            "opvalt. Gebruik dit als de vraag is wat er in deze configuratie verstopt zit. "
            "De regels lezen configuratievelden en bewijzen geen gedrag."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "beveiliging_verstopte_regelsArguments",
            "type": "object",
        },
    },
    "beveiliging_tls_baseline": {
        "description": (
            "Hoofdstuk beveiliging. Een TLS-cijfer per virtuele server (A+ tot en met T) met "
            "de bepalende kenmerken, plus de verdeling over de appliance en de gebruikte "
            "regelsetversie. Protocol en ciphers komen van het gebonden SSL-profiel als er "
            "een is. Dit is een configuratieweging, geen live scan."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "beveiliging_tls_baselineArguments",
            "type": "object",
        },
    },
    "beveiliging_beheervlak": {
        "description": (
            "Hoofdstuk beveiliging. Staat het beheer van deze appliance open: blootstelling "
            "op data-plane-adressen, cleartext transport, het default beheercertificaat op "
            "productieverkeer en de RBAC-hardening. Elk van de vier is PASS, FAIL of NIET "
            "BEOORDEELD. Een netwerk-ACL voor het beheeradres ziet dit antwoord niet."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "beveiliging_beheervlakArguments",
            "type": "object",
        },
    },
    "beveiliging_headers": {
        "description": (
            "Hoofdstuk beveiliging. Staan de zes HTTP-securityheaders er echt op: per header "
            "aanwezig en gebonden, wel gedefinieerd maar niet gebonden, afwezig of niet "
            "beoordeeld. Een action of policy zonder effectieve RESPONSE-binding telt niet. "
            "HSTS telt alleen via een FrontEnd-SSL-profiel met hsts=ENABLED; de vserverbinding "
            "is afzonderlijk bewijs."
        ),
        "inputSchema": {
            "properties": {"doel": _DOEL},
            "title": "beveiliging_headersArguments",
            "type": "object",
        },
    },
    "beveiliging_scorekaart": {
        "description": "Hoofdstuk beveiliging. De Level-1 scorekaart uit de export: per control PASS, FAIL of NIET BEOORDEELD, met ernst, zekerheid en toepasselijkheid. De kop is 'X van Y beoordeeld' - nooit een percentage en nooit een letter voor de appliance als geheel. Onderaan staat vast wat buiten het bereik van deze meting valt.",
        "inputSchema": {"properties": {"doel": _DOEL}, "title": "beveiliging_scorekaartArguments", "type": "object"},
    },
}


def test_full_tool_surface_matches_master_baseline(tmp_path):
    targets, collect_script = _scan_config(tmp_path)
    server = build_server(
        _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        targets_path=targets,
        collect_script=collect_script,
        onderhoud=maintenance_config(tmp_path),
    )
    tools = {t.name: t for t in asyncio.run(server.list_tools())}

    assert set(tools) == set(_BASELINE_SURFACE) | {"onderhoud_upgrade_stand", "rapport_na_upgrade"}

    for name, baseline in _BASELINE_SURFACE.items():
        assert tools[name].description == baseline["description"], (
            f"description of {name} drifted from the master baseline"
        )
        assert tools[name].inputSchema == baseline["inputSchema"], (
            f"inputSchema of {name} drifted from the master baseline"
        )


# The five WRITING tools, which only exist when a `handelen` section is
# configured (action_script + fixture_dir) - and only at
# openheid `volledig`. They are as much product surface as the eleven reading
# tools: an AI client reads their whole description before it dares call
# them. The design (sections 10 and 11) named twelve pinned tools;
# `status_update_advies` (B2, design 2.3) is the thirteenth,
# `status_update_preflight` (B3, design 2.3) the fourteenth,
# `onderhoud_backup_maken` (B4) the fifteenth and
# `onderhoud_upgrade_plan` (B7) - a READING tool, in
# `_BASELINE_SURFACE` above, not here - the sixteenth.
_HANDELEN_SURFACE = {
    "certificaat_klaarzetten": {
        "description": (
            "Hoofdstuk certificaat. Zet een vervangend certificaat klaar op de appliance "
            "zonder het te binden. Eerste aanroep geeft een voorstel ZONDER code: de "
            "bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel "
            "nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool "
            "dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler "
            "is ingesteld. Gebruik dit als er een nieuw certificaat klaargezet moet "
            "worden."
        ),
        "inputSchema": {
            "properties": {
                "certnaam": {"title": "Certnaam", "type": "string"},
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "required": ["certnaam"],
            "title": "certificaat_klaarzettenArguments",
            "type": "object",
        },
    },
    "certificaat_vervangen": {
        "description": (
            "Hoofdstuk certificaat. Wisselt op een dienst het gebonden certificaat om naar "
            "een ander; het schrijfscript leest terug en het product geeft die uitkomst "
            "letterlijk door. Eerste aanroep geeft een voorstel ZONDER code: de "
            "bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel "
            "nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool "
            "dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler "
            "is ingesteld. Gebruik dit als een certificaat vervangen moet worden."
        ),
        "inputSchema": {
            "properties": {
                "dienst": {"title": "Dienst", "type": "string"},
                "nieuwcert": {"title": "Nieuwcert", "type": "string"},
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "required": ["dienst", "nieuwcert"],
            "title": "certificaat_vervangenArguments",
            "type": "object",
        },
    },
    "dienst_lid_uitschakelen": {
        "description": (
            "Hoofdstuk dienst. Haalt een lid uit een servicegroup (OUT OF SERVICE); het "
            "schrijfscript leest terug en het product geeft die uitkomst letterlijk door. Het "
            "argument dienst is hier de servicegroup - de naam die dienst_status onder "
            "'servicegroup' toont - niet de virtuele server. Eerste aanroep geeft een "
            "voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar "
            "jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code "
            "doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als "
            "er meer dan een NetScaler is ingesteld. Gebruik dit als een webserver uit de "
            "dienst moet."
        ),
        "inputSchema": {
            "properties": {
                "dienst": {"title": "Dienst", "type": "string"},
                "lid": {"title": "Lid", "type": "string"},
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "required": ["dienst", "lid"],
            "title": "dienst_lid_uitschakelenArguments",
            "type": "object",
        },
    },
    "dienst_lid_inschakelen": {
        "description": (
            "Hoofdstuk dienst. Zet een eerder uitgeschakeld lid weer in de servicegroup; het "
            "schrijfscript leest terug en het product geeft die uitkomst letterlijk door. Het "
            "argument dienst is hier de servicegroup - de naam die dienst_status onder "
            "'servicegroup' toont - niet de virtuele server. Eerste aanroep geeft een "
            "voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar "
            "jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code "
            "doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als "
            "er meer dan een NetScaler is ingesteld. Gebruik dit om een uitschakeling "
            "ongedaan te maken."
        ),
        "inputSchema": {
            "properties": {
                "dienst": {"title": "Dienst", "type": "string"},
                "lid": {"title": "Lid", "type": "string"},
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "required": ["dienst", "lid"],
            "title": "dienst_lid_inschakelenArguments",
            "type": "object",
        },
    },
    "onderhoud_backup_maken": {
        "description": (
            "Hoofdstuk onderhoud. Laat de NetScaler zelf een volledige backup maken en leest "
            "die terug in de backupcollectie; de naam wordt hier gevormd in UTC. Eerste "
            "aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de "
            "beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de "
            "beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. "
            "Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit voordat er "
            "aan de NetScaler gewerkt wordt."
        ),
        "inputSchema": {
            "properties": {
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "title": "onderhoud_backup_makenArguments",
            "type": "object",
        },
    },
    "config_opslaan": {
        "description": (
            "Hoofdstuk config. Laat de NetScaler de draaiende configuratie opslaan (save ns "
            "config) en leest daarna terug dat de laatste opslag niet ouder is dan de laatste "
            "wijziging. Weigert op een node die secondary is. Eerste aanroep geeft een voorstel "
            "ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een "
            "voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze "
            "tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is "
            "ingesteld. Gebruik dit als config_drift regels toont die bewaard moeten blijven."
        ),
        "inputSchema": {
            "properties": {
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "title": "config_opslaanArguments",
            "type": "object",
        },
    },
    "onderhoud_upgrade_fase": {
        "description": (
            "Hoofdstuk onderhoud. Voert een van de zeven fasen (R0 t/m R6) van een upgrade "
            "binnen 14.1 uit op de node die aantoonbaar secondary is, elke fase met een eigen "
            "bevestigingscode. Het oordeel komt uit het ledger en niet uit dit antwoord: vraag "
            "het na met onderhoud_upgrade_stand. Eerste aanroep geeft een voorstel ZONDER "
            "code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een "
            "voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze "
            "tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler "
            "is ingesteld."
        ),
        "inputSchema": {
            "properties": {
                "fase": {"title": "Fase", "type": "string"},
                "run": {"default": "", "title": "Run", "type": "string"},
                "snapshotverwijzing": {
                    "default": "",
                    "title": "Snapshotverwijzing",
                    "type": "string",
                },
                "doelbuild_geaccepteerd": {
                    "default": False,
                    "title": "Doelbuild Geaccepteerd",
                    "type": "boolean",
                },
                "drift_geaccepteerd": {
                    "default": False,
                    "title": "Drift Geaccepteerd",
                    "type": "boolean",
                },
                "standalone_geaccepteerd": {
                    "default": False,
                    "title": "Standalone Geaccepteerd",
                    "type": "boolean",
                },
                "oude_buildbomen_opruimen": {
                    "default": False,
                    "title": "Oude Buildbomen Opruimen",
                    "type": "boolean",
                },
                "bevestiging": {"default": "", "title": "Bevestiging", "type": "string"},
                "doel": {"default": "", "title": "Doel", "type": "string"},
            },
            "required": ["fase"],
            "title": "onderhoud_upgrade_faseArguments",
            "type": "object",
        },
    },
    "onderhoud_upgrade_stand": {
        "description": (
            "Hoofdstuk onderhoud. Leest het ledger van een upgraderun en geeft per fase de "
            "poorten met hun uitkomst, plus hoe oud de laatste regel is. Zonder run: de "
            "laatste run op dat doel. Deze tool leest alleen en wijzigt niets. Gebruik dit "
            "om te zien hoe een fase is afgelopen."
        ),
        "inputSchema": {
            "properties": {
                "doel": {"default": "", "title": "Doel", "type": "string"},
                "run": {"default": "", "title": "Run", "type": "string"},
            },
            "title": "onderhoud_upgrade_standArguments",
            "type": "object",
        },
    },
    "rapport_na_upgrade": {
        "description": (
            "Hoofdstuk rapport. Zet de stand van voor en na een upgrade naast elkaar: per "
            "bron voor en na, het CVE-oordeel op de nieuwe build, de extra stap die het "
            "bulletin na de upgrade vraagt als eigen controle, en het genormaliseerde "
            "configuratie-anker met het aantal uitgesloten blob-regels per soort. Gebruik dit "
            "na een upgrade om te zien wat er veranderd is."
        ),
        "inputSchema": {
            "properties": {
                "doel": {"default": "", "title": "Doel", "type": "string"},
                "run": {"default": "", "title": "Run", "type": "string"},
            },
            "title": "rapport_na_upgradeArguments",
            "type": "object",
        },
    },
}


def test_status_ververs_description_matches_the_pinned_text():
    """The pin above is a literal, not the constant itself: comparing the
    constant with itself proved nothing. THIS is the comparison."""
    assert STATUS_VERVERS_DESCRIPTION == _STATUS_VERVERS_TEXT


# The verdict sentence design 2.1.1 pins VERBATIM behind `verstreken` -
# see `stand_answer()` (upgrade.py). This was
# asserted only by two substrings (tests/test_upgrade_stand.py); every
# verdict sentence is pinned byte-for-byte HERE, and a one-off manual
# comparison script is not a test.
_SOAK_VERSTREKEN_TEXT = (
    "Het soakvenster is verstreken. Dat is geen goedkeuring: de volgende stap - de failover "
    "en de tweede node - is een menselijke handeling."
)


def test_soak_verstreken_sentence_matches_the_pinned_text():
    from nsmcp.upgrade import SOAK_VERSTREKEN_SENTENCE

    assert SOAK_VERSTREKEN_SENTENCE == _SOAK_VERSTREKEN_TEXT


# Three Dutch refusal
# sentences pinned nowhere byte-for-byte before this fix - asserted,
# where at all, only by substring elsewhere (tests/test_upgrade_fase.py,
# tests/test_handelen_zonder_code.py). Same discipline as
# `_SOAK_VERSTREKEN_TEXT` above.
_RUN_NAAM_ONVEILIG_TEXT = (
    "de fase wordt niet gestart: de run-naam voor deze fase is geen veilig pad-segment; dit "
    "product gebruikt geen ongecontroleerde tekst als bestandsnaam"
)
_LEDGERPAD_BUITEN_LEDGERMAP_TEXT = (
    "de fase wordt niet gestart: het ledgerpad voor deze run wijst buiten onderhoud.ledgermap"
)
_BEVESTIGER_NIET_VASTGELEGD_TEXT = "niet vastgelegd (dit codekanaal kan de bevestiger niet identificeren)"


def test_the_three_refusal_sentences_match_the_pinned_text():
    from nsmcp.mcp_server import (
        BEVESTIGER_NIET_VASTGELEGD_TEXT,
        LEDGERPAD_BUITEN_LEDGERMAP_TEXT,
        RUN_NAAM_ONVEILIG_TEXT,
    )

    assert RUN_NAAM_ONVEILIG_TEXT == _RUN_NAAM_ONVEILIG_TEXT
    assert LEDGERPAD_BUITEN_LEDGERMAP_TEXT == _LEDGERPAD_BUITEN_LEDGERMAP_TEXT
    assert BEVESTIGER_NIET_VASTGELEGD_TEXT == _BEVESTIGER_NIET_VASTGELEGD_TEXT


# `rapport_na_upgrade`: the five sentences of the
# extra-step table (`nsmcp.after_upgrade`) - four from the original design
# verbatim, plus this module's own new "no bulletin carries an extra step"
# fallback. Same discipline as `_SOAK_VERSTREKEN_TEXT` above: pinned as a
# separate literal, so a rewrite of the constant is caught here rather than
# comparing the constant with itself.
_EXTRA_STEP_DONE_TEXT = "de extra stap is uitgevoerd"
_EXTRA_STEP_PENDING_TEXT = "de extra stap moet nog"
_EXTRA_STEP_TOO_OLD_TEXT = "build te oud, stap nog niet mogelijk"
_EXTRA_STEP_NO_COMMAND_TEXT = "de extra stap noemt geen herkenbaar commando"
_EXTRA_STEP_NONE_IN_KNOWLEDGE_TEXT = "geen enkel bulletin in dit kennispakket draagt een extra stap na de upgrade"


def test_the_extra_step_sentences_match_the_pinned_text():
    from nsmcp.after_upgrade import (
        EXTRA_STEP_DONE,
        EXTRA_STEP_NO_COMMAND,
        EXTRA_STEP_NONE_IN_KNOWLEDGE,
        EXTRA_STEP_PENDING,
        EXTRA_STEP_TOO_OLD,
    )

    assert EXTRA_STEP_DONE == _EXTRA_STEP_DONE_TEXT
    assert EXTRA_STEP_PENDING == _EXTRA_STEP_PENDING_TEXT
    assert EXTRA_STEP_TOO_OLD == _EXTRA_STEP_TOO_OLD_TEXT
    assert EXTRA_STEP_NO_COMMAND == _EXTRA_STEP_NO_COMMAND_TEXT
    assert EXTRA_STEP_NONE_IN_KNOWLEDGE == _EXTRA_STEP_NONE_IN_KNOWLEDGE_TEXT


# The two anchor sides of block 4 do
# not come from the same kind of reading, and the customer-visible evidence
# says which is which. Pinned for the same reason as the five sentences
# above - this is the copy that keeps a `verschillend` caused by the SHAPE
# of the two sources distinguishable from real configuration drift.
_ANCHOR_SOURCE_R0_TEXT = "uit de export van voor de upgrade (parsed/runningconfig.txt, geredigeerd verzameld)"
_ANCHOR_SOURCE_R5_TEXT = "live gelezen na de upgrade (show ns runningConfig over SSH)"
_ANCHOR_SOURCES_DIFFER_TEXT = (
    "de twee ankers komen uit verschillende bronnen: de export van R0 is bij het verzamelen "
    "geredigeerd, de live lezing van R5 niet. Een verschil hoeft daarom geen "
    "configuratiewijziging te zijn; zie docs/klant/OPENSTAANDE-METINGEN.md"
)


def test_the_anchor_source_sentences_match_the_pinned_text():
    from nsmcp.after_upgrade import (
        ANCHOR_SOURCE_R0,
        ANCHOR_SOURCE_R5,
        ANCHOR_SOURCES_DIFFER,
    )

    assert ANCHOR_SOURCE_R0 == _ANCHOR_SOURCE_R0_TEXT
    assert ANCHOR_SOURCE_R5 == _ANCHOR_SOURCE_R5_TEXT
    assert ANCHOR_SOURCES_DIFFER == _ANCHOR_SOURCES_DIFFER_TEXT


# Block 2's own subject when the freshness
# gate fires, and its two own reasons (the third, "no R5 closing row at
# all", reuses the already-pinned "R5 draagt geen sluitregel in dit
# ledger" - one phrase, not a second copy of it here).
_BLOCK_TWO_SUBJECT_TEXT = "CVE-oordeel op de nieuwe build"
_FRESHNESS_EXPORT_OUDER_TEXT = "export ouder dan de upgrade"
_FRESHNESS_BUILD_AFWIJKEND_TEXT = "de build in de export komt niet overeen met de build die R5 na de upgrade live las"


def test_the_freshness_gate_sentences_match_the_pinned_text():
    from nsmcp.after_upgrade import (
        BLOCK_TWO_SUBJECT,
        FRESHNESS_BUILD_AFWIJKEND_TEXT,
        FRESHNESS_EXPORT_OUDER_TEXT,
    )

    assert BLOCK_TWO_SUBJECT == _BLOCK_TWO_SUBJECT_TEXT
    assert FRESHNESS_EXPORT_OUDER_TEXT == _FRESHNESS_EXPORT_OUDER_TEXT
    assert FRESHNESS_BUILD_AFWIJKEND_TEXT == _FRESHNESS_BUILD_AFWIJKEND_TEXT


def test_openstaande_metingen_does_not_contradict_its_own_family_counts_section():
    """The intro paragraph of the `rapport_na_upgrade`
    blok-1 section used to say block 4 carries "het genormaliseerde
    configuratie-anker met de acht familietellingen" - read as a delivered
    comparison - a few lines above the section that says the family-count
    HALF of that same block stays `niet vastgesteld` today (R5 writes no
    `familietellingen`-poort). A customer-facing document must not
    contradict its own next section."""
    tekst = (Path(__file__).parent.parent / "docs" / "klant" / "OPENSTAANDE-METINGEN.md").read_text(encoding="utf-8")
    assert "genormaliseerde configuratie-anker met de acht familietellingen" not in tekst
    assert "acht familietellingen van R5" in tekst
    assert "niet vastgesteld" in tekst


def test_handleiding_documents_the_sso_payloads_doel_and_voorstel_fields():
    """`HANDLEIDING.md` used to describe the `sso` protocol's outgoing
    payload as exactly the four fields `SsoCodeChannel.__call__` sent
    (`vingerafdruk`/`code`/`autoriteit`/`aanduiding`) - the same gap the
    code itself had. The documentation must match the six-field payload
    the fix adds `doel`/`voorstel` to.

    The doc pin only ever tested TWO of the fields
    (`doel`/`voorstel`) by name, so `SSO_PROTOCOL_FIELDS` (A6, `code_
    channel.py`) growing to eight became the one copy nothing tested the
    doc against. Every canonical field name is checked now, not a
    hand-picked subset."""
    from nsmcp import code_channel

    tekst = (Path(__file__).parent.parent / "docs" / "klant" / "HANDLEIDING.md").read_text(encoding="utf-8")
    for veld in code_channel.SSO_PROTOCOL_FIELDS:
        assert f'"{veld}":' in tekst, veld
    assert "vierde veld" not in tekst


def test_handleiding_documents_rapport_na_upgrades_doel_argument_and_freshness_gate():
    """`HANDLEIDING.md` used to say `rapport_na_upgrade` "kent, anders
    dan onderhoud_upgrade_stand, geen doel-argument" - true before this
    argument was added - and did not mention that block 2's CVE-oordeel is
    judged only on an export proven to postdate the upgrade."""
    tekst = (Path(__file__).parent.parent / "docs" / "klant" / "HANDLEIDING.md").read_text(encoding="utf-8")
    sectie = tekst.split("**Het gereedschap `rapport_na_upgrade`.**", 1)[1]
    assert "geen `doel`-argument" not in sectie
    assert "Argumenten: `doel`" in sectie
    assert "export ouder dan die sluitregel" in sectie


# The supplier's internal tooling (its knowledge layer, the tools it builds
# with) comes from the needle list outside the tracked tree
# (tests/private_needles.py), so this file names none of it.


def _internal_tooling_offenders(root: Path, rel_paths: list[str], needles: tuple[str, ...]) -> list[str]:
    """Every line in `rel_paths` (relative to `root`) that names the
    supplier's internal tooling, in any case. A file that does not read as
    UTF-8 text is binary and has no line to name anything in."""
    offenders = []
    for rel in rel_paths:
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if any(needle.lower() in line.lower() for needle in needles):
                offenders.append(f"{rel}:{number}: {line.strip()}")
    return offenders


def test_no_tracked_file_names_the_suppliers_internal_knowledge_tooling():
    """A customer document once instructed the reader to run the journal
    command of the supplier's own internal knowledge layer and named that
    layer as the knowledge source - a command a customer cannot run at all.
    The guard first swept `docs/klant/` only; measured after that, the name
    still stood in seven places elsewhere in the shipped tree (the project
    metadata, three modules, the SSH transport and scripts/README), each
    citing a lab lesson by the name of the system that holds it. Now swept
    across every tracked file (`git ls-files`), this one included: the
    lesson's own slug says what was measured, the system's name tells a
    reader outside the supplier nothing."""
    import subprocess

    from private_needles import needles_or_skip

    needles = needles_or_skip("naam")
    root = Path(__file__).parent.parent
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    tracked = [rel for rel in listing.decode("utf-8").split("\0") if rel]
    assert len(tracked) > 100, len(tracked)
    offenders = _internal_tooling_offenders(root, tracked, needles)
    assert offenders == [], offenders


def test_the_internal_tooling_guard_catches_any_case_and_skips_a_binary_file(tmp_path):
    (tmp_path / "noot.md").write_text("zie de KennisLaag-les\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe" + b"kennislaag")
    assert _internal_tooling_offenders(tmp_path, ["noot.md", "blob.bin"], ("kennislaag",)) == [
        "noot.md:1: zie de KennisLaag-les"
    ]


def test_full_tool_surface_with_handelen_matches_the_twenty_four_pinned_tools(tmp_path):
    """The eleven reading tools plus the seven writing/onderhoud tools: the
    surface a customer with a `handelen` section AND `onderhoud_upgrade_fase`
    allowed on at least one target actually gets served. The reading-only
    surface above never registered the writing tools, so their names,
    descriptions and input schemas sat outside every parity guard.
    `onderhoud_backup_maken` (B4) is the fifth writing tool: the
    first one that forms its own object instead of taking one as an
    argument, so it carries no object property at all - only `bevestiging`
    and `doel`. `onderhoud_upgrade_plan` (B7) is the eleventh
    reading tool, already counted in `_BASELINE_SURFACE` above - it needs no
    `handelen` section at all, so it is on the surface with or without one.
    `onderhoud_upgrade_fase` is the SEVENTEENTH and sixth
    writing tool - the longest description in the product, and the place
    where "voer een voorstel nooit zelf uit" is written for the faserunner.
    It used to be pinned NOWHERE, because
    `_handelen_server(tmp_path)` (conftest.py) builds without `onderhoud`
    and without an allowlist that grants it - the tool's own extra
    registration gate (design 3.1) then never fires and `list_tools()`
    silently returns sixteen instead of seventeen, without this test ever
    noticing the difference.

    `onderhoud_upgrade_stand` is the EIGHTEENTH tool and a
    READING one - it registers whenever `onderhoud` is configured (no
    `writing_allowed`/allowlist gate at all, unlike `onderhoud_upgrade_fase`
    above it), so it is on the surface here too.

    `rapport_na_upgrade` is the NINETEENTH tool, also a
    READING one and gated the same way (`onderhoud` configured; its own
    "rapport" chapter is on by default) - block 1 of its design (the
    comparison engine) is not wired in on this branch, see
    `nsmcp.after_upgrade`'s module docstring, but the tool itself registers
    and is on the surface here regardless.

    The server construction used to be, and for the sixteen
    OTHER tools still is, `tests/conftest.py`'s shared `_handelen_server`.
    THIS test now calls `_full_handelen_server` (this file, above) instead -
    the same construction PLUS `onderhoud` and an allowlist entry, so the
    seventeenth tool's own gate fires too. It still takes the raw server
    back, not the `BuiltServer` wrapper, because this test reads
    `inputSchema` as well as `description`, which `BuiltServer` deliberately
    does not expose."""
    server = _full_handelen_server(tmp_path)
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    baseline = {**_BASELINE_SURFACE, **_HANDELEN_SURFACE}

    # De bewegingen van dit getal: 12 -> 17 (rapport_dekking, status_namen,
    # ha_stand, beveiliging_verstopte_regels, beveiliging_tls_baseline); een latere
    # uitbreiding bracht de release op 24 (status_update_advies, status_update_preflight, onderhoud_upgrade_plan,
    # onderhoud_upgrade_stand, rapport_na_upgrade en zes schrijvende); een volgende ronde voegt
    # beveiliging_beheervlak (A7), dienst_keten (A9) en status_gezondheid (A10) toe:
    # 27 op 14-9-2026. Een latere toevoeging voegt rapport_vergelijk (A17) toe: 30 op
    # 14-9-2026 (24 lezend, 6 schrijvend). Een laatste toevoeging voegt
    # rapport_wat_is_er_veranderd toe (dunne schil op dezelfde motor): 31
    # (25 lezend, 6 schrijvend). Het hoofdstuk config voegt config_drift
    # (lezend) en config_opslaan (schrijvend) toe: 33 (26 lezend, 7
    # schrijvend). status_doelen (lezend, altijd aangemeld) maakt er 34
    # van (27 lezend, 7 schrijvend). Dit getal verandert alleen samen met het
    # ontwerp.
    assert len(baseline) == 34
    assert set(tools) == set(baseline)

    for name, pinned in baseline.items():
        assert tools[name].description == pinned["description"], (
            f"description of {name} drifted from the pinned product surface"
        )
        assert tools[name].inputSchema == pinned["inputSchema"], (
            f"inputSchema of {name} drifted from the pinned product surface"
        )


def test_the_module_docstring_states_the_true_tool_count():
    """`mcp_server.py`'s own module docstring drifted
    stale before (it once said "sixteen tools. Eleven READ ... five WRITE",
    then "twenty-four tools. Eighteen READ" while the measured baseline was
    already thirty). The `config` chapter and `status_doelen` bring the true,
    full count to thirty-four (twenty-seven read, seven write) - the test above
    pins that; the docstring must say that number, not a stale one."""
    doc = mcp_server_module.__doc__ or ""
    assert "sixteen tools" not in doc
    assert "twenty-four tools" not in doc
    assert "thirty tools" not in doc
    assert "thirty-one tools" not in doc
    assert "thirty-two tools" not in doc
    assert "thirty-three tools" not in doc
    assert "thirty-four tools" in doc
    assert "Twenty-seven READ" in doc
    assert "seven WRITE" in doc


_REGISTER_CLAIM = re.compile(r"Het volledige register bevat \d+ gereedschappen: \d+ lezende en \d+ schrijvende")


def test_every_customer_document_that_states_the_register_count_states_the_measured_one(tmp_path):
    """14-9-2026: two tool additions later, the "Integratiegrens"
    paragraph of `docs/klant/OPENSTAANDE-METINGEN.md` and of
    `docs/klant/BEVEILIGING-EN-DATASTROMEN.md` still said "27 gereedschappen:
    21 lezende". Nothing tripped: `tests/test_no_network.py`'s document test
    reads README.md, HANDLEIDING.md and SECURITY.md only, and the two
    stragglers were fixed by hand (3ec405b). This guard closes the gap from
    the other side. It does not LIST the carriers of that sentence - it
    FINDS every one under docs/ (plus README.md) and holds each occurrence
    to the count the built server measures. A sixth carrier with an old
    number, or a thirty-second tool that leaves five documents behind, trips
    it; the set of carriers is pinned so a document that silently drops the
    sentence is visible too."""
    server = _full_handelen_server(tmp_path)
    all_tools = {t.name for t in asyncio.run(server.list_tools())}
    writing = all_tools & set(WRITE_TOOLS)
    assert writing == set(WRITE_TOOLS)
    expected = (
        f"Het volledige register bevat {len(all_tools)} gereedschappen: "
        f"{len(all_tools - writing)} lezende en {len(writing)} schrijvende"
    )

    root = Path(__file__).resolve().parent.parent
    carriers: dict[str, list[str]] = {}
    for path in [root / "README.md", *sorted((root / "docs").rglob("*.md"))]:
        text = " ".join(path.read_text(encoding="utf-8").split())
        for found in _REGISTER_CLAIM.findall(text):
            carriers.setdefault(path.relative_to(root).as_posix(), []).append(found)

    assert set(carriers) == {
        "README.md",
        "docs/klant/BEVEILIGING-EN-DATASTROMEN.md",
        "docs/klant/HANDLEIDING.md",
        "docs/klant/OPENSTAANDE-METINGEN.md",
        "docs/klant/SECURITY.md",
    }, f"dragers van de registertelling: {sorted(carriers)}"
    for name, claims in carriers.items():
        for found in claims:
            assert found == expected, f"{name}: {found!r} wijkt af van de meting {expected!r}"


def test_the_fase_gestart_answer_is_pinned_byte_for_byte(tmp_path):
    """The answer stays
    inside the openness seam (`render()`/`Answer.to_text()`, never a bare
    string that skips it) but its wording is now as close to the original
    five FASE-GESTART lines as that seam allows, and is PINNED here.

    Only the part of the text that is not INHERENTLY dynamic is pinned by
    equality: `run` carries a UTC timestamp (`nsmcp.upgrade.run_id()`), and
    the trailing "Kennisbasis van .../Gegevens van ..." stamps carry an age
    in days measured against "today" (`stamp_data()`) against the fixed
    2026-09-06 date this fixture's knowledge/export files carry - both
    change with the clock, not with the product surface, so pinning them
    byte-for-byte would make this test fail on every day that is not the
    day it was written. The five FINDING lines (and their `bewijs:` lines)
    do not depend on the clock beyond the run-id substitution below, and
    ARE pinned byte-for-byte.

    Reuses the shared `tests/upgrade_fase_harness.py`
    (`_server`/`_propose`/`_call`/`_text`) instead of rebuilding a second
    copy of it here - the same reasoning the module docstring above gives
    for importing `_export_dir`/`_knowledge_file` from conftest.py rather
    than duplicating them.

    That import used to come from
    `tests/test_upgrade_fase.py` - a test importing another TEST module, so
    a change to `_server`'s signature broke this product-surface pin in a
    confusing place. The harness is a module of its own now; nothing here
    depends on another test file."""
    from upgrade_fase_harness import _call, _propose, _server, _text

    server = _server(tmp_path)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)
    tekst = _text(r)

    run_regel = next(regel for regel in tekst.splitlines() if regel.startswith("- run: "))
    run_name = run_regel[len("- run: ") :].split(" [", 1)[0]

    expected = (
        "Vraag: uitvoering onderhoud_upgrade_fase\n"
        "\n"
        "- onderhoud_upgrade_fase: FASE GESTART (onderhoud_upgrade_fase). [vastgesteld]\n"
        f"    bewijs: regel fase_gestart in het ledger, run {run_name}\n"
        f"- run: {run_name} [vastgesteld]\n"
        "    bewijs: run-id van deze upgrade\n"
        "- fase: R0 [vastgesteld]\n"
        "    bewijs: argument van deze aanroep\n"
        "- oordeel: Het oordeel over deze fase komt uit het ledger, niet uit dit antwoord. "
        "Vraag het na met onderhoud_upgrade_stand. [vastgesteld]\n"
        "    bewijs: ontwerp 3.5, de ledger is de waarheid\n"
        "- bevestiger: jan.de.beheerder@voorbeeld.invalid [vastgesteld]\n"
        "    bewijs: wat het codekanaal over de bevestiger kon zeggen bij het inwisselen van "
        "de code\n"
    )
    assert tekst.startswith(expected)


def test_the_undecided_start_refusal_is_pinned_byte_for_byte(tmp_path, monkeypatch):
    """A confirmed phase whose runner wrote no `fase_gestart` within the
    wait holds its target: the next proposal is refused through the openness
    seam (`render()`, an `Answer` with one finding, never a bare string),
    with the reason in the product's own words. Pinned like the FASE GESTART
    answer above: the run id and the three moments are clock values and are
    read back out of the text; every other character is fixed. The wait
    itself is taken out (`wait_for_start` answers "no row" at once), the
    same shortcut tests/test_upgrade_fase.py uses for the timeout text."""
    from upgrade_fase_harness import _call, _nep_runner, _propose, _server, _text

    monkeypatch.setattr(mcp_server_module, "wait_for_start", lambda *a, **k: None)
    runner = _nep_runner(tmp_path, "zwijgt.py", write_gestart=False)
    server = _server(tmp_path, runner=runner)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    eerste = _call(
        server,
        "onderhoud_upgrade_fase",
        {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code},
    )
    assert eerste.isError
    time_re = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
    assert re.search(
        "Het doel blijft geblokkeerd voor elke schrijvende tool, ook voor een nieuw voorstel, tot die regel "
        rf"verschijnt of de tijdslimiet van fase R0 \(3600 s\) verstrijkt, om {time_re}\.",
        _text(eerste),
    ), _text(eerste)

    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1"})
    assert r.isError
    tekst = _text(r)
    m = re.search(rf"\(run (?P<run>[^)]+)\) nog onbeslist.*?om (?P<deadline>{time_re});", tekst)
    assert m, tekst
    gestart = re.search(rf"faserunner gestart om (?P<t>{time_re})", tekst)
    assert gestart, tekst
    run_name, deadline, gestart_om = m.group("run"), m.group("deadline"), gestart.group("t")
    expected = (
        "Vraag: voorstel onderhoud_upgrade_fase\n"
        "\n"
        f"- onderhoud_upgrade_fase: op dit doel is de start van fase R0 (run {run_name}) nog onbeslist: de "
        "faserunner is losgekoppeld gestart en heeft binnen 20 s geen regel fase_gestart geschreven; het doel "
        "blijft geblokkeerd tot die regel verschijnt of de tijdslimiet van fase R0 (3600 s) verstrijkt, om "
        f"{deadline}; vraag de stand na met onderhoud_upgrade_stand [vastgesteld]\n"
        f"    bewijs: faserunner gestart om {gestart_om}, geen regel fase_gestart binnen 20 s, deadline {deadline}\n"
    )
    assert expected in tekst, tekst
    assert tekst.index(expected) < 60, "de weigering hoort het antwoord te openen"


def test_the_open_phase_refusal_is_rendered_and_pinned_byte_for_byte(tmp_path):
    """The open-phase refusal went out as a bare string, while the undecided
    start next to it goes through the openness seam. Now both do: an
    `Answer` with one finding, rendered, with the ledger fact as evidence.
    Pinned on the confirmed call of the phase tool against a foreign run's
    open R1; the start moment is written by the test, so every character is
    fixed."""
    from datetime import timedelta

    from upgrade_fase_harness import _call, _propose, _regel, _server, _text

    from nsmcp.upgrade import append_line

    ledger = tmp_path / "ledger"
    ledger.mkdir()
    gestart = datetime.now(UTC).replace(microsecond=0)
    stamp = gestart.strftime("%Y-%m-%dT%H:%M:%SZ")
    row = _regel(run="andere-run", fase="R1", gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stamp)
    row["tijd"] = stamp
    append_line(ledger / "andere-run.jsonl", row)
    server = _server(tmp_path, ledgermap=ledger)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code},
    )
    assert r.isError
    tekst = _text(r)
    vervalt = (gestart + timedelta(seconds=3600)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expected = (
        "Vraag: uitvoering onderhoud_upgrade_fase\n"
        "\n"
        "- onderhoud_upgrade_fase: er staat nog een fase open op dit doel; vraag de stand op met "
        f"onderhoud_upgrade_stand. (fase R1 is gestart op {stamp}; komt er geen sluitregel, dan vervalt deze "
        f"weigering vanzelf na de tijdslimiet van 3600 s, om {vervalt}) [vastgesteld]\n"
        f"    bewijs: ledger van dit doel: regel fase_gestart voor fase R1 zonder sluitregel, gestart om {stamp}\n"
    )
    assert expected in tekst, tekst
    assert tekst.index(expected) < 60, "de weigering hoort het antwoord te openen"


def test_the_open_phase_evidence_sentences_match_the_pinned_text():
    from nsmcp.mcp_server import OPEN_FASE_EVIDENCE, OPEN_FASE_ZONDER_TIJD_EVIDENCE

    assert OPEN_FASE_EVIDENCE == (
        "ledger van dit doel: regel fase_gestart voor fase {fase} zonder sluitregel, gestart om {gestart}"
    )
    assert OPEN_FASE_ZONDER_TIJD_EVIDENCE == (
        "ledger van dit doel: regel fase_gestart voor fase {fase} zonder sluitregel en zonder leesbare starttijd"
    )


_ONBESLISTE_START_TEXT = (
    "op dit doel is de start van fase {fase} (run {run}) nog onbeslist: de faserunner is losgekoppeld "
    "gestart en {hoe}; het doel blijft geblokkeerd tot die regel verschijnt of de tijdslimiet van fase "
    "{fase} ({limiet} s) verstrijkt, om {deadline}; vraag de stand na met onderhoud_upgrade_stand"
)
_ONBESLISTE_START_STAND_TEXT = (
    "de start van fase {fase} (run {run}) is onbeslist: de faserunner is losgekoppeld gestart en {hoe}; "
    "elke schrijvende tool op dit doel weigert tot die regel verschijnt of de tijdslimiet van fase "
    "{fase} ({limiet} s) verstrijkt, om {deadline}"
)
_ONBESLISTE_START_VERVALLEN_TEXT = (
    "de start van fase {fase} (run {run}) bleef onbeslist tot de tijdslimiet van {limiet} s: er "
    "verscheen geen regel fase_gestart in het ledger; het doel is weer vrij"
)
_ONBESLIST_TIMEOUT_TEXT = (
    " Het doel blijft geblokkeerd voor elke schrijvende tool, ook voor een nieuw voorstel, tot die regel "
    "verschijnt of de tijdslimiet van fase {fase} ({limiet} s) verstrijkt, om {deadline}."
)


def test_the_undecided_start_sentences_match_the_pinned_text():
    """Every sentence of the undecided start, pinned as written: the
    refusal, the stand's own finding, the lift at the time limit, the wait
    that still runs, the two ways the wait ended, and the sentence the
    timeout answer ends with."""
    from nsmcp.mcp_server import (
        ONBESLIST_AFGEBROKEN_EVIDENCE,
        ONBESLIST_AFGEBROKEN_TEXT,
        ONBESLIST_GEWACHT_EVIDENCE,
        ONBESLIST_GEWACHT_TEXT,
        ONBESLIST_TIMEOUT_TEXT,
        ONBESLIST_WACHT_EVIDENCE,
        ONBESLIST_WACHT_TEXT,
        ONBESLISTE_START_EVIDENCE,
        ONBESLISTE_START_STAND_TEXT,
        ONBESLISTE_START_TEXT,
        ONBESLISTE_START_VERVALLEN_EVIDENCE,
        ONBESLISTE_START_VERVALLEN_TEXT,
    )

    assert ONBESLISTE_START_TEXT == _ONBESLISTE_START_TEXT
    assert ONBESLISTE_START_STAND_TEXT == _ONBESLISTE_START_STAND_TEXT
    assert ONBESLISTE_START_VERVALLEN_TEXT == _ONBESLISTE_START_VERVALLEN_TEXT
    assert ONBESLIST_TIMEOUT_TEXT == _ONBESLIST_TIMEOUT_TEXT
    assert ONBESLIST_WACHT_TEXT == "de server wacht nog op zijn regel fase_gestart (tot {tot})"
    assert ONBESLIST_WACHT_EVIDENCE == "het wachten op de regel fase_gestart loopt tot {tot}"
    assert ONBESLIST_GEWACHT_TEXT == "heeft binnen {wacht} s geen regel fase_gestart geschreven"
    assert ONBESLIST_AFGEBROKEN_TEXT == "het wachten op zijn regel fase_gestart brak af"
    assert ONBESLISTE_START_EVIDENCE == "faserunner gestart om {gestart}, {wat}, deadline {deadline}"
    assert ONBESLIST_GEWACHT_EVIDENCE == "geen regel fase_gestart binnen {wacht} s"
    assert ONBESLIST_AFGEBROKEN_EVIDENCE == "het wachten op de regel fase_gestart brak af"
    assert ONBESLISTE_START_VERVALLEN_EVIDENCE == (
        "faserunner gestart om {gestart}, geen regel fase_gestart tot de tijdslimiet, om {deadline}"
    )


class _BackupCodeSpy:
    """A code channel that names the confirmer the way the shipped `sso`
    kind does: bound to the CODE, never a bare attribute."""

    label = "sso"

    def __init__(self) -> None:
        self.codes: list[str] = []
        self._per_code: dict[str, str] = {}

    def __call__(self, tool, target, arguments, code, proposal_text, marker, section) -> None:
        self.codes.append(code)
        self._per_code[code] = "jan.de.beheerder@voorbeeld.invalid"

    def bevestiger_for(self, code: str):
        return self._per_code.pop(code, None)


def _backup_answer_server(tmp_path: Path):
    """A server that can run `onderhoud_backup_maken` end to end against an
    injected write script - self-contained here, so this pin depends on no
    other test module."""
    script = tmp_path / "schrijf.ps1"
    script.write_text("# leeg; action_run vervangt dit", encoding="utf-8")

    def run(arguments, timeout_s):
        naam = arguments[arguments.index("-BackupNaam") + 1]
        if "-WatIs" in arguments:
            return (
                0,
                (
                    f"[OK] zou doen: backup maken met naam {naam}\n[TARGET] doel\n"
                    "[EINDSTATUS] WAT-IS: er is niets gewijzigd\n"
                ),
                "",
            )
        return (
            0,
            (
                f"[ACTIEID] id-1\n[TARGET] doel\n"
                f"[OK] teruggelezen op de collectie config/systembackup: {naam}.tgz, 41 MB, "
                "2026-09-06T14:03:12Z, level full\n"
                "[EINDSTATUS] backup gemaakt en teruggelezen\n"
            ),
            "",
        )

    presenter = _BackupCodeSpy()
    server = build_server(
        _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        action_script=script,
        fixture_dir=tmp_path,
        action_run=run,
        code_presenter=presenter,
        onderhoud=maintenance_config(tmp_path),
        allowlist=Allowlist(per_target={"lab": {"onderhoud_backup_maken": True}}),
    )
    server.code_spy = presenter
    return server


def test_the_backup_bevestiger_line_is_pinned_byte_for_byte(tmp_path):
    """`onderhoud_backup_maken` printed
    "- bevestiger: bevestiger: <waarde>" - `_bevestiger_regel()` prepended
    the word and `Answer.to_text()`'s own `- <subject>: ` prefix repeated
    it - and that answer text was pinned nowhere. The sibling tool's line
    was fixed earlier; this is the same line one path over, now pinned
    the same way."""
    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    server = _backup_answer_server(tmp_path)

    def call(args):
        async def go():
            async with create_connected_server_and_client_session(
                server,
                client_info=types.Implementation(name="claude-desktop", version="1.0"),
            ) as client:
                return await client.call_tool("onderhoud_backup_maken", args)

        return asyncio.run(go())

    voorstel = call({})
    tekst_voorstel = " ".join(b.text for b in voorstel.content if hasattr(b, "text"))
    assert not voorstel.isError, tekst_voorstel
    r = call({"bevestiging": server.code_spy.codes[-1]})
    tekst = " ".join(b.text for b in r.content if hasattr(b, "text"))
    assert not r.isError, tekst

    expected_line = (
        "- bevestiger: jan.de.beheerder@voorbeeld.invalid [vastgesteld]\n"
        "    bewijs: wat het codekanaal over de bevestiger kon zeggen bij het inwisselen van "
        "de code"
    )
    assert expected_line in tekst, tekst
    assert "bevestiger: bevestiger:" not in tekst


_CONFIG_OPSLAAN_ZONDER_DOEL_TEXT = (
    "dit doel staat niet in doelen; config_opslaan heeft het adres, het credential-target en de gepinde "
    "hostsleutel van het doel nodig en slaat zonder die drie niet op"
)
_CONFIG_OPSLAAN_ROL_TEXT = "wordt bij de uitvoering live bepaald; op een secondary wordt niet opgeslagen"
_CONFIG_OPSLAAN_INVERSE_TEXT = (
    "opslaan heeft geen inverse; de vorige opgeslagen configuratie zit alleen in een backup die vooraf met "
    "onderhoud_backup_maken is gemaakt; config_opslaan controleert dat niet"
)
_CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE = "show ns config over SSH, direct na save ns config"
_SAVE_ROLE_GATE = "doel is primary of standalone"
_SAVE_ON_SECONDARY_REASON = "opslaan op een secondary propageert niet; sla op op de primary"


_HUMAN_STEPS_TEXT = (
    "Na het soakvenster: de failover, de tweede node en het terugzetten van haStatus zijn menselijke "
    "handelingen; daar is geen gereedschap voor, de tweede node is een menselijke handeling. Daarna "
    "volgt config_opslaan op de primary na de eindvalidatie."
)
_DRIFT_OPSLAAN_REASON = (
    "de configuratie is gewijzigd na de laatste opslag (show ns config); kies eerst opslaan met "
    "config_opslaan op de primary of het standalone-doel, of zet drift_geaccepteerd=true"
)
_DRIFT_ONGELEZEN_REASON = (
    "de configuratiestand is niet vastgesteld; sla eerst op met config_opslaan of zet drift_geaccepteerd=true"
)
_R1_DRIFT_KEUZES_TEXT = (
    "R1 meet de stand zelf met show ns config en opent de driftpoort op een van drie manieren: "
    "aantoonbaar niets gewijzigd sinds de laatste opslag, eerst opgeslagen met config_opslaan op de "
    "primary of het standalone-doel, of bewust geaccepteerd met drift_geaccepteerd=true"
)


def test_the_r1_drift_sentences_are_pinned_byte_for_byte():
    from nsmcp import upgrade, upgrade_plan

    assert upgrade_plan.HUMAN_STEPS == _HUMAN_STEPS_TEXT
    assert upgrade.DRIFT_OPSLAAN_REASON == _DRIFT_OPSLAAN_REASON
    assert upgrade.DRIFT_ONGELEZEN_REASON == _DRIFT_ONGELEZEN_REASON
    assert mcp_server_module.R1_DRIFT_KEUZES_TEXT == _R1_DRIFT_KEUZES_TEXT
    assert "drift afwezig of bewust geaccepteerd (bewijs of mens)" in upgrade_plan.PHASE_GATES["R1"]


def test_the_config_opslaan_sentences_are_pinned_byte_for_byte():
    from nsmcp import upgrade

    assert mcp_server_module.CONFIG_OPSLAAN_ZONDER_DOEL_TEXT == _CONFIG_OPSLAAN_ZONDER_DOEL_TEXT
    assert mcp_server_module.CONFIG_OPSLAAN_ROL_TEXT == _CONFIG_OPSLAAN_ROL_TEXT
    assert mcp_server_module.CONFIG_OPSLAAN_INVERSE_TEXT == _CONFIG_OPSLAAN_INVERSE_TEXT
    assert mcp_server_module.CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE == _CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE
    assert upgrade.SAVE_ROLE_GATE == _SAVE_ROLE_GATE
    assert upgrade.SAVE_ON_SECONDARY_REASON == _SAVE_ON_SECONDARY_REASON


_FLOOR_GATE = "doelbuild op of boven de vloer, of bewust geaccepteerd"
_FLOOR_BELOW_REASON = (
    "de doelbuild ligt onder de vloer; zet een bundel op of boven de vloer in onderhoud.firmwaremap, "
    "of zet doelbuild_geaccepteerd=true"
)
_FLOOR_ABSENT_REASON = "geen vloer bekend in het kennispakket voor deze tak"
_FLOOR_BRANCH_REASON = (
    "de doelbuild en de vloer liggen op een andere tak en zijn niet te vergelijken, "
    "ook niet met doelbuild_geaccepteerd=true"
)
_FLOOR_UNREADABLE_REASON = (
    "doelbuild, huidige build, vloer of bulletin heeft niet de verwachte vorm; de vloer is niet getoetst"
)
_FLOOR_LINE_REASON = (
    "de doelbuild ligt in een andere releaselijn dan de huidige build; "
    "dit gereedschap doet geen overstap tussen releaselijnen"
)
_FLOOR_CURRENT_ABSENT_REASON = (
    "de huidige build is niet bekend uit de export; een overstap tussen releaselijnen is dan niet uit te "
    "sluiten; ververs de export, of zet doelbuild_geaccepteerd=true"
)


def test_the_floor_gate_sentences_are_pinned_byte_for_byte():
    from nsmcp import upgrade

    assert upgrade.FLOOR_GATE == _FLOOR_GATE
    assert upgrade.FLOOR_BELOW_REASON == _FLOOR_BELOW_REASON
    assert upgrade.FLOOR_ABSENT_REASON == _FLOOR_ABSENT_REASON
    assert upgrade.FLOOR_BRANCH_REASON == _FLOOR_BRANCH_REASON
    assert upgrade.FLOOR_UNREADABLE_REASON == _FLOOR_UNREADABLE_REASON
    assert upgrade.FLOOR_LINE_REASON == _FLOOR_LINE_REASON
    assert upgrade.FLOOR_CURRENT_ABSENT_REASON == _FLOOR_CURRENT_ABSENT_REASON


_TARGET_BUILD_EVIDENCE = "de enige bundel in onderhoud.firmwaremap ({naam}, {mb} MB)"
_TARGET_BUILD_NOT_READ = "onderhoud.firmwaremap is niet meegegeven; de doelbuild is de enige bundel in die map"
_FLOOR_VERDICT_SUBJECT = "doelbuild tegenover vloer"
_FLOOR_VERDICT_ABOVE = "op of boven de vloer; R0 opent de vloerpoort op bewijs"
_FLOOR_VERDICT_BELOW = "ONDER de vloer; blijven open: {open}; R0 sluit tenzij doelbuild_geaccepteerd=true"
_FLOOR_VERDICT_BRANCH = "andere tak dan de vloer; R0 sluit, ook met doelbuild_geaccepteerd=true"
_FLOOR_VERDICT_NO_TARGET = (
    "de doelbuild is niet vastgesteld; zonder eenduidige bundel in onderhoud.firmwaremap start geen enkele fase"
)
_FLOOR_ABSENT_CONSEQUENCE = "zonder vloer sluit R0 de vloerpoort tenzij doelbuild_geaccepteerd=true"
_FLOOR_VERDICT_NO_FLOOR = (
    "de vloer is niet vastgesteld; zonder vloer sluit R0 de vloerpoort tenzij doelbuild_geaccepteerd=true"
)
_FLOOR_VERDICT_FORM = (
    "de doelbuild, de huidige build of de vloer heeft niet de vorm <tak>-<build> die de faserunner aanneemt; "
    "R0 sluit de vloerpoort, ook met doelbuild_geaccepteerd=true"
)
_FLOOR_VERDICT_LINE = "andere releaselijn dan de huidige build; R0 sluit, ook met doelbuild_geaccepteerd=true"
_FLOOR_VERDICT_NO_CURRENT = (
    "de huidige build is niet vastgesteld; zonder huidige build sluit R0 de vloerpoort "
    "tenzij doelbuild_geaccepteerd=true"
)
_FLOOR_ACCEPTED_IN_THIS_CALL = "als mens: doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
_FLOOR_VERDICT_BELOW_ACCEPTED = (
    "ONDER de vloer; blijven open: {open}; R0 opent de vloerpoort als mens: "
    "doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
)
_FLOOR_ABSENT_ACCEPTED = (
    "zonder vloer opent R0 de vloerpoort als mens: doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
)
_FLOOR_VERDICT_NO_FLOOR_ACCEPTED = (
    "de vloer is niet vastgesteld; zonder vloer opent R0 de vloerpoort als mens: "
    "doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
)
_FLOOR_VERDICT_NO_CURRENT_ACCEPTED = (
    "de huidige build is niet vastgesteld; zonder huidige build opent R0 de vloerpoort als mens: "
    "doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
)
_DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT = (
    "de fase wordt niet gestart: doelbuild_geaccepteerd kan de faserunner niet bereiken, want de vloer of "
    "de huidige build heeft niet de vorm <tak>-<build> die de faserunner aanneemt (zoals een FIPS-trein); "
    "R0 sluit daar ook met doelbuild_geaccepteerd=true"
)
_CURRENT_BUILD_SUBJECT = "huidige build"


_RUN_DOELBUILD_AFWIJKEND_TEXT = (
    "de doelbuild van deze run (R0) wijkt af van de bundel in onderhoud.firmwaremap; start een nieuwe run"
)
_RUN_DOELBUILD_ONLEESBAAR_TEXT = (
    "de doelbuild van deze run (R0) staat niet leesbaar in het ledger; start een nieuwe run"
)


_FIRMWAREMAP_GEEN_BUNDEL_TEXT = "de ingestelde firmwaremap bevat geen bundel"
_FIRMWAREMAP_MEER_BUNDELS_TEXT = "de ingestelde firmwaremap bevat meer dan een bundel"


def test_the_firmware_directory_reasons_below_volledig_are_pinned_byte_for_byte():
    from nsmcp import handelen

    assert handelen.FIRMWAREMAP_GEEN_BUNDEL_TEXT == _FIRMWAREMAP_GEEN_BUNDEL_TEXT
    assert handelen.FIRMWAREMAP_MEER_BUNDELS_TEXT == _FIRMWAREMAP_MEER_BUNDELS_TEXT


def test_the_run_binding_refusals_are_pinned_byte_for_byte():
    from nsmcp import upgrade

    assert upgrade.RUN_DOELBUILD_AFWIJKEND_TEXT == _RUN_DOELBUILD_AFWIJKEND_TEXT
    assert upgrade.RUN_DOELBUILD_ONLEESBAAR_TEXT == _RUN_DOELBUILD_ONLEESBAAR_TEXT


def test_the_floor_lines_of_the_plan_and_the_proposal_are_pinned_byte_for_byte():
    from nsmcp import upgrade_plan

    assert upgrade_plan.TARGET_BUILD_EVIDENCE == _TARGET_BUILD_EVIDENCE
    assert upgrade_plan.TARGET_BUILD_NOT_READ == _TARGET_BUILD_NOT_READ
    assert upgrade_plan.FLOOR_VERDICT_SUBJECT == _FLOOR_VERDICT_SUBJECT
    assert upgrade_plan.FLOOR_VERDICT_ABOVE == _FLOOR_VERDICT_ABOVE
    assert upgrade_plan.FLOOR_VERDICT_BELOW == _FLOOR_VERDICT_BELOW
    assert upgrade_plan.FLOOR_VERDICT_BRANCH == _FLOOR_VERDICT_BRANCH
    assert upgrade_plan.FLOOR_VERDICT_NO_TARGET == _FLOOR_VERDICT_NO_TARGET
    assert upgrade_plan.FLOOR_ABSENT_CONSEQUENCE == _FLOOR_ABSENT_CONSEQUENCE
    assert upgrade_plan.FLOOR_VERDICT_NO_FLOOR == _FLOOR_VERDICT_NO_FLOOR
    assert upgrade_plan.FLOOR_VERDICT_FORM == _FLOOR_VERDICT_FORM
    assert upgrade_plan.FLOOR_VERDICT_LINE == _FLOOR_VERDICT_LINE
    assert upgrade_plan.FLOOR_VERDICT_NO_CURRENT == _FLOOR_VERDICT_NO_CURRENT
    assert upgrade_plan.FLOOR_ACCEPTED_IN_THIS_CALL == _FLOOR_ACCEPTED_IN_THIS_CALL
    assert upgrade_plan.FLOOR_VERDICT_BELOW_ACCEPTED == _FLOOR_VERDICT_BELOW_ACCEPTED
    assert upgrade_plan.FLOOR_ABSENT_ACCEPTED == _FLOOR_ABSENT_ACCEPTED
    assert upgrade_plan.FLOOR_VERDICT_NO_FLOOR_ACCEPTED == _FLOOR_VERDICT_NO_FLOOR_ACCEPTED
    assert upgrade_plan.FLOOR_VERDICT_NO_CURRENT_ACCEPTED == _FLOOR_VERDICT_NO_CURRENT_ACCEPTED
    assert upgrade_plan.CURRENT_BUILD_SUBJECT == _CURRENT_BUILD_SUBJECT
    assert "doelbuild op of boven de vloer, of bewust geaccepteerd (bewijs of mens)" in upgrade_plan.PHASE_GATES["R0"]


def test_the_refusal_of_an_acceptance_that_cannot_reach_the_runner_is_pinned_byte_for_byte():
    assert mcp_server_module.DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT == _DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT


def _config_opslaan_answer_server(tmp_path: Path, export_dir: Path | None = None):
    """A server that runs `config_opslaan` end to end against an injected save
    script, self-contained here like `_backup_answer_server` above."""
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# niet gebruikt door config_opslaan", encoding="utf-8")
    (tmp_path / "Invoke-GjkConfigOpslaan.ps1").write_text("# stand-in", encoding="ascii")
    doelen = tmp_path / "doelen-opslaan.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "192.0.2.10",
                        "credentialTarget": "GJK/Test/lab",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    stand = (Path(__file__).parent / "fixtures" / "configstand" / "show-ns-config-opgeslagen.txt").read_text(
        encoding="ascii"
    )

    def run(arguments, timeout_s):
        kop = "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n"
        if "-WatIs" in arguments:
            return (
                0,
                kop
                + "[OK] zou doen: save ns config op lab na een rolcontrole\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n",
                "",
            )
        actie = arguments[arguments.index("-Actieid") + 1]
        metingen = "".join(f"[METING] show ns config: {r.replace(chr(9), ' ')}\n" for r in stand.split("\n"))
        return (
            0,
            kop + f"[ACTIEID] {actie}\n{metingen}[METINGSTATUS] show ns config: exitcode=0\n"
            "[EINDSTATUS] OPGESLAGEN: save ns config gegeven; de teruglezing beoordeelt de server\n",
            "",
        )

    presenter = _BackupCodeSpy()
    server = build_server(
        export_dir or _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=run,
        code_presenter=presenter,
        onderhoud=maintenance_config(tmp_path),
        allowlist=Allowlist(per_target={"lab": {"config_opslaan": True}}),
        targets_path=doelen,
    )
    server.code_spy = presenter
    return server


def test_the_config_opslaan_drift_line_for_an_export_of_another_target_is_pinned(tmp_path):
    """The drift counts belong to the appliance in the export. When the export
    describes another target than this save, the proposal says the drift is
    not established, with the refusal the reading tools give - never the
    other appliance's counts as [vastgesteld]."""
    import hashlib
    import shutil

    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    export_dir = tmp_path / "export-ander-doel"
    shutil.copytree(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826", export_dir)
    digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"lab-ander\n{digest}\n", encoding="utf-8")
    server = _config_opslaan_answer_server(tmp_path, export_dir)

    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-desktop", version="1.0")
        ) as client:
            return await client.call_tool("config_opslaan", {})

    voorstel = asyncio.run(go())
    tekst = " ".join(b.text for b in voorstel.content if hasattr(b, "text"))
    assert not voorstel.isError, tekst
    assert (
        "- drift: niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: scan-doel.txt van de export tegenover het doel van deze handeling\n"
        "    reden: de export van deze server beschrijft een ander doel (lab-ander); ververs eerst met"
        " status_ververs\n"
    ) in tekst, tekst
    assert "alleen in running" not in tekst


def test_the_config_opslaan_answers_are_pinned_byte_for_byte(tmp_path):
    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    server = _config_opslaan_answer_server(tmp_path)

    def call(args):
        async def go():
            async with create_connected_server_and_client_session(
                server,
                client_info=types.Implementation(name="claude-desktop", version="1.0"),
            ) as client:
                return await client.call_tool("config_opslaan", args)

        return asyncio.run(go())

    voorstel = call({})
    tekst_voorstel = " ".join(b.text for b in voorstel.content if hasattr(b, "text"))
    assert not voorstel.isError, tekst_voorstel
    assert (
        "- ongedaan maken: opslaan heeft geen inverse; de vorige opgeslagen configuratie zit alleen in een "
        "backup die vooraf met onderhoud_backup_maken is gemaakt; config_opslaan controleert dat niet "
        "[vastgesteld]\n"
        "    bewijs: vaste tekst van dit gereedschap\n"
        "- drift: volgens de export niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: de running- en saved-configuratie in de export\n"
        "    reden: de export draagt geen leesbare running- en saved-configuratie of geen leesbaar tijdstempel\n"
        "- rol: wordt bij de uitvoering live bepaald; op een secondary wordt niet opgeslagen [vastgesteld]\n"
        "    bewijs: de rolcontrole (show ha node) loopt in het opslagscript, vlak voor save ns config"
    ) in tekst_voorstel, tekst_voorstel

    klaar = call({"bevestiging": server.code_spy.codes[-1]})
    tekst = " ".join(b.text for b in klaar.content if hasattr(b, "text"))
    assert not klaar.isError, tekst
    assert "- config_opslaan: UITGEVOERD (config_opslaan) [vastgesteld]\n    bewijs: actie-id config-opslaan-" in tekst
    assert (
        "- teruglezing: laatste opslag Thu Sep 24 10:14:40 2026 is niet ouder dan laatste wijziging "
        "Thu Sep 24 10:12:03 2026 [vastgesteld]\n"
        "    bewijs: show ns config over SSH, direct na save ns config"
    ) in tekst, tekst


def test_config_keys_and_cli_usage_are_frozen():
    assert start._REQUIRED_FIELDS == {"profiel", "exportmap", "kennispad"}
    assert start._HANDELEN_FIELDS == {"schrijfscript", "fixturemap", "codekanaal", "toegestaan"}
    assert start._OPTIONAL_FIELDS == {
        "doelen",
        "verzamelscript",
        "openheid",
        "hoofdstukken",
        "handelen",
        "onderhoud",
        "bewaren",
        "kennispin",
        # 1.0.2
        "scriptpin",
        "uitvoeringsbeleid",
    }
    # The `onderhoud` key surface is configuration the
    # customer types, exactly like the three sets above, and was the only
    # one of them that could drift unpinned.
    assert start._ONDERHOUD_FIELDS == {
        "runner",
        "ledgermap",
        "firmwaremap",
        "soak_uren",
        "ssh_gebruiker",
    }
    assert start._ONDERHOUD_OPTIONAL_FIELDS == {"actieregister"}
    assert start._USAGE == "Gebruik: netscaler-mcp <pad-naar-config.json>"


def test_enum_values_stay_dutch():
    assert {z.value for z in Certainty} == {"vastgesteld", "niet vastgesteld"}
    assert {p.value for p in Profile} == {"online", "afgeschermd", "dienst"}
    assert {o.value for o in Disclosure} == {"volledig", "beperkt", "minimaal"}
    assert {c.value for c in CertAgreement} == {"keten", "vingerafdruk"}


def test_on_disk_artifact_names_survive_in_source():
    src = Path(__file__).resolve().parent.parent / "src" / "nsmcp"
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in sorted(src.glob("*.py")))
    for literal in (
        '"scan-doel.txt"',
        '"export-manifest.json"',
        '"openheid-vertaaltabel.json"',
        '"kennisverversing.log"',
        '"vervangen"',
        '"afgekeurd"',
        ".vorig",
        ".mislukt",
        ".lock",
    ):
        assert literal in corpus, f"on-disk product name {literal} disappeared from the source"


def test_masked_error_text_is_frozen():
    fout = mask_error(RuntimeError("boom"))
    assert str(fout) == (
        "Onverwachte fout bij het beantwoorden van deze vraag. "
        "De details van deze fout zijn niet bewaard: dit product logt alleen "
        "zijn schrijfhandelingen."
    )


def test_the_backup_target_name_refusal_texts_are_frozen():
    """Commit 6b74860 changed `backup_name()`'s
    refusal text and added a new `ConfigError` text in `start._allowlist()`
    without pinning either - both are operator-visible Dutch product
    surface (see
    the regression coverage below).
    A later fix changed the wording again (added the length
    rule) - this pins the FINAL wording, byte for byte, so a future change
    to either text must touch this test too."""
    with pytest.raises(ValueError) as fout:
        backup_name("lab noord", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))
    assert str(fout.value) == (
        "doelnaam 'lab noord' voldoet niet aan de eisen (alleen tekens uit [A-Za-z0-9._-], "
        "niet de gereserveerde waarde '.' of '..', en ten hoogste 32 tekens (de gevormde "
        "appliance-naam mag zelf niet langer zijn dan 63 tekens - dezelfde grens als "
        "handelen._NAME)); een backupnaam voor de appliance mag dat niet dragen"
    )

    with pytest.raises(start.ConfigError) as fout2:
        start._allowlist({"lab noord": {}})
    assert str(fout2.value) == (
        "handelen.toegestaan: doelnaam 'lab noord' voldoet niet aan de eisen (alleen tekens "
        "uit [A-Za-z0-9._-], niet de gereserveerde waarde '.' of '..', en ten hoogste 32 "
        "tekens (de gevormde appliance-naam mag zelf niet langer zijn dan 63 tekens - "
        "dezelfde grens als handelen._NAME)); deze naam wordt straks onderdeel van een "
        "appliance-side objectnaam (bijvoorbeeld bij een backup)"
    )


def test_the_target_name_run_safety_refusal_text_is_frozen():
    """A later fix (`start._require_safe_upgrade_target_names()`) adds
    a SECOND, later gate over the same doelnaam - narrower than
    `_allowlist()`'s character grammar above (only reachable once a name
    already passed that one), and never pinned on its own. A semantic-merge
    fix: `_allowlist()` now runs first and
    shadows this gate for a doelnaam WITH A SPACE, so
    `tests/test_upgrade_fase.py` exercises it with a trailing dot instead
    - this test pins that same sentence, byte for byte, calling the gate
    directly rather than through a full config file."""
    allowlist = start._allowlist({"lab02.": {"onderhoud_upgrade_fase": True}})
    with pytest.raises(start.ConfigError) as fout:
        start._require_safe_upgrade_target_names(allowlist)
    assert str(fout.value) == (
        "doel lab02. mag onderhoud_upgrade_fase uitvoeren maar de doelnaam is geen veilig "
        "pad-segment; onderhoud_upgrade_fase vormt uit deze doelnaam de eerste run-naam "
        "(alleen letters, cijfers, punt, liggend streepje en koppelteken)"
    )


def test_golden_answer_text_is_frozen():
    antwoord = Answer(
        question="wat verloopt er binnen 90 dagen",
        findings=[
            Finding(
                subject="cert_a",
                outcome="verloopt over 12 dagen",
                certainty=Certainty.ESTABLISHED,
                evidence="daystoexpiration=12",
            )
        ],
        read_gaps=[ReadGap(source="config/sslvserver", reason="read niet bruikbaar: RBAC_DENIED")],
        not_assessed=[NotAssessed(subject="keten", reason="deze versie beoordeelt de keten niet")],
        knowledge_age_days=1,
        knowledge_date="2026-08-25",
        data_age_days=0,
        data_date="2026-08-26",
        data_target="lab",
    )
    assert antwoord.to_text() == (
        "Vraag: wat verloopt er binnen 90 dagen\n"
        "\n"
        "- cert_a: verloopt over 12 dagen [vastgesteld]\n"
        "    bewijs: daystoexpiration=12\n"
        "\n"
        "NIET VASTGESTELD (geen stille aanname):\n"
        "- config/sslvserver: read niet bruikbaar: RBAC_DENIED\n"
        "\n"
        "NIET BEOORDEELD IN DEZE VERSIE (bewust buiten bereik, geen aanname):\n"
        "- keten: deze versie beoordeelt de keten niet\n"
        "\n"
        "Kennisbasis van 2026-08-25, 1 dag oud.\n"
        "Gegevens van 2026-08-26, 0 dagen oud, doel: lab."
    )


def test_the_twelve_refusal_sentences_are_frozen():
    """The Dutch text of every refusal the writing path can produce, byte for
    byte, plus the reason codes themselves.

    `handelen.Refusal` writes each sentence ONCE, in one place, so this is
    the one pin that covers all of them - and the codes are pinned next to
    them because a caller (and the reading advice) acts on the CODE, not on
    the Dutch."""
    from nsmcp.handelen import REFUSAL_CODES, Refusal

    assert REFUSAL_CODES == (
        "onbekende-handeling",
        "onbekend-argument",
        "argument-ontbreekt",
        "argument-niet-tekst",
        "naamgrammatica",
        "beheerdienst",
        "appliance-certificaat",
        "niet-toegestaan",
        "doel-onbekend",
        "doel-nodig",
        "objectloze-vorm-niet-toegestaan",
        "run-naamgrammatica",
    )

    def zin(code, tool="tool_x", **kw):
        return str(Refusal(code, tool, **kw))

    assert zin("onbekende-handeling") == "onbekende handeling 'tool_x'"
    assert zin("onbekend-argument", field="veldje") == "onbekend argument voor tool_x: veldje"
    assert zin("argument-ontbreekt", field="veldje") == "argument 'veldje' ontbreekt voor tool_x"
    assert zin("argument-niet-tekst", field="veldje") == ("argument 'veldje' moet tekst zijn voor tool_x")
    assert zin("naamgrammatica", field="veldje", value="waarde") == (
        "'waarde' voldoet niet aan de naamgrammatica (begint met een letter, daarna letters, "
        "cijfers, punt, streepje, underscore; maximaal 63 tekens)"
    )
    assert zin("run-naamgrammatica", field="run", value="../evil") == (
        "'../evil' voldoet niet aan de run-naamgrammatica (begint met een letter of cijfer, "
        "daarna letters, cijfers, punt, streepje, underscore; maximaal 128 tekens; geen "
        "gereserveerde Windows-apparaatnaam en niet eindigend op een punt)"
    )
    assert zin("beheerdienst", field="veldje", value="waarde") == (
        "'waarde' is een beheerdienst van de appliance en blijft buiten bereik"
    )
    assert zin("appliance-certificaat", field="veldje", value="waarde") == (
        "'waarde' is een appliance-eigen certificaat en blijft buiten bereik"
    )
    assert zin("niet-toegestaan") == "'tool_x' staat niet op de allowlist voor dit doel"
    assert zin("niet-toegestaan", field="veldje", value="waarde") == (
        "'waarde' staat niet op de allowlist voor veldje van tool_x"
    )
    # The one refusal that says something about the TOOL rather than about
    # the call: which of two names the `dienst` argument of the member tools
    # means. It names nothing the caller did not supply.
    assert zin("niet-toegestaan", tool="dienst_lid_uitschakelen", field="dienst", value="waarde") == (
        "'waarde' staat niet op de allowlist voor dienst van dienst_lid_uitschakelen; let op: "
        "'dienst' is hier de servicegroup - de naam die dienst_status onder \"servicegroup\" "
        "toont - en niet de virtuele server"
    )
    assert zin("doel-onbekend") == ("onbekend doel; de allowlist in de configuratie kent dit doel niet")
    assert zin("doel-nodig") == ("geef doel op: de allowlist in de configuratie draagt meer dan een doelnaam")
    assert zin("objectloze-vorm-niet-toegestaan") == (
        "de allowlist zet tool_x als geheel aan of uit, maar tool_x vormt zijn object niet zelf; "
        "zet per argument de toegestane waarden"
    )


# --- getattr regression guards ---------------------------------------------
# action.py and disclosure.py (`_collect_names`, `_limit`) look up the
# affected-vservers field by STRING (getattr with a fail-closed default).
# A field rename that forgets those strings fails silently; these fail loudly.


def _knowledge() -> Knowledge:
    return Knowledge(version="2026.08", date="2026-08-16", age_days=1, missing=False)


def _impact_answer() -> ImpactAnswer:
    # The vserver name deliberately occurs ONLY in `affected_vservers` and in
    # a text field that the name collection does NOT read (`bewijs`). The
    # collection reads finding subjects and the affected-vservers field; if
    # the string-based lookup of that field goes stale, the name below is no
    # longer known, stays unreplaced in the evidence line, and the disclosure
    # guard fails loudly. With the name also in a subject, a stale lookup
    # would hide behind the subject collection.
    return ImpactAnswer(
        question="wat breekt er met cert_a",
        findings=[
            Finding(
                subject="cert_a",
                outcome="valt uit",
                certainty=Certainty.ESTABLISHED,
                evidence="binding met LB_VS_GEHEIM",
            )
        ],
        affected_vservers=("LB_VS_GEHEIM",),
    )


def test_action_module_reads_the_affected_vservers_field():
    antwoord = what_to_do(_impact_answer(), _knowledge(), "cert_a")
    assert "Koppel het om op: LB_VS_GEHEIM" in antwoord.to_text()


def test_disclosure_name_collection_reads_the_affected_vservers_field(tmp_path):
    tekst = render(
        _impact_answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=(),
        pseudonym_table_path=tmp_path / "openheid-vertaaltabel.json",
    )
    assert "LB_VS_GEHEIM" not in tekst
    assert "object-" in tekst


def test_disclosure_copy_pseudonymizes_the_affected_vservers_field(tmp_path):
    from nsmcp.disclosure import _limit

    kopie = _limit(_impact_answer(), (), tmp_path / "openheid-vertaaltabel.json")
    assert kopie.affected_vservers, "the limited copy lost the affected-vservers field"
    assert all(n.startswith("object-") for n in kopie.affected_vservers)


def _impact_answer_with_a_service() -> ImpactAnswer:
    # Same construction as `_impact_answer`: the service name occurs ONLY in
    # `affected_services` and in the evidence line, so a stale string lookup
    # of the field cannot hide behind the subject collection.
    return ImpactAnswer(
        question="wat breekt er met cert_a",
        findings=[
            Finding(
                subject="cert_a",
                outcome="valt uit",
                certainty=Certainty.ESTABLISHED,
                evidence="service-binding met SVC_GEHEIM",
            )
        ],
        affected_vservers=(),
        affected_services=("SVC_GEHEIM",),
    )


def test_disclosure_name_collection_reads_the_affected_services_field(tmp_path):
    tekst = render(
        _impact_answer_with_a_service(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=(),
        pseudonym_table_path=tmp_path / "openheid-vertaaltabel.json",
    )
    assert "SVC_GEHEIM" not in tekst
    assert "object-" in tekst


def test_disclosure_copy_pseudonymizes_the_affected_services_field(tmp_path):
    from nsmcp.disclosure import _limit

    kopie = _limit(_impact_answer_with_a_service(), (), tmp_path / "openheid-vertaaltabel.json")
    assert kopie.affected_services, "the limited copy lost the affected-services field"
    assert all(n.startswith("object-") for n in kopie.affected_services)


def test_action_module_reads_the_affected_services_field():
    antwoord = what_to_do(
        ImpactAnswer(
            question="wat breekt er met cert_a",
            findings=[],
            affected_vservers=(),
            issued_certificates=(),
            affected_services=("nshttps-127.0.0.1-443",),
        ),
        _knowledge(),
        "cert_a",
    )
    assert antwoord.findings[0].outcome == (
        "geen wijzigingsvoorstel: dit certificaat draagt beheerverkeer van de appliance zelf"
    )


def test_the_certificate_service_sentences_are_pinned():
    from nsmcp.action import MANAGEMENT_REFUSAL_OUTCOME
    from nsmcp.impact import MANAGEMENT_SERVICE_OUTCOME, SERVICE_OUTCOME, _other_bindings_dimension

    assert MANAGEMENT_SERVICE_OUTCOME == "beheerverkeer van de appliance zelf; TLS op deze beheerdienst valt uit"
    assert SERVICE_OUTCOME == "raakt deze SSL-dienst (service); TLS valt uit voor deze dienst"
    assert MANAGEMENT_REFUSAL_OUTCOME == (
        "geen wijzigingsvoorstel: dit certificaat draagt beheerverkeer van de appliance zelf"
    )
    grens = _other_bindings_dimension("geen hash in het manifest; geen hash is geen vertrouwen")
    assert grens.subject == "gebruik van dit certificaat buiten de bindingen met virtuele servers"
    assert grens.reason == (
        "sslcertkey_binding.by-parent.json is niet gelezen (geen hash in het manifest; geen hash is geen"
        " vertrouwen); in dat bestand legt de collector de OVERIGE bindingen van een certificaat vast, dus"
        " daardoor blijven ongelezen: SSL-diensten (services) en servicegroepen waaraan dit certificaat"
        " gebonden is, waaronder de interne diensten waarop het beheerverkeer van de appliance zelf staat,"
        " en verder authenticatie-objecten, CA-bundels en monitors; een certificaat waarvoor hier geen"
        " gebonden virtuele server gevonden is, kan dus nog altijd aan zulke diensten hangen, en dat is bij"
        " een certificaatwissel het pad dat als eerste stilvalt"
    )


def test_the_proposal_marker_form_is_frozen():
    """C3, design 3.7. The form of the marker is product surface: an operator
    reads it in a window and in a chat and has to recognise ONE thing. A loose
    capital, prefixed by one lower-case word, and nothing else."""
    from nsmcp.confirm import MARKER_LETTERS, MARKER_PREFIX, marker_line

    assert MARKER_PREFIX == "voorstel"
    assert MARKER_LETTERS == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert marker_line("A") == "voorstel A"
    assert marker_line("Z") == "voorstel Z"


def test_the_freshness_sentence_is_frozen_in_both_forms():
    """C4, design 3.7. Both forms are product surface, and both are correct
    Dutch: `is 1 handeling` against `zijn 2 handelingen`. A count of zero has
    no sentence at all - an answer that said "0 handelingen" would be noise
    under every answer this product ever gives."""
    from nsmcp.mcp_server import WriteCounter, freshness_line

    assert freshness_line(1) == ("sinds die scan is 1 handeling uitgevoerd - ververs voor een betrouwbare leescontrole")
    assert freshness_line(2) == (
        "sinds die scan zijn 2 handelingen uitgevoerd - ververs voor een betrouwbare leescontrole"
    )
    teller = WriteCounter()
    assert teller.sentence() is None
    teller.record_write()
    assert teller.sentence() == freshness_line(1)
    teller.reset()
    assert teller.sentence() is None


# ---------------------------------------------------------------------------
# `onderhoud_upgrade_stand`'s new product
# copy was asserted only by substring in
# tests/test_upgrade_stand.py. Pinned byte-for-byte here, the same
# discipline `test_soak_verstreken_sentence_matches_the_pinned_text` above
# already applies to `SOAK_VERSTREKEN_SENTENCE`.
# ---------------------------------------------------------------------------


def test_the_unknown_doel_refusal_matches_the_pinned_text():
    from nsmcp.mcp_server import ONBEKEND_DOEL_TEXT

    assert ONBEKEND_DOEL_TEXT == ("onbekend doel; dit doel staat niet in de geconfigureerde doelen")


def test_the_status_doelen_texts_are_pinned():
    from nsmcp import doelen
    from nsmcp.mcp_server import STATUS_DOELEN_DESCRIPTION

    assert STATUS_DOELEN_DESCRIPTION == (
        "Hoofdstuk status. Welke NetScalers deze server kent: per doel de naam, het adres, hoe oud de export "
        "van dat doel is, de laatste onderhoudsrun en welke schrijvende gereedschappen voor dat doel zijn "
        "toegestaan. Credential-namen staan er nooit in. Gebruik dit als eerste vraag als niet duidelijk is "
        "welke doelen er zijn."
    )
    assert doelen.GEEN_DOEL_TEXT == "Er is geen doel ingesteld; deze server antwoordt op een aangeleverde export."
    assert doelen.DOELEN_QUESTION == "welke doelen kent deze server"
    assert doelen.DOELEN_TELLING_EVIDENCE == "het doelenbestand en handelen.toegestaan in de configuratie"
    assert doelen.DOEL_EVIDENCE == "het doelenbestand, handelen.toegestaan, het exportmanifest en het ledger"
    assert doelen.ALLEEN_IN_ALLOWLIST_TEXT == "alleen in de allowlist, niet in het doelenbestand; geen adres"
    assert doelen.GEEN_EXPORT_TEXT == "geen export in deze server"
    assert doelen.GEEN_EXPORT_VAN_DIT_DOEL_TEXT == (
        "geen export van dit doel in deze server (de export beschrijft een ander doel)"
    )
    assert doelen.EXPORT_ZONDER_DOEL_TEXT == (
        "niet vast te stellen of de export van dit doel is (de export zegt niet welk doel hij beschrijft)"
    )
    assert doelen.GEEN_LEDGER_TEXT == "geen ledger ingesteld (onderhoud staat niet in de configuratie)"
    assert doelen.GEEN_ONDERHOUDSRUN_TEXT == "geen onderhoudsrun"
    assert doelen.LEDGER_ONLEESBAAR_TEXT == "laatste onderhoudsrun niet vast te stellen: het ledger is niet leesbaar"
    assert doelen.LEDGER_ONLEESBAAR_REASON == (
        "het ledger kon niet gelezen worden, dus de laatste onderhoudsrun van dit doel is niet vastgesteld"
    )
    assert doelen.LEDGER_ONLEESBAAR_GAP == (
        "het ledger kon niet gelezen worden; de laatste onderhoudsrun is voor geen enkel doel vast te stellen"
    )
    assert doelen.RUN_NAAM_NIET_GETOOND_TEXT == (
        "laatste onderhoudsrun met een naam die geen veilige run-naam is; niet getoond"
    )
    assert doelen.NIET_AANGEMELD_PREFIX == "in de allowlist maar op deze server niet aangemeld: "


def test_the_doel_refusals_of_the_reading_tools_are_pinned():
    from nsmcp.mcp_server import EXPORT_ANDER_DOEL_TEXT, EXPORT_DOEL_ONBEKEND_TEXT, ander_doel_text

    assert EXPORT_ANDER_DOEL_TEXT == (
        "de export van deze server beschrijft een ander doel; ververs eerst met status_ververs"
    )
    assert EXPORT_DOEL_ONBEKEND_TEXT == (
        "de export van deze server zegt niet welk doel hij beschrijft; ververs eerst met status_ververs"
    )
    # At 'volledig' the refusal names the target the export does describe;
    # below it the sentence stays without a name.
    assert ander_doel_text("lab-02", Disclosure.FULL) == (
        "de export van deze server beschrijft een ander doel (lab-02); ververs eerst met status_ververs"
    )
    assert ander_doel_text("lab-02", Disclosure.LIMITED) == EXPORT_ANDER_DOEL_TEXT
    assert ander_doel_text("lab-02", Disclosure.MINIMAL) == EXPORT_ANDER_DOEL_TEXT


def test_the_export_target_refusal_after_the_redeem_is_pinned():
    """`onderhoud_upgrade_fase` reads the export again after the code is
    redeemed; the refusal then says that nothing started and that the code
    is spent, around one of the two refusals above."""
    from nsmcp.mcp_server import (
        EXPORT_DOEL_ONBEKEND_TEXT,
        EXPORTDOEL_NA_INWISSELEN_EVIDENCE,
        EXPORTDOEL_NA_INWISSELEN_TEXT,
    )

    assert EXPORTDOEL_NA_INWISSELEN_TEXT == "De handeling is niet gestart: {reden}. De bevestigingscode is verbruikt."
    assert EXPORTDOEL_NA_INWISSELEN_TEXT.format(reden=EXPORT_DOEL_ONBEKEND_TEXT) == (
        "De handeling is niet gestart: de export van deze server zegt niet welk doel hij beschrijft; ververs"
        " eerst met status_ververs. De bevestigingscode is verbruikt."
    )
    assert EXPORTDOEL_NA_INWISSELEN_EVIDENCE == (
        "scan-doel.txt van de export tegenover het doel van deze handeling, na het inwisselen"
    )


def test_the_export_target_refusal_before_the_redeem_is_pinned():
    """The same refusal BEFORE the code is redeemed: nothing ran and the code
    is still good, so the operator refreshes and confirms with it again."""
    from nsmcp.mcp_server import EXPORT_ANDER_DOEL_TEXT, EXPORTDOEL_VOOR_INWISSELEN_TEXT

    assert EXPORTDOEL_VOOR_INWISSELEN_TEXT == (
        "De handeling is niet uitgevoerd: {reden}. De bevestigingscode is niet ingewisseld en blijft geldig"
        " tot hij verloopt."
    )
    assert EXPORTDOEL_VOOR_INWISSELEN_TEXT.format(reden=EXPORT_ANDER_DOEL_TEXT) == (
        "De handeling is niet uitgevoerd: de export van deze server beschrijft een ander doel; ververs eerst"
        " met status_ververs. De bevestigingscode is niet ingewisseld en blijft geldig tot hij verloopt."
    )


def test_golden_status_doelen_answer_is_frozen(tmp_path):
    """The whole answer at `volledig`, byte for byte: two targets in the
    targets file (one with a pinned host key, one without), one section only
    in the allowlist, one run in the ledger, and one granted tool this server
    does not offer."""
    import hashlib
    from datetime import date

    from nsmcp.answer import stamp_data
    from nsmcp.doelen import LedgerView, targets_answer
    from nsmcp.export import load_export
    from nsmcp.target import Target

    export_dir = _export_dir(tmp_path)
    digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"lab-02\n{digest}\n", encoding="utf-8")
    export = load_export(export_dir)
    targets = {
        "lab-02": Target(
            name="lab-02",
            address="192.0.2.2",
            credential_target="GJK/Test/lab-02/nitro-read",
            agreement=CertAgreement.CHAIN,
            ssh_hostsleutel_vingerafdruk="10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f",
        ),
        "lab-03": Target(
            name="lab-03",
            address="192.0.2.3",
            credential_target="GJK/Test/lab-03/nitro-read",
            agreement=CertAgreement.CHAIN,
        ),
    }
    allowlist = Allowlist(
        per_target={
            "lab-02": {"onderhoud_backup_maken": True, "onderhoud_upgrade_fase": True, "config_opslaan": True},
            "lab-04": {"onderhoud_backup_maken": False},
        }
    )
    run = "20260923T130216Z-lab-02"
    rows = tuple(
        {"tijd": tijd, "run": run, "doel": "lab-02", "fase": fase, "gebeurtenis": gebeurtenis, "uitkomst": "x"}
        for tijd, fase, gebeurtenis in (
            ("2026-09-23T13:02:16Z", "R0", "fase_gestart"),
            ("2026-09-23T13:05:00Z", "R0", "voormeting_vast"),
            ("2026-09-23T13:06:00Z", "R1", "fase_gestart"),
            ("2026-09-23T13:11:53Z", "R1", "fase_geslaagd"),
        )
    )
    today = date(2026, 9, 24)
    knowledge = Knowledge(version="golden", date="2026-09-24", age_days=0, missing=False)
    answer = targets_answer(
        targets=targets,
        allowlist=allowlist,
        offered=frozenset({"onderhoud_backup_maken", "config_opslaan"}),
        export=export,
        ledger=LedgerView(configured=True, rows={"lab-02": rows}),
        today=today,
        knowledge=knowledge,
    )
    answer = stamp_data(answer, export.collected_at, today, export.target_name)
    assert render(answer, Disclosure.FULL, tool="status_doelen") == (
        "Vraag: welke doelen kent deze server\n"
        "\n"
        "- doelen: 2 in het doelenbestand, 1 met een toestemming in de allowlist, 1 alleen in de allowlist"
        " [vastgesteld]\n"
        "    bewijs: het doelenbestand en handelen.toegestaan in de configuratie\n"
        "- lab-02: adres 192.0.2.2; export van 2026-08-19, 36 dagen oud; laatste onderhoudsrun"
        " 20260923T130216Z-lab-02, laatste regel R1 geslaagd om 2026-09-23T13:11:53Z; toegestaan:"
        " config_opslaan, onderhoud_backup_maken; in de allowlist maar op deze server niet aangemeld:"
        " onderhoud_upgrade_fase; hostsleutel gepind: ja [vastgesteld]\n"
        "    bewijs: het doelenbestand, handelen.toegestaan, het exportmanifest en het ledger\n"
        "- lab-03: adres 192.0.2.3; geen export van dit doel in deze server (de export beschrijft een ander"
        " doel); geen onderhoudsrun; toegestaan: geen; hostsleutel gepind: nee [vastgesteld]\n"
        "    bewijs: het doelenbestand, handelen.toegestaan, het exportmanifest en het ledger\n"
        "- lab-04: alleen in de allowlist, niet in het doelenbestand; geen adres; geen export van dit doel in"
        " deze server (de export beschrijft een ander doel); geen onderhoudsrun; toegestaan: geen [vastgesteld]\n"
        "    bewijs: het doelenbestand, handelen.toegestaan, het exportmanifest en het ledger\n"
        "\n"
        "Kennisbasis van 2026-09-24, 0 dagen oud.\n"
        "Gegevens van 2026-08-19, 36 dagen oud, doel: lab-02."
    )


def test_the_run_finding_phrases_match_the_pinned_text():
    from nsmcp.mcp_server import (
        AANROEP_ARGUMENT_TEXT,
        DOEL_ENIGE_GECONFIGUREERDE_TEXT,
        RUN_GEEN_LEESBARE_TIJD_TEXT,
        RUN_LAATSTE_OP_DOEL_TEXT,
        RUN_NIET_BEPAALD_TEXT,
    )

    assert AANROEP_ARGUMENT_TEXT == "argument van deze aanroep"
    assert DOEL_ENIGE_GECONFIGUREERDE_TEXT == "enige geconfigureerde doel"
    assert RUN_LAATSTE_OP_DOEL_TEXT == "laatste run met een leesbare tijd op dit doel"
    assert RUN_NIET_BEPAALD_TEXT == "niet bepaald"
    assert RUN_GEEN_LEESBARE_TIJD_TEXT == ("geen ledgerregel met een leesbare tijd en een run-naam op dit doel")


def test_the_unknown_ledger_word_phrases_match_the_pinned_text():
    """The two PREFIX constants carry a `!r`-repr of the untrusted ledger
    word after them, never on their own - pinned here together with a
    KNOWN word's repr, matching exactly what `stand_answer()` builds for
    it (`tests/test_upgrade_stand.py`'s own
    `test_an_unrecognized_event_word_is_reported_as_not_established_with_a_
    reason` / `..._gate_outcome_word_...` only assert the WORD is present
    as a substring, not the whole reason)."""
    from nsmcp.upgrade import (
        GEEN_REDEN_OPGEGEVEN_TEXT,
        ONBEKEND_UITKOMST_WOORD_PREFIX,
        ONBEKENDE_GEBEURTENIS_PREFIX,
    )

    assert ONBEKENDE_GEBEURTENIS_PREFIX == "onbekende gebeurtenis in de ledgerregel: "
    assert ONBEKEND_UITKOMST_WOORD_PREFIX == "onbekend uitkomst-woord in de ledgerregel: "
    assert GEEN_REDEN_OPGEGEVEN_TEXT == "geen reden opgegeven in de ledgerregel"
    assert f"{ONBEKENDE_GEBEURTENIS_PREFIX}{'iets_anders'!r}" == (
        "onbekende gebeurtenis in de ledgerregel: 'iets_anders'"
    )
    assert f"{ONBEKEND_UITKOMST_WOORD_PREFIX}{'raar'!r}" == ("onbekend uitkomst-woord in de ledgerregel: 'raar'")


def test_knowledge_refresh_labels_and_sentences_are_pinned(tmp_path, capsys):
    """New Dutch surface from `nsmcp.knowledge_refresh`,
    pinned byte for byte: the three outcome labels, the two reason
    sentences `install_package()` builds (both deterministic - neither
    carries a timestamp, unlike the beheer-log line itself), and the
    CLI's own bracket vocabulary end to end."""
    import json
    from datetime import date

    from nsmcp.knowledge_refresh import (
        FAILED_LABEL,
        INSTALLED_LABEL,
        REJECTED_LABEL,
        install_package,
        main,
    )

    assert REJECTED_LABEL == "AFGEKEURD"
    assert INSTALLED_LABEL == "GEINSTALLEERD"
    assert FAILED_LABEL == "MISLUKT"

    oud = {"versie": "2026.08", "datum": "2026-08-01", "cve": [], "uitleg": {}, "begrippen": {}}
    geldig = {"versie": "2026.09", "datum": "2026-09-01", "cve": [], "uitleg": {}, "begrippen": {}}

    huidig = tmp_path / "kennis.json"
    huidig.write_text(json.dumps(geldig), encoding="utf-8")
    kandidaat_oud = tmp_path / "oud.json"
    kandidaat_oud.write_text(json.dumps(oud), encoding="utf-8")
    ouder = install_package(kandidaat_oud, huidig, date(2026, 9, 6), tmp_path / "_beheer1")
    assert ouder.reason == ("kandidaat is ouder dan het huidige pakket (kandidaat: 2026-08-01, huidig: 2026-09-01)")

    huidig2 = tmp_path / "kennis2.json"
    huidig2.write_text(json.dumps(oud), encoding="utf-8")
    kandidaat_geldig = tmp_path / "geldig.json"
    kandidaat_geldig.write_text(json.dumps(geldig), encoding="utf-8")
    geinstalleerd = install_package(kandidaat_geldig, huidig2, date(2026, 9, 6), tmp_path / "_beheer2")
    assert geinstalleerd.reason == "versie 2026.09 geinstalleerd"

    exitcode = main([str(kandidaat_geldig), str(huidig), "--beheer", str(tmp_path / "_beheer3")])
    uitvoer = capsys.readouterr()
    assert exitcode == 0
    assert uitvoer.out == (
        f"[START] kennisverversing: kandidaat={kandidaat_geldig} huidig={huidig}\n"
        "[OK] versie 2026.09 geinstalleerd\n"
        "[EINDSTATUS] kennispakket geinstalleerd\n"
    )

    kapot = tmp_path / "kapot.json"
    kapot.write_text(json.dumps({"versie": "kapot"}), encoding="utf-8")
    exitcode = main([str(kapot), str(huidig2), "--beheer", str(tmp_path / "_beheer4")])
    uitvoer = capsys.readouterr()
    assert exitcode == 1
    assert uitvoer.err == (
        "[FOUT] kennispakket mist verplicht veld: cve\n"
        "[EINDSTATUS] kennispakket afgekeurd - het oude pakket staat er nog\n"
    )


def test_knowledge_refresh_new_surface_is_pinned(tmp_path, capsys, monkeypatch):
    """A later fix: new/changed Dutch lines on the VISIBILITY
    leg of the one rule (preservation, logging), pinned byte for byte just
    like the rest of this module's surface above.

    - A preservation failure (`_keep_rejected()`) now speaks
      through `[WAARSCHUWING]`, the same as an existing log-write failure
      already did.
    - An unexpected exception escaping `install_package()` (here:
      a `huidig` path `_sibling_path()` cannot build a sibling name for)
      still ends in `[FOUT]`/`[EINDSTATUS]`, never a bare traceback.
    """
    import json

    from nsmcp.knowledge_refresh import main

    geldig = {"versie": "2026.09", "datum": "2026-09-01", "cve": [], "uitleg": {}, "begrippen": {}}
    oud = {"versie": "2026.08", "datum": "2026-08-01", "cve": [], "uitleg": {}, "begrippen": {}}

    # --- [WAARSCHUWING] on a log write that cannot happen -------------
    huidig = tmp_path / "kennis.json"
    huidig.write_text(json.dumps(oud), encoding="utf-8")
    kandidaat = tmp_path / "geldig.json"
    kandidaat.write_text(json.dumps(geldig), encoding="utf-8")
    beheer_is_een_bestand = tmp_path / "_beheer_bestand"
    beheer_is_een_bestand.write_text("ik ben een bestand, geen map", encoding="utf-8")
    exitcode = main([str(kandidaat), str(huidig), "--beheer", str(beheer_is_een_bestand)])
    uitvoer = capsys.readouterr()
    assert exitcode == 0
    log_path = beheer_is_een_bestand / "kennisverversing.log"
    assert uitvoer.err == f"[WAARSCHUWING] kon geen regel wegschrijven naar {log_path}\n"

    # --- [WAARSCHUWING] on a preservation failure ----------------------
    huidig2 = tmp_path / "kennis2.json"
    huidig2.write_text(json.dumps(oud), encoding="utf-8")
    kandidaat_kapot = tmp_path / "kapot2.json"
    kandidaat_kapot.write_text(json.dumps({"versie": "kapot"}), encoding="utf-8")

    def kapotte_copy(*_args, **_kwargs):
        raise OSError("kunstmatige kopieerfout voor de test")

    monkeypatch.setattr("nsmcp.localpath.create_local", kapotte_copy)  # 1.1 B: de kopie via localpath
    exitcode = main([str(kandidaat_kapot), str(huidig2), "--beheer", str(tmp_path / "_beheer6")])
    monkeypatch.undo()
    uitvoer = capsys.readouterr()
    assert exitcode == 1
    assert uitvoer.err == (
        f"[WAARSCHUWING] kon de afgekeurde kandidaat niet bewaren naast {huidig2}\n"
        "[FOUT] kennispakket mist verplicht veld: cve\n"
        "[EINDSTATUS] kennispakket afgekeurd - het oude pakket staat er nog\n"
    )

    # --- unexpected exception (not OSError) never escapes main() ------
    kandidaat_geldig2 = tmp_path / "geldig2.json"
    kandidaat_geldig2.write_text(json.dumps(geldig), encoding="utf-8")
    beheer7 = tmp_path / "_beheer7"
    exitcode = main([str(kandidaat_geldig2), ".", "--beheer", str(beheer7)])
    uitvoer = capsys.readouterr()
    assert exitcode == 1
    assert uitvoer.out == f"[START] kennisverversing: kandidaat={kandidaat_geldig2} huidig=.\n"
    # The ORIGINAL pin compared the whole line
    # against "WindowsPath('.') has an empty name" - CPython's own pathlib
    # wording, which reads `PosixPath('.')` on any POSIX runner (the class
    # name pathlib prints is platform-dependent) and can reword with a
    # future CPython. Only the two things THIS product actually wrote are
    # pinned byte-for-byte: the Dutch prefix and the `[EINDSTATUS]` line.
    # The stdlib tail is asserted loosely (it must still name the same
    # fault: an empty path name), never compared for equality.
    fout_regel, eindstatus_regel = uitvoer.err.splitlines()
    assert fout_regel.startswith("[FOUT] onverwachte fout tijdens installatie: ")
    assert "has an empty name" in fout_regel
    assert eindstatus_regel == "[EINDSTATUS] kennispakket afgekeurd - het oude pakket staat er nog"
    log7 = (beheer7 / "kennisverversing.log").read_text(encoding="utf-8")
    assert "MISLUKT" in log7
    assert "onverwachte fout tijdens installatie" in log7


def test_the_2_1_1_judgement_and_tool_state_words_are_frozen():
    """Design 2.1.1, "Het oordeelsvocabulaire, in een tabel": this file is
    the single index for the judgement vocabulary and the tool-specific
    state words - a plan or an implementation may not invent a word that
    is not pinned here. The five constants below sat, byte-correct, in
    their own module tests instead (`tests/test_update_advice.py`,
    `tests/test_preflight.py` twice, `tests/test_advice.py`,
    `tests/test_knowledge.py`); the content was right, only the location
    was wrong, so they move here. Each module test file still measures its
    own BEHAVIOUR against these words (a check produces `NOT_ASSESSED`, a
    heading appears only when all nine pass, and so on) - only the pure
    byte-equality pins moved.

    Every assertion below compares the module constant against a LITERAL,
    never against the constant itself: a pin that compares a constant with
    itself proves nothing, the same trap `_STATUS_VERVERS_TEXT` above
    exists to close."""
    from nsmcp.advice import ADVICE_WORDS
    from nsmcp.knowledge import OFFERED_ABSENT
    from nsmcp.preflight import CONCLUSIVE_HEADING, PREFLIGHT_WORDS
    from nsmcp.update_advice import UPDATE_WORDS

    assert UPDATE_WORDS == (
        "op de aangeboden build",
        "onder aangeboden maar op-of-boven de vloer",
        "onder de vloer",
        "tak niet bekend",
        "niet vastgesteld",
    )

    assert PREFLIGHT_WORDS == ("geen blokkade", "blokkade", "aandachtspunt", "niet beoordeeld")

    assert ADVICE_WORDS == (
        "dit product kan dit uitvoeren",
        "niet in de allowlist",
        "handmatige actie",
    )

    assert OFFERED_ABSENT == "aangeboden build niet vastgelegd"

    assert CONCLUSIVE_HEADING == "negen toetsen, geen blokkade"


def _scan_config(tmp_path: Path) -> tuple[Path, Path]:
    """A targets file and a collect script, because status_ververs is only
    registered when both halves of a scan configuration are there (security
    19). The pinned surface is the surface of a FULLY configured server.

    Shape of the targets file: the same one tests/test_mcp_server.py writes -
    that helper is the truth about the format target.load_targets() reads."""
    targets = tmp_path / "doelen.json"
    targets.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg; deze test voert niets uit", encoding="utf-8")
    return targets, script


def test_a16_phase_vocabulary_is_pinned():
    """Design 2.1 calls itself "the only index"
    for assessment vocabulary - a tool-specific state word may not be
    invented off to the side where nothing gates it. `PHASE_WORDS` used to
    be dead (nothing imported it, nothing asserted it), so any of the three
    words - or any of the five phase names the diagnosis cascades over -
    could be renamed with the suite green. `PhaseReport.__post_init__`
    (collect.py) now refuses any word outside this tuple at construction
    time; this pin is the other half, so the two can only move together,
    deliberately."""
    assert PHASE_WORDS == ("bereikt", "mislukt", "niet vastgesteld")
    assert PHASE_ORDER == ("DNS", "TCP", "TLS", "NITRO-login", "identiteit")
    assert set(PHASE_NAMES.values()) == set(PHASE_ORDER)
    assert set(PHASE_NAMES) == {"DNS", "TCP_443", "TLS", "NITRO_LOGIN", "IDENTITY"}


def test_status_ververs_carries_a_fourth_unpinned_headline_vocabulary():
    """MEASURED: `status_ververs` prints FOUR more
    headline words (gelukt / niet gelukt / voltooid / onbekend) in the SAME
    answer that carries A16's own pinned vocabulary (bereikt / mislukt /
    niet vastgesteld) - none of the four is in design 2.1.1, none is in the
    ledger's open A16 design-change request. `collect.py` separately adds
    THREE printed phase labels outside `PHASE_ORDER` itself, so a customer
    can read "- (fase-invoer): mislukt" - a phase name design 2.1 never
    named. Fixing the vocabulary (or folding it into A16) is a design
    decision for the controller, out of scope here (see the ledger's A16
    entry); this test only PINS what exists today, byte-for-byte, so none
    of these seven words can drift silently while that design question is
    still open.
    """
    mcp_server_src = (Path(__file__).resolve().parent.parent / "src" / "nsmcp" / "mcp_server.py").read_text(
        encoding="utf-8"
    )
    for literal in (
        "De scan van '{name}' is gelukt.",
        "De scan van '{name}' is niet gelukt: {reden}",
        "De scan van '{name}' is voltooid: de annulering kwam nadat de ",
        "De scan van '{name}' is voltooid, maar onbekend is of de annulering ",
    ):
        assert literal in mcp_server_src, f"headline verdwenen uit mcp_server.py: {literal!r}"

    collect_src = (Path(__file__).resolve().parent.parent / "src" / "nsmcp" / "collect.py").read_text(encoding="utf-8")
    for literal in ('"(fase-invoer)"', 'f"fase-invoer {index}"', '"(onbekende fase)"'):
        assert literal in collect_src, f"fase-label verdwenen uit collect.py: {literal!r}"


def test_the_empty_result_sentence_is_frozen():
    from nsmcp.answer import NO_FINDINGS

    assert NO_FINDINGS == (
        "Geen bevindingen: binnen deze vraag is niets gevonden, en er is geen enkele bron onleesbaar gebleven."
    )


def _minimal_golden_answer() -> Answer:
    return Answer(
        question="wat verloopt er binnen 90 dagen",
        findings=[
            Finding(
                subject="cert_a",
                outcome="verloopt over 12 dagen",
                certainty=Certainty.ESTABLISHED,
                evidence="daystoexpiration=12",
                days_left=12,
            )
        ],
        read_gaps=[ReadGap(source="config/sslvserver", reason="read niet bruikbaar: RBAC_DENIED")],
        not_assessed=[NotAssessed(subject="keten", reason="deze versie beoordeelt de keten niet")],
        knowledge_age_days=1,
        knowledge_date="2026-08-25",
        data_age_days=0,
        data_date="2026-08-26",
        data_target="lab",
    )


def test_a_minimal_answer_never_claims_there_were_no_findings():
    """An answer that reports a finding AND a read gap may never also say that
    nothing was found and that no source stayed unreadable. That is not
    ugliness, it is untrue - and it would be untrue on the whole 'minimaal'
    surface at once, because the emptied copy is empty by construction."""
    from nsmcp.answer import NO_FINDINGS

    text = render(_minimal_golden_answer(), Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    assert "1 bevinding(en)" in text
    assert "1 leesgat(en) (niet vastgesteld, geen stille aanname)" in text
    assert NO_FINDINGS not in text


def test_golden_minimal_answer_text_is_frozen():
    """The last line says `doel: niet getoond op deze stand.`,
    not `doel: lab.`. This design choice wins over this golden on purpose - a target
    NAME on the `minimaal` stand is a leak (a pseudonym for a single value
    carries nothing a reader could not infer by asking twice), and every
    other value on this stand is already withheld. Deliberately NOT changed
    one screen up: the FULL rendering still names the target, which is what
    `volledig` is for. The golden moves; the gate does not."""
    assert render(_minimal_golden_answer(), Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er") == (
        "Vraag: certificaat_wat_verloopt_er (stand: minimaal)\n"
        "\n"
        "- 1 bevinding(en)\n"
        "- 1 leesgat(en) (niet vastgesteld, geen stille aanname)\n"
        "- 1 dimensie(s) bewust niet beoordeeld\n"
        "- kortste resterende looptijd: 12 dagen\n"
        "- actie nodig: niet vast te stellen uit dit antwoord\n"
        "\n"
        "Kennisbasis van 2026-08-25, 1 dag oud.\n"
        "Gegevens van 2026-08-26, 0 dagen oud, doel: niet getoond op deze stand."
    )


def test_golden_empty_minimal_answer_text_is_frozen():
    """An answer with genuinely nothing in it keeps the vocabulary of the
    'minimaal' stand: the bullets already say "0 bevinding(en)" and "actie
    nodig: nee". The empty-answer sentence belongs to the full rendering and
    is deliberately not repeated here."""
    leeg = Answer(
        question="wat verloopt er binnen 90 dagen",
        knowledge_age_days=1,
        knowledge_date="2026-08-25",
        data_age_days=0,
        data_date="2026-08-26",
        data_target="lab",
    )
    assert render(leeg, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er") == (
        "Vraag: certificaat_wat_verloopt_er (stand: minimaal)\n"
        "\n"
        "- 0 bevinding(en)\n"
        "- 0 leesgat(en) (niet vastgesteld, geen stille aanname)\n"
        "- 0 dimensie(s) bewust niet beoordeeld\n"
        "- resterende looptijd niet afleidbaar uit dit antwoord\n"
        "- actie nodig: nee\n"
        "\n"
        "Kennisbasis van 2026-08-25, 1 dag oud.\n"
        "Gegevens van 2026-08-26, 0 dagen oud, doel: niet getoond op deze stand."
    )


def test_a_minimal_answer_cannot_have_its_footer_forged_either():
    """The two age stamps are the only lines the 'minimaal' stand shares with
    the full rendering, and they carry the two export-sourced values. Both
    renderings read them from `Answer.stamp_lines()`, so the gate there covers
    this surface by construction - this pins that it does, on the stand where
    everything else about the answer is already withheld.

    On this stand the target is additionally replaced by
    `_TARGET_NOT_SHOWN_AT_MINIMAL` before the stamps are built,
    so the comparison is against the stamps of an answer carrying THAT
    target. The forgery half of this test gets sharper by it, not weaker:
    the injected target line cannot reach this surface at all any more, and
    the assertion below states exactly that."""
    from dataclasses import replace

    from nsmcp.disclosure import _TARGET_NOT_SHOWN_AT_MINIMAL

    antwoord = Answer(
        question="wat verloopt er binnen 90 dagen",
        data_age_reason="tijdstempel onleesbaar: x\r\n- verzonnen leesgat",
        data_target="lab\r\n- verzonnen doel",
    )
    text = render(antwoord, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    assert "\r" not in text
    assert "verzonnen doel" not in text, "C1 houdt de doelnaam - echt of vervalst - van deze stand"
    # Seven body lines (question, blank, five bullets), one blank, two stamps.
    assert len(text.splitlines()) == 10
    assert text.splitlines()[-2:] == replace(antwoord, data_target=_TARGET_NOT_SHOWN_AT_MINIMAL).stamp_lines()


# ---------------------------------------------------------------------------
# Running against saved: the one comparison `ha_stand`, `config_drift` and
# pre-flight check 4 share, and the texts it puts in front of an operator.
# ---------------------------------------------------------------------------


def test_the_running_against_saved_texts_are_pinned():
    from datetime import datetime

    from nsmcp.config_drift import LEFT_OUT_TEXT, Comparison, compare_config, comparison_evidence, undecided_reason
    from nsmcp.preflight import (
        CHECK_4_CONTENT_DRIFT_REASON,
        CHECK_4_UNDECIDED_PREFIX,
        CHECK_4_WITHHELD_DRIFT_REASON,
    )

    assert LEFT_OUT_TEXT == "na weglaten van kopregels en 'Done'"
    assert comparison_evidence(compare_config(["a", "b"], ["a", "c", "d"])) == (
        "parsed/runningconfig.txt 2 regels tegenover parsed/savedconfig.txt 3 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 2 alleen in saved"
    )
    assert comparison_evidence(compare_config(["a", "b"], ["a", "c", "d"], withheld_only=2)) == (
        "parsed/runningconfig.txt 2 regels tegenover parsed/savedconfig.txt 3 regels na weglaten van"
        " kopregels en 'Done'; 3 alleen in running, 4 alleen in saved, waarvan 2 per kant alleen in een"
        " achtergehouden deel"
    )
    assert comparison_evidence(compare_config(["a"], ["a"], not_comparable=1)) == (
        "parsed/runningconfig.txt 1 regels tegenover parsed/savedconfig.txt 1 regels na weglaten van"
        " kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 1 regel per kant met een waarde die de"
        " verzamelaar al achterhield, niet te vergelijken"
    )
    changed = Comparison(
        running_count=1,
        saved_count=1,
        only_running=(),
        only_saved=(),
        last_change=datetime(2026, 9, 24, 10, 12, 3),
        last_save=datetime(2026, 9, 23, 12, 59, 15),
        not_comparable=3,
    )
    assert undecided_reason(changed) == (
        "3 regels per kant dragen een waarde die de verzamelaar al achterhield en die niet te vergelijken is;"
        " de kopregels melden een wijziging na de laatste opslag, en of die in zo'n waarde zit, is uit deze"
        " export niet vast te stellen"
    )
    assert undecided_reason(compare_config(["a"], ["a"], not_comparable=1)) == (
        "1 regel per kant draagt een waarde die de verzamelaar al achterhield en die niet te vergelijken is;"
        " de kopregels dragen geen leesbaar tijdstempel, dus of er na de laatste opslag iets in zo'n waarde is"
        " gewijzigd, is uit deze export niet vast te stellen"
    )
    assert CHECK_4_UNDECIDED_PREFIX == "config-drift is onbevestigd: "
    assert CHECK_4_CONTENT_DRIFT_REASON == (
        "de draaiende configuratie wijkt af van de opgeslagen configuratie; een herstart tijdens de"
        " upgrade verliest wat alleen in running staat (config_drift toont welke regels)"
    )
    assert CHECK_4_WITHHELD_DRIFT_REASON == (
        "de draaiende configuratie wijkt af van de opgeslagen configuratie in een deel dat een geheim kan"
        " dragen; een herstart tijdens de upgrade verliest die wijziging (config_drift telt deze regels"
        " maar toont ze niet)"
    )


def test_the_config_drift_texts_are_pinned():
    from nsmcp import config_drift as drift
    from nsmcp.mcp_server import CONFIG_DRIFT_DESCRIPTION

    assert CONFIG_DRIFT_DESCRIPTION == _BASELINE_SURFACE["config_drift"]["description"]
    assert drift.QUESTION == "wijkt de draaiende configuratie af van de opgeslagen configuratie"
    assert drift.ONLY_RUNNING_LABEL == "alleen in running"
    assert drift.ONLY_SAVED_LABEL == "alleen in saved"
    assert drift.HEAD_RUNNING_LABEL == "commandohoofd alleen in running"
    assert drift.HEAD_SAVED_LABEL == "commandohoofd alleen in saved"
    assert drift.HEADERS_LABEL == "kopregels"
    assert drift.HEADERS_AGAINST_CONTENT_LABEL == "kopregels tegenover inhoud"
    assert drift.WITHHELD_ONLY_LABEL == "verschil in achtergehouden deel"
    assert drift.WITHHELD_ONLY_EVIDENCE_SUFFIX == ", waarvan {n} per kant alleen in een achtergehouden deel"
    assert drift.WITHHELD_ONLY_EVIDENCE_TEXT == (
        "running en saved vergeleken met en zonder dat deel; alleen een telling, nooit de inhoud"
    )
    assert (drift.withheld_only_text(1), drift.withheld_only_text(3)) == (
        "1 regel per kant verschilt alleen in een deel dat een geheim kan dragen; dat deel wordt in geen stand getoond",
        "3 regels per kant verschillen alleen in een deel dat een geheim kan dragen; dat deel wordt in geen"
        " stand getoond",
    )
    assert drift.SECRET_WITHHELD_TEXT == "(regel met een geheim of een geredigeerde waarde; niet getoond)"
    assert drift.SECRET_NON_ASCII_TEXT == "(regel met letters buiten ASCII; niet getoond)"
    assert drift.SECRET_HEAD_TEXT == "(commandohoofd met een geheim; niet getoond)"
    assert drift.UNKNOWN_HEAD_TEXT == "(commando niet herkend)"
    assert drift.APPLIANCE_TIME_TEXT == "(tijd van de appliance)"
    assert drift.HEADERS_EVIDENCE_TEXT == (
        "regel 2 van parsed/runningconfig.txt en van parsed/savedconfig.txt; bewijs, geen oordeel:"
        " het oordeel rust op de inhoud"
    )
    assert drift.HEADERS_UNREADABLE_TEXT == "draagt geen tijdstempel in de vorm die deze versie kent"
    assert drift.HEADERS_AGAINST_CONTENT_TEXT == (
        "de kopregels melden een wijziging na de laatste opslag, maar de inhoud is gelijk"
    )
    assert drift.HEADS_EVIDENCE_TEXT == (
        "het commandohoofd van regels die alleen in {bron} staan; argumenten en namen weggelaten"
    )
    assert drift.LINE_EVIDENCE_TEXT == "{bron}; niet in {ander}"
    assert drift.MORE_LINES_EVIDENCE_TEXT == "maximaal {n} regels per kant getoond; de telling staat bij config-drift"
    assert drift.MORE_HEADS_EVIDENCE_TEXT == "maximaal {n} commandohoofden per kant getoond"
    assert drift.LINE_CUT_NOTE == " [...] (regel afgekapt op 200 tekens)"
    assert (drift.more_lines_text(1), drift.more_lines_text(5)) == ("en 1 regel meer", "en 5 regels meer")
    assert (drift.more_heads_text(1), drift.more_heads_text(2)) == (
        "en 1 commandohoofd meer",
        "en 2 commandohoofden meer",
    )


def test_golden_config_drift_answer_is_frozen(tmp_path):
    """The whole answer at `volledig`, byte for byte, on a synthetic pair
    with one line only in running and one only in saved."""
    from datetime import date

    from config_export_harness import RUNNING_HEADER, SAVED_HEADER, config_pair

    from nsmcp.answer import stamp_data
    from nsmcp.config_drift import drift_answer
    from nsmcp.export import load_export

    base = ["add server SRV-001 192.0.2.10", "add lb vserver LBV-001 HTTP 192.0.2.20 80"]
    export = load_export(
        config_pair(
            tmp_path,
            RUNNING_HEADER + base + ["set lb vserver LBV-001 -comment acceptatietest", " Done"],
            SAVED_HEADER + base + ["add server SRV-002 192.0.2.11"],
        )
    )
    knowledge = Knowledge(version="golden", date="2026-09-24", age_days=0, missing=False)
    answer = stamp_data(drift_answer(export, knowledge), export.collected_at, date(2026, 9, 24), None)
    assert render(answer, Disclosure.FULL, tool="config_drift") == (
        "Vraag: wijkt de draaiende configuratie af van de opgeslagen configuratie\n"
        "\n"
        "- config-drift: aan [vastgesteld]\n"
        "    bewijs: parsed/runningconfig.txt 3 regels tegenover parsed/savedconfig.txt 3 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 1 alleen in saved\n"
        "- alleen in running: set lb vserver LBV-001 -comment acceptatietest [vastgesteld]\n"
        "    bewijs: parsed/runningconfig.txt; niet in parsed/savedconfig.txt\n"
        "- alleen in saved: add server SRV-002 192.0.2.11 [vastgesteld]\n"
        "    bewijs: parsed/savedconfig.txt; niet in parsed/runningconfig.txt\n"
        "- commandohoofd alleen in running: set lb vserver (1 regel) [vastgesteld]\n"
        "    bewijs: het commandohoofd van regels die alleen in parsed/runningconfig.txt staan; argumenten en"
        " namen weggelaten\n"
        "- commandohoofd alleen in saved: add server (1 regel) [vastgesteld]\n"
        "    bewijs: het commandohoofd van regels die alleen in parsed/savedconfig.txt staan; argumenten en"
        " namen weggelaten\n"
        "- kopregels: laatste wijziging Thu Sep 24 10:12:03 2026, laatste opslag Wed Sep 23 12:59:15 2026"
        " (tijd van de appliance) [vastgesteld]\n"
        "    bewijs: regel 2 van parsed/runningconfig.txt en van parsed/savedconfig.txt; bewijs, geen oordeel:"
        " het oordeel rust op de inhoud\n"
        "\n"
        "Kennisbasis van 2026-09-24, 0 dagen oud.\n"
        "Gegevens van 2026-09-24, 0 dagen oud, doel: niet vastgelegd."
    )


# Moved here from tests/test_disclosure.py: this guard is about the product
# surface, not about the disclosure seam, and a contributor who wants to
# understand or extend it looks here.
def test_name_neutrality_no_product_name_in_code():
    """The product line name is a working name and can change while the brand
    clearance is not yet final. It therefore belongs EXCLUSIVELY in
    documentation, never in code or identifiers.

    An earlier version deliberately scanned only `src/`, reasoning that
    `tests/` was allowed to DESCRIBE the finding itself. The counter: that
    reasoning breaks as soon as the working name sits as a LITERAL STRING
    anywhere in `tests/` - and that was the case here, in the scan line of
    THIS very test (the contiguous search term stood UNSPLIT in the source
    until this repair). A guard that leaves its own search term in the
    scanned corpus proves nothing once that corpus is extended.

    So the repair is not "skip tests/" but: DO scan `tests/`, and take
    the search term from the needle list outside the tracked tree
    (tests/private_needles.py), so the working name appears nowhere in the
    scanned corpus - not even in this scan line.
    """
    from private_needles import needles_or_skip

    root = Path(__file__).resolve().parent.parent
    forbidden_names = [name.lower() for name in needles_or_skip("werknaam")]
    hits = [
        f"{p}:{n}"
        for dir_ in (root / "src", root / "tests")
        for p in dir_.rglob("*.py")
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if any(name in line.lower() for name in forbidden_names)
    ]
    assert hits == [], f"productnaam gevonden in code: {hits}"


# ---------------------------------------------------------------------------
# The sentences of the shared binding reader and of the tools that read the
# aggregate shape through it, byte for byte.
# ---------------------------------------------------------------------------

_DOH_EXPORT = Path(__file__).parent / "fixtures" / "lab-export-vpx-doh-synthetic"


def test_the_aggregate_reader_refusal_is_pinned():
    from nsmcp.export import AGGREGATE_WITHOUT_CHILDREN_REASON

    assert AGGREGATE_WITHOUT_CHILDREN_REASON == (
        "bindingsvorm 'aggregate' wordt alleen per kindsleutel gelezen en deze lezing noemde geen"
        " kindsleutel; alle geneste lijsten samenvoegen zou de ene bindingssoort als de andere laten"
        " meetellen"
    )


def test_the_chain_sentences_are_pinned():
    from nsmcp.chain import NOT_FOLLOWED, service_chain
    from nsmcp.export import load_export

    assert NOT_FOLLOWED == {
        "Gateway-vserver": "een Gateway-vserver hangt niet aan een servicegroup; die keten volgt deze versie niet",
    }
    text = service_chain(load_export(_DOH_EXPORT), _knowledge(), "").to_text()
    assert text.splitlines()[2:4] == [
        "- samenvatting: 17 ketens: 11 keten compleet, 6 gat in de keten [vastgesteld]",
        "    bewijs: ingangen: 5 Contentswitching-vserver, 12 Loadbalancing-vserver, 0 Gateway-vserver",
    ]


def test_the_cs_chain_sentences_are_pinned():
    """Every reason `_cs_chain()` can produce, pinned directly against the
    function (no full export/fixture scaffolding needed - the same
    isolated-sentence idiom `_CertSideExport` above uses for impact.py).
    Each branch that involves an UNRESOLVED policy also carries a real
    default load balancer whose own chain is `keten compleet` on its own,
    so this test additionally proves the branch actually blocks that
    favourable verdict rather than being silently skipped."""
    from nsmcp.answer import ReadGap
    from nsmcp.chain import CS_LBVSERVER_CHILD, CS_POLICY_CHILD, Chain, Link, _cs_chain

    entry_link = Link("ingang", "CSV-X")
    binding_file = "csvserver_binding.by-parent.json"
    complete_lb = Chain(
        "LBV-1",
        "Loadbalancing-vserver",
        "keten compleet",
        (Link("ingang", "LBV-1"), Link("backendgroep", "SG-1"), Link("lid", "srv1")),
    )
    lb_by_name = {"LBV-1": complete_lb}

    def cs(
        rows,
        *,
        cspolicy_index=None,
        cspolicy_gap=None,
        csaction_index=None,
        csaction_nonlb_index=None,
        csaction_gap=None,
        other_kinds=(),
    ):
        return _cs_chain(
            "CSV-X",
            "Contentswitching-vserver",
            entry_link,
            binding_file,
            rows,
            lb_by_name,
            None,
            cspolicy_index or {},
            cspolicy_gap,
            csaction_index or {},
            csaction_nonlb_index or {},
            csaction_gap,
            other_kinds=other_kinds,
        )

    no_route = cs([])
    assert no_route.verdict == "gat in de keten"
    assert (
        no_route.reason
        == "csvserver_binding.by-parent.json draagt voor CSV-X geen standaard load balancer en geen csbeleid"
    )

    unread_kind = cs([], other_kinds=("csvserver_gslbvserver_binding",))
    assert unread_kind.verdict == "niet vastgesteld"
    assert unread_kind.reason == (
        "csvserver_binding.by-parent.json draagt voor CSV-X geen standaard load balancer en geen csbeleid,"
        " wel een bindingssoort die deze versie niet leest (csvserver_gslbvserver_binding); niet vast te"
        " stellen waarnaar deze vserver routeert"
    )

    next_to_a_route = cs([(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-1"})], other_kinds=("csvserver_vpnvserver_binding",))
    assert next_to_a_route.verdict == "niet vastgesteld"
    assert next_to_a_route.reason == (
        "csvserver_binding.by-parent.json draagt voor CSV-X ook een bindingssoort die deze versie niet leest"
        " (csvserver_vpnvserver_binding); die route volgt deze versie niet; alleen de standaard load balancer"
        " en de beleidsnamen zijn hier vastgesteld"
    )
    next_to_a_policy_binding = cs(
        [(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-1"})], other_kinds=("csvserver_responderpolicy_binding",)
    )
    assert next_to_a_policy_binding.verdict == "keten compleet"

    list_shape = cs([("csvserver_binding", {"name": "CSV-X", "lbvserver": "LBV-1"})])
    assert list_shape.verdict == "niet vastgesteld"
    assert list_shape.reason == (
        "csvserver_binding.by-parent.json draagt voor CSV-X bindingen in de lijstvorm, niet gegroepeerd als"
        " standaard load balancer of csbeleid; die vorm volgt deze versie voor een contentswitchingroute niet;"
        " niet vast te stellen waarnaar deze vserver routeert"
    )

    bad_lb_field = cs([(CS_LBVSERVER_CHILD, {"lbvserver": ["A", "B"]})])
    assert bad_lb_field.verdict == "niet vastgesteld"
    assert bad_lb_field.reason == (
        "een standaard-LB-binding van CSV-X draagt lbvserver als een waarde van het type list in plaats"
        " van tekst; niet vast te stellen waarnaar deze vserver routeert"
    )

    missing_policyname = cs([(CS_POLICY_CHILD, {"priority": "100"})])
    assert missing_policyname.verdict == "niet vastgesteld"
    assert missing_policyname.reason == (
        "een beleidsbinding van CSV-X draagt policyname niet als tekst (de sleutel ontbreekt); niet vast"
        " te stellen waarnaar deze vserver routeert"
    )

    bad_direct_target = cs([(CS_POLICY_CHILD, {"policyname": "CSPOL-1", "targetlbvserver": ["X"]})])
    assert bad_direct_target.verdict == "niet vastgesteld"
    assert bad_direct_target.reason == (
        "een beleidsbinding van CSV-X draagt targetlbvserver als een waarde van het type list in plaats"
        " van tekst; niet vast te stellen waarnaar deze vserver routeert"
    )

    policy_rows = [(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-1"}), (CS_POLICY_CHILD, {"policyname": "CSPOL-1"})]

    cspolicy_missing = cs(policy_rows, cspolicy_gap=ReadGap(source="config/cspolicy", reason="test-reden"))
    assert cspolicy_missing.verdict == "niet vastgesteld"
    assert cspolicy_missing.reason == (
        "cspolicy is niet vast te stellen: test-reden; alleen de standaard load balancer en de"
        " beleidsnamen zijn hier vastgesteld"
    )

    no_action = cs(policy_rows, cspolicy_index={})
    assert no_action.verdict == "niet vastgesteld"
    assert no_action.reason == (
        "beleid CSPOL-1 van CSV-X heeft geen leesbare actie in cspolicy; alleen de standaard load"
        " balancer en de beleidsnamen zijn hier vastgesteld"
    )

    csaction_missing = cs(
        policy_rows,
        cspolicy_index={"CSPOL-1": "CSACT-1"},
        csaction_gap=ReadGap(source="config/csaction", reason="test-reden"),
    )
    assert csaction_missing.verdict == "niet vastgesteld"
    assert csaction_missing.reason == (
        "csaction is niet vast te stellen: test-reden; alleen de standaard load balancer en de"
        " beleidsnamen zijn hier vastgesteld"
    )

    no_target = cs(policy_rows, cspolicy_index={"CSPOL-1": "CSACT-1"})
    assert no_target.verdict == "niet vastgesteld"
    assert no_target.reason == (
        "actie CSACT-1 van beleid CSPOL-1 heeft geen leesbaar doel in csaction; alleen de standaard load"
        " balancer en de beleidsnamen zijn hier vastgesteld"
    )

    nonlb_target = cs(
        policy_rows,
        cspolicy_index={"CSPOL-1": "CSACT-1"},
        csaction_nonlb_index={"CSACT-1": "CSV-OTHER"},
    )
    assert nonlb_target.verdict == "niet vastgesteld"
    assert nonlb_target.reason == (
        "actie CSACT-1 van beleid CSPOL-1 verwijst naar een vserver die geen loadbalancing-vserver is;"
        " die stap volgt deze versie niet; alleen de standaard load balancer en de beleidsnamen zijn hier"
        " vastgesteld"
    )

    # And the favourable control: the SAME default-LB row, alone, resolves
    # to the LB's own already-complete chain - proving the branches above
    # are what blocks "keten compleet", not a mistaken lb_by_name lookup.
    only_default_lb = cs([(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-1"})])
    assert only_default_lb.verdict == "keten compleet"

    # The last two reasons need a DIFFERENT `lb_by_name`/`lb_entry_gap` than
    # `cs()` above fixes, so these two call `_cs_chain()` directly: a
    # resolved target this version cannot even check because
    # `config/lbvserver` itself is unread, versus one it checked and simply
    # does not exist.
    unread_lbvserver = _cs_chain(
        "CSV-X",
        "Contentswitching-vserver",
        entry_link,
        binding_file,
        [(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-1"})],
        {},
        ReadGap(source="config/lbvserver", reason="test-reden"),
        {},
        None,
        {},
        {},
        None,
    )
    assert unread_lbvserver.verdict == "niet vastgesteld"
    assert unread_lbvserver.reason == "config/lbvserver is niet gelezen: test-reden"

    unknown_target = _cs_chain(
        "CSV-X",
        "Contentswitching-vserver",
        entry_link,
        binding_file,
        [(CS_LBVSERVER_CHILD, {"lbvserver": "LBV-ONBEKEND"})],
        {},
        None,
        {},
        None,
        {},
        {},
        None,
    )
    assert unknown_target.verdict == "gat in de keten"
    assert unknown_target.reason == (
        "CSV-X routeert naar loadbalancing-vserver LBV-ONBEKEND, die niet voorkomt in config/lbvserver"
    )


def test_the_expiry_sentences_are_pinned():
    from datetime import date

    from nsmcp.expiry import binding_kind_names, what_expires
    from nsmcp.export import load_export

    export = load_export(_DOH_EXPORT)
    text = what_expires(export, _knowledge(), 90, today=date.fromisoformat(export.collected_at[:10])).to_text()
    assert text.splitlines()[2:4] == [
        "- certificaten: geen certificaat verloopt binnen 90 dagen (9 certificaten gelezen) [vastgesteld]",
        "    bewijs: config/sslcertkey; gerekend vanaf vandaag, export van 0 dagen oud",
    ]
    assert binding_kind_names(("sslcertkey_crldistribution_binding", "X\ny_binding")) == (
        "sslcertkey_crldistribution_binding, een bindingssoort zonder de vorm van een resourcenaam"
    )


def test_the_chain_summary_over_an_unread_entry_source_is_pinned():
    from nsmcp.chain import _summary_finding

    finding = _summary_finding((), (ReadGap(source="config/lbvserver", reason="read niet bruikbaar: RBAC_DENIED"),))
    assert (finding.subject, finding.outcome, finding.certainty, finding.evidence, finding.reason) == (
        "samenvatting",
        "0 ketens",
        Certainty.NOT_ESTABLISHED,
        "ingangen: 0 Contentswitching-vserver, 0 Loadbalancing-vserver, 0 Gateway-vserver",
        "niet elke ingangsbron is gelezen: config/lbvserver",
    )


class _CertSideExport:
    """The smallest export for the certificate-side sentences: one
    certificate, no vserver binding, and a certificate-side document."""

    def __init__(self, cert_side):
        self._cert_side = cert_side

    def bindings(self, file_name):
        return [], None

    def objects(self, resource):
        return [{"certkey": "cert_a"}], None

    def binding_parents(self, file_name):
        from nsmcp.export import ParentCoverage

        return ParentCoverage()

    def binding_rows(self, file_name, *, children=None):
        return self._cert_side, None

    def binding_child_keys(self, file_name):
        return {p: tuple(sorted({k for k, _r in pairs or ()})) for p, pairs in self._cert_side.items()}, None


def test_the_certificate_side_sentences_of_the_impact_are_pinned():
    from nsmcp.impact import what_breaks

    closing = what_breaks(_CertSideExport({"cert_a": []}), _knowledge(), "cert_a").findings[-1]
    assert closing.outcome == (
        "geen gebonden virtuele servers, geen gebonden SSL-diensten en geen uitgegeven certificaten"
        " gevonden in deze export"
    )
    assert closing.evidence == (
        "sslvserver_sslcertkey_binding.by-parent.json: gelezen en gecontroleerd, geen binding met deze naam;"
        " config/sslcertkey: gelezen en gecontroleerd, geen certificaat met linkcertkeyname op deze naam;"
        " sslcertkey_binding.by-parent.json: gelezen en gecontroleerd, geen service-binding op deze naam"
    )

    absent = what_breaks(_CertSideExport({}), _knowledge(), "cert_a").read_gaps
    assert [(g.source, g.reason) for g in absent] == [
        (
            "sslcertkey_binding.by-parent.json",
            "sslcertkey_binding.by-parent.json draagt geen parent-vermelding voor cert_a; de bindingen van"
            " dit certificaat buiten virtuele servers zijn niet gelezen",
        )
    ]
    unknown = what_breaks(
        _CertSideExport({"cert_a": [("sslcertkey_crldistribution_binding", {"certkey": "cert_a"})]}),
        _knowledge(),
        "cert_a",
    ).read_gaps
    assert [(g.source, g.reason) for g in unknown] == [
        (
            "sslcertkey_binding.by-parent.json",
            "sslcertkey_binding.by-parent.json draagt voor cert_a een bindingssoort die deze versie niet leest"
            " (sslcertkey_crldistribution_binding); of dit certificaat daar ook uitvalt, is niet vast te stellen",
        )
    ]
    unreadable = what_breaks(
        _CertSideExport({"cert_a": [("sslcertkey_service_binding", {"certkey": "cert_a", "servicename": 5})]}),
        _knowledge(),
        "cert_a",
    ).read_gaps
    assert [(g.source, g.reason) for g in unreadable] == [
        (
            "sslcertkey_binding.by-parent.json (service-binding 1)",
            "servicename is niet bruikbaar: een waarde van het type int; niet vast te stellen welke"
            " SSL-dienst aan 'cert_a' hangt",
        )
    ]


def test_the_usage_state_of_an_unread_kind_is_pinned():
    from nsmcp.expiry import usage_per_certificate

    usage = usage_per_certificate(
        _CertSideExport({"cert_a": [("sslcertkey_crldistribution_binding", {"certkey": "cert_a"})]})
    )
    assert [(u.certkey, u.state, u.reason) for u in usage] == [
        (
            "cert_a",
            "onbekend",
            "niet vast te stellen of dit certificaat ergens aan hangt: sslcertkey_binding.by-parent.json"
            " draagt voor dit certificaat een bindingssoort die deze versie niet leest"
            " (sslcertkey_crldistribution_binding)",
        )
    ]


def test_the_service_step_of_the_advice_is_pinned():
    antwoord = what_to_do(
        ImpactAnswer(
            question="wat breekt er met cert_a",
            findings=[],
            affected_vservers=("LB_VS_A",),
            issued_certificates=(),
            affected_services=("SVC_WEB",),
        ),
        _knowledge(),
        "cert_a",
    )
    stappen = antwoord.findings[0].outcome.splitlines()
    assert stappen[2] == "3. Koppel het ook om op de SSL-diensten (services): SVC_WEB. (handmatige actie)"
    assert stappen[4] == (
        "5. Terugleescontrole: lees de binding per virtuele server terug en bevestig de nieuwe naam, en lees"
        " daystoexpiration van het nieuwe certificaat terug. Lees daarnaast de certificaatbinding van die"
        " SSL-diensten terug. (handmatige actie)"
    )
    assert antwoord.findings[0].evidence == (
        "afgeleid uit 1 vastgesteld geraakte virtuele server(s), 1 vastgesteld geraakte SSL-dienst(en)"
        " en 0 vastgesteld uitgegeven certificaten"
    )


# ---------------------------------------------------------------------------
# The certificate use outside the bindings (SAML actions, SAML IdP profiles,
# SSL servicegroups), byte for byte.
# ---------------------------------------------------------------------------


def _use(kind, owner, role, reason=""):
    from nsmcp.cert_usage import CertUse

    return CertUse(certkey="cert_a", kind=kind, owner=owner, role=role, evidence="bewijs", reason=reason)


def test_the_certificate_use_sentences_are_pinned():
    from nsmcp.cert_usage import (
        FAMILIES_TEXT,
        REFUSED_KEY_REASON,
        SOURCES,
        SOURCES_TEXT,
        CertGap,
        absent_dimension,
        other_usage,
    )

    assert SOURCES == (
        ("config/authenticationsamlaction", "SAML-acties"),
        ("config/authenticationsamlidpprofile", "SAML-IdP-profielen"),
        ("sslservicegroup_sslcertkey_binding.by-parent.json", "SSL-servicegroups"),
    )
    assert FAMILIES_TEXT == "SAML-acties, SAML-IdP-profielen of SSL-servicegroups"
    assert SOURCES_TEXT == (
        "config/authenticationsamlaction, config/authenticationsamlidpprofile en"
        " sslservicegroup_sslcertkey_binding.by-parent.json"
    )
    rows = [
        (_use("SAML-actie", "SAML_X", "IdP-certificaat"), "gebruikt als IdP-certificaat door SAML-actie SAML_X"),
        (
            _use("SAML-actie", "SAML_X", "signing-certificaat"),
            "gebruikt als signing-certificaat door SAML-actie SAML_X",
        ),
        (_use("IdP-profiel", "IDP_Y", "IdP-certificaat"), "gebruikt als IdP-certificaat door IdP-profiel IDP_Y"),
        (_use("IdP-profiel", "IDP_Y", "SP-certificaat"), "gebruikt als SP-certificaat door IdP-profiel IDP_Y"),
        (_use("SSL-servicegroup", "SG_Z", "CA: ja"), "gebonden aan SSL-servicegroup SG_Z (CA: ja)"),
        (_use("SSL-servicegroup", "SG_Z", "CA: nee"), "gebonden aan SSL-servicegroup SG_Z (CA: nee)"),
        (_use("SSL-servicegroup", "SG_Z", ""), "gebonden aan SSL-servicegroup SG_Z; rol niet vast te stellen"),
    ]
    for use, outcome in rows:
        assert use.outcome == outcome
    assert _use("SAML-actie", "SAML_X", "IdP-certificaat").label == "SAML-actie SAML_X (IdP-certificaat)"
    assert _use("SSL-servicegroup", "SG_Z", "").label == "SSL-servicegroup SG_Z (rol niet vastgesteld)"
    [reading] = [r for r in other_usage(object()).readings if r.family == "SAML-acties"]
    grens = absent_dimension(reading)
    assert (grens.subject, grens.reason) == (
        "certificaatgebruik door SAML-acties",
        "niet vastgesteld: bron config/authenticationsamlaction niet in de export; welke certificaten"
        " SAML-acties gebruiken, is met deze export niet vast te stellen",
    )
    assert REFUSED_KEY_REASON == (
        "de manifestsleutel van deze bron heeft niet de vorm die deze versie leest en is aan de exportgrens"
        " geweigerd; de bron is niet gelezen"
    )
    gap = CertGap(
        certkey="cert_a",
        source="config/authenticationsamlaction (SAML-actie op positie 1)",
        kind="SAML-actie",
        field="samlidpcertname",
        shape="de sleutel ontbreekt",
    ).gap("cert_a")
    assert gap.reason == (
        "deze SAML-actie verwijst in samlidpcertname naar cert_a, maar draagt geen bruikbare naam (de sleutel"
        " ontbreekt); welke SAML-actie dat is, is niet vast te stellen"
    )


class _ServicegroupParentExport:
    """No servicegroup binding file, no SAML sources; `config/sslservicegroup`
    in the state a test gives it."""

    file_hashes: dict = {}
    refused_resource_keys = ()
    refused_file_keys = ()
    manifest_missing = False

    def __init__(self, status, rows=(), gap=None):
        self._status, self._rows, self._gap = status, list(rows), gap

    def status(self, resource):
        return self._status if resource == "config/sslservicegroup" else "NIET_IN_MANIFEST"

    def objects(self, resource):
        return self._rows, self._gap


def test_the_servicegroup_parent_source_sentences_are_pinned():
    from nsmcp.cert_usage import coverage_findings, join_list, other_usage

    assert join_list(("a",), "en") == "a"
    assert join_list(("a", "b"), "of") == "a of b"
    assert join_list(("a", "b", "c"), "en") == "a, b en c"

    denied = other_usage(
        _ServicegroupParentExport(
            "RBAC_DENIED", gap=ReadGap(source="config/sslservicegroup", reason="read niet bruikbaar: RBAC_DENIED")
        )
    )
    assert [(g.source, g.reason) for g in denied.shared_gaps] == [
        (
            "config/sslservicegroup",
            "read niet bruikbaar: RBAC_DENIED; zonder deze parentbron is niet vast te stellen welke"
            " SSL-servicegroups er zijn, en sslservicegroup_sslcertkey_binding.by-parent.json staat niet in de"
            " export",
        )
    ]
    missing = other_usage(_ServicegroupParentExport("OK", rows=[{"servicegroupname": "SG_Z"}]))
    assert [(g.source, g.reason) for g in missing.shared_gaps] == [
        (
            "sslservicegroup_sslcertkey_binding.by-parent.json",
            "config/sslservicegroup kent 1 SSL-servicegroup(s), maar dit bindingsbestand staat niet in de"
            " export; welke certificaten daaraan hangen, is niet gelezen",
        )
    ]
    [line] = [
        f
        for f in coverage_findings(_ServicegroupParentExport("EMPTY"))
        if f.subject == "sslservicegroup_sslcertkey_binding.by-parent.json"
    ]
    assert (line.outcome, line.evidence) == (
        "gelezen (certificaatgebruik door SSL-servicegroups)",
        "export-manifest.json: config/sslservicegroup gelezen, zonder SSL-servicegroups",
    )


def test_the_certificate_bound_read_gap_in_the_coverage_report_is_pinned():
    """`rapport_dekking` lists a read gap bound to one certificate without
    naming that certificate: the report is about every certificate at once."""
    from nsmcp.cert_usage import CertGap
    from nsmcp.coverage import CERT_GAP_SUBJECT

    assert CERT_GAP_SUBJECT == "een certificaat"
    gap = CertGap(
        certkey="CERT-X",
        source="config/authenticationsamlaction (SAML-actie op positie 1)",
        kind="SAML-actie",
        field="samlidpcertname",
        shape="ontbreekt",
    ).gap(CERT_GAP_SUBJECT)
    assert gap.reason == (
        "deze SAML-actie verwijst in samlidpcertname naar een certificaat, maar draagt geen bruikbare naam"
        " (ontbreekt); welke SAML-actie dat is, is niet vast te stellen"
    )


def test_the_cs_route_source_coverage_sentences_are_pinned():
    """What `rapport_dekking` says about a policy source a contentswitching
    route asks for and cannot read: absent from the manifest, a line and a
    read gap; in the manifest with a tally line that costs nothing on its own
    (OPTIONEEL AFWEZIG), only the read gap; lost (GEWEIGERD), nothing extra -
    the tally already made both."""
    from nsmcp.coverage import Coverage, SourceState, _route_source_lines

    result = Coverage(
        verdict="gedeeltelijk",
        sources=(
            SourceState("config/csaction", "config/csaction", "OPTIONEEL AFWEZIG", "test-reden"),
            SourceState("config/csvserver", "config/csvserver", "GEWEIGERD", "test-reden"),
        ),
        route_source_gaps=(
            ReadGap(source="config/cspolicy", reason="resource staat niet in het manifest van deze export"),
            ReadGap(source="config/csaction", reason="test-reden"),
            ReadGap(source="config/csvserver", reason="test-reden"),
        ),
    )
    lines, gaps = _route_source_lines(result, {"config/csaction", "config/csvserver"})
    absent = (
        "niet vastgesteld: bron config/cspolicy niet in de export; waarheen een contentswitchingbeleid zonder"
        " eigen doel routeert, is met deze export niet vast te stellen"
    )
    assert [(f.subject, f.outcome, f.certainty.value, f.evidence, f.reason) for f in lines] == [
        ("config/cspolicy", "niet in de export", "niet vastgesteld", "export-manifest.json", absent)
    ]
    assert [(g.source, g.reason) for g in gaps] == [
        ("config/cspolicy", absent),
        (
            "config/csaction",
            "test-reden; waarheen een contentswitchingbeleid zonder eigen doel routeert, is met deze export"
            " niet vast te stellen",
        ),
    ]

    # A key the export boundary refused: in the manifest, so never "niet in
    # de export"; the line only (the tally line of the key's shape carries the
    # read gap).
    refused_lines, refused_gaps = _route_source_lines(
        Coverage(verdict="gedeeltelijk", route_source_gaps=(ReadGap(source="config/cspolicy", reason="x"),)),
        set(),
        ("config/cspolicy ",),
    )
    assert [(f.subject, f.outcome, f.certainty.value, f.reason) for f in refused_lines] == [
        (
            "config/cspolicy",
            "niet bruikbaar gelezen",
            "niet vastgesteld",
            "de manifestsleutel van deze bron heeft niet de vorm die deze versie leest en is aan de exportgrens"
            " geweigerd; de bron is niet gelezen; waarheen een contentswitchingbeleid zonder eigen doel"
            " routeert, is met deze export niet vast te stellen",
        )
    ]
    assert refused_gaps == []


class _VserverBindings:
    """Only the virtual-server binding file, as `replacement_findings`
    reads it before it asks anything else."""

    def __init__(self, rows, gap=None):
        self._rows, self._gap = rows, gap

    def bindings(self, file_name):
        return self._rows, self._gap


def test_the_replacement_proposal_boundary_sentences_are_pinned():
    """The evidence of the "niet vastgesteld" line when the export is about
    another target than the action, or no longer about the current binding.
    The reasons are the existing pinned sentences of the target check and of
    the freshness line."""
    from nsmcp.mcp_server import VERVANGEN_DOEL_EVIDENCE, VERVANGEN_VERSHEID_EVIDENCE

    assert VERVANGEN_DOEL_EVIDENCE == "scan-doel.txt van de export tegenover het doel van deze handeling"
    assert VERVANGEN_VERSHEID_EVIDENCE == "de export tegenover de handelingen van deze server sinds de laatste scan"


def test_the_replacement_proposal_sentences_are_pinned():
    from nsmcp.action import (
        REPLACED_CERTIFICATE_SUBJECT,
        USE_NOT_ESTABLISHED_OUTCOME,
        USED_ELSEWHERE_OUTCOME,
        replacement_findings,
    )
    from nsmcp.export import load_export

    assert USED_ELSEWHERE_OUTCOME == (
        "dit certificaat is ook elders in gebruik: {uses}; die gebruiken raakt deze vervanging niet, neem ze zelf mee"
    )
    assert USE_NOT_ESTABLISHED_OUTCOME == "gebruik buiten de binding niet vastgesteld"
    assert REPLACED_CERTIFICATE_SUBJECT == "te vervangen certificaat"

    export = load_export(Path(__file__).parent / "fixtures" / "certgebruik-saml")
    [finding] = replacement_findings(export, _knowledge(), "LBV-WEB-01")
    assert (finding.subject, finding.outcome, finding.certainty, finding.evidence) == (
        "CERT-VS",
        "dit certificaat is ook elders in gebruik: SAML-actie SAML-ACTIE-01 (signing-certificaat); die"
        " gebruiken raakt deze vervanging niet, neem ze zelf mee",
        Certainty.ESTABLISHED,
        "de export, gelezen zoals certificaat_wat_breekt_er: CERT-VS hangt aan LBV-WEB-01",
    )

    def reason(export):
        [only] = replacement_findings(export, _knowledge(), "VS_A")
        assert (only.subject, only.outcome, only.certainty) == (
            "te vervangen certificaat",
            "gebruik buiten de binding niet vastgesteld",
            Certainty.NOT_ESTABLISHED,
        )
        return only.reason

    assert reason(_VserverBindings([])) == (
        "de export noemt geen certificaat aan VS_A; welk certificaat deze vervanging losmaakt, en waar dat"
        " verder in gebruik is, is niet vast te stellen"
    )
    assert reason(_VserverBindings([{"vservername": "VS_A", "certkeyname": 5}])) == (
        "een binding aan VS_A draagt geen bruikbare certkeyname; welk certificaat deze vervanging losmaakt,"
        " is niet vast te stellen"
    )
    assert reason(
        _VserverBindings([], ReadGap(source="x", reason="geen hash in het manifest; geen hash is geen vertrouwen"))
    ) == (
        "welk certificaat nu aan VS_A hangt, is niet te lezen: geen hash in het manifest; geen hash is geen vertrouwen"
    )


def test_the_certificate_use_step_of_the_advice_is_pinned():
    from nsmcp.action import ELSEWHERE_READBACK, elsewhere_warning

    assert elsewhere_warning(("SAML-actie SAML_X (IdP-certificaat)", "SSL-servicegroup SG_Z (CA: nee)")) == (
        "Let op: dit certificaat is ook buiten de virtuele servers in gebruik: SAML-actie SAML_X"
        " (IdP-certificaat), SSL-servicegroup SG_Z (CA: nee). certificaat_vervangen wisselt alleen de"
        " binding op een virtuele server om; zet deze verwijzingen zelf om, want dit product heeft daarvoor"
        " geen schrijfactie."
    )
    assert ELSEWHERE_READBACK == (
        " Lees daarnaast bij de objecten buiten de virtuele servers terug dat ze naar het nieuwe certificaat verwijzen."
    )


def test_action_module_reads_the_other_uses_field():
    """The string-based lookup of `other_uses` in action.py, on a hand-built
    answer: a rename that forgets the string fails here, loudly."""
    antwoord = what_to_do(
        ImpactAnswer(
            question="wat breekt er met cert_a",
            findings=[],
            affected_vservers=(),
            issued_certificates=(),
            other_uses=(_use("SAML-actie", "SAML_GEHEIM", "signing-certificaat"),),
        ),
        _knowledge(),
        "cert_a",
    )
    stappen = antwoord.findings[0].outcome.splitlines()
    assert stappen[2].startswith(
        "3. Let op: dit certificaat is ook buiten de virtuele servers in gebruik: SAML-actie SAML_GEHEIM"
        " (signing-certificaat)."
    )
    assert antwoord.findings[0].evidence == (
        "afgeleid uit 0 vastgesteld geraakte virtuele server(s) en 0 vastgesteld uitgegeven certificaten,"
        " plus 1 vastgesteld gebruik(en) buiten de virtuele servers"
    )


def test_disclosure_name_collection_reads_the_other_uses_field(tmp_path):
    """The owner name occurs ONLY inside `other_uses` and in the evidence
    line, so a stale lookup of the field cannot hide behind the subject."""
    antwoord = ImpactAnswer(
        question="wat breekt er met cert_a",
        findings=[
            Finding(
                subject="cert_a",
                outcome="valt uit",
                certainty=Certainty.ESTABLISHED,
                evidence="verwijzing vanuit SAML_GEHEIM",
            )
        ],
        other_uses=(_use("SAML-actie", "SAML_GEHEIM", "IdP-certificaat"),),
    )
    tekst = render(
        antwoord,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=(),
        pseudonym_table_path=tmp_path / "openheid-vertaaltabel.json",
    )
    assert "SAML_GEHEIM" not in tekst
    assert "object-" in tekst
