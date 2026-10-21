"""B6 - de grens rond firmware en herstarten, als test in plaats van als zin.

Deze test leest het TOOLREGISTER van een echt gebouwde server en de
argumentopbouw van elke schrijftool. Hij hangt niet aan een lijst die
iemand moet bijwerken: komt er een schrijftool bij die `installns` aanroept
of herstart, dan valt hij om.

Twee takken, een test. Ontwerp 2.8 zegt: het product zet firmware over en
herstart uitsluitend binnen een runnerfase op de node die aantoonbaar
secondary is (B8). Op de `built_server`-fixture van deze tests staat
`onderhoud_upgrade_fase` - de enige tool die volgens `handelen.WRITE_TOOLS`
de runner zou zijn - niet geregistreerd: `onderhoud` is er wel
geconfigureerd, maar de fixture geeft geen allowlist-toestemming voor die
tool op enig doel (`build_server()`'s eigen registratiepoort, design 3.1),
dus meldt de runner zich daar niet aan. Is de runner niet geregistreerd,
dan wordt de zin strenger: er bestaat dan GEEN ENKELE geregistreerde tool
die firmware overzet of herstart. `built_server.tool_names()` bewijst dat
elke keer opnieuw, in plaats van dat deze test het aanneemt.

Een eerdere versie van `test_only_the_runner_may_be_registered_as_a_firmware_tool`
opende met `{n for n in geregistreerd if n == RUNNER_TOOL} <= {RUNNER_TOOL}`
- een tautologie, waar voor ELK denkbaar register, dus getest niets. Die
regel is hier VERVANGEN (niet aangevuld) door een echte grens-over-de-
beschrijvingen: geen enkele geregistreerde tool behalve de runner mag een
beschrijving dragen die firmware- of herstartwoorden noemt. Het rapport
bevat het mutatiebewijs dat dit een tweede, elders geregistreerde
firmwaretool ook echt omver haalt.

Tweede afwijking van de plancode, gevonden door de RODE run: een kale
substring-toets op "upgrade" faalt op `onderhoud_backup_maken`,
wiens backupnaam altijd het gereviewde voorvoegsel `gjk_preupgrade_` draagt
(`backup.py`) - een naamgevingsafspraak, geen firmwarehandeling.

De twee
firmwaretoetsen hieronder vergelijken NIET meer op dezelfde manier - dat is
opzettelijk, geen inconsistentie:
- de BUILT ARGUMENTS-toets (`test_no_write_tool_except_the_runner_builds_a_
  firmware_or_reboot_argument`) vergelijkt op EIGEN TOKEN (woordgrens,
  `_bevat_los_woord`), omdat `gjk_preupgrade_` dat afdwingt - die valse
  treffer is gemeten en echt (zie hierboven).
- de DESCRIPTION-toets (`test_only_the_runner_may_be_registered_as_a_
  firmware_tool`) vergelijkt op een KALE SUBSTRING, omdat Nederlandse
  samenstellingen AANEENGESCHREVEN zijn: "firmwarebestand", "herstarten" en
  "upgradepad" bevatten alle drie hun signaalwoord, maar `_bevat_los_woord`
  mist ze alle drie (geen woordgrens tussen het signaalwoord en de rest van
  de samenstelling) - gemeten met de repo-venv (zie de RED/GREEN-run
  hieronder). De naamgebonden vrijstelling
  (`DESCRIPTION_WORD_EXEMPT`) verwijdert de twee bekende valse treffers aan
  deze kant (`status_update_preflight`, en later ook
  `onderhoud_upgrade_plan`), dus een kale substring-toets hoeft hier geen
  andere valse treffer te verdragen.
Een eerdere versie liet de description-toets per ongeluk ook op
woordgrens vergelijken (een "opschoning" die de gate verzwakte in plaats
van hem te laten staan); dat is hier teruggedraaid.

Een eerdere versie liet "upgrade" HELEMAAL weg
uit `FIRMWARE_DESCRIPTION_WORDS` om `status_update_preflight` niet te laten
struikelen - een repo-brede woordverwijdering voor een tool die het woord
alleen adviserend gebruikt, precies de verruiming waar deze poort voor
waarschuwt: elke TOEKOMSTIGE tool die "upgrade" in zijn beschrijving zet zou
daarmee ook onopgemerkt blijven. "upgrade" staat nu terug in de woordenlijst
en `status_update_preflight` is met NAAM vrijgesteld (`DESCRIPTION_WORD_EXEMPT`,
een eenregelige allowmap) - elke andere tool, ook een nieuwe, wordt nog
gewoon op "upgrade" getoetst. Het mutatiebewijs hieronder
registreert een tweede tool die ALLEEN "upgrade" draagt en laat de
gesterkte test daar wel op omvallen.

Dezelfde test toetste niet WAT hij scande. Als
`built_server` ooit zijn `code_presenter` verliest (of `openheid: minimaal`
draagt), registreert `build_server()` geen enkele schrijftool meer
(`mcp_server.py`) en scant deze test dan stilzwijgend 10 lees-gereedschappen
in plaats van 15 - en slaagt nog steeds, want hij toetste nooit of de
schrijftools er echt stonden. Een dekkingsassertie repareert dat: valt de
registratie van een schrijftool ooit weg, dan valt deze test daar nu
zelf over, in plaats van zwijgend minder te dekken dan hij claimt.
"""

import re

import pytest
from conftest import BuiltServer

from nsmcp.handelen import WRITE_TOOLS, Allowlist, build_arguments

# The words that mean "firmware moves" or "the box restarts", in the
# vocabulary of the write script's own arguments. Lowercase; the comparison
# lowercases too. Matched as a WORD, not a bare substring - see
# `_bevat_los_woord` below for why: the first RED run of this test failed
# against `onderhoud_backup_maken`, whose backup name always
# carries the reviewed `gjk_preupgrade_` prefix (`backup.py`, "this backup
# happened before an upgrade" - a naming convention, not a firmware
# action). A bare substring check flags "upgrade" inside "preupgrade" and
# would keep failing on that legitimate, unrelated tool forever; a word
# boundary does not, because "pre" and "upgrade" touch with no boundary
# between them.
FIRMWARE_WORDS = ("installns", "reboot", "herstart", "firmware", "upgrade", "nsinstall")


def _bevat_los_woord(tekst: str, woord: str) -> bool:
    """Is `woord` aanwezig als eigen token in `tekst`, niet als stuk van een
    langer woord (zie de RED-vondst hierboven: "preupgrade" mag niet als
    "upgrade" tellen)."""
    return re.search(rf"\b{re.escape(woord)}\b", tekst) is not None


# The same signal, but scoped to a TOOL DESCRIPTION rather than to a built
# argument list. "upgrade" USED to be dropped from this list
# entirely because status_update_preflight's own description says it checks
# "of een upgrade... kunnen tegenhouden" - an advisory sentence about
# upgrades in general, not a claim that the tool itself moves firmware. A
# repo-wide word deletion for one known tool is exactly the loosening this
# gate exists to prevent: ANY future tool could then carry "upgrade" in its
# own description and this check would stay silent. "upgrade" is back in
# the set; the one tool allowed to carry it is named explicitly below.
FIRMWARE_DESCRIPTION_WORDS = ("installns", "nsinstall", "reboot", "herstart", "firmware", "upgrade")

# The ONE tool, BY NAME, allowed to carry "upgrade" in its own description
# without being treated as a firmware mover - a one-entry allow map, not a
# convenience. `status_update_preflight` is a legitimate, registered READING
# tool: its description names "upgrade" only to say which of its nine checks
# can stop one; it never moves firmware or restarts anything (proven
# separately: `test_no_write_tool_except_the_runner_builds_a_firmware_or_
# reboot_argument` above only ever looks at WRITE_TOOLS, and this tool is
# not one). Verified against the real, live registry:
# of the sixteen registered tools, two
# descriptions contain any of the six words in FIRMWARE_DESCRIPTION_WORDS -
# this one and `onderhoud_upgrade_plan` below - and both are exactly
# "upgrade".
# A SECOND exemption here is a design decision, not a convenience - it needs
# its own name in this map and its own comment saying why, same as this one.
DESCRIPTION_WORD_EXEMPT: dict[str, tuple[str, ...]] = {
    "status_update_preflight": ("upgrade",),
    # Same reasoning as `status_update_preflight` above: this is
    # a registered READING tool (never in `handelen.WRITE_TOOLS`) whose whole
    # job is to DESCRIBE an upgrade window - the seven phases, the HA order,
    # the soak, the rollback path per phase - and it says so in its own
    # description. `test_the_upgrade_plan_makes_no_write_call`
    # (tests/test_upgrade_plan.py) proves it never calls `handelen.perform`
    # or `handelen.default_runner`; it never moves firmware or restarts
    # anything. A second, named entry, exactly as the comment above demands.
    "onderhoud_upgrade_plan": ("upgrade",),
    # Integration on the release (14-9-2026), same reasoning again:
    # `onderhoud_upgrade_stand` is a registered READING tool (never in
    # `handelen.WRITE_TOOLS`) whose whole job is to READ the ledger of an
    # upgrade run - per phase the gates and their outcome - and it says so
    # in its own description. tests/test_no_network.py proves it opens no
    # socket. A third, named entry, exactly as the comment above demands.
    "onderhoud_upgrade_stand": ("upgrade",),
    # And `rapport_na_upgrade`: a READING tool of the `rapport`
    # chapter that puts the state before and after an upgrade side by side
    # from the export and the ledger - it cannot describe itself without
    # the word. Never in `handelen.WRITE_TOOLS`; tests/test_no_network.py
    # proves it opens no socket. Fourth named entry, same demand.
    "rapport_na_upgrade": ("upgrade",),
}

RUNNER_TOOL = "onderhoud_upgrade_fase"


def _all_write_tools_except_the_runner():
    return [naam for naam in WRITE_TOOLS if naam != RUNNER_TOOL]


def test_no_write_tool_except_the_runner_builds_a_firmware_or_reboot_argument(tmp_path):
    lijst = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": ("cert-a",)},
                "certificaat_vervangen": {"dienst": ("lb_vs_a",), "nieuwcert": ("cert-a",)},
                "dienst_lid_uitschakelen": {"dienst": ("sg_a",), "lid": ("web01",)},
                "dienst_lid_inschakelen": {"dienst": ("sg_a",), "lid": ("web01",)},
                "onderhoud_backup_maken": True,
            }
        }
    )
    argumenten = {
        "certificaat_klaarzetten": {"certnaam": "cert-a"},
        "certificaat_vervangen": {"dienst": "lb_vs_a", "nieuwcert": "cert-a"},
        "dienst_lid_uitschakelen": {"dienst": "sg_a", "lid": "web01"},
        "dienst_lid_inschakelen": {"dienst": "sg_a", "lid": "web01"},
        "onderhoud_backup_maken": {},
    }
    for naam in _all_write_tools_except_the_runner():
        if naam == "config_opslaan":
            # Its own argument builder: the save script's arguments, for a
            # preview and for a real run.
            from nsmcp.handelen import MaintenanceConfig, build_save_arguments
            from nsmcp.target import CertAgreement, Target

            doel = Target(
                name="lab",
                address="192.0.2.10",
                credential_target="GJK/Test/lab",
                agreement=CertAgreement.CHAIN,
                ssh_hostsleutel_vingerafdruk="AA:BB",
            )
            onderhoud = MaintenanceConfig(
                runner=tmp_path / "runner.ps1",
                ledgermap=tmp_path,
                firmwaremap=tmp_path,
                soak_uren=24,
                ssh_gebruiker="nsroot",
            )
            for preview, actie in ((True, ""), (False, "config-opslaan-x")):
                plat = " ".join(build_save_arguments(doel, onderhoud, preview=preview, actie_id=actie)).lower()
                for woord in FIRMWARE_WORDS:
                    assert not _bevat_los_woord(plat, woord), f"{naam} bouwt een argument dat {woord} noemt"
            continue
        args = build_arguments(
            naam,
            argumenten[naam],
            script=tmp_path / "s.ps1",
            fixture_dir=tmp_path,
            preview=False,
            bundle="handeling-x",
            target="lab",
            allowlist=lijst,
        )
        plat = " ".join(args).lower()
        for woord in FIRMWARE_WORDS:
            assert not _bevat_los_woord(plat, woord), f"{naam} bouwt een argument dat {woord} noemt"


def test_only_the_runner_may_be_registered_as_a_firmware_tool(built_server):
    """Gaat B8 niet mee, dan bestaat er GEEN firmwaretool - en dan is deze
    test strenger, zonder dat er iets aan hem verandert.

    Zie de moduledocstring: dit leest
    het ECHTE register van een echt gebouwde server (`built_server`, uit
    tests/conftest.py) en toetst elke beschrijving behalve die van de
    runner tegen `FIRMWARE_DESCRIPTION_WORDS`. Dat vangt een tweede
    firmwaretool ONGEACHT zijn naam - hij hoeft geen `RUNNER_TOOL` te heten
    om deze test om te laten vallen, hij hoeft alleen geregistreerd te zijn
    met een beschrijving die zichzelf verraadt. Het mutatiebewijs hieronder
    registreert precies
    zo'n tweede tool en laat deze test er echt op omvallen.

    Eerst de DEKKING vaststellen, niet aannemen. Deze test
    beweert dat hij alle schrijftools scant behalve de runner; zonder deze
    assertie zou een `built_server` die zijn `code_presenter` verliest (of
    `openheid: minimaal` draagt) stilzwijgend minder scannen - de lus hierna
    zou dan gewoon over een kortere lijst lopen en niets zou dat melden.

    Deze beschrijvingstoets vergelijkt met een KALE
    SUBSTRING (`woord not in beschrijving`), NIET met `_bevat_los_woord`
    (woordgrens). Zie de moduledocstring voor de volledige redenering; kort:
    Nederlandse samenstellingen zijn aaneengeschreven ("firmwarebestand",
    "herstarten", "upgradepad"), dus een woordgrenstoets mist ze alle drie -
    gemeten, zie `test_description_gate_catches_closed_dutch_compounds`
    hieronder."""
    geregistreerd = built_server.tool_names()
    assert set(WRITE_TOOLS) - {RUNNER_TOOL} <= geregistreerd, (
        "de fixture registreerde niet alle schrijvende gereedschappen die dit "
        "product op deze branch kan aanmelden - deze poort zou dan stilzwijgend "
        "minder beschrijvingen scannen dan hij claimt"
    )
    for naam in geregistreerd - {RUNNER_TOOL}:
        beschrijving = built_server.description_of(naam).lower()
        vrijgesteld = DESCRIPTION_WORD_EXEMPT.get(naam, ())
        for woord in FIRMWARE_DESCRIPTION_WORDS:
            if woord in vrijgesteld:
                continue
            assert woord not in beschrijving, (
                f"{naam} is geregistreerd en zijn beschrijving noemt {woord!r} - "
                f"alleen {RUNNER_TOOL} mag firmware overzetten of de NetScaler herstarten"
            )


def test_description_gate_catches_closed_dutch_compounds(built_server):
    """Corrigeert een eerdere fix die de gate
    verzwakte: pin dat de ECHTE gate (`test_only_the_runner_may_be_
    registered_as_a_firmware_tool`, hierboven) een beschrijving met een
    aaneengeschreven Nederlandse samenstelling weigert.

    Gemeten met de repo-venv (zie de volledige RED/GREEN-run hieronder):
    `_bevat_los_woord` (woordgrens) geeft False
    voor "firmware" in "firmwarebestand" en voor "herstart" in "herstarten"
    - beide zijn Nederlandse samenstellingen, aaneengeschreven, dus zonder
    woordgrens tussen het signaalwoord en de rest. Een kale substring-toets
    vangt ze wel; dat is de vorm die de gate hierboven nu gebruikt.

    Deze test roept de PRODUCTIEFUNCTIE zelf aan (geen herbouwde,
    parallelle logica die zelf ook een fout kan bevatten) tegen een echte,
    rechtstreeks op de gebouwde server aangemelde tool (buiten
    `WRITE_TOOLS`/`_act` om) met precies zo'n beschrijving. Komt de gate ooit terug
    naar een woordgrenstoets (de fout die deze fix herstelt), dan
    geeft de productiefunctie geen `AssertionError` meer op deze tool en
    valt dit `pytest.raises`-blok zelf om - deze test is dus zelf de
    regressie-wacht op die eis."""
    server = built_server.server

    @server.tool()
    def rogue_debug_firmwarebestand() -> str:
        """Plaatst het firmwarebestand en herstarten gebeurt daarna."""
        return "n.v.t."

    verse_server = BuiltServer(server)
    with pytest.raises(AssertionError, match="firmwarebestand"):
        test_only_the_runner_may_be_registered_as_a_firmware_tool(verse_server)


def test_the_security_document_states_the_boundary(built_server):
    """Zelfde tak-detectie als de vorige test, en om dezelfde reden: welke
    eerste alinea het document moet dragen, hangt af van of `RUNNER_TOOL`
    ECHT geregistreerd is op de `built_server`-fixture - niet van een
    handmatig bijgehouden vlag. Op die fixture (geen allowlist-toestemming
    voor de runner) is dat de "zet geen firmware over"-tak; geeft een
    fixture straks wel toestemming, dan verwacht deze test
    vanzelf de andere alinea, zonder dat iemand dit bestand hoeft te
    veranderen."""
    from pathlib import Path

    # Relatief aan de CWD was de enige plek in de
    # suite die dat deed - relatief aan dit testbestand werkt ongeacht
    # vanuit welke map pytest gestart wordt.
    repo_root = Path(__file__).resolve().parent.parent
    tekst = (repo_root / "docs" / "klant" / "SECURITY.md").read_text(encoding="utf-8")
    if RUNNER_TOOL in built_server.tool_names():
        assert "uitsluitend binnen een runnerfase" in tekst
    else:
        assert "dit product zet geen firmware over en herstart niets" in tekst.lower()
    assert "een terugrol van de firmware herstelt de build, niet de configuratie" in tekst.lower()


def test_the_off_box_backup_boundary_is_stated_in_the_customer_docs():
    """Design 2.8 pins a second row right next to the one above: 'off-box
    backup' - a backup made ON the appliance is not an off-box backup, and
    downloading it is a step this product does not do (B4). Measured
    before this fix: neither docs/klant/SECURITY.md nor
    docs/klant/HANDLEIDING.md said so anywhere - both only describe what
    `onderhoud_backup_maken` DOES (make the backup, read it back into the
    backup collection on the appliance), never what it does not do (carry
    a copy off the box). This test pins the exact Dutch sentence in both
    customer-facing documents, the same way the test above pins the
    firmware-rollback sentence, so an edit that removes it fails the
    suite instead of only misleading a reader. Both documents hand-wrap
    prose at roughly ninety characters, and this sentence is longer than
    that, so the check compares against whitespace-normalised text rather
    than requiring the sentence to sit on a single physical line.

    An earlier review found that design 2.8's own header reads
    "Toetsbare regels voor README en docs/klant/SECURITY.md" - README is
    named, not optional, and the original version of this test skipped it.
    There is nothing technical stopping a test from reading README.md;
    tests/test_no_network.py already reasons about README's claims
    (see lines ~13, ~27 and ~601 there). So this test now also pins
    README.md, with the English rendering it actually carries."""
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    zin = (
        "een backup op de appliance is geen off-box backup; het downloaden "
        "ervan is een aparte stap die dit product niet doet"
    )
    for pad in ("SECURITY.md", "HANDLEIDING.md"):
        tekst = (repo_root / "docs" / "klant" / pad).read_text(encoding="utf-8")
        genormaliseerd = " ".join(tekst.split()).lower()
        assert zin in genormaliseerd, f"{pad} mist de off-box-backupzin"

    sentence = (
        "a backup made on the appliance is not an off-box backup; "
        "downloading it is a separate step this product does not do"
    )
    readme_tekst = (repo_root / "README.md").read_text(encoding="utf-8")
    readme_genormaliseerd = " ".join(readme_tekst.split()).lower()
    assert sentence in readme_genormaliseerd, "README.md mist de off-box-backupzin"
