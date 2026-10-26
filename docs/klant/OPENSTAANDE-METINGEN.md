# Openstaande metingen

## Openstaande meting: A15a (DNS over HTTPS) en A15b (FIPS) - de acceptatiepoort van cve.py

Twee takken van `cve.py` rusten vandaag op synthetische fixtures en
vendordocumentatie, niet op een meting aan een echte appliance -
`tests/test_cve.py` bewaakt dat zichtbaar met een luide skip (`pytest -rs`
toont de reden), nooit met een stille groene suite.

**A15a - DNS over HTTPS (1.0-must, GESLOTEN).** `dnsOverHttps` is
CONFIGURATIE en dus op een werkbank te maken - en dat is gebeurd: op
6-9-2026 is op een werkbank een export met `-dnsOverHttps ENABLED`
verzameld en is de DoH-vorm van `cve.py` daarop gemeten. Die export
staat niet in deze repository en komt er ook niet in: een echte export draagt
configuratie die niet aan ons is om te publiceren, en het schoningsgereedschap
dekt vrije tekst (commentaarvelden, monitorteksten, herschrijfpaden) niet.

De vorm is vastgelegd in een SYNTHETISCHE fixture,
`tests/fixtures/lab-export-vpx-doh-synthetic/`, geschreven door
`scripts/make_doh_fixture.py`: elke naam, elk adres en elke waarde daarin is
verzonnen, in de bestandsvorm die de verzamelaar schrijft (manifest met
hashes, objects/, bindings/, parsed/). De poorttest
`tests/test_cve.py::test_the_doh_shape_against_the_synthetic_doh_export`
slaagt tegen die fixture.

Wat de fixture draagt en de suite via de bestaande, gecureerde bulletinset
en zonder een tweede detector vastpint: de vier vormen die de voorwaarde
`heeft_lb_oracle_of_dns` kent - een SSL-lbvserver en een SSL-csvserver met
`-dnsOverHttps ENABLED` op de add-regel, de `set lb vserver`- en
`set cs vserver`-vorm die het achteraf aanzet, en een DNS-profiel met
`-recursiveResolution ENABLED` - plus twee klassieke DNS-proxy's
(servicetype DNS en DNS_TCP) en een negatieve controle (SSL met
`dnsoverhttps=DISABLED`) die in geen enkele bewijsregel voorkomt.
CVE-2026-8655 komt daardoor GERAAKT uit. De meting van 6-9-2026 bracht ook
een los defect aan het licht dat geen synthetische test raakte:
HTTP-ECV-monitorregels met een `q/.../`-vorm waren onleesbaar voor de
tokeniser; dat is gerepareerd, en de synthetische fixture draagt die vorm
zodat de suite het blijft bewaken.

**A15b - FIPS (blijvende grens van 1.0, geen tijdelijke).** Een
FIPS-versietekst is HARDWARE, en die doos staat in geen van beide labs.
De FIPS-tak blijft daarom in 1.0 uitsluitend op synthetische fixtures
beproefd (`tests/test_cve.py::test_the_fips_branch_against_a_real_fips_export`,
skipt zolang `tests/fixtures/fips-export/` leeg is). Dit is geen "nog niet
gemeten" dat binnenkort volgt: er is geen FIPS-appliance gepland in enig
lab, en dit document formuleert het daarom als een blijvende grens van
1.0, niet als een tijdelijke slag om de arm.

Bewijs bij de release-notes: per mutatieproef welke poort is uitgezet, welke test daardoor omviel,
en dat de wijziging is teruggedraaid. Een mutatieproef die alleen op een Windows-werkbank draait,
bewijst niets op de bouwmachine waar de vrijgave op leunt - vandaar dat elke poort in
`src/nsmcp/upgrade.py` staat en niet in de PowerShell-kant van de runner.

## Mutatieproeven van de runner

| # | poort | uitgezet in | test die omviel | status |
|---|---|---|---|---|
| 10 | schijfruimte R1 (`disk_gate`) | `if int(free_mb) < drempel:` vervangen door `if False:` | `test_free_space_below_the_vendor_floor_closes_the_gate` | uitgevoerd, teruggedraaid |
| 11 | soakvenster (`soak_gate`) | `if now < einde:` (binnen `soak_gate`, niet `soak_state`) vervangen door `if False:` | `test_the_soak_window_cannot_be_shortened_by_a_tool` | uitgevoerd, teruggedraaid |
| 12 | vendor-precheck (`precheck_gate`) | `if global_status_ruw.lower() == "failed" or gezakt:` vervangen door `if False:` (poort altijd `open`, alsof de exitcode telt) | `test_the_vendor_precheck_gate_ignores_the_exit_code` | uitgevoerd, teruggedraaid |
| 13 | primary-node (`secondary_gate`) | Een latere fix: `secondary_gate` beoordeelt sindsdien alleen het blok van de LOKALE node (`Node ID: 0`) uit `show ha node`, niet de hele tekst - de eerdere vorm zocht `"secondary"` over de VOLLEDIGE uitvoer en opende de poort op de PEER's regel terwijl deze fase op de PRIMARY draaide. Herhaalde mutatie op de huidige regel `if staat == "secondary":` vervangen door `if True:` (poort altijd `open`) | `test_a_phase_on_the_primary_node_of_a_real_ha_pair_is_refused_despite_the_peers_secondary_line` (een ECHTE two-node `show ha node`-fixture; de eerdere single-node fixture van deze proef kon de fout niet vangen en blijft daarnaast bestaan als `test_a_phase_on_the_primary_node_is_refused`) | uitgevoerd, teruggedraaid |
| 9 | hostsleutelcontrole | `start._require_upgrade_hostkeys()`: `if doel is None or not doel.ssh_hostsleutel_vingerafdruk:` vervangen door `if False:` (de startcontrole op `ssh_hostsleutel_vingerafdruk` altijd overslaan) | `test_the_runner_refuses_an_unknown_host_key` | uitgevoerd, teruggedraaid |
| 8 | identiteitsvereiste | `mcp_server._act()`: `if bevestiger is None:` vervangen door `if False:` (de weigering bij een niet-identificerend codekanaal altijd overslaan) | `test_the_runner_refuses_a_channel_that_cannot_identify_the_confirmer` | uitgevoerd, teruggedraaid |
| 14 | startdiagnose: werkmap (1.1) | `mcp_server`: de takken `RunnerWorkdirUnusable` en `RunnerLogUnopenable` van de losgekoppelde start afgebeeld op `RUNNER_NIET_GESTART_PROCES` (alles op PROCES) | `test_unusable_workdir_is_named_as_such` | uitgevoerd 26-10-2026, teruggedraaid |
| 15 | startdiagnose: scriptpin (1.1) | `mcp_server`: de tak `except ScriptPinMismatch` rond `upgrade_command` weggehaald (de fout valt dan in de tak `PowerShellMissing`) | `test_script_pin_mismatch_is_not_reported_as_missing_powershell` | uitgevoerd 26-10-2026, teruggedraaid |
| 16 | startdiagnose: doel bezet na `Popen` (1.1) | `handelen.start_detached`: een fout van de Job Object-meting na een geslaagde `Popen` afgebeeld als `RunnerProcessNotStarted` | `test_failure_after_popen_keeps_the_target_reserved` | uitgevoerd 26-10-2026, teruggedraaid |
| 17 | startdiagnose: controle vooraf (1.1) | `mcp_server`: in de `-WatIs`-tak van `onderhoud_upgrade_fase` de afbeelding op type weggehaald (`detail` alleen nog de klassenaam) | `test_a_preview_that_cannot_start_on_the_proposal_names_why`, `test_a_preview_that_cannot_start_on_the_confirmed_call_names_why` | uitgevoerd 26-10-2026, teruggedraaid |

Voor elk van de vier uitgevoerde proeven (10-13): de bewuste regel is met een enkel woord uitgezet
(`if False:` of `if True:`), de genoemde test viel om op precies de reden die de poort bewijst, en
de wijziging is meteen teruggedraaid - de werkkopie was daarna weer schoon en de volledige
testsuite stond weer op groen voor er iets werd vastgelegd.

**Telkens opnieuw uitgevoerd wanneer de poorten veranderden.** De vier proeven zijn na elke
wijziging aan de poorten herhaald tegen de gewijzigde code: `disk_gate` (aangenomen bundelgrootte
in plaats van een stille nul), `precheck_gate` (begrensd bewijs), `soak_gate` (parseerbare
UTC-tijden, en het venster dat op de nieuwste begintijd bindt in plaats van op de volgorde van de
ledgerbestanden). De uitgezette expressie van de vendor-precheck heet daardoor anders dan
de eerste keer; de vier testnamen in de tabel hierboven zijn onveranderd en blijven de proef. Alle vier vielen elke
keer om op precies de reden die de poort bewijst, en elke wijziging is meteen teruggedraaid - de
volledige testsuite stond daarna weer groen voor er iets werd vastgelegd.

De twee proeven bij het gereedschap `onderhoud_upgrade_fase` (8 en 9 in de tabel hierboven): elke uitgezette regel bracht
precies de genoemde test om, en beide wijzigingen zijn meteen teruggedraaid - de werkkopie was
daarna weer schoon en de volledige testsuite stond weer op groen voor er iets werd vastgelegd.

De drie proeven van de startdiagnose (14-16, versie 1.1): elke mutatie is in de werkkopie
aangebracht, de genoemde test is alleen gedraaid en viel om op zijn eigen bewering (14: de zin over
de werkmap ontbrak; 15: de zin over de scriptpin ontbrak; 16: het antwoord noemde "het proces kon
niet worden gestart" terwijl er een kindproces bestond), en het bestand is daarna byte voor byte
teruggezet - `git status` was weer schoon.

## Gemeten: de faserunner is eind-tot-eind tegen een appliance gedraaid (8-9-2026)

De volledige route R0 tot en met R6 is op 8-9-2026 achter elkaar gedraaid tegen een standalone
VPX-labappliance, van 14.1 build 66.59 naar 72.57, langs het echte productpad
(`onderhoud_backup_maken`, `status_ververs`, `onderhoud_upgrade_fase` per fase,
`onderhoud_upgrade_stand`). Het ledger van die run staat gepseudonimiseerd in de repo
(`tests/fixtures/runner-ledger-lab-02-20260908/`) en wordt door `tests/test_runner_ledger_evidence.py`
bewaakt. Gemeten, per fase: de upload van de bundel (1,1 GB) ruim 8 minuten, waarna de sha256 OP de
doos gelijk was aan de vendorwaarde; `installns --pre_check` beslist op `global_status` (hier
`warning`, nul gezakte checks) en niet op de exitcode; `installns -Y -n` meldt `END_TIME` (op stderr);
de reboot gaf SSH-authenticatie terug na 110 seconden met de hostsleutel opnieuw gepind; R5 las de
doelbuild exact terug en berekende het anker; R6 opende het soakvenster en een volgende fase werd
geweigerd met de vroegste eindtijd erin. De aannames die hieronder eerder als onbewezen stonden
(`sha256 -q` op de doos, de `df`-parse, het pre-check-pad, `END_TIME`, de reboot-terugkeer) zijn
daarmee gemeten - en een deel bleek anders dan aangenomen: de appliance zet een waarschuwingsblok voor
elke shell-uitvoer, `installns` schrijft zijn tijdmarkers naar stderr, het precheck-bestand draagt dat
blok plus een afsluitregel rond de JSON, een standalone appliance meldt zich als Primary, en
buildbomen liggen genest onder `/var/nsinstall/<tak>/`. Al die vondsten zitten in de code.

**Wat deze run NIET bewijst, en dat hoort erbij:**

- **een HA-paar**: de labappliance is standalone; de secondary-eerst-volgorde en de failover-poort
  (`doel is secondary` met een peer) zijn alleen op fixtures bewezen. Op standalone geldt de
  expliciete menselijke acceptatie `standalone_geaccepteerd` (downtime);
- **`extraStapNaUpgrade`**: `http2smallwndtimeout` bestaat niet onder 72.61, dus die controle blijft op
  fixtures bewezen;
- **SDX, chassis-instances en FIPS**;
- **het menselijke bevestigingspad**: deze run bevestigde elke fase met een bestandsrelay in plaats van
  een mens aan de sso-presenter (de bevestiger heet in het ledger dan ook `labproef-driver
  (bestandsrelay, geen mens)`); de acceptatietest van de eigenaar met de Windows-presenter is het
  bewijs van dat pad.

**Wat een hertest vraagt, gemeten:** een fase die `poort dicht` of `mislukt` sluit, kan niet in
dezelfde run opnieuw; een hertest is een nieuwe run, en de doelbuildboom van de vorige poging moet
eerst van `/var/nsinstall` (anders sluit R1 terecht op de schijfruimtepoort).

## Openstaande meting: `rapport_na_upgrade` blok 1

`rapport_na_upgrade` draagt vandaag drie van de vier ontworpen blokken: het CVE-oordeel op de
nieuwe build (blok 2), de extra stap na de upgrade als eigen controle (blok 3), en blok 4 (het
genormaliseerde configuratie-anker) - alle drie uitsluitend uit bronnen die al op deze branch
bestaan (`cve.cve_check`, het kennispakket, het ledger). De acht familietellingen die ook bij
blok 4 horen, blijven vandaag `niet vastgesteld` - zie de eigen sectie daarover hieronder.

**Blok 1 - de dekkingsuitspraak van beide exports (voor en na) naast elkaar - is bewust niet
gebouwd.** `compare.py` en `retention.py` bestaan inmiddels wel: `compare.compare_answer()` kent
een modus `pre/post` die twee exports van hetzelfde doel rond een wijziging vergelijkt, en
`retention.newest_kept(export_dir)` levert de vorige bewaarde export van diezelfde exportmap.
Beide zijn daarmee in principe geschikt voor blok 1 - maar `after_upgrade.py` roept geen van
beide aan: `report_after_upgrade()` neemt `before` wel aan, gooit het meteen weg (`del before`)
en levert in plaats daarvan de vaste `NotAssessed`-melding hieronder. Het aansluiten van blok 1
is dus geen nieuwe motor bouwen, maar de bestaande `compare_answer()`/`newest_kept()` vanuit
`after_upgrade.py` aanroepen.

Er komt geen tweede vergelijkingsmotor en geen tweede manier om de vorige export te vinden - dat
was precies het probleem dat een gescheiden `compare.py`/`retention.py` voorkomt. Zolang blok 1
ontbreekt, noemt het antwoord dat expliciet als `NIET BEOORDEELD IN DEZE VERSIE` (`nsmcp.
after_upgrade.BLOCK_ONE_SUBJECT`/`BLOCK_ONE_REASON`) - nooit een stille leegte die leest als
"niets aan de hand", en nooit een `GERAAKT`/`NIET GERAAKT` op dekking die dit product niet las.

## Openstaande meting: de acht familietellingen van R5

Blok 4 van `rapport_na_upgrade` zet acht familietellingen van vóór en na de upgrade naast elkaar:
`lbvserver`, `csvserver`, `vpnvserver`, `authenticationvserver`, `service`, `servicegroup`,
`sslcertkey` en `lbmonitor`. **Die vergelijking blijft vandaag `niet vastgesteld`**, en het
antwoord zegt er per regel bij waarom: R5 schrijft geen `familietellingen`-poort in zijn
sluitregel. R0 doet dat wel, uit de export.

**Waarom dat niet even is bij te bouwen.** R0 telt objecten uit de export — de NITRO-telling per
resource. R5 leest niet uit een export maar live over SSH, en het enige dat die fase in handen
heeft is de draaiende configuratie (`show ns runningConfig`). Tellen uit die configuratie is een
ándere telling dan tellen uit de export. Gemeten op de labexport
(`tests/fixtures/lab-export-vpx-20260826`):

| familie | objecten in de export | `add`-regels in de configuratie |
|---|---|---|
| `lbmonitor` | 31 | 0 |
| `sslcertkey` | 4 | 3 |
| de overige zes | gelijk | gelijk |

Ingebouwde monitors en het ingebouwde servercertificaat bestaan wél als NITRO-object, maar staan
niet als `add`-regel in de configuratie. Een R5 die uit de configuratie telt, zou dus permanent
`verschillend` melden op twee van de acht families, zonder dat er iets veranderd is. Erger: een
telling uit de configuratie kan "nul geconfigureerd" niet onderscheiden van "verkeerd geteld", en
zou bij een fout stilletjes op `gelijk: R0=0, R5=0` uitkomen. Dat is precies het soort
schijnzekerheid dat dit product nergens accepteert.

**Wat er nodig is om het wél te leveren.** Een tweede export, verzameld ná de upgrade, en R5 die
zijn familietellingen daaruit haalt zoals R0 dat doet — dezelfde meting aan beide kanten. Dat is
een uitbreiding van de route (een verzamelstap tussen R4 en R5), geen regel code die er nu bij
kan. Tot die tijd staan de acht regels er wél, elk met de reden erbij; ze springen vanzelf aan
zodra R5 de poort schrijft.

## Openstaande meting: de twee ankers komen uit verschillende bronnen

Hetzelfde blok 4 vergelijkt het genormaliseerde configuratie-anker van R0 met dat van R5. Die twee
hashes worden over verschillende teksten berekend:

- **R0** hasht de draaiende configuratie **uit de export** (`parsed/runningconfig.txt`).
- **R5** hasht de draaiende configuratie **live**, over SSH (`show ns runningConfig`).

De verzamelaar redigeert credentialvelden op de jumphost vóór hij de export wegschrijft
(`collect-log.txt`: "geredigeerd op de jumphost"); de live lezing van R5 is niet geredigeerd. Het
anker sluit regels met `set ns encryptionParams`, `set ns rpcNode` of `-encrypted` uit en telt ze
apart — maar niet elke geredigeerde regel draagt een van die drie markeringen. Gemeten op de
labexport: drie regels `add vpn sessionAction ... -ssoCredential <REDACTED>` blijven staan en gaan
dus mee in de hash.

**Gevolg.** Op een appliance met zulke regels is `verschillend` het permanente antwoord, ook als er
niets aan de configuratie veranderd is. Het antwoord noemt daarom bij elk anker zijn eigen bron en
zet er bij een verschil een reden bij die dit uitlegt. Een `verschillend` is een aanleiding om te
kijken, geen vaststelling dat de configuratie gewijzigd is.

**Wat er nodig is om het wél waterdicht te maken.** Beide kanten uit dezelfde soort bron laten
komen — dezelfde tweede export als hierboven, of een redactie die aan beide kanten identiek
gebeurt. Zolang dat er niet is, blijft dit een gerichte aanwijzing en geen bewijs.

## Openstaande meting: een gewijzigd wachtwoord tussen running en saved

`config_drift`, `ha_stand` en pre-flight toets 4 tellen een regel die tussen de draaiende en de
opgeslagen configuratie alleen verschilt in het deel dat een geheim kan dragen, als drift - maar
alleen als de export die waarde draagt. De uitgebrachte verzamelaar vervangt zulke waarden op de
jumphost aan beide kanten door `<REDACTED>` (gemeten: tien regels per kant op de eerste labexport,
dertien op de tweede); een gewijzigd wachtwoord dat niet is opgeslagen, staat dan als twee gelijke
regels in de export. Het product telt die regels als "niet te vergelijken" en zegt `onbevestigd`
zolang de kopregels een wijziging na de laatste opslag melden of onleesbaar zijn.

**Wat niet gemeten is.** Of NetScaler een versleutelde waarde in de draaiende en de opgeslagen
configuratie gelijk schrijft. Op een export die de waarden wél draagt, zou een waarde die bij
opslaan opnieuw versleuteld wordt als drift tellen terwijl er niets gewijzigd is. De labexports
kunnen dat niet laten zien: daar draagt elke zulke regel het merkteken, dus de telling is er per
constructie nul. Evenmin gedraaid: de vormen (system user, LDAP-bindwachtwoord, RPC-wachtwoord,
monitorwachtwoord) tegen een appliance met een echt gewijzigd, niet opgeslagen wachtwoord;
`-ldapBindDnPassword` komt in geen van beide labexports voor. Evenmin gemeten: of een wijziging van
uitsluitend een wachtwoord op de appliance zelf de kopregel `Last modified` van de draaiende
configuratie verzet (en `Last Config Changed Time` in de teruglezing van `config_opslaan`). De
uitkomst `uit` op een export met zulke gemarkeerde regels leunt op die aanname - alleen wanneer de
kopregels een wijziging na de laatste opslag melden, telt het antwoord `onbevestigd` in plaats van
`uit`; verzet een ongeopslagen wachtwoordwijziging die kopregel niet, dan blijft het antwoord `uit`
terwijl de wijziging wel bestaat.

**Wat er nodig is.** Een export die de waarden draagt (of een vingerafdruk per scan in plaats van
het vaste merkteken), van een appliance waarop een wachtwoord gewijzigd en niet opgeslagen is, en
van dezelfde appliance na opslaan. Om de premisse hierboven zelf te meten: een export van vlak vóór
en van vlak ná het wijzigen van uitsluitend een wachtwoord, zonder tussentijds op te slaan, om vast
te stellen of de kopregel van de draaiende configuratie dat wijzigingsmoment verzet.

## Openstaande meting: de vloerpoort van R0 en de runbinding op een appliance

R0 draagt de poort `doelbuild op of boven de vloer, of bewust geaccepteerd`, en R1 tot en met R6
weigeren een bundel die afwijkt van die waarmee R0 van dezelfde run startte. **Beide zijn vandaag
alleen offline bewezen**: met eenheidstests op de poort en de weigering, en met de faserunner
tegen een nep-transport (de runner geeft de huidige build en de vloer door, de poort staat in
`terugrolpunt_vast` en in de sluitregel, een afwijkende vorm weigert bij de binding). Geen van
beide is op een appliance gedraaid; R0 raakt de appliance ook niet aan, maar de keten server -
runner - ledger is op het lab nog niet met een echte vloer en een echte huidige build doorlopen.

**Wat de meting moet laten zien.** Op het lab met doelbuild 14.1-72.57 en vloer 14.1-73.32
(CTX696939): een R0 zonder acceptatie sluit met de vloerpoort dicht en noemt doelbuild, vloer,
bulletin en de huidige build uit de export; dezelfde R0 met `doelbuild_geaccepteerd=true` opent
die poort als menselijke beslissing; `onderhoud_upgrade_plan` en het R0-voorstel noemen vooraf de
huidige build en `ONDER de vloer` met CTX696604 en CTX696939 als open bulletins. Daarna een
bundelwissel in `onderhoud.firmwaremap` na een gesloten R0: het voorstel van R1 weigert met "de
doelbuild van deze run (R0) wijkt af van de bundel in onderhoud.firmwaremap; start een nieuwe
run", zonder code.

**Wat het niet dekt.** Een FIPS/NDcPP-doos: de vloer van een FIPS-trein heeft niet de vorm die de
runner aanneemt, gaat dus niet mee, en `doelbuild_geaccepteerd=true` gaat dan ook niet mee; R0
sluit daar op "geen vloer" (het plan zegt dat erbij). Dat is fail-closed, maar niet op een echte
FIPS-appliance gemeten. Evenmin gemeten: een tak zonder bekende vloer, waar R0 alleen met
`doelbuild_geaccepteerd=true` opent als menselijke beslissing. Ook de releaselijntoets is
alleen offline bewezen: een doelbuild in een andere releaselijn dan de huidige build sluit R0,
ook met acceptatie en ook zonder vloer, en een export zonder leesbare build laat R0 alleen met
acceptatie open, met "huidige build niet bekend" in het bewijs. Een echte bundel van een andere
releaselijn is op het lab niet aangeboden.

## Aanvullende meetgrenzen uit de publieke basis

**netscaler-mcp** · wat dit product bewust nog niet vaststelt

Dit product zegt liever "niet vastgesteld" dan iets aannemelijks. Deze pagina noemt waar dat
vandaag gebeurt en wat er nodig is om die gaten te sluiten. U kunt ze in een antwoord tegenkomen;
het zijn geen storingen. Hoe u een antwoord leest, staat in
[HANDLEIDING.md](HANDLEIDING.md); wat het product met uw gegevens doet, in
[BEVEILIGING-EN-DATASTROMEN.md](BEVEILIGING-EN-DATASTROMEN.md).

## Een bron zonder hash wordt niet gelezen

Het verzamelscript hoort bij elke bron een SHA-256 van het opgehaalde bestand in het manifest te
schrijven. Dit product vergelijkt die hash met het bestand op schijf voordat het er iets uit
leest. Klopt de hash niet, dan wordt de bron niet vertrouwd. **Staat er geen hash, dan wordt de
bron evenmin vertrouwd** — geen hash is geen vertrouwen. Er is geen tussenweg waarin een bestand
"waarschijnlijk wel goed" is.

Dat heeft een zichtbaar gevolg. In de export waarop dit product is gemeten, meldt het manifest
voor de bron `config/lbmonitor` status OK en 31 objecten, maar liet het verzamelscript de hash
leeg. Het gevolg:

- `rapport_dekking` telt die bron als **MISLUKT**, niet als gelezen bron, en noemt de reden erbij;
- `beveiliging_verstopte_regels` zet de twee regels die deze bron nodig hebben op
  **niet beoordeeld**, in plaats van ze stilzwijgend als "niet geraakt" af te vinken.

Beide gereedschappen zeggen daarmee hetzelfde over dezelfde bron. Dat is de bedoeling: twee
antwoorden die elkaar tegenspreken zijn erger dan een antwoord dat iets niet weet.

**Wat het sluit:** een verzamelscript dat ook voor deze bron een hash schrijft. Dit is werk aan de
verzamelkant, niet aan de leeskant. Zodra die hash er is, valt deze bron niet langer op de
hashpoort; het objectbestand zelf staat al op schijf.

## Twee bindingsbestanden zijn niet te kruiscontroleren

`rapport_dekking` legt de parentlijst van elk bindingsbestand naast de objectbron van die parents.
Dat gebeurt voor beide vormen die het verzamelscript schrijft (een platte lijst per parent, en een
document per parent met een lijst per soort binding). Op de gemeten export met elf
bindingsbestanden blijven er daarna **twee** over met een gat, en geen van beide is een vorm die dit
product niet kan lezen:

- `lbmonitor_binding.by-parent.json`: de objectbron `config/lbmonitor` heeft geen hash (zie
  hierboven), dus de parentlijst is niet te kruiscontroleren;
- `sslcipher_binding.by-parent.json`: het verzamelscript haalt de objectbron `config/sslcipher`
  niet op, dus die staat niet in het manifest en er is niets om tegen te kruiscontroleren.

Het antwoord meldt dan "2 van de 11 bindingsbestanden dragen een gat", met bij elk bestand deze
reden. Dat is eerlijk: de bindingen zelf zijn gelezen, alleen de volledigheid van de parentlijst is
niet te bewijzen.

**Wat het sluit:** een verzamelscript dat `config/lbmonitor` met een hash wegschrijft en
`config/sslcipher` ophaalt. Ook dit is werk aan de verzamelkant.

## De ciphergroep wordt niet uitgeklapt

`beveiliging_tls_baseline` geeft per virtuele server een cijfer volgens dezelfde regelset als de
healthcheck waar dit product zich aan spiegelt. Verwijst de cipherbinding alleen naar een
**groepsnaam** (bijvoorbeeld `DEFAULT`), dan levert de export de leden van die groep niet mee: het
bestand waarin ze zouden staan ontbreekt.

Staat er op de virtuele server geen SSL-profiel, dan rekent de healthcheck in dat geval met de
groepsnaam zelf. Dit product doet dat ook, want een ander cijfer voor dezelfde configuratie maakt
het vergelijk tussen beide onbruikbaar. Draagt de virtuele server wél een SSL-profiel en ontbreekt
de expansie van de gebonden groep, dan wordt er niet met de groepsnaam gerekend — maar het gevolg
voor uw antwoord is hetzelfde als hieronder.

Wat dit product er in beide gevallen bij zegt: het cijfer draagt **niet vastgesteld** in plaats
van vastgesteld. Op de bewijsregel staat `ciphergroep niet uitgeklapt; letter volgens de
NSHC-regel`, in de kenmerken staat `ciphergroep niet uitgesplitst`, en onder de kop
`NIET VASTGESTELD (geen stille aanname):` staat de reden nog een keer voluit. Bij het cijfer staat
dus welke regelset en welke versie het volgt, en waar het op steunt en waar niet.

Wie de leden van een groep niet kent, weet niet of er een zwakke cipher tussen zit: het cijfer kan
in werkelijkheid lager uitvallen dan de letter die er staat.

**Wat het sluit:** een export die de leden van een gebonden ciphergroep meelevert. Dat is opnieuw
werk aan de verzamelkant.

## Een enkele appliance zonder partner

Staat er maar één HA-node in de export, dan zijn er twee standen in `ha_stand` die niets te
beschrijven hebben: de rolverdeling en de propagatie naar een partner. Die staan dan op
`niet van toepassing` — niet op `uit`, want er is geen rolverdeling die uit staat. Ze houden ook
geen wijziging tegen. De geforceerde stand en het verschil tussen de running en de saved config
worden zonder partner gewoon beoordeeld.

## Certificaatgebruik dat niet gevolgd wordt

De certificaattools volgen een certificaat naar de virtuele servers en SSL-diensten waaraan het
gebonden is, naar de certificaten die het uitgeeft, en naar drie gebruikers buiten die bindingen:
SAML-acties (IdP- en signing-certificaat), SAML-IdP-profielen (IdP- en SP-certificaat) en
SSL-servicegroups (met de CA-vlag). Een van die drie bronnen die niet in de export staat, geeft
"niet vastgesteld: bron ... niet in de export" en nooit "geen gebruik".

Wat deze versie **niet** volgt:

- **OAuth en OpenID Connect**: een certificaatverwijzing in een OAuth-actie of -profiel wordt niet
  gelezen;
- **certificaten in monitors**: een monitor die met een eigen certificaat of SSL-profiel naar de
  backend kijkt, wordt niet als gebruiker van dat certificaat gezien;
- **client-cert-CA-ketens buiten de binding**: een CA-certificaat dat alleen via een SSL-profiel,
  een CRL- of OCSP-instelling of een ketenlink een rol speelt, en niet via een binding met een
  virtuele server, een SSL-dienst of een SSL-servicegroup.

Noemt het bindingsbestand van de certificaatkant voor een certificaat een soort binding die deze
versie niet leest, dan zegt het antwoord dat met die soort erbij, en staat dat certificaat op
"onbekend" in plaats van "los".

De parentlijst van het servicegroupbestand wordt gekruiscontroleerd tegen `config/sslservicegroup`,
de objectbron die het bestand zelf als parentbron noemt. Is die bron niet bruikbaar gelezen, dan is
de kruiscontrole niet te maken: dat is een leesgat, en dan komt er geen wijzigingsvoorstel. Een
appliance zonder SSL-servicegroups is vastgesteld zodra `config/sslservicegroup` gelezen en leeg is.

Op een export zonder deze bronnen staat een certificaat zonder vastgesteld gebruik op "onbekend" in
plaats van "los". Dat raakt ook toets 5 van `status_update_preflight`: verloopt zo'n certificaat
binnen dertig dagen, dan is die toets "niet beoordeeld". Een nieuwe scan met verzamelscript 1.1.0
lost dat op.

**Wat het sluit:** een verzamelscript dat die bronnen ophaalt, en leesregels in dit product die ze
volgen. Tot die tijd noemt `certificaat_wat_moet_ik_doen` alleen de gebruikers die het kent; kijk
bij een certificaat met een van de bovenstaande rollen zelf na waar het nog meer in gebruik is.

## Wat dit product niet bewijst

Dit is geen live scan. Wat de appliance in een echte TLS-handshake aanbiedt — de volgorde van de
certificaatketen, OCSP-stapling in de praktijk — volgt niet uit een configuratie. Het TLS-antwoord
zegt dat zelf, onder de kop `NIET BEOORDEELD IN DEZE VERSIE (bewust buiten bereik, geen aanname):`.
Een HA-antwoord bewijst evenmin een werkende failover: het leest de standen, het schakelt niets om,
en het zegt ook dat op dezelfde manier.

## Integratiegrens

Het volledige register bevat 34 gereedschappen: 27 lezende en 7 schrijvende,
in negen hoofdstukken. Alle namen die beginnen met `onderhoud_` worden alleen
aangemeld wanneer `onderhoud` is geconfigureerd; hun bestaande schrijf- en
allowlistpoorten blijven daarnaast gelden. De enige netwerkuitzonderingen
voor leestools zijn `status_ververs` en `status_update_preflight`.

Het actielogboek op stderr bevat per voorstel en per uitvoerpoging een
gestructureerde regel met tien velden. `voorstel` is dezelfde letter als in
het codekanaal en wordt voor het inwisselen gelezen. `bevestiger` komt uit
het kanaal voor die specifieke code, of is null. De code zelf staat nooit
in het logboek. Een gestart runnerproces krijgt `uitkomst: gestart`; dat is
geen geslaagde fase. Het faseoordeel komt uit het ledger. Sinds 1.1 draagt een
regel waarbij een kindproces niet startte een elfde veld, `oorzaak`: de soort
fout (de klassenaam), nooit de tekst ervan.

De twaalf bevindingen uit de externe review zijn in deze integratie verwerkt
(14-9-2026), met drie bewuste afwijkingen van de aangedragen patches: een MCP-host
binnen een Windows Job Object wordt niet geweigerd maar gemeten (zie "Gemeten: de
faserunner en het Job Object van de host" in OPENSTAANDE-METINGEN.md); de vendorbanner
wordt herkend op zijn gemeten eerste zin, niet op een exacte tweede zin; en de
volledigheidseis aan `show ha node` geldt alleen op het pad dat met
`standalone_geaccepteerd` opent. Historische ledgergegevens zijn niet herschreven.

## Gemeten: de faserunner en het Job Object van de host (14-9-2026)

Gemeten op het werkstation, niet beredeneerd: elke MCP-server die de desktopclient start,
draait binnen een Windows Job Object (`IsProcessInJob` op alle zes draaiende productservers:
waar). Een Job Object kan zijn leden beëindigen zodra zijn laatste handle sluit.
`onderhoud_upgrade_fase` vraagt daarom eerst om losmaking uit dat Job Object
(`CREATE_BREAKAWAY_FROM_JOB`, alleen toegestaan als het Job Object dat toelaat), meet daarna
waar de faserunner terecht is gekomen, en meldt dat als regel `faserunner:` in het antwoord —
een van drie vaste zinnen: `losgekoppeld`, `host-gebonden` of `niet beoordeeld`. Een host
binnen een Job Object wordt dus niet geweigerd: dat zou precies de host weigeren waarvoor dit
product gebouwd is.

Niet gemeten: of een host-gebonden faserunner het afsluiten van de host daadwerkelijk
overleeft, en of het Job Object van de desktopclient losmaking toestaat. Het antwoord zegt
welke van de standen de start kreeg; de acceptatietest van de eigenaar meet voor het eerst op
een echte desktopclient welke dat is.


## Scorekaart: ontbrekende licentie- en protocolmetingen (14-9-2026)

De gemeten EXPRESS-export draagt geen `daystoexpiration` in `config/nslicense`.
ANNA-LIC-001 blijft daarom NIET BEOORDEELD/Hoog, bewust afwijkend van de
NSHC-default PASS/Info. Een gemeten verloopdatum sluit dit leesgat. Ontbrekende
featurelicentievelden blijven eveneens onbekend; alleen expliciet false bewijst
niet-gelicentieerd.

Het SSLv2-veld ontbreekt op de profielgedragen vservers van deze build. L1-010
behoudt dit als leesgat; een veilige stand is zonder aanvullende meting niet bewezen.

## De Gateway-keten blijft open

`dienst_keten` volgt de stap van contentswitching naar loadbalancing (standaard
load balancer en beleid, elk beleid via `cspolicy`/`csaction` naar zijn doel, en van daar de
bestaande loadbalancing-keten). De Gateway-keten volgt deze versie nog steeds niet: een
Gateway-vserver hangt niet aan een servicegroup, en de sessiepolicy-keten die er wel toe leidt
vraagt om prioriteitsgedrag dat zonder bewijs uit een testomgeving niet sluitend te bepalen is
(zie het antwoord zelf, onder `NIET BEOORDEELD IN DEZE VERSIE`). Dit blijft een bewuste grens
van deze versie, geen toevallig leesgat.

Kan een beleid niet worden opgelost — `cspolicy` of `csaction` staan niet, of niet leesbaar, in
de export (GEWEIGERD, MISLUKT, of gewoon geen vermelding in het manifest), of een verwijzing
daarin (een beleid zonder actie, een actie zonder doel) wijst nergens naartoe — dan is de HELE
route "niet vastgesteld" met de reden erbij, en toont het antwoord alleen de standaard load
balancer en de beleidsnamen zelf — nooit een gegokt doel; de standaard load balancer wordt in
dat geval ook niet verder gevolgd. De uitgebrachte verzamelaar leest `cspolicy`/`csaction` al
mee (beide labexports dragen ze); "niet in de export" is dus in de praktijk eerder een
leesprobleem of een niet-oplosbare verwijzing dan een oudere collectorversie.

Een contentswitching-vserver die geen standaard load balancer en geen beleid draagt, maar wel
een andere binding (een GSLB-vserver, een VPN-vserver of een soort die deze versie niet kent),
routeert via die binding. Die route volgt deze versie niet: de vserver is dan "niet
vastgesteld" en de reden noemt de bindingssoort, nooit "gat in de keten". Draagt de vserver
zo'n binding naast een standaard load balancer of beleid, dan is de hele route evengoed "niet
vastgesteld" met de bindingssoort in de reden - hetzelfde antwoord als voor een csaction met
een doel dat geen loadbalancing-vserver is. Een beleidsbinding (responder, rewrite en
soortgelijk beleid) stuurt niet naar een andere vserver en laat het oordeel staan. Geen van
beide labexports draagt zo'n routerende binding; dit gedrag is alleen op synthetische exports
gemeten.
