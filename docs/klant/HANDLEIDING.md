# Handleiding

**netscaler-mcp** · voor de beheerder die het product installeert en gebruikt

Deze handleiding beschrijft de installatie, de configuratie en het dagelijks gebruik. Wat het
product met uw gegevens doet en welke garanties daarbij gelden, staat in
[BEVEILIGING-EN-DATASTROMEN.md](BEVEILIGING-EN-DATASTROMEN.md); de beveiligingsverklaring staat
in [SECURITY.md](SECURITY.md). Wat het product bewust nog niet vaststelt - en wat er nodig is om
die gaten te sluiten - staat in [OPENSTAANDE-METINGEN.md](OPENSTAANDE-METINGEN.md).

## Wat is dit

Dit product beantwoordt via uw AI-assistent beheervragen over een Citrix
NetScaler en voert, met een mens in de lus, een beperkt aantal handelingen uit. De
configuratie kent negen hoofdstukken (zie "De hoofdstukken" onder Configuratie); de 34
gereedschappen hieronder horen bij de volgende negen:

- **certificaat** — `certificaat_wat_verloopt_er` (welke certificaten verlopen binnen de
  horizon, standaard 90 dagen), `certificaat_wat_breekt_er` (welke virtuele servers vallen
  uit als dit certificaat verloopt, ook via de certificaten die het uitgeeft; de SSL-diensten
  (services) aan het certificaat komen uit het bindingsbestand van de certificaatkant, en een
  beheerdienst van de appliance zelf (`nshttps-`, `nsrpcs-`) wordt benoemd als beheerverkeer
  van de appliance zelf; het gebruik buiten die bindingen staat er met object en rol bij: een
  SAML-actie, een SAML-IdP-profiel en een SSL-servicegroup, zie "Certificaatgebruik buiten de
  virtuele servers" onder Dagelijks gebruik), `certificaat_wat_moet_ik_doen` (de wijziging, de terugrol en de
  terugleescontrole, alleen als de impact vaststaat; draagt het certificaat beheerverkeer van
  de appliance zelf, dan komt er geen voorstel - dat valt onder de ingebouwde denylist - en een
  gewone SSL-dienst krijgt een eigen handmatige stap, net als een SAML-object of een
  SSL-servicegroup), `certificaat_klaarzetten` (zet een vervangend certificaat klaar
  zonder het te binden) en `certificaat_vervangen` (wisselt het gebonden certificaat op een
  dienst om);
- **status** — `status_ververs` (scant een ingesteld doel opnieuw; dit duurt minuten),
  `status_overzicht` (build, HA-stand, aantal virtuele servers en gegevensleeftijd),
  `status_namen` (welke namen deze NetScaler kent, per familie: loadbalancing-,
  contentswitching- en Gateway-vservers, servicegroups, services en certificaten),
  `status_doelen` (welke doelen deze server kent, uit het doelenbestand en de allowlist: per
  doel de naam, het adres, hoe oud de export van dat doel is, de laatste onderhoudsrun en welke
  schrijvende gereedschappen daar zijn toegestaan; nooit een credential-naam of vingerafdruk,
  zie "Welke doelen zijn er" onder Dagelijks gebruik),
  `status_gezondheid` (wat er DOWN stond op het moment van de scan: tellingen en namen per
  familie, met storing en dekkingsuitspraak strikt gescheiden; een momentopname uit de export
  met een gegevensleeftijd, geen bewaking) en
  `status_cve_controle` (toetst de build aan de securitybulletins uit het kennispakket; noemt een
  bulletin een aparte FIPS/NDcPP-tak, dan volgt hij de tak die de appliance zelf in zijn
  versietekst zet — een FIPS-build schrijft daar `(NS13.1-FIPS)` bij. De hardwarebeschrijving en
  `fipsusermode` kunnen zo'n FIPS-lezing alleen toevoegen, nooit weerspreken: ook een virtuele
  appliance kan een FIPS-appliance zijn. Wijst iets op FIPS terwijl het bulletin die tak niet
  noemt, dan is het antwoord "niet vastgesteld" — nooit het oordeel van de gewone tak) en
  `status_update_advies` (welke build erop hoort: de huidige build, de vloer uit het
  kennispakket en de aangeboden build van de vendor, drie naast elkaar met hun herkomst en
  leeftijd. Is de aangeboden build niet in het kennispakket vastgelegd, dan zegt het antwoord
  dat en blijft het oordeel op de vloer gebaseerd; is de build niet te lezen, dan is het een
  leesgat en geen oordeel) en `status_update_preflight` (negen toetsen die een upgrade binnen
  14.1 kunnen tegenhouden: licentie, classic-markers, HA-stand, drift tussen running en saved,
  certificaathorizon, build en tak, vormfactor, vrije ruimte op `/var` en het terugrolpad. Elke
  toets krijgt een van vier woorden: `geen blokkade`, `blokkade`, `aandachtspunt` of
  `niet beoordeeld`. De kop is alleen sluitend bij negen keer `geen blokkade`. Is een bron een
  leesgat, dan is die toets `niet beoordeeld` met de reden erbij, nooit `geen blokkade`. Toets 4
  (drift) leest de twee tijdstempels uit `config/nsconfig` als de export die bron draagt; de
  uitgebrachte collector verzamelt hem niet, en dan vergelijkt de toets de draaiende en de
  opgeslagen configuratie zelf, met dezelfde tellingen als `config_drift`. Een regel die alleen
  verschilt in een deel dat een geheim kan dragen, zoals een gewijzigd wachtwoord dat niet is
  opgeslagen, maakt toets 4 dan een `aandachtspunt` - als de export die waarde draagt. De
  uitgebrachte collector vervangt zulke waarden al op de jumphost, aan beide kanten, door
  `<REDACTED>`; zo'n wachtwoord is dan niet te vergelijken. Melden de kopregels een wijziging na
  de laatste opslag (of zijn ze onleesbaar), dan is toets 4 daarom `niet beoordeeld` (config-drift
  onbevestigd, met het aantal van zulke regels als reden), nooit `geen blokkade`. Toets 5
  (certificaathorizon) telt een certificaat alleen als vrij als vaststaat dat niets het
  gebruikt: op een export zonder de bronnen voor het certificaatgebruik
  buiten de virtuele servers (zie "Certificaatgebruik buiten de virtuele servers") staat een
  certificaat zonder vastgesteld gebruik op `onbekend`, en verloopt het binnen dertig dagen, dan is
  toets 5 `niet beoordeeld`. Een nieuwe scan met verzamelscript 1.1.0 lost dat op. Dit is
  geen vendor-precheck);
- **dienst** — `dienst_status` (de toestand van een dienst en van elk lid van de gebonden
  servicegroup, zoals de appliance die rapporteert; kent hij de gevraagde naam niet, dan noemt
  hij de virtuele servers waarvan de naam de gevraagde term bevat — hoogstens vijf, alfabetisch,
  hoofdletterongevoelig — zodat u zelf de juiste kunt kiezen; hij kiest er nooit zelf een),
  `dienst_keten` (de hele keten, van VIP tot backend; per keten staat er of hij compleet is,
  waar het gat zit, of dat hij niet vast te stellen is — dat laatste betekent dat een
  bindingsbestand niet te lezen was, of dat deze versie die stap niet volgt, nooit dat er geen
  backends zijn. Een loadbalancing-vserver wordt gevolgd naar zijn servicegroups, services en
  leden. Een contentswitching-vserver wordt gevolgd naar zijn standaard load balancer en naar
  zijn beleid (elk beleid naar zijn doel-load-balancer, rechtstreeks als de binding dat al
  draagt, anders via cspolicy en csaction) — en van daar dezelfde loadbalancing-keten. Kan een
  beleid niet worden opgelost (cspolicy of csaction staan niet, of niet leesbaar, in de export,
  of een verwijzing daarin wijst nergens naartoe), dan is de HELE route "niet vastgesteld" met
  de reden erbij, en toont het antwoord alleen de standaard load balancer en de beleidsnamen
  zelf — nooit een gegokt doel; de standaard-LB wordt in dat geval ook niet verder gevolgd.
  Draagt het bindingsbestand de bindingen van een contentswitching-vserver in de lijstvorm, niet
  gegroepeerd als standaard load balancer of beleid, dan is de route evenmin vastgesteld - nooit
  "gat in de keten".
  Staan cspolicy of csaction niet in de export terwijl een route ze nodig heeft, dan noemt
  `rapport_dekking` ze als "niet in de export" en is de dekking niet "volledig". Een
  Gateway-vserver blijft "niet vastgesteld" met de reden erbij: de sessieketen van een Gateway
  volgt deze versie niet. Laat het argument leeg voor alle ketens; het antwoord begint dan met
  een samenvattingsregel met het aantal ketens per oordeel), `dienst_lid_uitschakelen` (haalt een
  lid uit een dienst) en `dienst_lid_inschakelen` (zet een eerder uitgeschakeld lid terug);
- **kennis** — `kennis_uitleg` (legt een NetScaler-begrip uit vanuit het kennispakket, of
  zegt dat het er niet in staat);
- **rapport** - `rapport_na_upgrade` (leest het oordeel na een upgrade uit export en ledger),
  `rapport_dekking` (hoe compleet dit antwoord is: per bron of hij gelezen
  is, welke bronnen mislukten, geweigerd werden of ontbraken, en of de kruiscontrole op
  de bindingen rondkwam) en `rapport_vergelijk` (vergelijkt twee exportmappen in een van
  vier modi - HA-parity (HA-pariteit), drift, run-diff of pre/post - met configuratie-, stand- en
  dekkingsverschillen in drie gescheiden blokken; welke van de twee standen goed is, zegt
  dit antwoord niet) en `rapport_wat_is_er_veranderd` (dezelfde vergelijking, in de modus
  run-diff, met de twee mappen automatisch gekozen: de huidige export tegenover de
  nieuwste bewaarde export; is er geen bewaarde export, dan zegt het antwoord dat er
  niets te vergelijken is, nooit dat er geen verschillen zijn);
- **ha** - `ha_stand` (de HA-stand voor een wijziging: rolverdeling, sync en propagatie,
  geforceerde stand en het verschil tussen de running en de saved config, elk aan, uit of
  onbevestigd; het bewijst geen werkende failover en zegt niets over de configuratie van
  de partner);
- **config** - `config_drift` (welke regels alleen in de draaiende en welke alleen in de
  opgeslagen configuratie staan, uit de export; de kopregels en de afsluitende `Done` tellen
  niet mee. De regels zelf staan er alleen bij openheid `volledig`, en een regel met een herkend
  geheim of een geredigeerde waarde nooit; bij `beperkt` alleen het commandohoofd met een telling, bij
  `minimaal` alleen tellingen. Een regel die alleen verschilt in het deel dat de export achterhoudt
  omdat het een geheim kan dragen, telt als drift en staat er in elke stand alleen als aantal - als
  de export die waarde draagt; heeft de collector haar al door `<REDACTED>` vervangen en melden de
  kopregels een wijziging na de laatste opslag (of zijn ze onleesbaar), dan staat config-drift op
  `onbevestigd`) en
  `config_opslaan` (laat de NetScaler de draaiende configuratie
  opslaan met `save ns config`, over SSH met de gepinde hostsleutel en na een live rolcontrole: op
  een node die secondary is weigert het, want daar propageert opslaan niet. Daarna leest het
  product `show ns config` terug en oordeelt zelf of de laatste opslag niet ouder is dan de laatste
  wijziging. Vereist een `onderhoud`-configuratie en een doel met een gepinde hostsleutel; opslaan
  heeft geen tegenhanger - de vorige opgeslagen configuratie zit alleen in een backup die u vooraf
  met `onderhoud_backup_maken` maakte; `config_opslaan` controleert dat niet);
- **beveiliging** - `beveiliging_verstopte_regels` (de negenentwintig verstopte regels waar
  geen alarm op staat: per regel of hij geraakt is, op welke objecten, en waarom dat niet
  opvalt; de regels lezen configuratievelden en bewijzen geen gedrag) en
  `beveiliging_tls_baseline` (een TLS-cijfer per virtuele server, A+ tot en met T, met de
  bepalende kenmerken, plus de verdeling over de appliance en de gebruikte regelsetversie;
  protocol en ciphers komen van het gebonden SSL-profiel als er een is - een
  configuratieweging, geen live scan) en `beveiliging_beheervlak` (staat het beheer van de
  appliance open: blootstelling, transport, certificaat en RBAC, elk PASS, FAIL of NIET
  BEOORDEELD) en `beveiliging_headers` (de dekking van zes HTTP-securityheaders; een rewrite
  telt alleen met een effectieve RESPONSE-binding, en HSTS telt alleen als een vserver een
  FrontEnd-profiel met `hsts=ENABLED` bindt).
  `beveiliging_scorekaart` toont de Level-1-controls met ernst, zekerheid en toepasselijkheid.
  De kop telt alleen PASS en FAIL: X van 18 beoordeeld, of 19 bij bevestigde IPREP-scancontext.
  Vijf controls vallen buiten de noemer; zeven vaste onderwerpen staan onderaan buiten bereik.

- **onderhoud** - `onderhoud_upgrade_fase` (start een bevestigde fase via de runner), `onderhoud_upgrade_stand` (leest de stand uit het ledger) en `onderhoud_backup_maken` (laat de NetScaler zelf een volledige backup
  maken en leest die terug in de backupcollectie op de appliance; de naam wordt door het
  product zelf gevormd, in UTC. Een backup op de appliance is geen off-box backup; het
  downloaden ervan is een aparte stap die dit product niet doet. Dit gereedschap vormt zijn
  eigen object en heeft daarom geen objectargument, alleen `doel` en `bevestiging`. Er is geen
  tegenhanger: een backup is een
  terugrolpunt, geen wijziging, en het object blijft gewoon staan) en `onderhoud_upgrade_plan`
  (stelt het plan op voor een upgrade binnen 14.1: de zeven fasen, de HA-volgorde - secondary
  eerst, dan het soakvenster, dan pas de andere node -, het terugrolpad per fase en per fase de
  poort die open moet, en ook de doelbuild (de ene bundel in `onderhoud.firmwaremap`), de vloer
  uit het kennispakket en het oordeel van R0 daartussen. Een firmware-terugrol herstelt daarbij altijd de build, nooit de
  configuratie; de inverse van een upgrade blijft de backup of de hypervisor-snapshot. Deze
  tool leest alleen en wijzigt niets. Alle `onderhoud_`-tools vereisen een `onderhoud`-configuratie).

`certificaat_klaarzetten`, `certificaat_vervangen`, `dienst_lid_uitschakelen`,
`dienst_lid_inschakelen`, `onderhoud_backup_maken`, `onderhoud_upgrade_fase` en `config_opslaan` zijn de zeven
schrijvende gereedschappen:
zij wijzigen de appliance en handelen nooit op de eerste aanroep - zie "Dagelijks gebruik"
voor het bevestigingspatroon. Een hoofdstuk kunt u uitzetten in de configuratie
(`hoofdstukken`); de zeven schrijvende gereedschappen bestaan bovendien alleen met een
`handelen`-sectie in de configuratie (zie "Configuratie" hieronder). `onderhoud_upgrade_plan`
is geen schrijvend gereedschap, maar bestaat ook niet zonder meer: het vraagt het hoofdstuk
`onderhoud` en een `onderhoud`-sectie in de configuratie, en die sectie start alleen samen met
een `handelen`-sectie.

Elk antwoord draagt bewijs, benoemt wat niet kon worden vastgesteld (een leesgat), en meldt
hoe oud de gegevens en de kennisregels zijn. `kennis_uitleg` leest geen export en meldt
alleen de kennisleeftijd. Het product rekent de antwoorden uit; de AI-assistent formuleert
alleen de taal eromheen.

## Installatie

U heeft nodig:

1. **Python 3.11 of hoger** op de machine waar het product draait.
2. **Het productpakket.** Installeer het volgens de leveringsinstructie, of vanaf de broncode
   op GitHub zoals hieronder; daarna is het commando `netscaler-mcp` beschikbaar.
3. **Het verzamelscript van GJK NetScaler Healthcheck 1.0** (alleen nodig als het product
   zelf gaat scannen). Dit is een los PowerShell-bestand dat bij de levering hoort; zet het op
   een vaste plek en verwijs ernaar in de configuratie.
4. **Het kennispakket.** Dit komt uit het kennisabonnement van GJK Partners en wordt apart
   geleverd; het staat niet in het productpakket. Zonder kennispakket werkt het product wel,
   maar meldt elk antwoord dat de kennisbasis ontbreekt.

### Installeren vanaf GitHub

Vanaf een kloon van de repository, in PowerShell, in de map van de kloon:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-build.txt
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
```

Het commando staat daarna in `.venv\Scripts\netscaler-mcp.exe`, niet op het zoekpad van
Windows. Noem in de clientconfiguratie (zie "Starten en aansluiten") dus het volledige pad naar
dat bestand, of activeer de omgeving eerst.

De repository bevat een werkend voorbeeld: `config.example.json` wijst naar de meegeleverde
labexport `tests\fixtures\lab-export-vpx-20260826` en het voorbeeldkennispakket
`kennis.example.json` (dat geen echte CVE-basis bevat). Proberen zonder appliance:

```powershell
.\.venv\Scripts\python.exe examples\minimal_client.py
```

## Configuratie

Het product leest één configuratiebestand (JSON). Een volledig voorbeeld:

```json
{
  "profiel": "afgeschermd",
  "exportmap": "C:\\GJK\\netscaler-mcp\\export",
  "kennispad": "C:\\GJK\\netscaler-mcp\\kennis.json",
  "kennispin": {"versie": "2026.09", "digest": "<uitvoer van python -m nsmcp.knowledge --digest>"},
  "doelen": "C:\\GJK\\netscaler-mcp\\doelen.json",
  "verzamelscript": "C:\\GJK\\netscaler-mcp\\verzamel.ps1",
  "openheid": "volledig"
}
```

`profiel`, `exportmap` en `kennispad` zijn verplicht; `doelen`, `verzamelscript`,
`hoofdstukken`, `handelen`, `openheid`, `bewaren` en `kennispin` zijn optioneel. Bij een
onbekend veld, een ontbrekend verplicht veld of een onbekende waarde start het product niet,
met een duidelijke melding — er is nooit een stille terugval.

Paden in de configuratie: een relatief pad (zoals `tests\fixtures\...` in
`config.example.json`) telt vanaf de map waar het configuratiebestand staat, niet vanaf de
werkmap van het proces dat de server start. Vindt de server een map niet, dan noemt de
melding het uitgeschreven pad en die map. Een netwerkpad (`\\server\share\...`, ook als
`\\?\UNC\...`), een apparaatpad anders dan een lokale schijf, een dubbele punt na de
schijfletter (een alternatieve gegevensstroom), een pad dat van de huidige schijf afhangt
(`C:map` of `\map`) en een padonderdeel dat op een punt of spatie eindigt, weigert de server
bij de start. Dat geldt ook voor het configuratiebestand zelf en voor de plek waar een pad
uitkomt: de server volgt een junction of symbolische link stap voor stap zonder het doel te
openen, en weigert een configuratiebestand op een share (dan zou elk relatief pad een netwerkpad
worden), een koppeling naar een share of een gegevensstroom, en een netwerkstation
(`Z:` gekoppeld aan een share). Een junction naar een andere lokale map blijft toegestaan.
`handelen.codekanaal.pad` moet bovendien absoluut zijn.

### Het kennispakket vastpinnen (`kennispin`)

Wie het kennispad kan beschrijven, kan de kennis veranderen: een pakket waarin de getroffen
reeks en de fix-build samen verlaagd zijn, of waaruit een bulletin is weggehaald, ziet er voor
elke vormcontrole normaal uit en verlaagt dan de vloer en het aantal geraakte CVE's. Daarom
legt u in de configuratie vast welk pakket u hebt goedgekeurd:

```powershell
python -m nsmcp.knowledge --digest "C:\GJK\netscaler-mcp\kennis.json"
```

Dat drukt het blok af dat u in de configuratie zet: `"kennispin": {"versie": "...",
"digest": "..."}`. De digest is de sha256 van de inhoud van het pakket in één vaste vorm
(gesorteerde sleutels, geen witruimte), dus regeleinden en inspringing tellen niet mee. Een
pakket dat het product zelf zou weigeren, krijgt geen pin. Wat u daarna ziet:

- **Pin aanwezig en het pakket klopt:** de antwoorden zijn zoals altijd.
- **Pin aanwezig en het pakket wijkt af** (versie, inhoud of beide): het pakket geldt niet. De
  kennisregel onder de antwoorden zegt dan `Kennisbasis: ONBEKEND - er is geen kennispakket
  geladen.` De antwoorden die het pakket gebruiken (`status_cve_controle`,
  `status_update_advies`, `onderhoud_upgrade_plan`, `kennis_uitleg`, de scorekaart en het
  rapport na de upgrade) zeggen ook waarom: het kennispakket wijkt af van de kennispin, en welke
  van de twee afwijkt. De verwachte digest staat nooit in het antwoord.
- **Geen pin:** het pakket laadt, maar elke uitspraak over de vloer en elk CVE-oordeel draagt
  `[niet vastgesteld]` met de reden "kennispakket niet gepind in de configuratie"
  (`status_cve_controle`, `status_update_advies`, `onderhoud_upgrade_plan`,
  `status_update_preflight` stap 6, de scorekaart, en in het rapport na de upgrade zowel het
  CVE-oordeel als de extra stap na de upgrade). De vloerpoort
  van R0 behandelt dat als "geen vloer bekend": R0 sluit, tenzij u `doelbuild_geaccepteerd=true`
  meegeeft.

Na een kennisverversing ([Automatisering](AUTOMATISERING.md)) staat er een nieuw pakket op het
kennispad: bereken de digest opnieuw en werk de pin bij, anders weigert de server het nieuwe
pakket.

Los van de pin weigert het product elk pakket dat zichzelf tegenspreekt, met de reden erbij: een
bulletin waarvan de fix-build voor een tak onder de getroffen reeks ligt (`"< 73.37"` naast fix
`"66.00"`; een fix-build gelijk aan of boven de grens is geldig), een getroffen reeks of fix-build
die het product niet kan lezen, een bulletin dat twee keer voorkomt, of een CVE die in meer dan
één bulletin (of twee keer in één bulletin) staat. Zo'n pakket telt niets dubbel en verlaagt
geen vloer; elk antwoord zegt dat het kennispakket onbruikbaar is.

**Verplichte naconfiguratie (sinds 1.0.3).** Voor sommige CVE's is firmware alleen niet de
volledige oplossing: de vendor vraagt na de upgrade ook een configuratiestap. Een CVE-regel in het
pakket zegt dat met het optionele veld `"naconfiguratieVerplicht": true`; de stap zelf staat in
`extraStapNaUpgrade` van het bulletin. Op of boven de fix-build zegt `status_cve_controle` voor
zo'n CVE `NIET VASTGESTELD` met een leesgat "(naconfiguratie)" en het advies met de stap erbij,
want de firmwarevergelijking bewijst alleen de firmwarehelft. Alleen als de voorwaarde van de CVE
aantoonbaar afwezig is, blijft het `NIET GERAAKT`. Ontbreekt het veld, dan verandert er niets;
een waarde die geen `true` of `false` is, weigert het pakket.

### De scripts vastpinnen (`scriptpin`) en het uitvoeringsbeleid (`uitvoeringsbeleid`)

Het product start PowerShell-scripts: het verzamelscript, het schrijfscript, de faserunner en de
kleine SSH-scripts naast de runner (die de runner op naam inleest). Wie die bestanden kan
vervangen, draait zijn eigen PowerShell met de rechten van de server. Daarom kunt u per script de
sha256 vastleggen:

```powershell
python -m nsmcp.powershell --pin "C:\GJK\netscaler-mcp\verzamel.ps1" "C:\GJK\runner"
```

Dat drukt het blok af dat u in de configuratie zet: `"scriptpin": {"verzamel.ps1": "<sha256>",
...}`, met de kale bestandsnaam als sleutel. Een map staat voor elk script (`.ps1`, `.psm1`) erin;
pin zo de hele map van de runner, want de runner, de live meting en `config_opslaan` lezen hun
transport `GjkUpgrade-Ssh.ps1` op naam uit die map. Wat u daarna ziet:

- **`scriptpin` aanwezig:** vlak voor elke start leest het product de bytes van het script en van
  elk ander script (`.ps1`, `.psm1`) in dezelfde map. Wijkt er een af van zijn pin, of heeft het
  script dat gestart zou worden of een script ernaast geen pin, dan start er geen proces; het
  antwoord noemt de bestandsnaam en de reden. Een submap valt buiten deze controle; zet daar geen
  scripts die het gestarte script inleest.
- **Geen `scriptpin`:** er wordt niets gecontroleerd, zoals in eerdere versies. Het
  configuratiebestand en de scriptmappen zijn dan de enige bescherming.

Na een update van een script berekent u de pin opnieuw. `uitvoeringsbeleid` kiest het
PowerShell-uitvoeringsbeleid waarmee het product zijn scripts start: `Bypass` (standaard; de
scripts van het product zijn niet gesigneerd, en een beleid van de machine zou ze anders
tegenhouden), `AllSigned` of `RemoteSigned` (Windows beslist dan zelf, voor wie de scripts
signeert).

### De drie profielen

| Profiel | Betekenis |
|---|---|
| `dienst` | beantwoordt uitsluitend op een aangeleverde export; `doelen` of `verzamelscript` configureren is hier een fout en wordt geweigerd |
| `afgeschermd` | mag zelf scannen; configureer daarvoor `doelen` én `verzamelscript` (beide, niet één van de twee) |
| `online` | vandaag gelijk aan `afgeschermd`; de naam is gereserveerd voor een latere taak |

### Het verzamelscript en de live meting van `status_update_preflight`

`status_update_preflight` leest een ding niet uit de export maar **live**: de vrije ruimte op
`/var`. Het serverproces zelf opent daarvoor geen verbinding; een apart kindproces doet dat. Welke
route dat kindproces neemt, volgt uit de configuratie en niet uit een mislukking:

- **Over SSH**, als de sectie `onderhoud` is ingesteld en het doel een gepinde
  `ssh_hostsleutel_vingerafdruk` draagt. Het product start dan het kleine leesscript
  `Invoke-GjkLiveMeting.ps1` naast de faserunner. Dat gebruikt hetzelfde transport als de runner:
  de gepinde hostsleutel, de SSH-gebruiker uit `onderhoud.ssh_gebruiker`, het credential-target uit
  `doelen`, en dezelfde meting `df -k /var` als fase R1. De SSH-gebruiker moet dus `shell` mogen
  uitvoeren, net als voor de upgraderoute. De bewijsregel zegt dan "live gelezen via df -k /var
  over SSH".
- **Via het verzamelscript**, in elk ander geval: langs hetzelfde aparte proces als een scan, met
  hetzelfde doel en hetzelfde credential uit `doelen`. Het product vraagt het verzamelscript
  daarvoor om een enkele resource, met het argument `-OnlyResources`. De bewijsregel zegt dan
  "live gelezen via stat/system via het verzamelscript".

Is er geen doel of geen verzamelscript ingesteld, dan wordt er niets gelezen en zegt de
bewijsregel "niet gelezen: <reden>"; er staat dan geen route bij. Dat geldt ook als het proces niet
kon starten (een script dat van zijn pin afwijkt, geen PowerShell, geen tijdelijke map): dan zegt
de bewijsregel "niet gelezen: het verzamelscript is niet gestart: <reden>". Een route die wel liep
maar geen getal opleverde, staat er als "live gelezen via <route>, geen bruikbare waarde".
Mislukt de gekozen route, dan probeert het product de andere route niet stilletjes alsnog: toets 8
wordt `niet beoordeeld` met de reden erbij (geen sessie, een afwijkende hostsleutel, de
tijdslimiet van 120 seconden, geen geheel getal). Wat het product nooit doet, is er stil groen van
maken. De andere acht toetsen komen uit de export en worden gewoon beantwoord.

**Het verzamelscript staat buiten dit product** - u configureert het zelf - dus het product kan
de ondersteuning van `-OnlyResources` niet afdwingen. Kent uw script dat argument niet, dan stopt
het met een foutcode of zonder objectbestand, en dat is een leesgat zoals hierboven.

De bundelgrootte in toets 8 komt uit de ene firmwarebundel in `onderhoud.firmwaremap`, dezelfde
bundel waaruit de faserunner zijn doelbuild haalt. Zonder `onderhoud`, of met nul of meer dan een
bundel in die map, rekent de toets met een aangenomen grootte van 1100 MB en zegt dat erbij.

### Het doelenbestand

Dit doelenbestand bepaalt de doel- en credentialroute van de collector en upgraderunner.
De eerste vijf schrijfhandelingen gebruiken het ingestelde externe schrijfscript; controleer
ook diens eigen doel- en credentialconfiguratie. Een ontbrekend credential-target in dit
doelenbestand bewijst niet dat dat externe schrijfscript geen appliance kan wijzigen.

Als het product zelf scant, beschrijft het doelenbestand welke NetScalers dat zijn:

```json
{
  "doelen": [
    {
      "naam": "lab",
      "adres": "10.10.10.10",
      "credentialTarget": "GJK/netscaler/lab/inlog",
      "certificaat": "keten"
    },
    {
      "naam": "productie",
      "adres": "10.10.10.20",
      "credentialTarget": "GJK/netscaler/productie/inlog",
      "certificaat": "vingerafdruk",
      "vingerafdruk": "A1:B2:C3:D4:E5:F6:A7:B8:C9:D0:E1:F2:A3:B4:C5:D6:E7:F8:A9:B0"
    }
  ]
}
```

Per doel:

- `naam` — uw eigen label voor dit doel; het verschijnt in de antwoorden als `doel: <naam>`;
- `adres` — het beheeradres van de NetScaler. Voor een doel dat `onderhoud_upgrade_fase` mag
  uitvoeren MOET dit het letterlijke NSIP zijn, geen hostnaam: `secondary_gate` vergelijkt dit
  veld als tekst tegen het IP dat `show ha node` voor Node ID 0 meldt en doet geen naamresolutie
  — een hostnaam maakt R1 en R5 op dat doel onherroepelijk `niet beoordeeld`, en de server weigert
  dat daarom al bij het opstarten;
- `credentialTarget` — de targetnaam van de credential in Windows Credential Manager;
- `certificaat` — de certificaatafspraak: `"keten"` (het beheercertificaat valideert tegen de
  vertrouwensketen) of `"vingerafdruk"` (de vingerafdruk van het beheercertificaat staat
  vooraf vast in het veld `vingerafdruk`). Een derde vorm bestaat niet: valideert het
  certificaat niet en is er geen vingerafdruk, dan scant het product niet.

`naam` en `adres` gaan als `-Doel` en `-Adres` mee naar elk schrijfscript en staan in het etiket
waaraan een bevestigingscode hangt. Een regeleinde, tab of ander niet-afdrukbaar teken erin start
de server daarom niet ("draagt een stuurteken"), ook niet midden in de waarde; de schrijfscripts
weigeren zo'n waarde zelf ook.

Een appliance staat met precies een adres in het doelenbestand; staan twee doelen op hetzelfde
adres, dan weigert de server te starten ("hebben hetzelfde adres", met beide doelnamen). Wat een
tweede schrijver op een appliance tegenhoudt (de weigering voor een openstaande fase, de blokkade
van een onbesliste start en de eigen controle van de faserunner), houdt een doel bij zijn naam
vast; twee namen voor een appliance zouden elkaar daar niet tegenhouden. Het adres vergelijkt de
server als tekst - hoofdletters en witruimte tellen niet mee - zonder naamresolutie: zet dezelfde
appliance dus niet een keer onder een hostnaam en een keer onder zijn IP-adres in het bestand, want
dat ziet de server niet; hetzelfde geldt voor een IPv4-adres in een andere schrijfwijze
(voorloopnul, decimaal of hexadecimaal): gebruik alleen de gewone puntnotatie (`10.0.0.2`).

**De credential zelf staat uitsluitend in Windows Credential Manager**, onder de targetnaam
die u bij `credentialTarget` opgeeft. Wachtwoorden of tokens horen niet in het
configuratiebestand en niet in het doelenbestand; een bestand met een geheim-achtige
sleutelnaam (zoals `password`, `secret`, `token`, `apiKey`) wordt geweigerd voordat er iets
gebeurt.

### De hoofdstukken

Het optionele veld `hoofdstukken` kiest welke van de negen hoofdstukken
(`certificaat`, `status`, `dienst`, `kennis`, `beveiliging`, `rapport`, `ha`, `onderhoud`,
`config`) actief zijn; ontbreekt het veld, dan staan ze alle negen aan. Een lijst met een
onbekend hoofdstuk start het product niet, en een lege lijst ook niet - dat zou
een server zonder gereedschappen opleveren die er wel uitziet alsof hij werkt.

```json
{
  "hoofdstukken": ["certificaat", "status"]
}
```

### Vorige exports bewaren

Voor geplande scans en het bewaren van vorige exports: zie
[Automatisering](AUTOMATISERING.md). Het optionele veld `bewaren` accepteert
`exports_per_doel` (standaard 5) en `vrije_ruimte_vloer_mb` (standaard 2048).
Zonder dit veld staat bewaren uit; een leeg object kiest de standaardwaarden.
Een server deelt de exportmap tussen zijn doelen. Het opruimbeleid telt per
hashgebonden doelnaam in `scan-doel.txt`; exports zonder doelidentiteit vormen
een aparte groep per exportmap. Die groep heeft geen bewijs dat scans hetzelfde
doel betreffen. `exports_per_doel: 0` zet bewaren en opruimen van de bestaande
bewaarhistorie uit.

Na een geslaagde scan verdwijnen alleen overtollige bewaarde exports, oudste
eerst. De nieuwste per doel en exports zonder vastgesteld scanmoment blijven
staan. Onder de vrije-ruimtevloer of zonder geldige ruimtemeting wordt niets
opgeruimd; de ruimte wordt voor iedere verwijdering opnieuw gecontroleerd.
Verwijderingen en stops verschijnen als vaste, veilige waarschuwingen op
`stderr`. Laat de geplande taak die opslaan onder `<exportwortel>/_beheer/`;
zie [Automatisering](AUTOMATISERING.md) voor de grenzen en het logbeleid.

Staat `bewaren` aan, dan gebruikt `rapport_wat_is_er_veranderd` (hoofdstuk
rapport) automatisch de nieuwste bewaarde export als vergelijkingsmateriaal
naast de huidige export - dezelfde selectie die dit bewaarbeleid hier
beschrijft, u hoeft zelf geen mapnamen op te geven. Staat `bewaren` niet aan
of is er nog niets bewaard, dan zegt dat gereedschap eerlijk dat er niets te
vergelijken is.

### De sectie handelen

Zonder de sectie `handelen` bestaan de zeven schrijvende gereedschappen
(`certificaat_klaarzetten`, `certificaat_vervangen`, `dienst_lid_uitschakelen`,
`dienst_lid_inschakelen`, `onderhoud_backup_maken`, `onderhoud_upgrade_fase`, `config_opslaan`) niet - ze worden dan niet eens bij de
AI-assistent aangemeld.

**`handelen` werkt bij `openheid: volledig` en bij `openheid: beperkt`, niet bij
`openheid: minimaal`.** Alles wat een schrijvend gereedschap zegt gaat door dezelfde
openheidsfilter als een leesantwoord, en een weigering noemt niets meer dan u zelf gaf; in
`beperkt` levert u dus een pseudoniem aan en krijgt u een pseudoniem terug, terwijl de beheerder
in het codekanaal de echte naam ziet. In `minimaal` bestaan de zeven niet: die stand vat een
antwoord samen tot tellingen, en dan verdwijnen de regels van het voorstel en de aanwijzing om
opnieuw aan te roepen met de bevestigingscode — terwijl die code wél aan de beheerder getoond
wordt, dus de tweede stap zou onbereikbaar zijn. Staat `openheid` op `minimaal` terwijl er een
`handelen`-sectie is, dan weigert de server te starten met de melding *"de sectie handelen gaat
niet samen met openheid minimaal"* en de reden erbij. De lezende gereedschappen werken in alle
drie de standen gewoon; wilt u `minimaal`, laat de `handelen`-sectie dan weg.

Met
`handelen` erbij komen alleen de schrijvende gereedschappen mee van een hoofdstuk dat ook zelf
aanstaat (via `hoofdstukken`, of het ontbreken daarvan — dan staan alle hoofdstukken aan):
`certificaat_klaarzetten` en `certificaat_vervangen` hebben zowel `handelen` als het hoofdstuk
`certificaat` nodig; `dienst_lid_uitschakelen` en `dienst_lid_inschakelen` hebben zowel
`handelen` als het hoofdstuk `dienst` nodig; `onderhoud_backup_maken` heeft zowel `handelen`
als het hoofdstuk `onderhoud` nodig; `config_opslaan` heeft `handelen`, het hoofdstuk `config`,
een `onderhoud`-sectie en een doel met toestemming nodig. Schakelt u een hoofdstuk uit, dan verdwijnen ook de
schrijvende gereedschappen van dat hoofdstuk, ook als `handelen` verder correct staat ingevuld.

```json
{
  "handelen": {
    "schrijfscript": "C:\\GJK\\netscaler-mcp\\film\\Invoke-GjkWerkbankWrite.ps1",
    "fixturemap": "C:\\GJK\\netscaler-mcp",
    "codekanaal": { "soort": "venster" },
    "toegestaan": {
      "netscaler-01": {
        "certificaat_klaarzetten": { "certnaam": ["gjk-zaakportaal-2027"] }
      }
    },
    "verboden_adressen": ["10.0.0.9"]
  }
}
```

- `schrijfscript` — het pad naar het gereviewde PowerShell-schrijfscript dat de handelingen
  echt uitvoert; het moet bestaan als bestand, anders start het product niet;
- `fixturemap` — de map waaronder de bijbehorende bestanden voor het demolab staan; het
  schrijfscript verwacht ze in een submap `film` daarvan (bijvoorbeeld
  `<fixturemap>\film\<certnaam>.cer` en `.key` voor `certificaat_klaarzetten`); de fixturemap
  zelf moet bestaan als map, anders start het product niet;
- `codekanaal` — waar de bevestigingscode aan u wordt getoond. Altijd een object met een
  `soort`. Drie soorten in deze versie: `{"soort": "venster"}` toont de code in een venster op
  de machine waar de server draait, `{"soort": "bestand", "pad": "<absoluut pad>"}` schrijft
  hem naar dat ene bestand, en `{"soort": "sso", "pad": "<absoluut pad>", "autoriteit":
  "<https-url>", "wachttijd_s": <getal>}` stuurt hem naar een apart presenterproces dat een
  goedkeuringsketen aanroept en - als enige van de drie - kan zeggen WIE bevestigde. Een
  onbekende `soort` weigert bij het starten, met de soorten die deze versie wél kent in de
  melding. Het pad van `bestand` en van `sso` moet absoluut zijn, mag geen map zijn en mag niet
  in een map liggen die het product zelf leest (de exportmap, de fixturemap, de map van het
  schrijfscript, of de map van het kennis-, doelen- of verzamelscriptbestand); elk van die
  gevallen weigert bij het starten, met de reden erbij. Het bestand/de presenter krijgt geen
  eigen rechten van dit product: het erft de rechten van de map die u aanwijst — kies dus een
  map die alleen u kunt lezen.

  **Het protocol van `sso` is één regel JSON heen, één regel JSON terug.** Naar de stdin van de
  presenter: `{"vingerafdruk": "<sha256 van gereedschap+argumenten+doel-etiket+doelnaam>", "code": "<code>",
  "autoriteit": "<url>", "aanduiding": "<voorstel X>", "gereedschap": "<gereedschapsnaam>", "doel": "<doel-etiket>",
  "sectie": "<doelnaam>", "voorstel":
  "<begrensde voorsteltekst>", "fase": "<R0..R6, of leeg buiten onderhoud_upgrade_fase>",
  "argumenten": ["<naam>: <waarde>", ...]}`.
  `argumenten` draagt dezelfde regels die het venster onder `wat:` toont: één regel per argument
  van de handeling (elk argument van de aanroep behalve `doel` en `bevestiging`), op naam
  gesorteerd, elke waarde afgekapt op 120 tekens - bij `onderhoud_upgrade_fase` dus ook de
  snapshotverwijzing en de acceptatieschakelaars. De doelnaam (de sectie in
  `handelen.toegestaan`, het argument `doel` van de aanroep) is ook aan de code gebonden en staat
  niet in deze regels maar in een eigen veld `sectie`. Het veld `doel` is het doel-etiket dat het
  schrijfscript meldt, en dat is gelijk voor twee doelnamen die dezelfde handeling toestaan; het
  veld `sectie` houdt die twee voor de bevestiger uit elkaar. Het venster en het bestand tonen de
  doelnaam op een eigen regel `sectie: <doelnaam>` direct onder `doel:`, ook als doelnaam en
  etiket op elkaar lijken.
  Een presenter MOET elke regel van `argumenten` en de `sectie` tonen: de code is aan die waarden
  gebonden, en wie ze niet ziet, bevestigt iets wat hij niet gelezen heeft. Een presenter van vóór
  deze versie kent die velden niet en toont ze niet; hij spiegelt ook niets terug (zie het
  antwoord hieronder) en levert daarom geen code meer af. Werk presenter en server samen bij. De
  referentiepresenter weigert een aanvraag zonder `sectie`.
  `vingerafdruk` is een sha256 over gereedschap, argumenten, het getoonde doel-etiket en de
  doelnaam: twee voorstellen voor verschillende doelnamen met hetzelfde etiket en dezelfde
  argumenten krijgen een verschillende waarde. Het is niet per se de sleutel waaronder de server
  de code bewaart: die rekent met het etiket zoals het schrijfscript het meldde, de presenter
  krijgt het getoonde etiket.
  `aanduiding` is dezelfde aanduiding die `venster` en `bestand` ook tonen (de letter van dit
  voorstel, boven de code). `doel` en `voorstel` tonen de bevestiger het doel-etiket en de
  voorsteltekst, zoals het bestandskanaal. Het vensterkanaal toont alleen gereedschap, doel,
  doelnaam en argumenten boven de code. Zonder `doel` en `voorstel` kreeg de identificerende
  bevestiger alleen een code en een letter te zien, niets over WAT hij goedkeurde.
  `voorstel` is BEGRENSD, ruimer dan een regel op een scherm maar niet ongebreideld - bij
  `onderhoud_upgrade_fase` kan die begrenzing de fase middenin het voorstel afkappen, en juist
  daarom draagt `fase` de fase (`R0` t/m `R6`) ook als EIGEN veld: die overleeft elke afkapping
  van `voorstel`, ongeacht de lengte. Bij elke andere handeling is `fase` leeg. Het codekanaal
  valideert doel, doelnaam, gereedschap en fase voordat het de presenter start; die identiteit wordt
  volledig doorgegeven of geweigerd, nooit passend gemaakt door afkapping. De
  referentiepresenter toont het volledige doel en de volledige doelnaam (elk maximaal 256
  tekens), de fase, elke argumentregel en maximaal 1000 tekens voorsteltekst boven de code; de
  argumentregels staan los van de voorsteltekst, zodat het afkappen daarvan er geen wegneemt.
  `gereedschap` bepaalt
  of een fase vereist is: bij `onderhoud_upgrade_fase` uitsluitend R0 tot en met R6, bij andere
  schrijfacties een aanwezig maar leeg faseveld. Ontbrekende, niet-printbare of te lange
  context wordt voor het openen van het venster geweigerd. Werk presenter en server samen bij;
  de oude aanvraagvorm zonder deze context wordt niet geaccepteerd. Terug op zijn
  stdout: `{"afgeleverd": true, "sectie": "<doelnaam uit het verzoek>", "vingerafdruk": "<vingerafdruk
  uit het verzoek>", "bevestiger": "<ondoorzichtige tekenreeks>", "tijdstip": "<UTC>"}`,
  exitcode 0 bij aflevering en ongelijk aan nul bij elke andere afloop. `sectie` en
  `vingerafdruk` zijn verplicht in dat antwoord: de presenter spiegelt ze pas na de positieve keuze
  van de mens, en exact zoals hij ze ontving. Het kanaal telt een aflevering alleen als beide
  exact gelijk zijn aan wat het stuurde; ontbreekt er een, of hoort er een bij een ander verzoek,
  dan is er niets afgeleverd. Dat is wat er gebeurt met een presenter van vóór het veld `sectie`:
  hij toont de code zonder doelnaam en antwoordt toch "afgeleverd", maar zonder spiegel. U ziet
  in dat oude venster dus nog wel een code en klikt OK, maar het voorstel eindigt met *"bevestigingscode
  kon niet aan de beheerder getoond worden; er is niets gewijzigd"* en die code is al verbruikt:
  intypen levert "onbekend of al gebruikt" op. Op de logstroom van de server (stderr) staat dan
  één vaste regel, `[codekanaal] sso-presenter-protocol-oud`, zonder code en zonder doelnaam:
  daaraan ziet u dat het protocol de oorzaak is. Vervang de presenter dan door de meegeleverde
  referentiepresenter of werk uw eigen presenter bij. Het antwoord is precies één regel op
  stdout; een presenter die meer regels schrijft (ook een lege regel erachter) levert niets af,
  wat de eerste regel ook zegt. Er is geen apart versieveld en geen
  terugval naar het oude antwoord. De spiegel bewijst dat de presenter de doelnaam gelezen heeft,
  niet wat hij werkelijk toont; een eigen presenter moet u daarom zelf beoordelen. Overschrijdt de presenter
  `wachttijd_s`, dan telt dat als een NIET-aflevering en niet als een uitzondering, en verbrandt
  het product de zojuist uitgegeven code net zo goed als bij elke andere kanaalstoring. Van dat
  antwoord legt het product alleen `bevestiger` (en `tijdstip`) vast; `sectie` en `vingerafdruk`
  gebruikt het alleen voor die vergelijking. De code staat er per definitie niet in.

  Het codekanaal is bewust een insteekpunt: de configuratie noemt altijd een `soort`, zodat er
  een kanaal bij kan dat de goedkeurende persoon ook kan IDENTIFICEREN. `sso` is dat kanaal: het
  legt de bevestiger vast in het antwoord van het gereedschap. `venster` en `bestand` kunnen dat
  niet — daar toont het antwoord "bevestiger: niet vastgelegd" — en dat is geen gebrek van die
  twee soorten maar een grens die hoort bij wat ze zijn: een code op een scherm of in een bestand
  zegt niet vanzelf wie hem las.

- `toegestaan` - wat er per NetScaler per handeling is toegestaan; zie de volgende
  paragraaf;
- `verboden_adressen` - OPTIONEEL: een lijst adressen (IP's en/of namen) die de firmware-
  upgraderoute (`onderhoud_upgrade_fase`) altijd weigert, ongeacht fase of `-WatIs` - naast de
  vaste naamguard van de runner zelf. Elk element moet een niet-lege tekenreeks zijn zonder
  witruimte; ontbreekt dit veld, dan weigert de runner alleen op naam. Bedoeld voor een adres dat
  voorgoed read-only moet blijven (bijvoorbeeld een labappliance): dat adres hoort in uw eigen
  configuratie, nooit in de broncode van dit product - zie `scripts\README.md`, "Verboden
  adressen".

Vier van de vijf velden (`schrijfscript`, `fixturemap`, `codekanaal`, `toegestaan`) zijn
verplicht zodra `handelen` is opgegeven; `verboden_adressen` is optioneel. Een onbekend veld in
`handelen`, een ontbrekend verplicht veld, of een `verboden_adressen` dat geen lijst van
niet-lege, witruimtevrije tekenreeksen is, weigert het product te starten, met de naam van het
veld in de melding. `codekanaal` is nieuw: een configuratie van vóór deze versie start bewust niet
meer, omdat de bevestigingscode niet langer in het antwoord van het gereedschap staat.

**Het bestandskanaal is een oefen- en automatiseringskanaal.** Het bestaat zodat een
oefenharnas of demo-driver de code kan lezen zonder mens. Een AI-assistent met
bestandsgereedschap op dezelfde machine kan dat bestand óók lezen — en dan is de hele
bescherming weg. Gebruik voor een echte sessie of een opname dus `"venster"`.

Het bestand bevat na elk voorstel de code van het laatst getoonde voorstel: elk voorstel
overschrijft het. Staan er meerdere voorstellen tegelijk open, dan houdt elk zijn eigen code, en
een oudere code blijft tien minuten geldig, ook nadat het bestand is overschreven. De melding na
vijf foute pogingen (zie hierboven) overschrijft het bestand op dezelfde manier, ook als daar op
dat moment een nieuwere, nog geldige code van een andere handeling in stond — die code zelf blijft
gewoon geldig tot inwisseling of verval, u leest haar dan alleen niet meer terug uit dit bestand.
Wisselt u een code in, dan schrijft het product alleen "verbruikt" in het bestand
als daar nog precies die code staat; staat er intussen een nieuwere code in, dan blijft het
bestand ongemoeid en blijft die nieuwere code zichtbaar.

**Het vensterkanaal heeft één harde voorwaarde: de AI-client mag geen scherm- of UI-toegang
hebben tot het bureaublad van de machine waar de server draait.** De code komt op dat bureaublad
terecht; dat het model hem niet kan lezen, hangt dus af van uw omgeving en niet van dit product.
Praktisch, in Claude Desktop: zet computer-use en de browsergereedschappen UIT in het project
waarmee u deze server gebruikt. Kan of wilt u dat niet, laat de server dan draaien op een machine
waar de assistent geen scherm heeft. Anders leest de assistent het venster gewoon mee — precies
dezelfde grens als bij het bestandskanaal hierboven. Het venster sluit zichzelf overigens na tien
minuten, zodat er geen verlopen code op uw scherm blijft staan — op Windows-versies die dat
kunnen; ontbreekt die mogelijkheid, dan blijft het staan tot iemand het wegklikt.

`dienst_lid_uitschakelen` en `dienst_lid_inschakelen` handelen altijd op poort `3389`: die
poort ligt in dit product vast en is geen argument van de gereedschappen. Let op dat `dienst`
bij deze twee de **servicegroup** is (de naam die `dienst_status` onder "servicegroup" toont),
niet de virtuele server.

### De allowlist staat in de configuratie

De sectie `handelen` heeft een verplicht veld `toegestaan`. Daarin staat per doelnaam
per handeling wat is toegestaan: per argument een lijst met waarden, of `true`/`false` voor een
handeling die haar object zelf vormt (vandaag alleen `onderhoud_backup_maken` en
`onderhoud_upgrade_fase`). Ontbreekt het veld, dan start de server niet - een ontbrekende sleutel
stil lezen als "niets toegestaan" zou een derde, onzichtbare toestand maken naast aan en uit. Een
leeg object (`{}`) is geldig en betekent: niets toegestaan.

**Migratie vanaf een configuratie van voor 1.0.** Een configuratiebestand van voor deze versie
kent `codekanaal` en `toegestaan` nog niet; het product start dan niet, met een `Fout: handelen
mist veld: ...`-melding die elk ontbrekend veld noemt. Gemeten voor zo'n bestand (beide velden
ontbreken): `Fout: handelen mist veld: codekanaal, toegestaan; codekanaal zegt WAAR de
bevestigingscode heen gaat - hij staat niet meer in het antwoord van het gereedschap, want dat
leest het model mee. Kies {"soort": "venster"} (een venster op deze machine) of {"soort":
"bestand", "pad": "<absoluut pad>"} om te oefenen; de allowlist komt sinds 1.0 uit de
configuratie en niet meer uit de code. Zet 'toegestaan' in de handelen-sectie: per doelnaam per
handeling de toegestane waarden, of true/false voor een handeling die haar object zelf vormt. Een
lege sectie ({}) is geldig en betekent: niets toegestaan`. Ontbreekt alleen `toegestaan` (met
`codekanaal` al gemigreerd), dan luidt de melding korter: `Fout: handelen mist veld: toegestaan;
de allowlist komt sinds 1.0 uit de configuratie en niet meer uit de code. Zet 'toegestaan' in de
handelen-sectie: per doelnaam per handeling de toegestane waarden, of true/false voor een
handeling die haar object zelf vormt. Een lege sectie ({}) is geldig en betekent: niets
toegestaan`. Voeg beide sleutels toe voordat u opwaardeert. Een lege `toegestaan`-sleutel (`{}`)
is geldig en betekent niets toegestaan; een doel of handeling die er niet in staat, of die op
`false` staat, betekent ook niet toegestaan.

Een doelnaam (de sleutel per doel in `toegestaan`, bijvoorbeeld `netscaler-01` in het voorbeeld
hieronder) mag alleen letters, cijfers, een punt, een streepje of een underscore bevatten, niet de
losse waarde `.` of `..`, en is ten hoogste 32 tekens lang; de server start niet met een doelnaam
die daarbuiten valt, omdat die naam onderdeel wordt van een objectnaam op de appliance zelf
(bijvoorbeeld bij een backup) die zelf niet langer mag zijn dan 63 tekens.

Vier namen kunnen nooit worden vrijgegeven, ook niet door ze in `toegestaan` te zetten:
`nshttps-` en `nsrpcs-` (voorvoegsels), `ns-server-certificate` en `ns-sftrust-certificate`. Ze
staan op een ingebouwde denylist die VOOR de allowlist wordt toegepast en die niet configureerbaar is.

Voorbeeld:

    "handelen": {
      "schrijfscript": "C:\\pad\\naar\\schrijf.ps1",
      "fixturemap": "C:\\pad\\naar\\fixtures",
      "codekanaal": {"soort": "venster"},
      "toegestaan": {
        "netscaler-01": {
          "certificaat_vervangen": {
            "dienst": ["lb_vs_portaal_443"],
            "nieuwcert": ["portaal-2027"]
          },
          "onderhoud_backup_maken": true,
          "config_opslaan": true
        }
      }
    }

Is er meer dan een doelnaam ingesteld, geef dan `doel` mee aan de schrijvende gereedschappen.

## Starten en aansluiten

Sluit uw AI-assistent aan als MCP-client; de client start het product daarna zelf, telkens
als het nodig is. De meeste clients gebruiken een configuratie met een commando en
argumenten, bijvoorbeeld:

```json
{
  "mcpServers": {
    "netscaler": {
      "command": "netscaler-mcp",
      "args": ["C:\\GJK\\netscaler-mcp\\config.json"]
    }
  }
}
```

Staat `netscaler-mcp` niet op het zoekpad (bij een installatie vanaf GitHub staat het in
`.venv\Scripts\`), schrijf dan het volledige pad naar `netscaler-mcp.exe` bij `command`. Een
`cwd` in de clientconfiguratie is niet nodig: relatieve paden in de configuratie tellen vanaf
de map van het configuratiebestand.

Wilt u de configuratie eerst controleren, start het commando dan één keer handmatig:

```powershell
netscaler-mcp "C:\GJK\netscaler-mcp\config.json"
```

Is de configuratie goed, dan blijft het venster staan — dat hoort zo: de server wacht op
een MCP-client. Sluit het venster daarna gewoon; voor het echte gebruik start de client het
commando zelf. Foutmeldingen bij het starten verschijnen als `Fout: ...` op stderr; de
server start dan niet. Zonder argument toont het commando het gebruiksbericht
`Gebruik: netscaler-mcp <pad-naar-config.json>`.

## De openheidsknop

Het optionele veld `openheid` regelt hoeveel een antwoord prijsgeeft aan het taalmodel dat
meeleest. De filter wordt in code berekend; de werking staat volledig beschreven in
[BEVEILIGING-EN-DATASTROMEN.md](BEVEILIGING-EN-DATASTROMEN.md). Kort:

| Stand | Wat het antwoord toont |
|---|---|
| `volledig` (standaard) | echte objectnamen, dagen, bindingen en bewijs |
| `beperkt` | pseudoniemen in plaats van echte namen, met echte aantallen, dagen, ernst en acties |
| `minimaal` | alleen oordelen en aantallen; geen objectnamen en geen pseudoniemen |

De zeven schrijvende gereedschappen gaan gewoon door deze knop: alles wat zij zeggen - een
voorstel, een uitkomst, een weigering en ook een mislukking - gaat door dezelfde openheidsnaad
als een leesantwoord, en een weigering noemt niets meer dan de aanroeper zelf gaf. Ze bestaan bij
`openheid: volledig` en `openheid: beperkt`; in `beperkt` geeft u een pseudoniem mee en krijgt u
een pseudoniem terug - zie "De sectie handelen" onder Configuratie. Bij `openheid: minimaal`
bestaan ze niet: die stand vat een antwoord samen tot tellingen, waar geen voorstel in past, dus
weigert de server te starten zodra er toch een `handelen`-sectie in de configuratie staat. De
lezende gereedschappen werken in alle drie de standen gewoon.

In de stand `beperkt` houdt het product de koppeling tussen pseudoniem en echte naam bij in
het bestand `openheid-vertaaltabel.json`, naast het configuratiebestand (of in
`onderhoud.ledgermap` als die is ingesteld) en nooit in of naast de exportmap: wie de export
aanlevert, kan die map schrijven. Staat het configuratiebestand in de map rond de exportmap, dan
weigert de server bij `beperkt` te starten; zet het dan in een eigen beheermap. Dat bestand is uw enige
decodeersleutel: alleen daarmee vertaalt u eerdere rapportages terug naar echte namen. Bij
nieuwe namen verrijkt het product de tabel en schrijft het bestand opnieuw; bestaande
toewijzingen veranderen daarbij nooit, en een kapotte tabel wordt nooit overschreven of stil
hersteld. Het bestand verdient dezelfde bescherming als de export zelf.

Weigert een antwoord omdat de vertaaltabel kapot is (onleesbaar, of met verdachte inhoud),
dan noemt de melding het pad van het bestand. Herstel het bestand, of zet het aan de kant als
herstel niet lukt, en stel de vraag opnieuw. Houd er bij het aan de kant zetten rekening mee
dat nieuwe pseudoniemen dan niet meer aansluiten op eerdere rapportages.

## Dagelijks gebruik

Stel uw beheervragen gewoon in uw AI-assistent, per hoofdstuk: wat verloopt er, wat breekt er
dan, wat moet ik doen (certificaat); hoe staat de NetScaler ervoor en raakt een bekende CVE hem
(status); hoe staat een dienst ervoor (dienst); wat betekent een term (kennis). Gebruik
`status_ververs` als u actuele gegevens wilt; een scan duurt minuten en draait niet automatisch
bij elke vraag.

De verloopslijst staat op volgorde van impact, niet van dagen: eerst de
certificaten die in gebruik zijn (aan een virtuele server of een SSL-dienst, of
bij een SAML-actie, een SAML-IdP-profiel of een SSL-servicegroup), dan de
certificaten die andere certificaten uitgeven, dan de rest. Staat er "onbekend"
bij een certificaat, dan kon niet worden vastgesteld of het ergens aan hangt -
dat is iets anders dan "los". Dat gebeurt ook als de export voor dat certificaat
een soort binding noemt die deze versie niet leest; de reden noemt die soort.
Verloopt er binnen de horizon niets, dan zegt het antwoord dat in een zin met
het aantal gelezen certificaten, in plaats van een lege lijst.

De dagen tellen vanaf vandaag, niet vanaf het moment van de scan. De appliance
noemt in de export het aantal dagen tot verloop op de dag van de scan; het
product trekt de leeftijd van de export daar vanaf (dezelfde leeftijd als in de
regel "Gegevens van ..." onder elk antwoord) en het bewijs zegt dat erbij:
"gerekend vanaf vandaag, export van N dagen oud". Horizon, klasse en volgorde
gaan over die gecorrigeerde dagen. Een certificaat dat bij een scan van 56 dagen
geleden nog 100 dagen had, staat dus op 44 dagen. Is de datum van de export niet
te lezen, dan is de vervaldatum per certificaat "niet vastgesteld"; het product
toont dan nooit het ruwe getal alsof het vanaf vandaag telt. Hetzelfde geldt voor
toets 5 van `status_update_preflight` en, sinds 1.0.3, voor de TLS-grade (de
begrenzing bij een verlopen certificaat), het vervalcriterium van de TLS-basislijn en
de licentieregel van de scorekaart: een export van onbekende leeftijd geeft daar geen
gunstig vervaloordeel, maar "niet beoordeeld".

Wilt u weten wat het product NIET heeft kunnen lezen, gebruik dan
`rapport_dekking` (hoofdstuk rapport): dat noemt per bron of hij gelezen is en
of de kruiscontrole op de bindingen rondkwam. "2 van de 11 bindingsbestanden
dragen een gat" betekent: van elf bindingsbestanden ging bij twee de kruiscontrole
niet rond, met de reden per bestand - de parentlijst was niet naast zijn objectbron
te leggen, of beide waren leesbaar en noemen gemeten verschillende namen (een parent die
de objectbron niet kent, of omgekeerd). Op een echte
export zijn dat vaak gaten aan de verzamelkant (een objectbron zonder hash, of
een bron die het verzamelscript niet ophaalt); zie OPENSTAANDE-METINGEN.md.
`rapport_vergelijk` (hoofdstuk rapport) vergelijkt twee exportmappen. Kies de
modus die bij uw vraag past: `HA-parity` (HA-pariteit: primary tegenover
secondary), `drift` (nu tegenover een goedgekeurde baseline), `run-diff`
(dezelfde doos op twee momenten) of `pre/post` (rond een wijziging). Configuratieverschillen,
standverschillen en dekkingsverschillen staan in drie gescheiden blokken. Let
op het derde blok: een dekkingsverschil betekent dat een bron aan een kant
niet gelezen is - dat is geen drift.
`rapport_wat_is_er_veranderd` (hoofdstuk rapport) beantwoordt de vraag die u
echt stelt: wat is er anders sinds de vorige scan. Hij kiest de twee mappen
zelf. Staat `bewaren` niet aan, dan zegt hij eerlijk dat er niets te
vergelijken is.
Weet u de naam van een dienst of certificaat niet, vraag dan eerst
`status_namen` (hoofdstuk status): dat noemt per familie welke namen deze
NetScaler kent, met hun aantal en de gegevensleeftijd.
`status_gezondheid` (hoofdstuk status) laat zien wat er DOWN stond toen de scan
liep. Let op het verschil tussen de twee regels onderaan: "storing" gaat over de
appliance, "dekkingsuitspraak" gaat over deze export. Dit is een momentopname,
geen bewaking - er komt nooit een melding uit. De leden van servicegroups telt
hij mee; een lid staat er met zijn positie ("positie N"), nooit met zijn naam. Staan er veel
leden DOWN, dan wordt de storingregel daardoor een lange rij posities die weinig zegt: dat is
een bewuste grens van deze versie. Welke leden het zijn, leest u per dienst met `dienst_status`,
dat een lid met zijn server of adres en poort noemt.
Gaat u iets wijzigen op een appliance met HA, vraag dan eerst `ha_stand`
(hoofdstuk ha): rolverdeling, sync en propagatie, geforceerde stand en het
verschil tussen de running en de saved config, elk aan, uit of onbevestigd.
Een enkele appliance zonder partner staat op `niet van toepassing` bij de twee
standen die een paar beschrijven (rolverdeling en sync en propagatie) - die
houden daar dus ook geen wijziging tegen; geforceerde
stand en config-drift worden ook zonder partner gewoon beoordeeld. Het
antwoord zegt er dan bij dat er geen HA-paar in deze export zit. Config-drift
vergelijkt de inhoud: de kopregels (`# Last modified ...`) en de afsluitende
`Done` die de appliance onder de draaiende configuratie zet, tellen niet mee,
want dat zijn geen configuratieregels. Een export waarin alleen die regels
verschillen, staat dus op `uit`, wat de kopregels ook melden; de kopregels
tellen pas mee bij regels waarin de collector een waarde verving (zie
hieronder). Het deel van een regel dat een geheim kan
dragen (een wachtwoord, een versleutelde waarde) houdt de export achter voor
elke lezer, maar het telt wel mee: verschilt een regel alleen in dat deel -
een gewijzigd bind-, RPC- of monitorwachtwoord dat niet is opgeslagen - dan
staat config-drift op `aan`, met in het bewijs hoeveel regels per kant alleen
in zo'n achtergehouden deel verschillen. Wat er verschilt, staat er nooit.
Dat werkt alleen als de export de waarde draagt. De uitgebrachte collector
vervangt zulke waarden al op de jumphost door `<REDACTED>`, in de draaiende en
in de opgeslagen configuratie; een gewijzigd wachtwoord staat dan als twee
gelijke regels in de export en is niet te vergelijken. Melden de kopregels een
wijziging na de laatste opslag (of zijn ze onleesbaar), dan staat config-drift
daarom op `onbevestigd`, met als reden hoeveel regels per kant zo'n waarde
dragen - en dat houdt de wijziging tegen. Melden de kopregels opslag op of na
de laatste wijziging, dan blijft het `uit` en staat dat aantal in het bewijs.
Wilt u zien WELKE regels verschillen, vraag dan `config_drift` (hoofdstuk
config). Dat noemt per kant de regels die alleen in de draaiende of alleen in
de opgeslagen configuratie staan, met het commandohoofd (bijvoorbeeld
`set lb vserver`) en een telling, en zet de twee kopregels ernaast als bewijs:
laatste wijziging en laatste opslag, in de tijd van de appliance. Het oordeel
rust op de inhoud; zeggen de kopregels "gewijzigd na opslaan" terwijl de inhoud
gelijk is, dan staat dat er als aparte bevinding bij. Verschilt een regel alleen
in het deel dat de export achterhoudt omdat het een geheim kan dragen (een
gewijzigd wachtwoord dat niet is opgeslagen), dan is de inhoud niet gelijk: het
antwoord staat op `aan`, telt de regel mee bij "alleen in running" en "alleen in
saved" en noemt het aantal in de bevinding "verschil in achtergehouden deel" -
in elke stand, maar nooit de regel, het commandohoofd of wat erin verschilt.
Ook dat alleen als de export de waarde draagt: staat er aan beide kanten
`<REDACTED>` van de collector, dan is die regel niet te vergelijken, en melden
de kopregels een wijziging na de laatste opslag, dan staat het antwoord op
`onbevestigd` met dat aantal als reden - niet op `uit`, en zonder de bevinding
dat de inhoud gelijk is.
De regels zelf ziet u
alleen bij openheid `volledig`, hoogstens veertig per kant en elk hoogstens
tweehonderd tekens; een regel met een herkend geheim of een geredigeerde waarde
nooit, ook niet bij `volledig` - dan staat er alleen het commandohoofd met "(regel
met een geheim of een geredigeerde waarde; niet getoond)", en zou dat hoofd zelf
het geheim verraden (zoals `add system user`), dan alleen die melding. Herkend
betekent: een van de kenmerken en vormen die onder "Beveiliging" staan, ook met
witruimte of een onzichtbaar teken voor de dubbele punt van een header
(`Cookie : ...`). Het filter werkt op kenmerken, niet op betekenis: een geheim in
een parameter zonder herkenbaar kenmerk zou bij `volledig` zichtbaar zijn; kies
`beperkt` als u dat risico niet wilt dragen. Draagt een
regel geen van die kenmerken maar wel een letter buiten ASCII (zie
"Beveiliging" voor de reden), dan staat er in plaats daarvan "(regel met
letters buiten ASCII; niet getoond)" - een eigen tekst, want er hoeft geen
geheim in het spel te zijn. Bij `beperkt` ziet u
alleen de commandohoofden met hun telling, bij `minimaal` alleen tellingen. Is
een van de twee configuraties niet te lezen, dan staat config-drift op
`onbevestigd` met de reden, nooit op `uit`. Voor `doel` geldt de doelregel
onder "Welke doelen zijn er".
`beveiliging_verstopte_regels` (hoofdstuk beveiliging) loopt de
negenentwintig regels langs waar geen alarm op staat - van een
content-switching-vserver die de staat van zijn backend niet volgt tot een
syslog-route die de doos nooit verlaat. Per regel staat er of hij geraakt is,
op welke objecten, en waarom dat niet opvalt.
`beveiliging_tls_baseline` (hoofdstuk beveiliging) geeft per virtuele server
een cijfer van A+ tot en met T met de kenmerken die dat cijfer bepalen, en
noemt de versie van de regelset waarop dat cijfer rust. Er staat nooit een
cijfer voor de appliance als geheel: dat zou een gemiddelde zijn van dingen
die niets met elkaar te maken hebben.
`beveiliging_beheervlak` (hoofdstuk beveiliging) beantwoordt in vier
uitspraken of het beheer van de appliance openstaat: blootstelling, transport,
certificaat en RBAC. Elk van de vier is PASS, FAIL of NIET BEOORDEELD - en
"niet beoordeeld" betekent dat een bron niet gelezen kon worden, nooit dat het
in orde is. Dat geldt ook voor een gat binnen een bron: ontbreken de
certificaatbindingen van een vserver in de export, dan is "certificaat" NIET
BEOORDEELD en staat dat gat onder NIET VASTGESTELD - het standaardcertificaat kan
juist daar hangen.
`beveiliging_headers` (hoofdstuk beveiliging) meldt per HTTP-securityheader of
die aanwezig en gebonden, wel gedefinieerd maar niet gebonden, afwezig of niet
beoordeeld is. Een rewrite-action telt alleen via een effectieve RESPONSE-binding.
Voor HSTS telt een FrontEnd-SSL-profiel met `hsts=ENABLED` alleen als een vserver het
bindt: dan is HSTS "aanwezig en gebonden", met de namen van die vservers. Bindt geen
vserver zo'n eigen profiel, dan is het "wel gedefinieerd maar niet gebonden". De
ingebouwde profielen (`ns_default_ssl_profile_...`) staan op elke appliance en tellen
alleen mee als een vserver ze bindt. Is niet te lezen welk profiel een vserver bindt
(de bron of het veld `sslprofile` ontbreekt), dan is HSTS "niet beoordeeld" en staat
het leesgat onder NIET VASTGESTELD. Het product leest HSTS alleen via een profiel: HSTS
die rechtstreeks op een SSL-vserver aanstaat (zonder standaardprofiel), zien
`beveiliging_headers` en `beveiliging_tls_baseline` niet.

### Certificaatgebruik buiten de virtuele servers

Een certificaat hangt niet alleen aan virtuele servers. `certificaat_wat_breekt_er`
noemt ook, met het object en de rol erbij:

- "gebruikt als IdP-certificaat door SAML-actie X" en "gebruikt als
  signing-certificaat door SAML-actie X" (uit `config/authenticationsamlaction`);
- "gebruikt als IdP-certificaat door IdP-profiel Y" en "gebruikt als
  SP-certificaat door IdP-profiel Y" (uit `config/authenticationsamlidpprofile`);
- "gebonden aan SSL-servicegroup Z (CA: ja)" of "(CA: nee)" (uit
  `sslservicegroup_sslcertkey_binding.by-parent.json`).

Die bronnen haalt het verzamelscript vanaf versie 1.1.0 op, samen met
`config/sslservicegroup`: de lijst van SSL-servicegroups waar het
bindingsbestand zijn parents uit haalt. Een appliance zonder SSL-servicegroups is
daarmee vastgesteld: dan is er ook geen certificaat aan een SSL-servicegroup
gebonden, of het bindingsbestand nu zonder parents in de export staat of
ontbreekt. Een export van een ouder verzamelscript draagt deze bronnen niet. Het
antwoord zegt dan per bron onder NIET BEOORDEELD "niet vastgesteld: bron ... niet
in de export", en in de verloopslijst staat een certificaat waarvan de export
verder geen gebruik laat zien op "onbekend", niet op "los": dat een bron
ontbreekt, betekent niet dat er geen gebruik is. Staat een bron wel in de export
maar is hij niet bruikbaar gelezen, draagt hij een verwijzing die niet te lezen
is, of kent `config/sslservicegroup` servicegroups terwijl het bindingsbestand
ontbreekt, dan is dat een leesgat en komt er geen wijzigingsvoorstel.

`certificaat_wat_moet_ik_doen` noemt die gebruiken als handmatige stap, met de
waarschuwing erbij: `certificaat_vervangen` wisselt alleen de binding op een
virtuele server om. Dit product heeft geen schrijfactie voor een SAML-object of
een SSL-servicegroup; zet die verwijzingen dus zelf om en lees ze daarna terug.
Ook het voorstel van `certificaat_vervangen` zelf zegt het: gebruikt iets anders het
certificaat dat de vervanging van de virtuele server haalt (een andere virtuele server, een
SSL-dienst, een SAML-object, een SSL-servicegroup), dan staat in het voorstel "dit
certificaat is ook elders in gebruik: ...; die gebruiken raakt deze vervanging niet, neem ze
zelf mee", met object en rol per gebruik. Is dat niet vast te stellen, dan staat er "gebruik
buiten de binding niet vastgesteld" met de reden - ook als de export een ander doel beschrijft
dan de handeling, geen doel vastlegt, of als deze server sinds de laatste scan zelf al een
handeling uitvoerde. De uitvoering en de bevestigingscode veranderen daar niet door.
`rapport_dekking` noemt de drie bronnen apart: gelezen, niet in de export, of niet
bruikbaar gelezen. Een leesgat in die bronnen - ook een verwijzing naar een certificaat
vanuit een object zonder bruikbare naam - staat bij de leesgaten en maakt de dekking
"gedeeltelijk"; een bron die een ouder verzamelscript niet ophaalde, kost geen dekking.
Wat dit product nog niet volgt, staat in OPENSTAANDE-METINGEN.md.

### Welke doelen zijn er

Weet u niet welke NetScalers deze server kent, vraag dan eerst `status_doelen` (hoofdstuk
status). Dat noemt per doel uit het doelenbestand en uit de allowlist:

- de naam en het adres (een doel dat alleen in de allowlist staat, heeft geen adres);
- hoe oud de export van dat doel is. Een server heeft één export: die beschrijft het doel dat
  het laatst gescand is, en bij elk ander doel staat dat er in deze server geen export van is;
- de laatste onderhoudsrun uit het ledger, met de laatste regel daarvan (fase, uitkomst en
  tijd). De uitkomst is een woord van dit product zelf, nooit tekst uit het ledger, en een
  run-naam die geen veilige run-naam is, wordt niet getoond. Is het ledger niet te lezen, dan
  staat er dat de laatste run niet vast te stellen is - nooit "geen onderhoudsrun";
- welke schrijvende gereedschappen de allowlist daar toestaat, alleen bij naam. Staat er iets
  toegestaan dat op deze server niet is aangemeld (bijvoorbeeld zonder `handelen`-sectie), dan
  staat het apart onder "in de allowlist maar op deze server niet aangemeld";
- of er een SSH-hostsleutel is gepind: ja of nee.

Een credential-targetnaam, een vingerafdruk of een toegestane objectnaam staat er in geen enkele
stand in. Bij `beperkt` zijn namen en adressen pseudoniemen; bij `minimaal` blijven alleen
tellingen over. Is er geen enkel doel ingesteld, dan zegt het antwoord dat in één zin.

**De doelregel.** Elk lezend gereedschap dat uit de export antwoordt, neemt een optioneel
argument `doel` - alle lezende gereedschappen behalve `status_ververs`, `status_doelen`,
`kennis_uitleg`, `rapport_vergelijk` en `onderhoud_upgrade_stand`. `rapport_na_upgrade` valt er
ook onder, en strenger: het leest het ledger van het doel van het rapport (opgegeven, of het
enige ingestelde), maar het CVE-oordeel en de extra stap uit de export, dus die export moet van
dat doel zijn - ook als u `doel` weglaat. Laat u het bij de andere gereedschappen weg, dan
antwoordt het gereedschap zoals altijd, over de export die er staat; de regel
`doel: ...` onder het antwoord zegt welk doel dat is. Geeft u het op, dan is het een controle,
geen schakelaar: deze server heeft één export, dus het doel moet ingesteld zijn én het doel
zijn dat die export beschrijft.

- Een onbekend doel wordt geweigerd zonder het te herhalen.
- Een ander ingesteld doel wordt geweigerd met "de export van deze server beschrijft een ander
  doel; ververs eerst met status_ververs". Bij `volledig` staat de naam van het doel van de
  export erbij; daaronder niet.
- Zegt de export niet welk doel hij beschrijft, dan wordt elk opgegeven doel geweigerd: het
  product kan dan niet bewijzen dat het antwoord over dat doel gaat.
- Heeft deze server de export niet zelf voor dat doel verzameld, dan wordt het doel ook
  geweigerd: "doel niet vastgesteld: de export is niet door deze server voor dit doel
  verzameld; ververs eerst met status_ververs". `scan-doel.txt` in de export bewijst alleen dat
  de doelnaam en het manifest bij elkaar horen, niet wie ze schreef: wie een export aanlevert,
  kan beide schrijven. Daarom legt `status_ververs` na elke geslaagde scan buiten de exportmap
  vast welke export hij voor welk doel verzamelde (zie "Bestanden op schijf"), en telt alleen
  de nieuwste vastlegging van dat doel.
- Bij `beperkt` geeft u het pseudoniem op dat `status_doelen` voor een doel toont. Dat werkt ook
  voor `onderhoud_upgrade_stand`, `rapport_na_upgrade` en de schrijvende gereedschappen. Een
  onbekend pseudoniem krijgt precies dezelfde weigering als een onbekende naam.

Met een opgegeven doel meet `status_update_preflight` de vrije ruimte van dat doel, ook als er
meer dan één doel is ingesteld, en zegt `certificaat_wat_moet_ik_doen` of dit product een stap op
dat doel mag uitvoeren.

### Schrijvende gereedschappen: het bevestigingspatroon

Een schrijvend gereedschap (`certificaat_klaarzetten`, `certificaat_vervangen`,
`dienst_lid_uitschakelen`, `dienst_lid_inschakelen`, `onderhoud_backup_maken`,
`config_opslaan`) handelt nooit
op de eerste aanroep: die
aanroep levert een voorstel op — wat het zou doen en op welk doel — plus een
bevestigingscode van zes tekens die tien minuten geldig is en één keer werkt. Het voorstel leest
niets van de appliance: het doel-etiket erin volgt uit de handeling en haar argumenten, die het
schrijfscript uitrekent vóór het verbindt. Een voorstel zegt dus wat er zou veranderen en op
welk doel, en niet wat de huidige stand van dat object is — wilt u die weten, stel dan eerst de
leesvraag (`dienst_status`, `certificaat_wat_breekt_er`). Pas een
tweede aanroep van dezelfde tool met diezelfde code voert de handeling echt uit; vlak voor
die uitvoering draait het product opnieuw een verse voorbeeldrun en bindt de code aan het
doel dat het schrijfscript op dát moment meldt, dus een doel dat inmiddels is veranderd wordt
geweigerd en verbrandt de code. Vijf foute pogingen met dezelfde code verbranden het
voorstel op dezelfde manier; u ziet dat dan terug als melding in het codekanaal, zonder
dat de code zelf erin staat.

**De bevestigingscode bereikt de AI-assistent niet.** Hij staat niet in het resultaat van het
gereedschap, maar wordt aan de beheerder getoond: in een venster op de machine waar de server
draait, of — om te oefenen — in een bestand dat de beheerder zelf kiest
(`handelen.codekanaal`). Het voorstel in de chat houdt alles wat een mens nodig heeft om te
beslissen en zegt alleen dát de code aan de beheerder is getoond. Het model kan de tweede stap
dus alleen zetten met een code die een mens heeft opgelezen en ingetypt. Kan het kanaal de code
niet tonen, dan verbruikt het product de zojuist uitgegeven code en weigert het de handeling: er
is dan niets gewijzigd. Waar het voorstel vroeger de code zelf droeg, staat nu één regel:

```
- bevestigingscode: aan de beheerder getoond (venster op de server) - vraag de beheerder om de code en roep deze tool opnieuw aan met bevestiging=<code> [vastgesteld]
```

**Twee voorstellen tegelijk: waaraan u ziet welke code bij welke hoort.** Elk openstaand voorstel
krijgt een losse letter, in volgorde van uitgifte: `voorstel A`, `voorstel B`, en zo verder. Die
letter staat op twee plaatsen dezelfde: in het venster of het bestand waarin u de code krijgt, en
in het voorstel dat uw assistent laat zien. Zo ziet u zonder verder zoeken of de code op uw scherm
bij het voorstel in de chat hoort. De letter zegt verder niets: geen objectnaam, geen doel, geen
deel van de code. Zodra een voorstel bevestigd, geweigerd of verlopen is, komt zijn letter weer
vrij en kan hij aan een volgend voorstel worden uitgegeven; twee tegelijk openstaande voorstellen
delen nooit dezelfde letter. Meer dan 26 voorstellen tegelijk kan niet - het 27e wordt geweigerd
en er is dan niets gewijzigd.

Dat is de mens in de lus: de assistent kan de tweede stap niet uit zichzelf zetten, ook niet
binnen dezelfde beurt, want hij kent de code niet. Breekt uw client zo'n bevestigde aanroep
onderweg af (een time-out, of u drukt op stoppen), dan stopt alleen het wachten op het antwoord:
het schrijfscript draait door, de wijziging landt, een volgende handeling wacht netjes tot die
klaar is, en de uitkomst gaat met actie-id en eindstatus naar het logkanaal van de server (zie
SECURITY.md). Daarbovenop blijft de
aanroep-voor-aanroep-goedkeuring van de MCP-host gelden. Het schrijfscript zelf leest het gewijzigde
object na de uitvoering van de appliance terug en meldt dat; het product geeft de eindstatus van
het script letterlijk door — nooit een eigen "teruggelezen"-claim — en behandelt een exitcode
ongelijk aan nul, een ontbrekende actie-id- of doelmarker, een tijdslimiet of een fout als
mislukking, samen met het actie-id en het doel. Het product leest de eindstatus zélf niet: het
beoordeelt de exitcode en de markers en geeft de statusregel door zoals het script hem schreef.
`onderhoud_backup_maken` wijkt op EEN punt af: het schrijfscript leest niet het gewijzigde
object terug, maar zoekt de gemaakte backup terug in de LIJST van de backupcollectie op de
appliance (object, grootte, tijd en niveau) - een teruglezing die het object daar niet
vindt telt als een mislukking, nooit als een waarschuwing. `config_opslaan` wijkt verder af:
daar oordeelt het PRODUCT over de teruglezing, niet het script. Het opslagscript drukt de ruwe
uitvoer van `show ns config` af, direct na `save ns config` in dezelfde sessie gelezen, en het
product toetst die zelf - alleen de vormen die het kent, anders telt de handeling als mislukt.
Drie van de zeven handelingen zijn
ongedaan te maken met hun tegenhanger (`dienst_lid_uitschakelen` en `dienst_lid_inschakelen`
met dezelfde dienst en hetzelfde lid, of `certificaat_vervangen` met het vorige certificaat
als nieuwcert); een klaargezet certificaat ruimt het product zelf niet op - dat is een aparte
beheerstap -, een backup heeft helemaal geen tegenhanger: het is een terugrolpunt, geen
wijziging, en het object blijft gewoon staan, uitsluitend op de appliance - off-box downloaden
hoort daar niet bij - en een upgradefase (`onderhoud_upgrade_fase`) heeft geen tegenhangerfase:
het terugrolpad is diezelfde backup of een hypervisor-snapshot. Opslaan (`config_opslaan`) heeft
evenmin een tegenhanger: de vorige opgeslagen configuratie zit alleen in een backup die u vooraf
met `onderhoud_backup_maken` maakte, en `config_opslaan` controleert niet of die er is.

Welke objecten een schrijvend gereedschap mag noemen, stelt u zelf in onder
`handelen.toegestaan` (zie "De allowlist staat in de configuratie" onder Configuratie). Wat daar
niet in staat, weigeren de vier naamgebonden gereedschappen bij naam of, voor `onderhoud_backup_maken`,
`onderhoud_upgrade_fase` en `config_opslaan` (die geen object hebben), als geheel per doel; de ingebouwde denylist blijft daarnaast altijd
gelden. Zo'n weigering komt terug als een GEWOON antwoord, niet als een foutmelding van het
MCP-protocol: er is niets misgegaan aan de aanroep zelf, alleen de configuratie staat dit
object niet toe. Een client die op de foutvlag let om te zien of een handeling lukte, moet dus
ook de TEKST van een geslaagd antwoord lezen om een weigering te herkennen.

Het antwoord van `onderhoud_backup_maken` draagt een aparte regel `bevestiger:` die zegt wie de
code heeft ingewisseld. De kanalen `venster` en `bestand` identificeren die persoon niet;
de regel meldt dat expliciet. Het `sso`-kanaal levert de identiteit van de bevestiger
(zie "De sectie handelen" hierboven).

Zo leest u een antwoord:

- Onder de kop `NIET VASTGESTELD (geen stille aanname):` staan de leesgaten: bronnen die het
  product niet kon lezen, met de reden. Een leesgat betekent niet "geen impact" — het
  betekent dat het antwoord op dit punt niets kan beweren. Zolang een leesgat openstaat,
  doet `certificaat_wat_moet_ik_doen` geen wijzigingsvoorstel.
- De slotregel `Kennisbasis van <datum>, <n> dagen oud.` meldt hoe oud de kennisregels zijn;
  `Gegevens van <datum>, <n> dagen oud, doel: <naam>, herkomst: <herkomst>.` meldt hoe oud de
  export is, welk doel hij zegt te beschrijven en waar hij vandaan komt:
  `herkomst: verzameld door deze server op <datum> <tijd> UTC` als deze server die export zelf
  voor dat doel verzamelde, anders `herkomst: niet vastgesteld (aangeleverde export)`. Bij die
  tweede staat de doelnaam er wel, maar die komt dan uit de export zelf en is niet vastgesteld.
- Staat er `ONBEKEND` in die regels, dan ontbreekt het kennispakket of draagt de export geen
  bruikbaar tijdstempel. Dat is eerlijkheid, geen storing: het product verzint nooit een
  leeftijd. Een aangeleverde export zonder scan door dit product meldt `doel: niet
  vastgelegd` — ook dat is een feit, geen gok.

**Heeft dit product zelf iets gewijzigd sinds de laatste scan?** Dan staat dat als tweede zin onder
de gegevensleeftijd:

`sinds die scan is 1 handeling uitgevoerd - ververs voor een betrouwbare leescontrole`

(bij meer handelingen: `zijn 2 handelingen`). De zin verdwijnt zodra een verversing is gelukt DIE
alle getelde handelingen kan hebben meegenomen. Een handeling die landt TERWIJL een verversing al
bezig is, telt na afloop van die verversing gewoon door: het product weet niet zeker of de verse
export die handeling al bevat, en laat die twijfel in het midden in plaats van de zin stil te laten
verdwijnen - dus soms blijft de zin staan, met een lager aantal, direct na een geslaagde
verversing. Let op de grens, en die staat in de zin: geteld worden alleen de handelingen die via
dit product zijn uitgevoerd. Wijzigt iemand iets rechtstreeks op de appliance, dan weet dit product
daar niets van en zegt het er dus ook niets over - de gegevensleeftijd erboven blijft de eerste en
de leidende zin.

### Configuratie opslaan

Een wijziging op de NetScaler staat eerst alleen in de draaiende configuratie; pas `save ns
config` maakt haar blijvend. `config_opslaan` doet die stap, met dezelfde twee stappen als elk
schrijvend gereedschap: eerst een voorstel zonder code, dan de uitvoering met de code die de
beheerder doorgeeft. Het werkt alleen met een `onderhoud`-sectie, een doel in `doelen` met een
gepinde `ssh_hostsleutel_vingerafdruk` en `config_opslaan: true` in `handelen.toegestaan` voor
dat doel. Tijdens een openstaande upgradefase op hetzelfde doel weigert het.

Het voorstel zegt wat de export over drift weet - tellingen, nooit een configuratieregel - en dat
de rol pas bij de uitvoering live wordt bepaald:

```
- drift: volgens de export van 2026-09-24: 1 alleen in running, 0 alleen in saved (zie config_drift) [vastgesteld]
- rol: wordt bij de uitvoering live bepaald; op een secondary wordt niet opgeslagen [vastgesteld]
```

Staat config-drift in die export op `onbevestigd` (zie `config_drift`), dan zegt het voorstel dat
er met dezelfde reden bij: `... (zie config_drift), maar config-drift is onbevestigd [niet
vastgesteld]`.

Die tellingen gelden alleen als de export dit doel beschrijft. Beschrijft hij een ander doel, of
zegt hij niet welk doel hij beschrijft, dan staat er `drift: niet vastgesteld` met die reden
("de export van deze server beschrijft een ander doel; ververs eerst met status_ververs").

Bij de uitvoering opent het opslagscript een SSH-sessie met de gepinde hostsleutel, leest
`show ha node` en laat de rol beoordelen: alleen op de primary of een losse appliance (die meldt
zich ook als primary) gaat het verder, want opslaan op een secondary propageert niet. Daarna
`save ns config` en direct daarna `show ns config`. Het product toetst die teruglezing zelf:

```
- config_opslaan: UITGEVOERD (config_opslaan) [vastgesteld]
    bewijs: actie-id config-opslaan-20260924-101440, doel nsconfig/netscaler-01 (<adres>) - config opslaan
- teruglezing: laatste opslag Thu Sep 24 10:14:40 2026 is niet ouder dan laatste wijziging Thu Sep 24 10:12:03 2026 [vastgesteld]
    bewijs: show ns config over SSH, direct na save ns config
```

Toont de teruglezing een wijziging na de laatste opslag, of een vorm die het product niet kent,
dan telt de handeling als MISLUKT en is de code verbruikt; het actieregister krijgt dan een regel
`mislukt`. Een geslaagde opslag krijgt een regel `geslaagd` en telt mee in de zin "sinds die scan
is ... handeling uitgevoerd". Opslaan heeft geen tegenhanger: de vorige opgeslagen configuratie
zit alleen in een backup die u vooraf met `onderhoud_backup_maken` maakte; `config_opslaan`
controleert dat niet. Een nieuwe scan laat daarna zien of de drift weg is.

## Bestanden op schijf

In de exportmap staan de gegevens waarop het product antwoordt:

- `export-manifest.json` — het manifest met per bestand een controlehash;
- `scan-doel.txt` — het doel waarvoor de laatste scan draaide (alleen bij een scan door dit
  product);
- de mappen `objects/` en `bindings/` met de uitgelezen configuratie.

Buiten de exportmap legt `status_ververs` na elke geslaagde scan één regel vast in
`herkomst.jsonl`: het doel, de sha256 van het manifest, het tijdstip (UTC) en de exportmap. Die
staat in `<onderhoud.ledgermap>\herkomst\` als de sectie `onderhoud` is ingesteld, anders in een
map `herkomst` naast het configuratiebestand - bewust niet naast of in de exportmap, want die kan
wie een export aanlevert ook beschrijven. Ligt de herkomstmap toch in de exportmap (omdat het
configuratiebestand of de ledgermap daarin staat), of de exportmap in de herkomstmap, dan start
de server niet en zegt hij welke map in welke ligt. Hetzelfde geldt voor elk ander pad dat de
server leest, uitvoert of schrijft: het configuratiebestand, `kennispad`, `doelen`,
`verzamelscript`, `handelen.schrijfscript`, `handelen.fixturemap`, het codebestand of de presenter,
en `onderhoud.runner`, `onderhoud.ledgermap`, `onderhoud.firmwaremap` en
`onderhoud.actieregister` mogen niet in de exportmap liggen, en de exportmap niet in de ledgermap
of de firmwaremap. De server noemt dan het veld. Alleen `status_ververs` schrijft daar; de lezende
gereedschappen lezen het alleen. De regel draagt de manifest-hash die de scan zelf in zijn
werkmap berekende; staat er na de omwisseling een andere export in de exportmap, dan legt de
server niets vast. Kan de vastlegging niet geschreven worden, of is de export in de exportmap
niet die van de scan, dan zegt het antwoord van `status_ververs` dat, en weigeren antwoorden met
doel en de schrijvende gereedschappen die export tot een volgende scan.

De startcontrole kijkt naar paden, ook in een andere schrijfwijze van dezelfde plek (het
Windows-voorvoegsel `\\?\`, de UNC-vorm daarvan of de beheershare van de lokale schijf), maar
niet naar rechten. Wie in welke map mag schrijven, regelt u zelf:

- **Beheermappen**: de map met het configuratiebestand (en daarmee zonder `onderhoud` de map
  `herkomst`) en de ledgermap. Alleen de beheerder en het account waaronder de server scant
  mogen daar schrijven. In de hele keten van bovenliggende mappen daarvan, tot aan de
  schijfwortel, mag niemand anders een map hernoemen, verwijderen of vervangen: wie dat bij een
  hoger gelegen map kan, kan de hele tak met de herkomstmap erin vervangen, ook zonder rechten in
  de herkomstmap zelf. Let op overgenomen rechten van hoger gelegen mappen.
- **Exportmap**: apart van de beheermappen. Levert een andere partij de export aan, dan mag die
  partij in de exportmap schrijven, maar niet in een beheermap of in de map erboven. Aanbevolen
  indeling: scripts, kennispakket, doelenbestand, actieregister, firmwaremap en ledgermap in
  beheermappen naast de exportmap, nooit erin; de server weigert bij de start elk van die paden
  in de exportmap. De omgekeerde richting, de exportmap binnen een beheermap, weigert de server
  alleen voor de ledgermap, de herkomstmap en de firmwaremap; de map van het configuratiebestand
  en de map van de scripts mogen de exportmap wel bevatten, en dat toetst de server niet. Het
  voorbeeld onder "Configuratie" legt de exportmap zo onder de map van het verzamelscript. Dat is
  alleen veilig als de aanleverende partij in die bovenmap zelf niet kan schrijven, alleen in de
  exportmap; de aanbevolen indeling houdt de exportmap er apart van.
- **Niet doen**: de exportmap en de map `herkomst` naast elkaar onder één bovenmap die de
  aanleverende partij ook kan beschrijven. De server start dan wel, want de herkomstmap ligt
  niet in de exportmap, maar die gedeelde bovenmap is dan de zwakste plek: het herkomstbewijs
  is niet sterker dan de rechten daarop.

In het voorbeeld onder "Configuratie" staan configuratie, kennis en export samen onder
`C:\GJK\netscaler-mcp\`. Dat is alleen veilig zolang die map een beheermap is en de export door
deze server zelf wordt verzameld. Komt de export van een andere partij, zet de exportmap dan in
een eigen map buiten die boom, bijvoorbeeld `D:\aanlevering\export`.

Naast de exportmap kunnen drie zaken verschijnen, met dezelfde naam als de exportmap plus een
achtervoegsel:

| Bestand of map | Betekenis |
|---|---|
| `.vorig` | de vorige export, tijdens het omwisselen even opzij gezet; na een geslaagde omwisseling wordt hij opgeruimd |
| `.mislukt` | het resultaat van de laatste mislukte scan, bewaard als bewijs; elke nieuwe mislukking vervangt de vorige |
| `.lock` | het slotbestand van een lopende scan, met daarin het procesnummer (de pid) |

Het slotbestand voorkomt dat twee scans tegelijk naar dezelfde exportmap schrijven. Blijft
het na een crash staan, dan noemt de weigering van de volgende scan het pad en de pid. U mag
het bestand alleen handmatig verwijderen als er aantoonbaar geen scan meer loopt —
controleer dat de genoemde pid niet meer actief is.

Nog iets dat aan de openheidsstand hangt: **namen noemen bij een halve vraag gebeurt alleen bij
`volledig`.** Vraagt u naar een certificaat of dienst met een halve naam, dan noemt het antwoord
in die stand de namen die de term bevatten, zodat u de vraag kunt aanscherpen. In `beperkt` en
`minimaal` doet het dat niet — geen namen, geen pseudoniemen en ook geen aantal. Daar zijn de
pseudoniemen namelijk stabiel, en dan wordt zo'n wegwijzer een meetinstrument: wie achter elkaar
`a`, `ab`, `abc` … vraagt, leest af hoe een echte naam verdergaat. Om diezelfde reden bestaat de
"bedoelt u …?"-vraag van de schrijvende gereedschappen helemaal niet meer, in geen
enkele stand: een weigering noemt alleen nog een redencode en de waarde die u zelf typte.

In de stand `beperkt` staat naast de vertaaltabel ook `openheid-vertaaltabel.json.lock`: het
slotbestand dat voorkomt dat twee processen tegelijk in de vertaaltabel schrijven. Dit is een
ander slot dan het scan-slotbestand hierboven. Kan het product dat slot niet openen (er staat
bijvoorbeeld een map met die naam), dan zegt het antwoord dat, met het pad.

## Onderhoud: de firmware-upgraderoute

Een firmware-upgrade loopt gefaseerd (zeven fasen, R0 tot en met R6) op de node die aantoonbaar
secondary is. De uitvoering is een APART PROCES, in twee helften met een scherpe grens.

**Waar deze versie staat, in een zin.** De route is op 8-9-2026 eind-tot-eind gedraaid tegen een
standalone VPX-labappliance (66.59 naar 72.57, ledger in `tests/fixtures/runner-ledger-lab-02-20260908/`);
`docs/klant/OPENSTAANDE-METINGEN.md` noemt precies wat die run wel en niet bewijst (geen HA-paar,
geen SDX/FIPS, en het menselijke bevestigingspad apart).

- `scripts\Invoke-GjkUpgradeFase.ps1` en `scripts\GjkUpgrade-Ssh.ps1` (Windows PowerShell 5.1,
  Posh-SSH) doen EEN fase per aanroep. Voor R1 tot en met R5 meten ze wat er op de appliance
  staat en voeren ze de handeling van die fase uit, over een SSH-sessie met een GEPINDE
  hostsleutel — nooit een sleutel die automatisch wordt vertrouwd, en geen instelling die de
  hostsleutelcontrole uitschakelt.
- **R0 raakt de appliance helemaal niet aan.** Die fase legt het terugrolpunt vast en doet de
  voormeting waar R5 straks tegen afgezet wordt, en haalt daarvoor alles uit twee bronnen die er
  al zijn: de registerregel van de backup die eerder met een bevestigingscode gemaakt is, en een
  eerder verzamelde export van de doos. Er gaat in R0 geen enkel commando naar de appliance.
  R6 opent alleen het soakvenster en meet niets.
- Het oordeel — elke poort, elke fase-uitkomst, elke ledgerregel — komt uitsluitend uit het
  product zelf (`python -m nsmcp.upgrade_gate`). De scripts beslissen dat nooit zelf; zie
  `scripts\README.md` voor hoe de twee helften samenwerken.

**Vereist: Posh-SSH 3.2.7**, precies die versie, als PowerShell-module op de machine waar het
product draait: de controle van de hostsleutel is tegen die versie gemeten. De runner controleert
dat zelf bij elke aanroep, laadt alleen die versie en installeert niets — ontbreekt 3.2.7, of is
in dezelfde sessie al een andere versie geladen, dan stopt de fase met een duidelijke melding.
Andere versies mogen ernaast geïnstalleerd staan; ze worden niet geladen. Installeren (of
bijwerken naar precies die versie): `Install-Module -Name Posh-SSH -RequiredVersion 3.2.7
-Scope AllUsers`. Het modulepad van het account waaronder de server draait (`PSModulePath`, in
het bijzonder `%ProgramFiles%\WindowsPowerShell\Modules` en `$PSHOME\Modules`) is daarmee een
beheermap: de pin toetst de versie, en sinds 1.0.2 toetst het transport bij elke start ook de
inhoud tegen het gemeten manifest (zie hieronder), geen herkomst; wie daar mag schrijven, kan een
andere module dus niet stil als 3.2.7 laten laden, maar wel de SSH-route stilleggen. Dat geldt ook voor de modulemap in het eigen profiel van
dat account (de CurrentUser-scope, `Documents\WindowsPowerShell\Modules`): die wordt als eerste
doorzocht, is door dat account zelf te beschrijven en kan door mapomleiding in een
gesynchroniseerde documentenmap liggen. Wijkt de inhoud af, dan stopt de fase (of de live meting) met `[FOUT]` en exitcode 3. Dezelfde
toets los draaien kan ook, zonder iets te wijzigen:
`powershell.exe -NoProfile -File scripts\Get-GjkPoshSshManifest.ps1` vergelijkt een
sha256-manifest over de bestanden van elke geinstalleerde Posh-SSH 3.2.7 met de waarde die over
die versie uit de PowerShell Gallery is gemeten, drukt de volledige lijst af en eindigt met
exitcode 0 (gelijk), 1 (afwijkend) of 3 (niet gevonden).

**De firmwaremap.** `onderhoud.firmwaremap` wijst naar een map met daarin de firmwarebundel
(een `.tgz`-bestand, met de EXACTE naam `build-<tak>-<build>_nc_64.tgz` — de runner kiest nooit
de eerste `.tgz` die hij tegenkomt, en een bestand dat op het bundelpatroon lijkt maar andere
tekens dan cijfers en punten in tak of build draagt, weigert hij voordat de naam in een commando
komt) EN, ernaast, `<bundelnaam>.sha256` met de vendorwaarde erin.
Zonder dat sha256-bestand is de eerste overzetfase (R1) `dicht`: de hashpoort vergelijkt de
waarde van de vendor met een hash die NA de overzet OP DE APPLIANCE ZELF gemeten wordt (niet met
een hash van het lokale bestand voor de overzet) — een bundel zonder vendorwaarde ernaast bewijst
dus niets, en een afgebroken of beschadigde overzet valt zo ook echt op.

**De configuratiesectie `onderhoud`:**

```json
"onderhoud": {
  "runner": "C:\\pad\\naar\\scripts\\Invoke-GjkUpgradeFase.ps1",
  "ledgermap": "C:\\pad\\naar\\ledger",
  "firmwaremap": "C:\\pad\\naar\\firmware",
  "soak_uren": 24,
  "ssh_gebruiker": "nsroot",
  "actieregister": "C:\\pad\\naar\\actieregister.jsonl"
}
```

`onderhoud` staat niet los van `handelen`: een fase is een schrijvende handeling, dus zonder een
`handelen`-sectie weigert de server bij het opstarten. `soak_uren` is minimaal 24 —
kleiner is een startfout. De doelbuild wordt NIET apart geconfigureerd: die volgt uit de ene
firmwarebundel (`build-<tak>-<build>_nc_64.tgz`) die in `onderhoud.firmwaremap` staat. Wilt u
een andere build, zet dan alleen die bundel in de map; er is geen argument dat een andere
doelbuild kiest. Staat er geen bundel of meer dan een in de map, dan is de doelbuild niet
vastgesteld en start geen fase. De reden noemt het lokale pad van de map (of de bundels erin)
alleen bij openheid `volledig`; daaronder staat er "de ingestelde firmwaremap bevat geen bundel"
of "de ingestelde firmwaremap bevat meer dan een bundel".

**De doelbuild tegenover de huidige build en de vloer.** R0 draagt de poort `doelbuild op of
boven de vloer, of bewust geaccepteerd`. Die toetst de doelbuild eerst aan de huidige build: de
build die de doos volgens de export draait (`config/nsversion`, dezelfde bron als
`status_overzicht`). Ligt de doelbuild in een andere releaselijn dan de huidige build,
bijvoorbeeld een 14.1-bundel op een doos die 13.1 draait, dan sluit R0 altijd, ook met
`doelbuild_geaccepteerd=true`, met de reden "de doelbuild ligt in een andere releaselijn dan de
huidige build; dit gereedschap doet geen overstap tussen releaselijnen". Draagt de export geen
leesbare build, dan sluit R0; met `doelbuild_geaccepteerd=true` opent de poort als menselijke
beslissing, en het bewijs zegt "huidige build niet bekend".

Daarna toetst de poort de doelbuild aan de vloer: de hoogste fix-build van de eigen tak van de
doos in het kennispakket - dezelfde vloer als `status_update_advies` noemt, en op een
FIPS/NDcPP-doos die van de FIPS-trein. De poort opent op bewijs als de doelbuild op of boven de
vloer ligt, in dezelfde releaselijn als de huidige build, en hoger is dan de huidige build. Is de
doelbuild gelijk aan of lager dan de huidige build (een herinstallatie of een downgrade binnen de
lijn), dan sluit R0 met de reden "doelbuild niet hoger dan de huidige build (herinstallatie of
downgrade): menselijke acceptatie vereist; zet doelbuild_geaccepteerd=true als dat bewust is",
ook boven de vloer; met `doelbuild_geaccepteerd=true` opent de poort dan als menselijke
beslissing. Het bewijs noemt ook het kennispakket waar de vloer uit komt, met versie
en datum ("kennispakket 2026.09 van 2026-09-06"), en draagt een WAARSCHUWING als dat pakket
ouder is dan 30 dagen op de dag dat R0 draait: de vloer kan dan lager liggen dan wat de
leverancier nu voorschrijft. Die waarschuwing verandert de uitkomst niet; ververs het
kennispakket en de `kennispin` als u hem ziet. Ligt de doelbuild onder de vloer, dan sluit
R0, tenzij u bij R0 bewust `doelbuild_geaccepteerd=true` meegeeft: dan opent de poort als
menselijke beslissing, en het bewijs noemt doelbuild, vloer, bulletin en huidige build. Is er
geen vloer vast te stellen (geen kennispakket, een kennispakket zonder `kennispin` in de
configuratie, een tak die in geen bulletin staat, een platform dat niet vaststaat), dan sluit R0 met de reden "geen vloer bekend in het kennispakket voor deze
tak"; met `doelbuild_geaccepteerd=true` opent de poort ook dan als menselijke beslissing, met
"geen vloer bekend" en "bewust geaccepteerd" in het bewijs. Ligt de doelbuild op een andere tak
dan de vloer, dan sluit R0 ook mét die acceptatie: twee takken zijn niet te vergelijken. Op een
FIPS/NDcPP-doos gaat de vloer van de FIPS-trein niet mee naar de faserunner en de acceptatie
dan ook niet: daar sluit R0. De reden staat in de sluitregel van R0 en in `terugrolpunt_vast`.
Geeft u daar toch `doelbuild_geaccepteerd=true` mee, dan weigert het voorstel al voordat er een
code is, met die reden. Gaat de acceptatie wel mee, dan zegt het voorstel dat R0 de poort als
mens opent, in plaats van "tenzij doelbuild_geaccepteerd=true".
`onderhoud_upgrade_plan` en het voorstel van elke fase noemen huidige build, doelbuild, vloer en
dit oordeel vooraf, met de bulletins die onder de vloer open blijven.
Huidige build en vloer komen alleen uit een export van dit doel. Beschrijft de export van de
server een ander doel, dan weigert elke fase al bij het voorstel, voordat de faserunner iets
doet: "de export van deze server beschrijft een ander doel; ververs eerst met status_ververs"
(bij `volledig` met de naam van dat doel). Zegt de export niet welk doel hij beschrijft, dan luidt
de weigering "de export van deze server zegt niet welk doel hij beschrijft; ververs eerst met
status_ververs". Een export die niet door een scan van deze server voor dit doel is gemaakt
(zonder `scan-doel.txt`, of zonder de vastlegging van `status_ververs` buiten de exportmap, zie
"Bestanden op schijf") blokkeert zo de hele upgraderoute tot een verversing, met "doel niet
vastgesteld: de export is niet door deze server voor dit doel verzameld; ververs eerst met
status_ververs". Hetzelfde geldt voor de driftregel van `config_opslaan` en R1 en de
gebruiksregel van `certificaat_vervangen`: die zeggen dan "niet vastgesteld" met die reden. Weigert de uitvoering hierom voordat de code is ingewisseld, dan zegt het antwoord dat
de code niet is ingewisseld en geldig blijft tot hij verloopt. Landt zo'n scan pas na het
inwisselen, dan start er niets en zegt het antwoord dat de bevestigingscode verbruikt is.

**Een run, een bundel.** De doelbuild wordt bij elke fase opnieuw uit de map gelezen. R0 legt in
zijn `fase_gestart`-regel vast met welke doelbuild hij startte, en R1 tot en met R6 van dezelfde
run weigeren een bundel die daarvan afwijkt: "de doelbuild van deze run (R0) wijkt af van de
bundel in onderhoud.firmwaremap; start een nieuwe run". Het voorstel weigert al zodra die
afwijking leesbaar is, voordat er een code bestaat; de uitvoering weigert daarnaast ook een run
waarvan de R0-regel de doelbuild niet leesbaar draagt. Wisselt u de bundel, begin dan een nieuwe
run met een verse R0.

`actieregister` is OPTIONEEL: het pad naar het JSONL-bestand waarin dit product elke UITGEVOERDE
schrijvende handeling vastlegt - een JSON-object per regel met `tijd`, `tool`, `doel`, `actieid`,
`uitkomst` (`geslaagd` of `mislukt`), `bevestiger`, en voor een backup `objectnaam` (de naam die het
product zelf vormde en teruglas op de collectie). Een voorstel of controle vooraf schrijft niets.
R0 leest hieruit de backupregel voor zijn terugrolpunt. Staat de sleutel er niet, dan wordt er niets
geschreven en blijft de backup-poort van R0 `niet beoordeeld` — dat faalt dicht, het is nooit
`geslaagd`. Kan de regel niet geschreven worden, dan is de handeling toch uitgevoerd en zegt het
antwoord uitdrukkelijk dat het register niet is bijgewerkt.

De gepinde SSH-hostsleutel staat, anders dan de rest van `onderhoud`, PER DOEL in het
doelenbestand, naast de bestaande velden:

```json
{"naam": "netscaler-02", "adres": "10.0.0.2", "credentialTarget": "GJK/NetScaler/.../nitro-write",
 "certificaat": "vingerafdruk", "vingerafdruk": "AA:BB:...",
 "ssh_hostsleutel_vingerafdruk": "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f"}
```

Een doel dat in `handelen.toegestaan` `onderhoud_upgrade_fase: true` krijgt maar geen
`ssh_hostsleutel_vingerafdruk` draagt, weigert de server bij het opstarten — de runner pint de
hostsleutel en accepteert er nooit een. Draagt GEEN doel de handeling, dan is dat geen fout: het
gereedschap meldt zich dan simpelweg niet aan.

**Het gereedschap `onderhoud_upgrade_fase`.** Voert een van de zeven fasen (R0 t/m R6) uit op de
node die aantoonbaar secondary is, elke fase met een eigen bevestigingscode — hetzelfde
voorstel-dan-code-patroon als elk ander schrijvend gereedschap in deze handleiding. Het antwoord
zegt alleen dat de fase GESTART is: het oordeel komt uit het ledger, niet uit dit antwoord — vraag
het na met `onderhoud_upgrade_stand`. Dat is geen omslachtigheid maar de kern van het ontwerp: R1
duurt gemeten circa 8 minuten alleen al aan overzetten, en dat is langer dan de tijdslimiet van elk
schrijvend gereedschap (5 minuten) toestaat — de fase draait daarom losgekoppeld door, en dit
gereedschap wacht alleen tot de fase echt begonnen is (de ledgerregel `fase_gestart`, hoogstens 20
seconden). Al tijdens dat wachten weigert elk ander schrijvend gereedschap op dat doel, met de
reden dat de server nog op die regel wacht en tot wanneer; `onderhoud_upgrade_stand` meldt
hetzelfde.

Verschijnt die regel niet binnen die 20 seconden, dan antwoordt het gereedschap dat de fase niet
als gestart telt, en dat de faserunner losgekoppeld gestart is en nog steeds kan draaien. Een
trage start (een koude Windows PowerShell, een virusscanner die de module nakijkt) ziet er in het
ledger precies zo uit als een runner die nooit begon. Daarom houdt de server het doel vanaf dat
moment vast: elk schrijvend gereedschap op dat doel, ook een nieuw voorstel voor dezelfde fase en
run, weigert met de reden dat de start van die fase nog onbeslist is, tot de regel `fase_gestart`
alsnog verschijnt (dan geldt de gewone weigering voor een openstaande fase) of de tijdslimiet van
die fase verstrijkt, gerekend vanaf de start van de faserunner (dan vervalt de blokkade, en het
eerstvolgende antwoord zegt dat met een regel `onbesliste start`). Een tweede geconfigureerde naam
die alleen in hoofdletters of in het domeindeel van een FQDN verschilt, valt onder dezelfde
blokkade; een naam met een ander eerste deel is een ander doel, en twee doelen op hetzelfde adres
start de server niet (zie "Het doelenbestand"). Het antwoord op de time-out noemt het tijdstip
waarop de blokkade uiterlijk vervalt; `onderhoud_upgrade_stand` toont de onbesliste start als eigen regel, met het
tijdstip waarop de faserunner startte. Die blokkade zit
in het geheugen van de server: na een herstart beslist alleen het ledger weer. De faserunner zelf
schrijft zijn regel `fase_gestart` bovendien alleen als er op dat doel geen fase open staat binnen
zijn tijdslimiet, en stopt anders met exitcode 2 (zie SECURITY.md, "Er schrijft er hooguit één
tegelijk", en scripts/README.md).

Argumenten: `fase` (verplicht, `R0` t/m `R6`), `run` (het run-id, verplicht bij elke fase behalve
`R0` — R0 vormt zelf een nieuw run-id, met één uitzondering: staat er op dat doel nog een R0 open
die over zijn tijdslimiet heen is, dan pakt R0 die run op in plaats van er een tweede naast te
zetten), `snapshotverwijzing` (verplicht, alleen bij `R0`: de naam van de hypervisor-snapshot),
`doelbuild_geaccepteerd` (alleen bij `R0`: een doelbuild onder de vloer, zonder bekende vloer,
zonder bekende huidige build of niet hoger dan de huidige build bewust accepteren; nooit een
andere releaselijn, zie
"De doelbuild tegenover de huidige build en de vloer"),
`drift_geaccepteerd` en `oude_buildbomen_opruimen` (beide alleen bij `R1`), en `standalone_geaccepteerd`
(elke fase die de rol meet): een appliance ZONDER HA-peer meldt zichzelf altijd als Primary, dus de poort
`doel is secondary` gaat daar per ontwerp dicht; een upgrade betekent dan downtime en alleen een mens kan
dat accepteren. Met een peer aanwezig blijft Primary altijd dicht, ook met deze vlag. Een fase-eigen argument bij de verkeerde fase, of een `fase` buiten `R0`..`R6`, wordt
geweigerd voor er iets gebeurt.

Zes weigeringen gelden voordat er iets gebeurt: een codekanaal dat de bevestiger niet kan
identificeren (`venster`/`bestand` kunnen dat niet — alleen `sso`), een fase die al open staat op
dit doel, een lopend soakvenster (ook voor R0 van een volgende run), een vorige fase die niet
gesloten is, deze fase zelf die in het ledger van deze run al gesloten staat, en een onbekend of
verkeerd geplaatst argument. Voor R1 tot en met R6 komt daar de bundel bij die afwijkt van die van
R0 in dezelfde run (zie "Een run, een bundel").

Daarna toetst de runner voor iedere schrijfpoging in R1 tot en met R4 verse voorwaarden via
zijn eigen SSH-sessie. De lokale node moet aantoonbaar secondary zijn en de gelezen NSIP moet
bij het doel horen. R1 toetst daarnaast de vrije ruimte, de lokale firmwarebundel tegenover
de sidecar en de driftpoort (`drift afwezig of bewust geaccepteerd`). Die poort meet R1 zelf: in
dezelfde sessie leest het `show ns config`. Ze opent op een van drie manieren - aantoonbaar niets
gewijzigd sinds de laatste opslag (bewijs), eerst opgeslagen met `config_opslaan` op de primary
of het standalone-doel (daarna opent dezelfde meting op bewijs), of bewust geaccepteerd met
`drift_geaccepteerd=true` (mens, met de gemeten stand in het bewijs). Is de configuratie gewijzigd
na de laatste opslag en is dat niet geaccepteerd, dan sluit de poort met die keuze als reden; een
stand die niet te lezen is telt nooit als open. Opslaan binnen R1 gebeurt bewust niet: R1 draait
op de secondary, en daar propageert opslaan niet. Het voorstel van R1 noemt de drift uit de
export en deze drie keuzes vooraf. Zonder open driftpoort begint de upload niet; na upload
blijft ook de hashcontrole op de appliance verplicht. De voorafgaande
poorten komen als `voorpoort` in het ledger. Bij ontbrekend, mislukt of niet-open bewijs volgt
geen schrijfactie. De sluitende beoordeling vereist de voorpoort van dezelfde run, fase,
actie en poging; een eerdere open poort wordt niet hergebruikt na een retry of failover.
Ook de fasevolgorde wordt vooraf getoetst: zonder geslaagde vorige fase begint de schrijfactie
niet.

R2 gebruikt voor elke poging een eigen resultaatbestand. Vooraf moet vaststaan dat dit pad
niet bestaat, ook niet als symbolische link; achteraf wordt uitsluitend dat resultaat gelezen.
Een oud precheckresultaat of een mislukte lezing kan geen succes bewijzen. Het vendorresultaat en zijn controles bepalen
het oordeel; de vendor-exitcode alleen doet dat niet. R5 vergelijkt de gelezen tak en volledige
build exact met het bevestigde doel. Een mislukte configuratielezing levert geen anker op;
een geslaagde maar lege lezing wordt expliciet als leeg benoemd.

Zolang er een fase openstaat op een doel, weigeren ook de ÁNDERE schrijvende gereedschappen op dat
doel — de fase draait immers losgekoppeld door nadat dit gereedschap heeft geantwoord, EN dat geldt
net zo goed voor een herhaling van precies diezelfde fase en run: dit product kan een losgekoppelde
faserunner niet stoppen of zelfs maar waarnemen, dus de enige aanroep die het ooit veilig kan
onderscheiden van een tweede schrijver tegen dezelfde doos is er geen. Die weigering blijft niet
eeuwig hangen: staat een fase langer open dan zijn tijdslimiet zonder dat er een sluitregel in het
ledger komt, dan geldt hij als mislukt met reden tijdslimiet en vervalt de weigering vanzelf — pas
DAN mag dezelfde fase met dezelfde `run` opnieuw starten (bij `R0` hoeft u die `run` niet te
noemen: is de openstaande R0 op dat doel over zijn tijdslimiet heen, dan pakt `R0` die run vanzelf
op). Draait er op dat doel nog een fase BÍNNEN zijn tijdslimiet — ook een fase van uw eigen `run` —
dan weigert elke aanroep, zonder uitzondering en zonder een manier om dat eerder dan de tijdslimiet
te omzeilen: een fase die echt loopt deelt dit product met niemand, ook niet met zichzelf.
SECURITY.md beschrijft dit, met de tijdslimieten en de één uitzondering (een VERLOPEN eigen R0),
onder "Er schrijft er hooguit één tegelijk".

Dat is de OPEN kant. Staat een fase in het ledger van uw `run` al GESLOTEN — `geslaagd`, `mislukt`
of `poort dicht`, om het even welke — dan weigert een herhaling van precies die fase met precies
die `run` altijd en meteen, vóór de faserunner start: een gesloten fase wordt nooit opnieuw
beoordeeld. Dat is geen tijdslimiet die afloopt; er is geen wachten dat helpt. Wilt u die fase
opnieuw proberen, dan doet u dat als een NIEUWE run: een verse `R0` met een nieuw run-id (en, bij
`R0`, een nieuwe of dezelfde snapshotverwijzing) — nooit een tweede `fase_gestart` op een `run` die
deze fase al sloot.

**Het gereedschap `onderhoud_upgrade_stand`.** Leest het ledger van een upgraderun en zegt waar
die staat — het antwoord op `onderhoud_upgrade_fase`'s eigen FASE GESTART, dat zelf geen oordeel
geeft. Leest uitsluitend, wijzigt niets en bestaat daarom zodra het hoofdstuk `onderhoud`
aanstaat en er een `onderhoud`-sectie in de configuratie staat — zonder `handelen`-sectie en
zonder een vermelding in `toegestaan`, want er is niets om toe te staan. Het antwoord leest NOOIT
het `.log`-bestand naast het ledger: dat is diagnostiek, geen waarheid.

Argumenten: `doel` (optioneel als er precies één doel is ingesteld) en `run` (optioneel; zonder
`run` de laatste run op dat doel). Per fase R0 t/m R6 een van `gestart`, `poort dicht`,
`geslaagd`, `mislukt` of `niet beoordeeld`, met de poorten van die fase eronder en hun eigen
`open`/`dicht`/`niet beoordeeld` met bewijs. Een fase zonder ledgerregel is eerlijk
`niet beoordeeld` — nooit een stille aanname. Daarna de leeftijd van de laatste ledgerregel, en —
alleen als er een soakvenster op dit doel staat — `loopt` met de vroegste eindtijd, of
`verstreken`: dat laatste is nadrukkelijk geen goedkeuring om verder te gaan, de failover en de
tweede node blijven een menselijke handeling. Het plan (`onderhoud_upgrade_plan`) zegt daarna:
na de eindvalidatie volgt `config_opslaan` op de primary.

**Het gereedschap `rapport_na_upgrade`.** Zet de stand van voor en na een upgrade naast elkaar,
in drie blokken op deze versie (een vierde — de dekking van beide exports naast elkaar — wacht op
een volgende release; zie hieronder). Leest uitsluitend, wijzigt niets, en bestaat zodra het
hoofdstuk `rapport` aanstaat (standaard aan) en er een `onderhoud`-sectie in de configuratie staat.

- **Het CVE-oordeel op de nieuwe build** — dezelfde motor en hetzelfde vocabulaire als
  `status_cve_controle` (`GERAAKT` / `NIET GERAAKT` / `NIET VASTGESTELD`), tegen de build die
  net geïnstalleerd is. Dit blok controleert eerst of de geladen export dat OOK werkelijk is:
  zonder een sluitregel van R5 in het ledger, met een export ouder dan die sluitregel, of met een
  build die niet overeenkomt met de build die R5 zelf live las na de upgrade, antwoordt dit blok
  `NIET VASTGESTELD` met de reden erbij — nooit een oordeel op een oudere export, gepresenteerd
  alsof die de nieuwe build was.
- **De extra stap na de upgrade, als eigen controle.** Sommige bulletins vragen na de upgrade nog
  een handmatige of scripted stap (bijvoorbeeld een parameter die de vendor als workaround noemt).
  Dit gereedschap leest die stap uit het kennispakket, zoekt het bijbehorende object en de
  bijbehorende parameter op in de nieuwe export, en zegt `NIET GERAAKT` (stap uitgevoerd),
  `GERAAKT` (stap moet nog) of `NIET VASTGESTELD` — met reden "build te oud, stap nog niet
  mogelijk" als het veld in deze build nog niet bestaat, of "de extra stap noemt geen herkenbaar
  commando" als de zin in het kennispakket geen `set ns <object> ... -<parameter>` bevat. Dit is
  altijd een EIGEN controle, nooit een bijzin bij het CVE-oordeel: een build kan `NIET GERAAKT`
  zijn door de CVE zelf terwijl de extra stap nog openstaat, of andersom. Draagt de CVE-regel
  `naconfiguratieVerplicht`, dan zegt het CVE-oordeel op of boven de fix-build zelf al
  `NIET VASTGESTELD` (zie "Verplichte naconfiguratie" hierboven).
- **Het genormaliseerde configuratie-anker**, met per soort het aantal uitgesloten blob-regels
  (`set ns encryptionParams`, `set ns rpcNode`, `-encrypted`) — elk `gelijk`, `verschillend` of
  `niet vastgesteld`. Deze komen uitsluitend uit het ledger: de regel `voormeting_vast` van R0 en
  de sluitregel van R5. Ontbreekt een van beide, of staat de bijbehorende poort niet op `open`,
  dan is het anker `niet vastgesteld` — nooit `gelijk`, en de reden noemt welke kant ontbreekt.
  De twee ankers komen uit verschillende bronnen: dat van R0 uit de export van vóór de upgrade,
  dat van R5 uit een live lezing erna. Het antwoord zegt dat er zelf bij, want een verschil hoeft
  daardoor geen configuratiewijziging te zijn. Ook de acht familietellingen staan in dit blok,
  maar die blijven vandaag `niet vastgesteld`: R5 schrijft er nog geen meting voor. Zie
  `OPENSTAANDE-METINGEN.md`.

Argumenten: `doel` (optioneel als er precies één doel is ingesteld) en `run` (optioneel; zonder
`run` de laatste run op dat doel). Het doel van het rapport (opgegeven, of het enige ingestelde)
moet ook het doel van de export zijn (de doelregel hierboven): beschrijft de export een ander
doel, of zegt hij niet welk, dan komt er geen rapport maar de weigering met de reden.

**Wat deze versie NIET doet.** Blok 1 van het ontwerp — de dekkingsuitspraak van beide exports
(voor en na) naast elkaar - is niet aangesloten: de bestaande vergelijkingsmotor en selectie
van de vorige bewaarde export worden vanuit dit rapport nog niet aangeroepen. Het antwoord
noemt dat blok expliciet als "niet beoordeeld in deze versie", nooit als een stille leegte.
Zie `OPENSTAANDE-METINGEN.md` voor de precieze status.

## Als er iets misgaat

- **Een scan mislukt.** De vorige export blijft in vrijwel alle gevallen gelden; de
  melding beschrijft wat er gebeurde. De gegevensleeftijd in het eerstvolgende antwoord
  laat zien op welke gegevens u antwoordt. De melding noemt daarnaast de fase waarin de
  scan strandde: DNS, TCP, TLS, NITRO-login of identiteit. Die indeling komt uit het
  verzamelscript zelf, nooit uit de foutmelding erboven - een andere foutzin verandert de
  fase dus niet. Kon dit product geen fasegegevens vaststellen (of maar een deel), dan
  staat dat er eerlijk bij als "niet vastgesteld". Staat `openheid` op `beperkt` of
  `minimaal`, dan noemt de melding wel de exitcode en de fase, maar niet de eigen uitvoer van
  het verzamelscript - die staat er dan als "scriptuitvoer niet getoond op deze stand". Wat het
  script in zijn werkmap schreef, vindt u in `.mislukt` naast de export (zie de tabel hierboven).
- **Een omwisseling is onderbroken.** In het uitzonderlijke geval dat het proces precies
  tijdens het omwisselen stopt, kan de export als `.vorig` naast de map staan. De
  eerstvolgende scanpoging herstelt dat zelf, nog voordat hij scant.
- **Een generieke foutmelding.** De tekst "Onverwachte fout bij het beantwoorden van deze
  vraag. De details van deze fout zijn niet bewaard: dit product logt alleen zijn
  schrijfhandelingen." wijst op een interne fout. Meld die bij GJK Partners, met de vraag die u stelde en het moment
  waarop.

## Beveiliging

De beveiligingsverklaring — kwetsbaarheden melden, wat het product wel en niet doet, en de
grenzen van de garanties — staat in [SECURITY.md](SECURITY.md) in deze map. Welke gegevens
het product leest, waar die blijven en welke knoppen u zelf heeft, staat in
[BEVEILIGING-EN-DATASTROMEN.md](BEVEILIGING-EN-DATASTROMEN.md).

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
geen geslaagde fase. Het faseoordeel komt uit het ledger.

De twaalf bevindingen uit de externe review zijn in deze integratie verwerkt
(14-9-2026), met drie bewuste afwijkingen van de aangedragen patches: een MCP-host
binnen een Windows Job Object wordt niet geweigerd maar gemeten (zie "Gemeten: de
faserunner en het Job Object van de host" in OPENSTAANDE-METINGEN.md); de vendorbanner
wordt herkend op zijn gemeten eerste zin, niet op een exacte tweede zin; en de
volledigheidseis aan `show ha node` geldt alleen op het pad dat met
`standalone_geaccepteerd` opent. Historische ledgergegevens zijn niet herschreven.
