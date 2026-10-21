# Beveiliging en datastromen

**netscaler-mcp** · versie 1.0.2 · 21-10-2026

Dit document beantwoordt de vragen die een IT-beheerder of security officer stelt voordat
dit product een omgeving in mag: welke gegevens leest het product, waar blijven
die, wat verlaat de omgeving, en welke garanties gelden daarbij.

## Wat dit product is

Dit product beantwoordt beheervragen over een Citrix NetScaler: welke
certificaten verlopen binnenkort, wat valt er dan uit, en welke wijziging is nodig. Het werkt
op een export van de NetScaler-configuratie die lokaal bij u staat.

Twee eigenschappen bepalen het karakter:

- **De antwoorden worden berekend, niet bedacht.** Deterministische code rekent elk antwoord
  uit op basis van de export en een kennispakket. Een taalmodel formuleert alleen de taal
  eromheen; het leidt geen conclusies af. Dezelfde vraag op dezelfde gegevens geeft daardoor
  dezelfde uitkomst; alleen de leeftijdsstempels tellen door.
- **Schrijven gebeurt alleen met een mens in de lus.** Het is geen monitoringtool en geen
  autonome beheeragent. Zeven gereedschappen kunnen de NetScaler wijzigen (een certificaat
  klaarzetten, een certificaat vervangen, een lid van een servicegroup uit- of weer
  inschakelen, een backup maken, één fase van een firmware-upgrade uitvoeren, of de draaiende
  configuratie opslaan); geen van de zeven handelt op de eerste aanroep — die levert een voorstel en een
  bevestigingscode op die tien minuten geldig is en één keer werkt. Pas een tweede aanroep met
  die code handelt; vlak voor die uitvoering draait het product opnieuw een verse voorbeeldrun
  en bindt de code aan het doel dat het schrijfscript op dát moment meldt, dus een doel dat
  sindsdien is veranderd wordt geweigerd en verbrandt de code. Het schrijfscript zelf leest het
  gewijzigde object van de appliance terug en meldt dat; het product behandelt een exitcode
  ongelijk aan nul, een ontbrekende actie-id- of doelmarker, een tijdslimiet of een fout als
  mislukking en geeft de eindstatus van het script letterlijk door. Het leest die eindstatus zélf
  niet — het beoordeelt de exitcode en de markers — en het verzint zelf geen
  "teruggelezen"-claim, met één uitzondering: bij `config_opslaan` oordeelt het script nergens
  zelf en toetst het product de ruwe teruglezing van `show ns config`. Drie van de zeven zijn
  omkeerbaar via hun
  tegenhanger; het klaarzetten van een certificaat wordt niet door het product ongedaan gemaakt
  (aparte beheerstap), een backup heeft geen inverse: die is zelf al het terugrolpunt, geen
  wijziging om ongedaan te maken — en een firmware-upgradefase heeft geen tegenhangerfase: het
  terugrolpad daarvoor is diezelfde backup of een hypervisor-snapshot (zie verderop) - en ook
  opslaan heeft geen inverse: de vorige opgeslagen configuratie zit alleen in een backup die
  vooraf met `onderhoud_backup_maken` is gemaakt, en `config_opslaan` controleert dat niet. Het schrijven
  zelf gebeurt voor vijf van de zeven door het gereviewde PowerShell-schrijfscript van het
  demolab, voor de zesde door de upgraderunner en voor de zevende door een klein SSH-script naast
  die runner, elk als apart proces gestart - dit product bevat zelf geen NITRO-schrijfclient. De toegestane objectlijst komt uit de CONFIGURATIE, niet uit
  code: de sectie `handelen.toegestaan` zegt per doelnaam per gereedschap welke waarden zijn
  toegestaan, en het product valideert die sectie bij het opstarten. Voor dit demolab staat de
  configuratie vandaag zo: `certificaat_klaarzetten` neemt alleen een `certnaam` en accepteert
  daarvoor alleen `gjk-zaakportaal-2027`; het noemt geen dienst. `certificaat_vervangen`
  accepteert alleen de dienst `lb_vs_gjk_zaakportaal_443` met als `nieuwcert`
  `gjk-zaakportaal-2027` of, als terugrol-doel, `gjk-zaakportaal-2026`.
  `dienst_lid_uitschakelen`/`dienst_lid_inschakelen` accepteren alleen de servicegroup
  `gjkdemo_sg_proefdienst` met lid `gjkdemo_web01` of `gjkdemo_web02`, altijd op poort `3389` -
  die poort ligt als `MEMBER_PORT` in dit product vast en is geen argument. Los van die
  CONFIGUREERBARE allowlist draagt dit product een INGEBOUWDE denylist in code: namen die met
  `nshttps-` of `nsrpcs-` beginnen en de certificaten `ns-server-certificate` en
  `ns-sftrust-certificate` worden altijd geweigerd, ook als de allowlist ooit ruimer wordt - dat
  zijn de beheerdiensten en beheercertificaten van de appliance zelf. Die denylist wordt bij het
  opstarten EN bij elke aanroep voor de allowlist gecontroleerd, dus een allowlistregel kan een
  denylistnaam nooit vrijgeven. Zie `handelen.toegestaan` in de configuratie, en `MEMBER_PORT`,
  `DENIED_PREFIXES`, `DENIED_NAMES` en `validate()` in `src/nsmcp/handelen.py`, plus de validatie
  van de configuratie bij het opstarten (`_allowlist()` in `src/nsmcp/start.py`). Wijst u
  `handelen` naar uw eigen appliance zonder de configuratie aan te passen, dan weigeren de vier
  naamgebonden gereedschappen vandaag elk object bij naam - de voorbeeldwaarden hierboven staan in
  de configuratie van dit demolab, niet in de uwe. Zonder een `handelen`-sectie in de configuratie
  bestaan de zeven schrijvende
  gereedschappen niet; ze bestaan bij `openheid: volledig` en `openheid: beperkt`, en niet bij
  `openheid: minimaal` (zie "De openheidsknop" verderop). Alles wat het schrijfscript uitstoot en in een antwoord terechtkomt —
  de voorstelregels, het teruglees-blok, de eindstatus, het doel-etiket en de ruwe uitvoer op het
  faalpad — gaat door dezelfde maskering van bekende doelwaarden als een mislukte scan, met
  daarbovenop een limiet van tien regels per blok en een zichtbare melding hoeveel regels zijn
  ingekort. Het voorstel zelf leest niets van de appliance: het doel-etiket erin volgt uit de
  handeling en haar argumenten, die het schrijfscript uitrekent vóór het verbindt — een voorstel
  zegt dus wat er zou veranderen en op welk doel, niet wat de huidige stand van dat object is.
- **De bevestigingscode bereikt het model niet.** Hij staat niet in het resultaat van het
  gereedschap, maar wordt aan de beheerder getoond: in een venster op de machine waar de server
  draait, of — om te oefenen — in een bestand dat de beheerder zelf kiest
  (`handelen.codekanaal`). Het voorstel in de chat houdt alles wat een mens nodig heeft om te
  beslissen en zegt alleen dát de code aan de beheerder is getoond. Het model kan de tweede stap
  dus alleen zetten met een code die een mens heeft opgelezen en ingetypt. Het vensterkanaal heeft daarbij één harde voorwaarde: de AI-client mag geen scherm- of
  UI-toegang hebben tot het bureaublad van de machine waar de server draait. Dit product zet de
  code op dat bureaublad; dat het model hem niet kan lezen, is een uitspraak over de omgeving en
  niet iets wat dit product kan afdwingen. Een assistent met screenshots, computer-use of
  browsergereedschap op datzelfde bureaublad leest het venster mee, en dan is de bescherming weg.
  Het venster sluit zichzelf na tien minuten, zodat er geen verlopen code op een scherm
  achterblijft — op Windows-versies die dat kunnen; ontbreekt die mogelijkheid, dan blijft het
  staan tot iemand het wegklikt. Kan het kanaal de
  code meetbaar niet tonen (het venster geeft 0 terug of gooit een fout, binnen de meting van
  0,5 seconde), dan verbruikt het product de zojuist uitgegeven code en weigert het de
  handeling: er is dan niets gewijzigd. Die meting heeft een grens: een venster dat wordt
  opgeroepen maar nooit verschijnt omdat de sessie geen zichtbaar bureaublad heeft (bijvoorbeeld
  een dienst zonder interactieve sessie) keert niet binnen die 0,5 seconde terug, dus meldt het
  product de code als getoond terwijl niemand hem ziet. De code bereikt dan ook niemand — dus
  ook het model niet — maar de handeling kan vervolgens simpelweg niet bevestigd worden: er is
  geen beheerder die de code kan aflezen en intypen. Het bestandskanaal is een oefen- en
  automatiseringskanaal: een assistent met bestandsgereedschap op dezelfde machine kan dat
  bestand lezen, dus gebruik die vorm niet voor een echte sessie of een opname. De mens in de
  lus is daarmee de beheerder die de code opleest, samen met de aanroep-voor-aanroep-goedkeuring
  van de MCP-host.

## De vier datastromen

Het product kent vier datastromen: verzamelen, opslaan, beantwoorden en — in deze versie, en alleen
met een `handelen`-sectie in de configuratie — handelen.

### 1. Verzamelen: van de NetScaler naar een lokale export

Het product leest de configuratie via read-only NITRO-aanroepen (de standaard-API van de
NetScaler), met een serviceaccount waarvoor leesrechten volstaan. **In deze stroom worden geen
schrijfopdrachten verstuurd.** Dat is een uitspraak over het verzamelen, niet over het hele
product: schrijven gebeurt in de vierde stroom hieronder, langs een eigen script, een eigen
proces en een eigen bevestigingspatroon.

Het verzamelen zelf gebeurt niet door eigen code van dit product, maar door het vrijgegeven,
onafhankelijk gereviewde leespad van GJK NetScaler Healthcheck 1.0, dat als apart proces wordt
aangeroepen. De certificaatcontrole hieronder zit in dat leespad; dit product geeft de
instelling om haar te omzeilen nooit door — dat laatste is in de testsuite vastgelegd.

Voordat er inloggegevens naar de appliance gaan, controleert de verzamelketen eerst het
beheercertificaat van de appliance. Die controle kent twee vormen en geen derde: het
certificaat valideert tegen de vertrouwensketen, of de vingerafdruk van het certificaat is
vooraf vastgelegd in de configuratie. Is geen van beide het geval, dan stopt de keten voordat
er inloggegevens worden gebruikt. (De certificaatcontrole zelf vergt uiteraard netwerkcontact
met de appliance — dat is de TLS-handshake waarin de appliance haar certificaat toont; daarin
gaan geen inloggegevens mee.) Een instelling om die controle te omzeilen ("accepteer
self-signed") bestaat niet in dit product. Dit gedrag is op 26 augustus 2026 in twee
onafhankelijke labtests live aangetoond: op een appliance met een self-signed certificaat
stopte de keten na 0,8 respectievelijk 1,0 seconde; er zijn geen inloggegevens gebruikt en er
is geen export vastgelegd.

Een mislukte of afgebroken scan overschrijft nooit de vorige export: een nieuwe scan landt
eerst in een aparte werkmap, wordt gecontroleerd, en wisselt pas daarna om. Mislukt de scan,
dan blijft de vorige export bewaard en herstelbaar: in vrijwel alle gevallen blijft hij gewoon
de geldende, en alleen bij een falen midden in de omwisseling zelf staat hij tijdelijk opzij —
de eerstvolgende scan zet hem dan terug, of meldt zichtbaar dat dat niet lukte. De
gegevensleeftijd in elk beoordelend antwoord maakt dit vanzelf zichtbaar.

### 2. Opslaan: de export blijft bij u

De export staat lokaal op de machine waar het product draait, binnen uw eigen omgeving. Bij de
export hoort een manifest met per bron een SHA-256-hash (`payloadSha256`) en per bindingsbestand
een hash in `files`. Bij elke lezing controleert het product de inhoud tegen dat manifest:
objectbestanden, bindingsbestanden en de tekstprojectie van de runningconfig. Wijkt
een hash af, dan wordt dat bestand niet vertrouwd en meldt het antwoord dat als leesgat. Draagt
het manifest voor een bron helemaal geen hash, dan is dat zelf een leesgat - geen hash is geen
vertrouwen.

Het product stuurt niets naar GJK Partners of naar derden. Er is geen telemetrie, geen
gebruiksregistratie en geen "bel naar huis". Voor 25 van de 27 vraaggereedschappen is dat
geen belofte maar een gemeten eigenschap: de testsuite bevat een test die faalt zodra een van
hen een netwerkverbinding opent. Twee vraaggereedschappen raken wél het netwerk — uitsluitend
de appliance zelf, nooit GJK Partners of een derde partij. `status_ververs` is datastroom 1
hierboven: het start het verzamelscript en levert een nieuwe export op. `status_update_preflight`
is dát niet — zie de aparte, kleine datastroom hieronder bij "Beantwoorden".

### 3. Beantwoorden: elk antwoord draagt zijn eigen herkomst

De motor leest de lokale export en berekent het antwoord. Elk beoordelend antwoord meldt
daarbij standaard:

- **hoe oud de gegevens zijn** (de datum van de export en het aantal dagen sindsdien), op
  welk doel de export betrekking heeft, en of deze server hem zelf verzamelde
  (`herkomst: verzameld door deze server op <tijd>`) of dat hij is aangeleverd
  (`herkomst: niet vastgesteld (aangeleverde export)`). Daarvoor legt `status_ververs` na elke
  geslaagde scan lokaal één regel vast buiten de exportmap (doel, manifest-hash, tijdstip,
  exportmap); die regel verlaat de machine niet;
- **hoe oud de kennisregels zijn** (de datum van het kennispakket met onder meer CVE- en
  vervalregels);
- **wat niet vastgesteld kon worden**, met de reden erbij.

Een beoordelend antwoord zonder deze herkomst kan niet bestaan: de stempels zitten op de plek
waar elk beoordelend antwoord het product verlaat. Eén gereedschap leest geen export:
`kennis_uitleg` legt een begrip uit vanuit het kennispakket en meldt daarbij alleen hoe oud de
kennisregels zijn - de gegevensleeftijd is voor deze vraag niet van toepassing.

Eén vraaggereedschap wijkt af van "leest alleen de lokale export": `status_update_preflight`
leest voor precies één van zijn negen toetsen (de vrije ruimte op `/var`) een LIVE waarde van de
appliance, altijd via een apart kindproces. Welke route dat is, volgt uit de configuratie: met
een `onderhoud`-sectie en een gepinde SSH-hostsleutel op het doel is het het leesscript
`Invoke-GjkLiveMeting.ps1`, dat een SSH-verbinding opent naar het adres van het doel op poort 22
met de gepinde hostsleutel, de SSH-gebruiker uit `onderhoud` en het credential-target uit
`doelen`, en alleen `df -k /var` uitvoert; anders is het hetzelfde verzamelscript als datastroom 1
hierboven, met dezelfde `doelen`-credential. Mislukt de gekozen route, dan volgt geen tweede
poging via de andere. Dat is GEEN tweede scanroute: er landt geen nieuwe export en er wordt niets
omgewisseld — het is één losse, live waarde, gebruikt en meteen losgelaten. Het is wél
appliance-verkeer, dus geen stille aanname: dezelfde socketgarantie als hierboven geldt tot aan
het starten van dat kindproces, voor beide routes gemeten in `tests/test_no_network.py`
(`test_status_update_preflight_opens_no_socket_in_this_process` en
`test_status_update_preflight_reads_free_space_over_ssh_when_onderhoud_and_a_pin_are_there`).

### 4. Handelen: van een voorstel naar een wijziging op de NetScaler

Deze stroom bestaat alleen met een `handelen`-sectie in de configuratie, en alleen bij
`openheid: volledig` of `openheid: beperkt`. Zij loopt niet via NITRO-aanroepen van dit product, maar via
het gereviewde PowerShell-schrijfscript van het demolab, dat als apart kindproces wordt gestart
— precies zoals het verzamelscript in stroom 1.

`config_opslaan` neemt een tweede route in deze stroom: een klein SSH-script naast de
upgraderunner (`Invoke-GjkConfigOpslaan.ps1`), ook als apart kindproces. Dat opent een
SSH-verbinding naar het adres van het doel op poort 22 met de gepinde hostsleutel, de
SSH-gebruiker uit `onderhoud` en het credential uit Windows Credential Manager, en voert daar
precies drie commando's uit: `show ha node` (de rol, beoordeeld door dit product), bij een open
rol `save ns config`, en `show ns config` (de teruglezing). Wat terugkomt is de ruwe uitvoer van
die drie commando's, elke regel als afdrukbare ASCII achter een eigen voorvoegsel: de rolregel
(`[ROL]`), tot twintig regels uitvoer van het opslaan en eventuele foutuitvoer (`[SAVE]`), en de
teruglezing (`[METING]`, begrensd). Dit product beoordeelt de rol en de teruglezing zelf en geeft
geen configuratieregel door.

Wat er over de lijn gaat: de handeling en haar argumenten, na de allowlist- en
naamgrammaticacontrole van dit product. Wat er terugkomt: de uitvoer van het script, waaruit dit
product de eindstatus, het actie-id en het doel-etiket leest en die het — gemaskeerd op bekende
doelwaarden en begrensd op tien regels — letterlijk doorgeeft.

Elke aanroep begint met een voorbeeldrun (`-WatIs`): die wijzigt niets en levert het doel-etiket
waaraan de bevestigingscode wordt gebonden. Zonder geldige code draait het schrijfscript nooit
zonder `-WatIs`, en een ingewisselde code is altijd verbruikt — ook als de handeling mislukt.
Er schrijft er bovendien hooguit één tegelijk: een tweede bevestigde handeling wacht in
aankomstvolgorde, en wacht die langer dan de code leeft, dan wordt hij geweigerd zonder de code
te verbruiken. Breekt de client een lopende bevestigde aanroep af, dan stopt alleen het wachten
op het antwoord: het schrijfscript draait door, de wijziging landt, de poort blijft tot dat einde
dicht en de uitkomst gaat met actie-id en eindstatus naar het logkanaal van de server in plaats
van naar het gesprek. Die poort geldt per serverproces; draaien er twee servers naast elkaar op dezelfde
appliance, dan bewaakt het schrijfscript zijn eigen register met een eigen exclusief slot.

Er is een vijfde, kleine stroom die hierbij hoort en die BEWUST niet naar het model loopt: de
bevestigingscode zelf, van het product naar de beheerder. Bij `codekanaal: {"soort":
"venster"}` gaat die niet over een netwerk maar naar het beeldscherm van de machine waar de
server draait (een MessageBox, in een aparte thread, zodat de toolaanroep niet op een klik
wacht). Bij `codekanaal: {"soort": "bestand", "pad": "<absoluut pad>"}` gaat hij naar dat ene
bestand op dezelfde machine: elk nieuw voorstel overschrijft het bestand, dus het toont altijd
de NIEUWSTE code. Een oudere, nog niet ingewisselde code blijft daaronder gewoon tien minuten
geldig — ook nadat het bestand met een nieuwere code is overschreven. Wisselt de beheerder zo'n
oudere code in, dan laat het product het bestand ongemoeid: "verbruikt" komt er alleen in als
het bestand nog precies de ingewisselde code toont, zodat een nieuwere, nog geldige code af te
lezen blijft. Het pad mag niet relatief zijn, geen map
zijn en niet in een map liggen die het product zelf leest (exportmap, fixturemap, de map van het
schrijfscript, of de map van het kennis-, doelen- of verzamelscriptbestand).

Het codekanaal is bewust een insteekpunt: de configuratie noemt altijd een `soort`, zodat er
later een kanaal bij kan dat de goedkeurende persoon ook kan IDENTIFICEREN (bijvoorbeeld een
goedkeuring via SSO/Entra) en die identiteit in het actieregister kan vastleggen — vandaag niet
gebouwd.
Overschrijdt het script de tijdslimiet, dan wordt het kindproces gestopt en meldt het antwoord dat de
uitkomst NIET is vastgesteld. Op Windows is die stop meteen hard (`terminate()` is daar dezelfde
aanroep als `kill()`), dus het opruimblok van het schrijfscript draait dan niet; controleer in dat
geval de appliance zelf.

Dit product zet buiten één runnerfase geen firmware over en herstart niets. Een terugrol van de
firmware herstelt de
build, niet de configuratie: de upgrade wijzigt de configuratie en slaat die op, en na een
terugrol naar de oude build staat de gewijzigde configuratie er nog. De backup of de
hypervisor-snapshot is daarom het enige echte terugrolpad voor een upgrade — nooit de oude
firmware alleen. `tests/test_firmware_boundary.py` leidt dit af uit het echte gereedschapsregister
in plaats van uit een vlag: de test faalt zodra een ander schrijvend gereedschap dan de
upgraderunner (`onderhoud_upgrade_fase`) een argument opbouwt dat firmware, een herstart of
`installns` noemt, of de beschrijving van enig ander geregistreerd gereedschap dat doet. Op dat
laatste ("firmware, een herstart of `installns`") is er een met naam
vastgelegde uitzondering voor het woord "upgrade" alleen: vier lees-gereedschappen,
`status_update_preflight`, `onderhoud_upgrade_plan`, `onderhoud_upgrade_stand` en
`rapport_na_upgrade`, mogen dat woord wel in hun beschrijving
gebruiken (`DESCRIPTION_WORD_EXEMPT` in de test) - ze beoordelen een upgrade, ze voeren er geen
uit. Noemt een van die vier alsnog firmware, herstart, reboot, `installns` of `nsinstall`, dan
valt de test alsnog om. Van de overige geregistreerde gereedschappen mag alleen de runner die
firmware overzet en herstart (`onderhoud_upgrade_fase`) het woord "upgrade" in zijn
beschrijving dragen; elk ander gereedschap - lezend of schrijvend - wordt daar wel op getoetst.

## Fail-closed als grondregel

Wat het product niet kan lezen of niet kan vaststellen, heet een **leesgat** en staat
zichtbaar in het antwoord, met bron en reden. In de strengste stand van de openheidsknop
(zie verderop) blijft daarvan het aantal over — een leesgat verdwijnt nooit stilzwijgend.
Een bevinding zonder bewijs is in de code niet te construeren, en een niet-vastgestelde
bevinding zonder reden evenmin.

Dit werkt twee kanten op:

- **Geen vals groen.** Een onleesbare bron verdwijnt niet in een geruststellend antwoord;
  zolang een leesgat openstaat, doet het product geen wijzigingsvoorstel.
- **Geen verzonnen risico.** Het product presenteert nooit een gok als oordeel. Waar iets
  niet vaststaat, staat er "niet vastgesteld" met de reden, in plaats van een aanname.

Ook wat het product bewust níet beoordeelt, wordt benoemd: een dimensie die buiten het bereik
van de huidige versie valt, staat als zodanig in het antwoord, in plaats van stilzwijgend te
ontbreken.

## Inloggegevens

Het ontwerp is dat inloggegevens nooit in configuratiebestanden en nooit in antwoorden
staan. De configuratie bevat uitsluitend een verwijzing: de targetnaam van de credential in
Windows Credential Manager. Het product leest de credential daar op het moment van de scan;
de waarde zelf komt in geen bestand van het product terecht.

Een laadcontrole bewaakt het correcte gebruik van dat ontwerp: een configuratie- of
doelenbestand met een geheim-achtige sleutel (zoals `password`, `secret`, `token`, `apiKey`)
wordt geweigerd voordat er iets gebeurt. Die controle vangt vergissingen met herkenbare
sleutelnamen; ze is geen absolute garantie tegen verkeerd gebruik. Bekende gevoelige waarden
(adres, targetnaam, vingerafdruk) worden bovendien uit foutmeldingen gemaskeerd.

Twee eerlijke grenzen, in het verlengde daarvan. De geheimen-controle toetst sleutelnámen,
geen waarden — wie een echt wachtwoord als wáárde in het targetnaam-veld zet, wordt niet
tegengehouden: die waarde komt dan gewoon in de configuratie terecht en gaat bij de scan als
parameter mee. En de maskering dekt de drie genoemde bekende doelwaarden; ruwe foutuitvoer
van het verzamelscript (tot tien regels) gaat verder ongefilterd mee.

## Wat "lokaal" wel en niet betekent

Het product zelf draait lokaal en stuurt zelf niets naar buiten. Maar het product wordt
gebruikt via een AI-assistent, en **die client bepaalt waar de antwoorden heengaan**. Een
lokale antwoordmotor betekent dus niet automatisch dat alle gegevens lokaal blijven: koppelt u
een cloud-assistent, dan gaan de antwoorden — inclusief de objectnamen die erin staan — naar
die leverancier.

U heeft hierop drie knoppen:

1. **De keuze van de AI-client.** Omdat de waarheid berekend wordt en het taalmodel alleen
   formuleert, volstaat een klein lokaal model. Een volledig air-gapped opstelling is
   daarmee haalbaar. Kiest u een cloud-assistent, dan is dat een bewuste keuze met de
   bijbehorende datastroom.
2. **De openheidsknop** (volgende hoofdstuk) beperkt wat er hoe dan ook in een antwoord
   staat, ongeacht welke client meeleest.
3. **Uw eigen netwerk- en egress-beleid.** Het product dwingt geen netwerkbeleid af; welke
   verbindingen de machine mag maken, is en blijft uw handhavingslaag.

## De openheidsknop

De openheidsknop regelt hoeveel een antwoord prijsgeeft aan het taalmodel dat meeleest. De
filter wordt in code berekend, op de plek waar het antwoord het product verlaat — er wordt
dus nooit "aan het model gevraagd" om iets weg te laten, want het model is precies datgene
waartegen wordt afgeschermd. De analyse zelf verandert niet; alleen de weergave.

Drie standen:

| Stand | Wat het antwoord toont |
|---|---|
| **volledig** (standaard) | echte objectnamen, dagen, bindingen en bewijs |
| **beperkt** | neutrale pseudoniemen in plaats van echte namen, met echte aantallen, dagen, ernst en acties |
| **minimaal** | alleen oordelen en aantallen; geen objectnamen en geen pseudoniemen (het `doel:`-label zegt "niet getoond op deze stand", zie de slotalinea) |

In de stand **beperkt** worden de objectnamen die het product uit de export kent, vervangen
door pseudoniemen via een lokale vertaaltabel. Alleen de beheerder heeft die tabel en kan
terugvertalen; de tabel is zelf gevoelig en hoort dezelfde bescherming te krijgen als de
export. Eerlijk over de grens: de vervanging dekt de namen die het product uit de export
kent — een vrije tekstregel kan in theorie een tekenreeks bevatten die het product niet als
objectnaam herkent.

Eén soort uitspraak verdwijnt in `beperkt` en `minimaal` helemaal, en dat is bewust. Vraagt u
naar een certificaat of dienst met een halve naam, dan noemt het antwoord in de stand `volledig`
de namen die die term bevatten, zodat u de vraag kunt aanscherpen. In `beperkt` en `minimaal`
gebeurt dat niet: geen namen, geen pseudoniemen, en ook geen aantal. De pseudoniemen zijn daar
namelijk stabiel, en dan wordt zo'n regel een meetinstrument — wie achter elkaar `a`, `ab`,
`abc` … vraagt, leest aan de antwoorden af hoe een echte naam verdergaat en reconstrueert hem
zonder hem ooit te zien. Het aantal alleen is precies dezelfde meting. De vraag wordt gewoon
beantwoord, alleen zonder die wegwijzer.

Ook hier geldt fail-closed: een vertaaltabel die kapot of verdacht is (onleesbaar, dubbele of
tegenstrijdige toewijzingen, pseudoniemen die op echte namen lijken), leidt tot een zichtbare
weigering — nooit tot doorlekken: ook de foutmelding van de weigering noemt de inhoud van de
tabel niet. Bij een fout in een afzonderlijke vermelding wijst de melding die vermelding op
positie aan; is het bestand zelf niet leesbaar als JSON, dan noemt de melding regel en kolom
van de parsefout; een fout in de tekstcodering weigert als elke andere leesfout, met het pad
en de soort fout maar zonder enig inhoudsdetail; bij een fout op het topniveau is er geen
vermelding om aan te wijzen en blijft de weigering zichtbaar zonder enig inhoudsdetail. Er
wordt nooit stil hersteld; het tabelbestand wordt in dat geval niet aangeraakt, omdat het de
enige sleutel is waarmee de beheerder eerdere rapportages kan terugvertalen. Een onbekende
stand in de configuratie weigert de server te starten, zonder stille terugval naar een
andere stand.

De herkomststempels (gegevensleeftijd, kennisleeftijd) en de zichtbaarheid van leesgaten
overleven alle standen. In de stand minimaal blijft daarvan het aantal leesgaten over; bron
en reden zijn detail dat een stand die alleen aggregaten toont per definitie niet draagt.
Een leesgat verdwijnt dus nooit stilzwijgend — juist in de strengste stand is dat het bewijs
dat het antwoord eerlijk blijft.

**De schrijvende gereedschappen staan ónder deze knop.** Alles wat zij zeggen — een
voorstel, een uitkomst, een weigering en ook een mislukking — gaat door dezelfde filter als een
leesantwoord, en een weigering noemt niets meer dan de aanroeper zelf gaf. In `beperkt` levert u
een pseudoniem aan, lost de server dat via de vertaaltabel op naar de echte naam voor de
allowlistcontrole en het schrijfscript, en krijgt u het pseudoniem terug; de beheerder ziet in
het codekanaal en op het `[TARGET]`-etiket de echte naam, want een mens moet zien wat hij
bevestigt.

**Bij `openheid: minimaal` bestaan de zeven niet**, en niet omdat daar iets zou lekken — die stand
zegt juist minder. Zij kan een voorstel niet drágen: minimaal vat een antwoord samen tot
tellingen, dus de regels van het voorstel, de argumenten en de aanwijzing om opnieuw aan te
roepen met de bevestigingscode zouden verdwijnen, terwijl die code wél aan de beheerder getoond
wordt. De tweede stap zou dan onbereikbaar zijn. Staat `openheid` op `minimaal` en is er toch een
`handelen`-sectie, dan weigert de server te starten met een melding die dat uitlegt. Bouwt een
aanroeper de server rechtstreeks als bibliotheek, dan worden de zeven gereedschappen niet
aangemeld en verschijnt diezelfde reden op stderr. De lezende gereedschappen werken in alle drie
de standen onveranderd.

Eén stuk tekst in een lezend gereedschap volgt dezelfde regel als de schrijvende: de foutmelding
van een mislukte scan (`status_ververs`). Het verzamelscript is een ander product; wat het bij een
mislukking op zijn console zet, wordt alleen ontdaan van de drie bekende doelwaarden (adres,
credential-targetnaam, vingerafdruk) en kan verder elke tekenreeks bevatten - een aangetroffen
vingerafdruk, een tweede adres, een objectnaam. De filter hierboven kan zo'n tekst niet maskeren.
In `beperkt` en `minimaal` blijft die uitvoer daarom uit het antwoord: u leest de exitcode, de
fase waarin de scan strandde en de vaste tekst *"scriptuitvoer niet getoond op deze stand"*; de
eigen redenen van dit product (een scan die al loopt, een tijdslimiet) blijven gewoon leesbaar.

**Configuratieregels staan er alleen bij `volledig`.** Eén lezend gereedschap toont
configuratieregels zelf: `config_drift`, dat laat zien welke regels alleen in de draaiende of
alleen in de opgeslagen configuratie staan. Een configuratieregel draagt namen die in geen enkele
naamfamilie van de filter zitten; de vervanging hierboven kan zo'n regel dus niet betrouwbaar
maskeren. Daarom verschijnen de regels alleen in de stand `volledig`, hoogstens veertig per kant en
elk hoogstens tweehonderd tekens. In `beperkt` blijft per regel alleen het commandohoofd over
(bijvoorbeeld `set lb vserver`, nooit een argument) met een telling, in `minimaal` alleen de
tellingen. Een regel met een herkend geheim of een geredigeerde waarde - een wachtwoord, een sleutel, een
versleutelde waarde, een systeem- of AAA-gebruiker, een autorisatieheader of een cookie - verschijnt
in geen enkele stand, ook niet in `volledig`: daar staat alleen het commandohoofd met de melding dat
de regel niet getoond wordt, en zou dat hoofd zelf het geheim verraden, dan alleen de melding. De
volledige lijst kenmerken en wat het filter niet vangt, staat in
SECURITY.md.

Het `doel:`-label - de aanduiding die u zelf aan een scandoel geeft (bijvoorbeeld `doel: lab`) -
volgt dezelfde regel als een objectnaam: in `volledig` staat de naam er, in `beperkt` een
pseudoniem en in `minimaal` de tekst "niet getoond op deze stand".

**Doelen noemen: `status_doelen`.** Dat lezende gereedschap noemt per ingesteld doel de naam, het
adres, hoe oud de export van dat doel is, de laatste onderhoudsrun en welke schrijvende
gereedschappen de allowlist daar toestaat. Het volgt dezelfde knop: in `volledig` echte namen en
adressen, in `beperkt` pseudoniemen voor allebei, in `minimaal` alleen tellingen. Wat het in geen
enkele stand noemt: een credential-targetnaam, een vingerafdruk (alleen of er een SSH-hostsleutel
gepind is, ja of nee) en een toegestane objectnaam uit de allowlist - alleen de namen van de
gereedschappen. De opsomming van alle ingestelde doelen in een weigering (`status_ververs` met een
onbekend doel) blijft alleen bij `volledig`.

In `beperkt` geeft u als `doel` het pseudoniem terug dat `status_doelen` toonde; de server lost het
via de vertaaltabel op, net als een pseudoniem op de schrijfweg. Die oplossing is geen meetinstrument:
een onbekend pseudoniem, een pseudoniem van iets dat geen doel is en een onbekende naam krijgen
precies dezelfde weigering, zonder de opgegeven waarde te herhalen. Het antwoord noemt het echte doel
daarna nergens; ook dat gaat door dezelfde filter. En een weigering omdat de export een ander doel
beschrijft, noemt dat andere doel alleen in de stand `volledig`.

## Wat u zelf regelt

Het product beschermt wat binnen zijn eigen grens ligt. Daarbuiten liggen vier zaken bij u:

- **een read-only serviceaccount op de NetScaler voor het verzamelen** — het leespad (het
  verzamelscript) heeft geen schrijfrechten nodig en hoort ze ook niet te krijgen. Het schrijfpad
  is een aparte zaak: het schrijfscript van het demolab (zie "Schrijven gebeurt alleen met een
  mens in de lus" hierboven) heeft wél schrijfrechten nodig op de labappliance om er iets te
  veranderen — het product-proces zelf bezit die rechten niet en voert zelf geen enkele
  schrijfopdracht uit, het start alleen dat externe, gereviewde script;
- **de keuze en configuratie van de AI-client**, inclusief de afweging lokaal model versus
  cloud-assistent;
- **het netwerk- en egress-beleid** van de machine waarop het product draait;
- **de toegang tot de exportmap en de vertaaltabel** — beide bevatten uw werkelijke
  configuratiegegevens en objectnamen en horen onder uw normale toegangsbeheer te vallen.

## Verantwoording

Versie 1.0.2, 21-10-2026. Gewijzigd sinds 1.0.1: in de stand `beperkt` staat de vertaaltabel naast
het configuratiebestand (of in `onderhoud.ledgermap`), nooit naast de export; elk veld van een
antwoord gaat door een tekenfilter; de PowerShell-scripts kunnen per script worden vastgepind
(`scriptpin`). Zie de HANDLEIDING. De claims in dit document zijn herleidbaar tot de broncode en de
testsuite van dit product, met drie benoemde uitzonderingen: het leesgedrag tegen
de appliance zit in het vrijgegeven verzamelscript van GJK NetScaler Healthcheck 1.0 (zie
"Verzamelen"); het schrijfgedrag tegen de appliance — de terugleescontrole, de
vingerafdruk-pin, het eigendomsregister en de compensatie in omgekeerde volgorde — zit in het
gereviewde PowerShell-schrijfscript van het demolab, niet in dit product (zie "Schrijven gebeurt
alleen met een mens in de lus"). De objectallowlist en de naamgrammatica zijn de uitzondering
daarop: die staan in béide, als dubbele poort. Dit product weigert eerst, op zijn eigen regels -
de configureerbare allowlist (`handelen.toegestaan`, gevalideerd bij het opstarten door
`start.py`) met daarvoor altijd de ingebouwde, niet-configureerbare denylist (`DENIED_PREFIXES`,
`DENIED_NAMES` in `src/nsmcp/handelen.py`), gedekt door de testsuite - en het schrijfscript
weigert daarna nog een keer op de zijne. En de
waarneming dat de keten op een self-signed certificaat binnen ongeveer een seconde stopt komt
uit twee onafhankelijke labtests van 26 augustus 2026. De gedragingen rond certificaatcontrole,
manifestcontrole, leesgaten, geheimen-weigering, de openheidsknop en het bevestigingspatroon
(voorstel, code, verse doelbinding, teruglezen door het schrijfscript) worden door
geautomatiseerde tests afgedekt.

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
