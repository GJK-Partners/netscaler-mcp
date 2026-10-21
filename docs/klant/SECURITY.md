# Beveiliging

## Een kwetsbaarheid melden

Mail naar kevin.borger@gjk-partners.nl. Meld het niet als publieke issue tot er een oplossing is.
U krijgt binnen vijf werkdagen antwoord.

## Vertrouwensmodel en scope

Dit hoofdstuk zegt wat dit product vertrouwt, wat niet, en wat als
kwetsbaarheid telt.

### Wat het product vertrouwt

Vijf invoeren worden volledig vertrouwd. Geen van de vijf wordt geauthenticeerd:

| invoer | wat er vertrouwd wordt | wat er wel gecontroleerd wordt |
|---|---|---|
| de export | dat de gegevens een lezing van een appliance zijn; welk doel dat is alleen als deze server de export zelf voor dat doel verzamelde | het manifest, en per bron de SHA-256 van het bestand; omvang, nestdiepte en aantallen hebben een plafond. Voor een antwoord met doel en voor de schrijvende handelingen: de eigen herkomstvastlegging van `status_ververs` buiten de exportmap |
| het kennispakket | dat de CVE-basis (bulletins, getroffen reeksen, fix-builds en de extra stap na de upgrade), de aangeboden builds en de uitleg- en begripteksten kloppen - als vastgesteld alleen met een `kennispin` in de configuratie | de vorm van elk veld; een pakket dat niet voldoet wordt geweigerd met een reden, niet stilzwijgend genegeerd. Bulletin- en CVE-id's alleen in hun ASCII-vorm (`CTX` met cijfers, `CVE-jjjj-nnnn` met vier of meer cijfers achteraan); een id met bijvoorbeeld een Unicode-koppelteken of een spatie weigert het pakket; de reden noemt veld en vorm, niet de waarde. Verschilt het id van een eerder genoemd id alleen in hoofd- of kleine letters of in witruimte eromheen, dan weigert de dubbelcontrole het eerst; die reden noemt de spelling wel, tussen aanhalingstekens en met stuurtekens zoals een regeleinde zichtbaar gemaakt (`\n`). Een pakket dat zichzelf tegenspreekt (fix-build onder de getroffen reeks) of een bulletin of CVE dubbel noemt, wordt geweigerd. Met `kennispin`: versie en digest van de inhoud. Vrije tekstvelden worden genormaliseerd en afgekapt |
| het configuratiebestand | alles wat erin staat | de vorm, en dat er geen geheim-achtige sleutelnaam in staat |
| het verzamelscript | dat het het gereviewde NSHC-leespad is | alleen dat het bestaat |
| het schrijfscript | dat het het gereviewde schrijfpad met zijn eigen vangrails is | alleen dat het bestaat |

**De export is semi-vertrouwde invoer.** Dat de gegevens van de bedoelde
appliance komen wordt vertrouwd (zie de tabel hierboven); de vrije INHOUD
daarin niet. Een objectnaam - of een andere tekst uit de export of het
kennispakket - die een instructie lijkt te bevatten, komt als tekst in het
antwoord en niet als opdracht: dit product berekent op basis van gelezen
velden, het voert geen tekst uit. Het model mag die tekst dus niet als gezag
lezen. Zie "Prompt-injectie" verderop in dit hoofdstuk voor de vier paden
waarlangs zulke tekst het model bereikt.

**Wie de exportmap kan beschrijven, kan een export aanleveren - maar niet vastleggen dat deze
server hem verzamelde.** `scan-doel.txt` in de export noemt het doel en de SHA-256 van het
manifest; dat bewijst dat die twee bij elkaar horen, niet wie ze schreef. Een export van doel B,
omgezet naar doel A met een herberekende hash, werd gemeten als `[vastgesteld]` antwoord over A.
Daarom schrijft `status_ververs` - en alleen dat gereedschap - na elke geslaagde scan een
herkomstregel (doel, manifest-hash, tijdstip, exportmap) BUITEN de exportmap: in de ledgermap van
`onderhoud`, of in een map `herkomst` naast het configuratiebestand. Een antwoord met doel, de
upgradefasen en de exportregels van een schrijfvoorstel eisen dat de nieuwste regel van dat doel
de hash van de export draagt; anders luidt het "doel niet vastgesteld: de export is niet door
deze server voor dit doel verzameld". Zonder doel antwoordt een gereedschap wel, en zegt de
gegevensregel `herkomst: niet vastgesteld (aangeleverde export)`. De grens: wie de
herkomstmap zelf kan beschrijven (de ledgermap of de configuratiemap), kan ook dit bewijs
vervalsen - bescherm die mappen zoals het configuratiebestand. Ligt de herkomstmap in de
exportmap, of de exportmap in de herkomstmap, dan start de server niet; dat geldt ook als een
van beide in een andere schrijfwijze van dezelfde plek staat (het Windows-voorvoegsel `\\?\`,
de UNC-vorm daarvan of de beheershare van de lokale schijf).

**Niets wat de server leest, uitvoert of schrijft, mag in de exportmap staan.** Dezelfde
startcontrole geldt voor elk pad in de configuratie: het configuratiebestand zelf, `kennispad`,
`doelen`, `verzamelscript`, `handelen.schrijfscript`, `handelen.fixturemap`, het codebestand of
de presenter van `handelen.codekanaal`, en `onderhoud.runner`, `onderhoud.ledgermap`,
`onderhoud.firmwaremap` en `onderhoud.actieregister`. Een script in de exportmap is code die de
aanleverende partij via deze server laat draaien, een kennis- of doelenbestand daarin is inhoud
die zij kiest, en een ledger, register of firmwaremap daarin is toestand die zij herschrijft.
Omgekeerd mag de exportmap niet in de ledgermap, de herkomstmap of de firmwaremap liggen: wie de
export vervangt, schrijft in de map eromheen. In al die gevallen start de server niet en noemt
hij het veld. De omgekeerde richting, de exportmap binnen een beheermap, weigert de server alleen
voor de ledgermap, de herkomstmap en de firmwaremap; de map van het configuratiebestand en de map
van de scripts mogen de exportmap wel bevatten, en dat toetst de server niet. Het
configuratievoorbeeld in de handleiding legt de exportmap zo onder de map van zijn scripts. Dat is
alleen veilig als de aanleverende partij in die bovenmap zelf niet kan schrijven, alleen in de
exportmap; de aanbevolen indeling houdt de exportmap er apart van. Het codebestand en de
presenter mogen bovendien niet in een map staan die het
product zelf leest of schrijft: de exportmap, de fixturemap, de mappen van het schrijfscript, het
kennispad, het doelenbestand en het verzamelscript, de herkomstmap, en met `onderhoud` ook de
ledgermap, de map van het actieregister, de firmwaremap en de map van de faserunner.

**Die startcontrole vergelijkt paden, geen rechten.** Wie in een map mag schrijven, controleert
het product niet; dat is een beheereis:

- de configuratiemap en de ledgermap (met de herkomstmap erin) zijn alleen schrijfbaar voor de
  beheerder en het account waaronder de server scant. In de hele keten van bovenliggende mappen
  daarvan, tot aan de schijfwortel, mag niemand anders een map hernoemen, verwijderen of
  vervangen. Wie dat bij een hoger gelegen map kan (verwijderrecht op die map, of het recht om
  submappen te verwijderen in de map erboven), kan de hele tak met de herkomstmap erin
  vervangen - ook als hij in de herkomstmap zelf niets mag. Controleer daarbij ook de rechten
  die een map van zijn bovenliggende map overneemt;
- het actieregister (`onderhoud.actieregister`) valt onder dezelfde eis. Het is plat JSONL zonder
  handtekening: een regel met `tool` `onderhoud_backup_maken`, het doel en `uitkomst` `geslaagd`
  opent de backuppoort van R0, zonder dat R0 leeftijd, run of het bestaan van de backup op de
  appliance toetst. Wie het register kan beschrijven, kan die poort dus openen;
- ook `onderhoud.firmwaremap` hoort bij die beheermappen: wie daar mag schrijven, kiest welke
  bundel geïnstalleerd wordt én de vendorwaarde ernaast waartegen R1 de hash op de appliance
  toetst. Een bestandsnaam die op het bundelpatroon lijkt maar andere tekens dan cijfers en punten
  in tak of build draagt, weigert de faserunner wel (exitcode 4) voordat die naam in een commando
  op de appliance komt;
- ook het PowerShell-modulepad van het account waaronder de server draait (`PSModulePath`, in het
  bijzonder `%ProgramFiles%\WindowsPowerShell\Modules` en `$PSHOME\Modules`) is een beheermap: wie
  daar mag schrijven, kiest welke "Posh-SSH 3.2.7" het SSH-transport laadt. Dat geldt ook voor de
  modulemap in het eigen profiel van dat account (de CurrentUser-scope,
  `Documents\WindowsPowerShell\Modules`): die wordt als eerste doorzocht, is door dat account zelf
  te beschrijven en kan door mapomleiding in een gesynchroniseerde documentenmap liggen. Sinds
  1.0.2 toetst het SSH-transport (`Assert-GjkPoshSsh`, bij elke start van de faserunner, de live
  meting en config_opslaan) ook de inhoud: elke kopie van Posh-SSH 3.2.7 die geladen is of op het
  modulepad staat, moet hetzelfde sha256-manifest dragen als `scripts\Get-GjkPoshSshManifest.ps1`
  meet over de gewone modulebestanden (niet wat achter een directory-junction ligt, geen alternate
  data streams), met de waarde die over Posh-SSH 3.2.7 uit de PowerShell Gallery is gemeten.
  Wijkt een kopie af, dan laadt het transport niets en stopt het met `[FOUT]` en exitcode 3; de
  live meting wordt dan een leesgat met die reden. Een module in het eigen profiel wordt niet
  geweigerd zolang de inhoud klopt; wie daar kan schrijven, kan na de toets en voor het laden
  nog wisselen (een kort venster);
- een herkomstmap naast de exportmap, onder een bovenmap die de aanleverende partij ook kan
  beschrijven, is geen onafhankelijke vertrouwensgrens. De server start dan wel (de herkomstmap
  ligt niet ín de exportmap), maar het herkomstbewijs is niet sterker dan die gedeelde bovenmap;
- aanbevolen indeling: het configuratiebestand - en zonder `onderhoud` daarmee de map
  `herkomst` - de ledgermap, het actieregister, de firmwaremap, de scripts en het kennispakket in
  mappen die alleen de beheerder kan beschrijven; de exportmap apart daarvan, in een map waar de
  aanleverende partij wel mag schrijven maar die geen van de beheermappen bevat of in een ervan
  ligt. De server toetst bij de start voor elk van die paden dat het niet in de exportmap ligt, en
  dat de exportmap niet in de ledgermap, de herkomstmap of de firmwaremap ligt; de rechten toetst
  hij niet. Zie "Bestanden op schijf" in de handleiding.

**Wie het kennispad kan beschrijven, kan zonder pin de kennis veranderen.** Een pakket waarin
getroffen reeks en fix-build samen verlaagd zijn, of waaruit het laatste bulletin is gehaald,
doorstaat elke vormcontrole; het werd gemeten met een lagere vloer en minder geraakte CVE's,
`[vastgesteld]`. Vorm kan zo'n pakket niet van het echte onderscheiden, een vingerafdruk buiten
het kennispad wel: `kennispin` in de configuratie (versie en SHA-256 van de canonieke inhoud,
te berekenen met `python -m nsmcp.knowledge --digest <kennispad>`). Wijkt het pakket af, dan
geldt het niet, en het antwoord noemt welke helft afwijkt zonder de verwachte digest te
herhalen. Zonder pin draagt elk vloer- en CVE-oordeel, en de extra stap na de upgrade,
`[niet vastgesteld]` ("kennispakket niet gepind in de configuratie") en sluit de vloerpoort van R0, tenzij de beheerder de doelbuild
bewust accepteert. De pin is precies zo sterk als de bescherming van het configuratiebestand.

**De presenter van het `sso`-kanaal is code van de beheerder.** `handelen.codekanaal.pad` is een
programma dat dit product start en dat de bevestigingscode ontvangt; het wordt vertrouwd om het
protocol te spreken, niet gecontroleerd op wat het toont. Het antwoord moet precies één regel zijn
en `sectie` en `vingerafdruk` exact terugspiegelen; anders is er niets afgeleverd en is de code
verbruikt. De spiegel bewijst dat de presenter de doelnaam las, niet wat hij liet zien. Weigert
het kanaal een antwoord omdat de spiegel ontbreekt, dan schrijft de server één vaste regel op
stderr (`[codekanaal] sso-presenter-protocol-oud`), zonder code en zonder doelnaam.

**Het configuratiebestand is een code-uitvoerknop.** `verzamelscript` en
`handelen.schrijfscript` zijn vrije paden en worden gestart met
`-ExecutionPolicy <uitvoeringsbeleid> -File` (standaard `Bypass`). Sinds 1.0.2 kan
de configuratie per script een sha256 vastleggen (`scriptpin`): dan start het
product een script alleen als zijn bytes, en die van elk ander script (`.ps1`,
`.psm1`) in dezelfde map, vlak voor de start gelijk zijn aan hun pin; een script
zonder pin in die map weigert de start, want PowerShell kan het op naam inlezen
(de SSH-scripts doen dat met hun transport). Zonder `scriptpin` wordt er niets
gecontroleerd. Er is geen handtekeningcontrole door het product zelf;
`uitvoeringsbeleid: AllSigned` laat die aan Windows. Wie het configuratiebestand
kan schrijven, kan ook de pin aanpassen en draait dan willekeurige PowerShell met
de rechten van het serveraccount. Behandel het configuratiebestand daarom met
dezelfde zorg als een geplande taak: alleen de beheerder mag eraan schrijven.

**De identiteit van de aanroeper is zelfverklaard.** De clientnaam komt uit de
MCP-handshake, wordt per sessie vastgepind en getoetst aan een lijst geleende
gezagsnamen. Er is geen authenticatie. Wie de server kan aanroepen, kan zich
elke naam geven; de logregel per schrijfhandeling zegt dat er zelf bij.

**Vijf foute pogingen verbranden het voorstel.** Een bevestigingscode is
gekoppeld aan de handeling, de argumenten en het doel samen; wie vijf keer de
verkeerde code voor diezelfde combinatie aanbiedt, verbrandt de openstaande
code(s) voor die combinatie - er verandert dan niets, en het codekanaal toont
een melding dat dit gebeurd is, zonder de code zelf te tonen. Een AI-client
die zelf de tweede aanroep doet, kan een openstaand voorstel op deze manier
laten verbranden, met opzet of door verkeerd te gokken; dat is een
geaccepteerd gevolg, geen kwetsbaarheid - er wordt niets gewijzigd, de
beheerder vraagt het voorstel gewoon opnieuw aan.

**De pseudoniementabel kent vormcontrole, geen integriteitscontrole.** Een
gebroken tabel wordt fail-closed geweigerd; een boosaardig bewerkte tabel (rij
A wijst naar object B) niet. Bij `openheid: beperkt` worden pseudoniemen ook voor schrijven terugvertaald.
De beheerder moet daarom de echte namen in het codekanaal controleren; de
tabel en de configuratie moeten tegen wijziging door onbevoegden beschermd zijn.
Sinds 1.0.2 staat de tabel met haar slotbestand naast het configuratiebestand (of
in `onderhoud.ledgermap`), nooit naast de export; bij `openheid: beperkt` weigert
de server te starten als die map de exportmap is of de map eromheen, en een
slotbestand dat niet te openen is of te lang vastzit, is een weigering met reden.
De integriteitscontrole zelf ontbreekt nog steeds.

### Wat buiten scope valt

De volgende onderdelen horen bij uw omgeving, niet bij dit product. Een
zwakheid daarin is geen kwetsbaarheid van dit product:

- het besturingssysteem, de gebruikersaccounts en de rechten op de machine
  waarop de server draait;
- de MCP-host en de AI-client die de server aanroept, inclusief wat die client
  met een antwoord doet;
- het verzamelscript en het schrijfscript zelf, en de appliance waar ze heen
  gaan;
- de netwerkgrens (egress): welk verkeer uw netwerk naar buiten laat is uw
  beleid, niet een instelling in dit product;
- de cloud-AI-leverancier als ontvanger van wat er in de chat komt.

### Wat wel als kwetsbaarheid telt

- een antwoord dat een oordeel geeft op een bron die niet gelezen kon worden;
- een pad waarlangs de bevestigingscode het model bereikt;
- een pad waarlangs een leesgereedschap toch een socket opent;
- een echte objectnaam die bij `openheid: beperkt` of `minimaal` toch in een
  antwoord komt;
- code-uitvoering die niet uit het configuratiebestand of uit een van de twee
  scripts volgt.

### Prompt-injectie

Vreemde tekst uit het kennispakket en uit de export reist naar het model - dat
risico heet prompt-injectie. Vier paden zijn gemeten: de waarden onder
`uitleg` en `begrippen`; het `advies` en de `extraStapNaUpgrade` van een
bulletin; de `kern` van een CVE; en objectnamen uit de export. Een aanvaller
die het kennispakket of de export kan schrijven, kan daar tekst in zetten die
tegen het model spreekt.

#### Wat een injectie wel en niet kan

De bevestigingscode staat niet in het gereedschapsantwoord. Alleen als de
AI-client ook buiten dit antwoord geen toegang heeft tot het codekanaal,
kan een injectie de schrijfroute niet zelfstandig afmaken. Zie hieronder
bij "De bevestigingscode bereikt het model niet" voor de voorwaarden aan
de host, de Windows-sessie en het gekozen codekanaal.
Wat een injectie wel kan, is een MENS
overhalen om de code voor te lezen. Daarom staat in het bevestigingsvenster
altijd de handeling, het doel en de argumenten: klopt wat op het scherm staat
niet met wat in de chat staat, geef de code dan niet af.

Wat het product zelf doet: vrije tekstvelden uit het kennispakket worden
genormaliseerd op regeleinden en afgekapt op een plafond, met een zichtbare zin
dat er is afgekapt. Sinds 1.0.2 gaat elk veld van elk antwoord bovendien door een
tekenfilter: stuurtekens (zoals ESC), opmaaktekens (een zero-width space, de
tekens die de leesrichting omkeren) en de regel- en alineascheiders van Unicode
worden een zichtbaar vraagteken. Een objectnaam die zo'n teken draagt of langer is
dan 128 tekens, herhaalt `status_namen` niet; die noemt de rij dan bij positie.
Elke andere herhaling van een objectnaam die de export kent, en van een naam of
begrip dat de aanroeper zelf meegeeft, wordt in elk veld van het antwoord op 128
tekens afgekapt, met de zichtbare melding "...(naam afgekapt)". Dat begrenst de vorm en de omvang van een injectie; het is
geen filter op de inhoud, en dat wordt hier niet beweerd.

## Wat dit product wel en niet doet

- **Schrijven gebeurt alleen met een mens in de lus.** Zeven gereedschappen kunnen een appliance
  wijzigen (een certificaat klaarzetten, een certificaat vervangen, een lid van een servicegroup
  uit- of weer inschakelen, een backup maken, één fase van een firmware-upgrade uitvoeren, of de
  draaiende configuratie opslaan). Geen van de zeven handelt op de eerste aanroep: die levert een voorstel
  en een bevestigingscode van zes tekens op, geldig tien minuten en één keer bruikbaar. Pas een
  tweede aanroep met die code handelt; vlak voor die uitvoering draait het product opnieuw een
  verse voorbeeldrun en bindt de code aan het doel dat het schrijfscript op dát moment meldt, dus
  een doel dat sindsdien is veranderd wordt geweigerd en verbrandt de code. De code is daarnaast
  gebonden aan de doelnaam (de sectie in `handelen.toegestaan`) waarvoor het voorstel is gedaan:
  een code die onder een andere doelnaam wordt aangeboden wordt geweigerd en verbrandt, ook als
  het schrijfscript voor beide doelnamen hetzelfde doel meldt. Elk codekanaal toont die doelnaam
  aan de bevestiger: het venster en het bestand op een eigen regel `sectie:` direct onder het
  doel-etiket, het `sso`-kanaal in een eigen, verplicht veld `sectie` dat ook in de vingerafdruk
  voor de presenter zit — de referentiepresenter toont dat veld en spiegelt het na OK samen met
  de vingerafdruk ongewijzigd terug; het kanaal telt een aflevering alleen als beide exact gelijk
  zijn aan wat het stuurde. Een presenter van vóór deze versie negeert het veld, toont de code
  zonder doelnaam en antwoordt toch "afgeleverd", maar spiegelt niets terug: hij levert daardoor
  geen code meer af. De beheerder ziet dan in zijn oude venster nog wel een code, maar het
  voorstel wordt geweigerd met *"bevestigingscode kon niet aan de beheerder getoond worden; er is
  niets gewijzigd"* en die code is al verbruikt. Een eigen presenter moet de doelnaam zelf tonen;
  de spiegel bewijst dat hij het veld gelezen heeft, niet wat hij werkelijk op het scherm zette.
  Die garantie geeft alleen de meegeleverde referentiepresenter of een presenter die u zelf
  beoordeeld hebt. Twee voorstellen voor doelnamen met
  hetzelfde etiket en dezelfde argumenten zijn zo uit elkaar te houden voordat de code wordt
  afgegeven. Het schrijfscript zelf
  leest het gewijzigde object van de appliance terug en meldt dat; het product behandelt een
  exitcode ongelijk aan nul, een ontbrekende actie-id- of doelmarker, een tijdslimiet of een fout
  als mislukking en geeft de eindstatus van het script letterlijk door. Het leest die eindstatus
  zélf niet — het beoordeelt de exitcode en de markers — en het verzint zelf geen
  "teruggelezen"-claim. De ene uitzondering is `config_opslaan`: dat script oordeelt nergens zelf,
  dus toetst het product de ruwe teruglezing van `show ns config` zelf, fail-closed op de gemeten
  veldvormen. Drie van de zeven zijn
  omkeerbaar via hun tegenhanger (`dienst_lid_uitschakelen` ↔ `dienst_lid_inschakelen`; een
  vervangen certificaat kan met `certificaat_vervangen` teruggezet worden naar het vorige) —
  de andere vier hebben in dit product geen inverse: `certificaat_klaarzetten` ruimt zichzelf
  niet op (aparte beheerstap), `onderhoud_backup_maken` is zelf al het terugrolpunt, geen
  wijziging om ongedaan te maken - en die blijft op de appliance staan: off-box downloaden
  doet dit product niet - en `onderhoud_upgrade_fase` heeft geen tegenhangerfase: het
  terugrolpad is die backup of een hypervisor-snapshot (zie "Firmware en herstarten") - en
  `config_opslaan` heeft evenmin een inverse: de vorige opgeslagen configuratie zit alleen in een
  backup die vooraf met `onderhoud_backup_maken` is gemaakt, en `config_opslaan` controleert dat
  niet.
  Het schrijven gebeurt voor vijf van de zeven door het gereviewde PowerShell-schrijfscript van
  het demolab, voor de zesde door de upgraderunner en voor de zevende door een klein SSH-script
  naast die runner, elk gestart als apart proces; dit product bevat zelf geen
  NITRO-schrijfclient. De toegestane
  objectlijst komt uit de CONFIGURATIE, niet uit code: de sectie `handelen.toegestaan` zegt
  per doelnaam per gereedschap welke waarden zijn toegestaan (per argument een lijst, of
  `true`/`false` voor een gereedschap dat zijn object zelf vormt), en het product valideert die
  sectie bij het OPSTARTEN - een verkeerde vorm, een onbekend gereedschap of argument, of een
  ontbrekende waarde weigert de start meteen, in plaats van pas bij een voorstel. Voor dit demolab
  staat de configuratie vandaag zo: `certificaat_klaarzetten` neemt alleen een `certnaam` en
  accepteert daarvoor alleen `gjk-zaakportaal-2027`; het noemt geen dienst.
  `certificaat_vervangen` accepteert alleen de dienst `lb_vs_gjk_zaakportaal_443` met als
  `nieuwcert` `gjk-zaakportaal-2027` of, als terugrol-doel, `gjk-zaakportaal-2026`.
  `dienst_lid_uitschakelen`/`dienst_lid_inschakelen` accepteren alleen de servicegroup
  `gjkdemo_sg_proefdienst` met lid `gjkdemo_web01` of `gjkdemo_web02`, altijd op poort `3389` -
  die poort staat als `MEMBER_PORT` in dit product vast en is geen argument. Naast die
  CONFIGUREERBARE allowlist draagt dit product een INGEBOUWDE denylist die in code staat en daar
  los van staat: namen die met `nshttps-` of `nsrpcs-` beginnen en de certificaten
  `ns-server-certificate`/`ns-sftrust-certificate` worden altijd geweigerd, ook als een allowlist
  ze zou vrijgeven - dat zijn de beheerdiensten en beheercertificaten van de appliance zelf. Die
  denylist wordt op TWEE momenten voor de allowlist gecontroleerd: bij het opstarten weigert het
  product een configuratie die een denylistnaam in `toegestaan` zet, en bij elke aanroep
  controleert de validatiestap de denylist voor de allowlistcontrole - een allowlistregel kan een
  denylistnaam dus nooit vrijgeven, in geen van beide gevallen. Zie `handelen.toegestaan` in de
  configuratie, en `MEMBER_PORT`, `DENIED_PREFIXES`, `DENIED_NAMES` en `validate()` in
  `src/nsmcp/handelen.py`, plus de validatie van de configuratie bij het opstarten
  (`_allowlist()` in `src/nsmcp/start.py`).
  Wijst u `handelen` naar uw eigen appliance zonder de configuratie aan te passen, dan weigeren de
  vier naamgebonden gereedschappen vandaag elk object bij naam - de voorbeeldwaarden hierboven
  staan in de configuratie van dit demolab, niet in de uwe. Zonder een `handelen`-sectie in de
  configuratie bestaan de zeven schrijvende
  gereedschappen niet, en **ze bestaan bij `openheid: volledig` en `openheid: beperkt`**: alles wat
  een schrijvend gereedschap zegt — een voorstel, een uitkomst, een weigering en ook een mislukking
  — gaat door dezelfde openheidsnaad als een leesantwoord, en een weigering noemt niets meer dan de
  aanroeper zelf gaf. In `beperkt` geeft u dus een pseudoniem mee en krijgt u een pseudoniem terug;
  de beheerder ziet in het codekanaal de echte naam, want een mens moet zien wat hij bevestigt.
  **Bij `openheid: minimaal` bestaan de zeven niet.** Die stand vat een antwoord samen tot tellingen,
  en daar past geen voorstel in: de regels van het voorstel en de aanwijzing om opnieuw aan te
  roepen met de bevestigingscode zouden verdwijnen terwijl die code wél aan de beheerder getoond
  wordt. Staat `openheid` op `minimaal` en is er toch een `handelen`-sectie, dan weigert de server
  te starten; bouwt een aanroeper de server rechtstreeks, dan worden de zeven niet aangemeld en zegt
  een melding op stderr waarom.
- **Configuratie opslaan is een schrijfhandeling met een eigen route.** `config_opslaan` laat de
  NetScaler `save ns config` uitvoeren, alleen met een bevestigingscode, alleen op een doel met
  toestemming in `handelen.toegestaan` en alleen met een `onderhoud`-sectie. Het opslagscript
  gebruikt het transport van de upgraderunner: SSH naar het adres van het doel op poort 22, de
  gepinde hostsleutel (nooit een nieuwe sleutel accepteren), het credential uit Windows
  Credential Manager. Vóór het opslaan bepaalt het de rol live met `show ha node`; op een node die
  secondary is, of waarvan de rol niet eenduidig te lezen is, slaat het niet op. Direct na het
  opslaan leest het `show ns config` terug; het product telt de handeling alleen als uitgevoerd
  als de laatste opslag niet ouder is dan de laatste wijziging en de appliance zelf meldt dat er
  sinds de laatste opslag niets gewijzigd is. Elke onbekende vorm telt als mislukt. Tijdens een
  openstaande upgradefase op hetzelfde doel weigert het. Het gereedschap toont zelf geen
  configuratieregel: het voorstel noemt alleen tellingen uit de export.
- **Contract met het schrijfscript: het doel-etiket van een backup mag niet meebewegen met de
  naam.** Bij `onderhoud_backup_maken` vormt dit product zelf de tijdgestempelde `-BackupNaam`
  (zie `backup_name()` in `src/nsmcp/backup.py`), maar het `[TARGET]` dat het schrijfscript meldt
  moet IDENTIEK blijven over de hele poging, niet alleen tussen `-WatIs`-aanroepen: het voorstel,
  de verse controle die het product vlak voor het inwisselen van de code opnieuw draait, EN de
  echte, niet-`-WatIs` uitvoering die daarna volgt. Dat is het etiket van de beheerder voor de
  appliance, niet het object dat wordt gemaakt, en het mag dus geen naam en geen tijdstempel
  dragen die per aanroep verschilt. De bevestigingscode wordt aan dit etiket gebonden (zie
  hierboven); een etiket dat wisselt heeft twee verschillende gevolgen, naar waar het wisselt.
  Wisselt het tussen de twee `-WatIs`-aanroepen, dan wordt de bevestigingscode verbruikt en
  geweigerd (gemeld als een niet-passende bevestigingscode, niet als een mislukte backup) en
  faalt elke backup zo, telkens met een net-verbruikte code. Wisselt het pas tussen de
  laatste controle en de echte uitvoering, dan is dat te laat om nog te weigeren - er is dan al
  geschreven - en meldt het product in plaats daarvan "LET OP: doel na uitvoering ... wijkt af
  van het voorstel" bij een verder geslaagde backup. De teruglezing is de tweede helft van dit
  contract: het schrijfscript moet een regel afdrukken die (ongeacht hoofd-/kleine letters, na
  eventuele witruimte) begint met `[OK]`, direct gevolgd door `teruggelezen op de collectie
  config/systembackup:` en een niet-lege toelichting. Alleen zo'n positieve regel telt: een
  regel die dezelfde zin met een andere markering draagt (`[FOUT]`, `[WAARSCHUWING]`) of de woorden
  `ontbreekt` of `niet gevonden` bevat (ongeacht hoofdletters en witruimte tussen de woorden), telt
  nooit als gevonden, ook niet bij exitcode 0. Een regel die met `[FOUT]` begint en de backupnaam
  noemt, laat de hele teruglezing mislukken, ook naast een `[OK]`-regel; een `[WAARSCHUWING]`-regel
  naast een `[OK]`-regel niet, want dat paar drukt het schrijfscript af als de aanmaak een fout gaf
  maar het object er toch staat. Dit product LEEST die regel (`src/nsmcp/backup.py`, de
  `_READBACK`-expressie) en verzint het
  woord "teruggelezen" nooit zelf. Wat daadwerkelijk beslist over slagen of falen is nauwer dan
  dat voorbeeld doet vermoeden: exact de `-BackupNaam` die dit product zelf vormde moet letterlijk
  in die toelichting voorkomen - de extensie `.tgz`, de bestandsgrootte, het tijdstip en de
  afsluitende `, ...` zijn voorbeeldwaarden, geen eis. Het echte schrijfscript
  (`film\Invoke-GjkWerkbankWrite.ps1`) staat buiten deze repository: dit is dus een CONTRACT, en geen
  voltooid feit - de testsuite van deze repository meet alleen het GEVOLG van een gebroken
  contract (`tests/test_handelen_zonder_code.py`), nooit de naleving door het echte script zelf.
  Dat het echte script dit contract naleeft, moet nog blijken uit een aparte proef met dat echte
  script op een labomgeving; die proef heeft nu nog niet plaatsgevonden.
- **De bevestigingscode bereikt het model niet.** Hij staat niet in het resultaat van het
  gereedschap, maar wordt aan de beheerder getoond — in een venster op de machine waar de server
  draait (`codekanaal: {"soort": "venster"}`), of, om te oefenen, in een bestand dat de beheerder
  zelf kiest (`codekanaal: {"soort": "bestand", "pad": "<absoluut pad>"}`), of via een apart
  presenterproces achter een goedkeuringsketen
  (`codekanaal: {"soort": "sso", "pad": "<absoluut pad>", "autoriteit": "<https-url>",
  "wachttijd_s": <getal>}`). Het codekanaal is bewust een insteekpunt: de configuratie noemt
  altijd een `soort`, en `sso` is het bewijs dat een latere soort — die de goedkeurende persoon
  ook kan IDENTIFICEREN en die identiteit in het actieregister kan vastleggen — daar zonder een
  tweede configuratievorm bij kan. Het
  voorstel in de chat noemt doel, voorgenomen wijziging en herstel. Bij `volledig` staan er ook
  planregels van het schrijfscript; bij `beperkt` zijn die in de chat onderdrukt, zodat het model
  ze beneden volledige openheid nooit leest. Het EIGEN voorstel van de operator — de
  `proposal_text` die het bestands- en het SSO-kanaal tonen — draagt die planregels wel, op elke
  stand, op dezelfde manier gemaskeerd als een weigering: een mens die een fysieke handeling
  bevestigt moet zien wat het script zelf zei te gaan doen. Het venster toont geen voorsteltekst,
  op geen enkele stand — alleen gereedschap, doel, doelnaam en argumenten, boven de code. Het `sso`-kanaal
  stuurt diezelfde argumentregels mee in een eigen veld `argumenten`, en de referentiepresenter
  toont ze boven de code, los van de begrensde voorsteltekst. Het antwoord zegt alleen
  dát de code aan de beheerder is getoond. Het model kan de tweede stap dus alleen zetten met een
  code die een mens heeft opgelezen en ingetypt; dat is de mens in de lus, samen met de
  aanroep-voor-aanroep-goedkeuring van de MCP-host. **Het vensterkanaal werkt alleen onder één harde voorwaarde: de AI-client mag geen
  scherm- of UI-toegang hebben tot het bureaublad van de machine waar de server draait.** Dit
  product zet de code op dat bureaublad; dat het model hem niet kan lezen, is een uitspraak over
  de omgeving en niet iets wat dit product kan afdwingen. Een assistent met screenshots,
  computer-use of browsergereedschap op datzelfde bureaublad leest het venster gewoon mee, en dan
  is de bescherming weg — dezelfde soort grens als bij het bestandskanaal hieronder. Zet die
  gereedschappen dus uit in het project of profiel waarmee u deze server gebruikt, of laat de
  server draaien op een machine waar de assistent geen scherm heeft.

  **Een kanaal is precies zo gesloten als de machine waarop het uitkomt.** Dat
  geldt voor het bestandskanaal, en het geldt net zo goed voor het venster.
  Gemeten: het bevestigingsvenster is een gewone dialoog; een proces in dezelfde
  sessie op hetzelfde of een hoger integriteitsniveau kan de volledige tekst
  uitlezen - inclusief de code - met een handvol regels code en zonder enige
  rechtenverhoging. In scope van dat risico vallen dus niet alleen een AI-client
  met schermtoegang, maar ook: een tweede lokale gebruiker of proces, een RMM-
  of remote-controlagent, een lopende schermdeling of schermopname, en een
  RDP-shadowsessie.

  Wat dat betekent voor gebruik: zet het venster niet in op een machine die u
  deelt of laat meekijken. Bij het vensterkanaal blijft de Windows-sessie de
  grens, en bij het `sso`-kanaal met de referentiepresenter ook: die toont zijn
  venster in de sessie van de server. Het `sso`-kanaal verschuift die grens alleen
  als de MCP-host onder een ander account of in een andere sessie draait dan de
  beheerder.

  Het venster sluit zichzelf na tien minuten, zodat er geen code op een scherm
  blijft staan die toch al verlopen is - op Windows-versies die dat kunnen;
  ontbreekt die mogelijkheid, dan blijft het venster staan tot iemand het
  wegklikt (de code erin is dan allang verlopen).
  Fail-closed geldt voor een DIRECT gemeten
  mislukking: geen Windows, of het venster geeft binnen de meting van 0,5 seconde 0 terug of
  gooit een fout (bij het bestandskanaal: een onschrijfbaar pad). Dan verbruikt het product de
  zojuist uitgegeven code en weigert het de handeling met *"bevestigingscode kon niet aan de
  beheerder getoond worden; er is niets gewijzigd"* — er is dan niets gewijzigd en het
  schrijfscript heeft alleen met `-WatIs` gedraaid. Die meting heeft een grens: wordt het venster
  opgeroepen zonder ooit te verschijnen — de sessie heeft geen zichtbaar bureaublad, bijvoorbeeld
  een dienst zonder interactieve sessie — dan keert `MessageBoxW` niet binnen die 0,5 seconde
  terug, en meldt het product de code als getoond terwijl niemand hem ziet. De code bereikt dan
  ook niemand, dus ook het model niet, maar de handeling kan vervolgens simpelweg niet bevestigd
  worden: er is geen beheerder die de code kan aflezen en intypen. Een `handelen`-sectie zonder
  `codekanaal` start niet. Het bestandskanaal is nadrukkelijk een oefen- en
  automatiseringskanaal: een assistent met bestandsgereedschap op dezelfde machine kan dat
  bestand lezen, dus gebruik die vorm niet voor een echte sessie of een opname. Die waarschuwing
  staat hier nog een keer omdat ze de kern is van beide kanalen: een kanaal is precies zo gesloten
  als de machine waarop het uitkomt. De soorten `venster` en `bestand` tonen een code aan wie op
  dat moment achter het scherm zit of wie het bestand kan lezen. Ze kunnen die persoon niet
  noemen; `bevestiger` is dan niet vastgelegd, en het antwoord zegt dat. De referentiepresenter
  van de soort `sso` legt als `bevestiger` het aanmeldaccount van de serversessie vast: het account
  waaronder de server draait, wie er ook op OK klikt - geen geverifieerde goedkeurder. Elk proces in
  dezelfde sessie kan dat venster lezen en bevestigen, dus de harde voorwaarde van het venster
  hierboven geldt onverkort ook voor `sso`. Betekenisvol is die identiteit alleen als de MCP-host
  onder een ander account of in een andere sessie draait dan de beheerder; goedkeuring buiten de
  sessie om (een push- of MFA-melding) zit niet in deze versie. De faserunner weigert te starten op
  een kanaal dat geen bevestiger vastlegt.
  Het codebestand
  toont altijd de NIEUWSTE code: elk voorstel overschrijft het. Een oudere, nog niet ingewisselde
  code blijft daaronder gewoon tien minuten geldig, ook nadat het bestand is overschreven;
  wisselt de beheerder zo'n oudere code in, dan laat het product het bestand ongemoeid.
  "verbruikt" komt er alleen in als het bestand nog precies de ingewisselde code toont, zodat een
  nieuwere, nog geldige code in beeld blijft. Het bestand krijgt
  geen eigen ACL — het erft de rechten van de map die de beheerder aanwijst, en die map mag
  daarom niet het schrijfscript bevatten of een andere map zijn die het product zelf leest. Naast
  `status_ververs` en `status_update_preflight` (die beide lezen, zie hieronder) raken alleen
  deze zeven gereedschappen een appliance, elk via zijn eigen apart proces.
- **Er schrijft er hooguit één tegelijk.** Een tweede bevestigde handeling wacht op de eerste in
  aankomstvolgorde in plaats van er dwars doorheen te lopen; duurt dat wachten langer dan de code
  leeft (tien minuten), dan weigert het product met *"een andere handeling loopt nog; probeer
  straks opnieuw"* en is de code **niet** verbruikt — u kunt hem daarna gewoon opnieuw gebruiken.
  Voorstellen wachten niet: die draaien het schrijfscript alleen met `-WatIs` en wijzigen niets.
  Ook een AFGEBROKEN handeling houdt de poort dicht: breekt uw client een lopende bevestigde
  aanroep af (een time-out, of u drukt op stoppen), dan stopt daarmee alleen het wachten op het
  antwoord — het schrijfscript draait door en de wijziging landt op de appliance. De poort gaat
  pas open als dat script klaar is, dus een volgende handeling wacht netjes op de afgebroken.
  De uitkomst van zo'n afgebroken handeling komt niet meer in het gesprek terecht; het product
  schrijft die met actie-id en eindstatus naar zijn eigen logkanaal (stderr), en u kunt de stand
  daarna gewoon opnieuw opvragen. De bevestigingscode is dan verbruikt.
  De grens van die belofte, expliciet: **de poort geldt per serverproces.** Draaien er twee
  servers naast elkaar op dezelfde appliance, dan bewaakt niet dit product maar het schrijfscript
  zijn eigen register, met een eigen exclusief slot; dit product kan van een ander proces niets
  weten.
  **Een tweede grens, specifiek voor `onderhoud_upgrade_fase`:** die handeling wordt
  LOSGEKOPPELD gestart (R1 alleen al duurt gemeten 460 seconden aan overzetten, en dat is langer
  dan de tijdslimiet van 5 minuten die elk ander schrijvend gereedschap heeft) en geeft de
  bovenstaande poort daarom AL vrij zodra de ledgerregel `fase_gestart` er staat — niet pas als
  de fase klaar is. In dat venster loopt de faserunner nog gewoon door. Of die faserunner
  ook het afsluiten van de MCP-host overleeft, wordt bij de start gemeten en in het antwoord
  gemeld (regel `faserunner:`, zie OPENSTAANDE-METINGEN.md), nooit aangenomen. Elk ANDER schrijvend
  gereedschap in dit product weigert daarom expliciet zolang er op hetzelfde doel nog een fase
  openstaat — dezelfde weigering en dezelfde zin als `onderhoud_upgrade_fase` op zichzelf al
  gebruikte (*"er staat nog een fase open op dit doel; vraag de stand op met
  onderhoud_upgrade_stand"*), nu voor elk ander schrijvend gereedschap op dat doel, ook nog voor
  het voorstel. Op een ANDER doel verandert er niets: die weigering kijkt per doel, nooit
  serverbreed. Een doel is daarbij een naam uit het doelenbestand, waarbij hoofdletters en het
  domeindeel van een FQDN niet meetellen. Een appliance staat met precies een adres in het
  doelenbestand; staan twee doelen op hetzelfde adres, dan weigert de server te starten, met beide
  doelnamen in de reden - twee namen voor een appliance zouden elkaar hier anders niet tegenhouden.
  Dat adres vergelijkt de server als tekst (hoofdletters en witruimte tellen niet mee), zonder
  naamresolutie: dezelfde appliance een keer onder een hostnaam en een keer onder zijn IP-adres ziet
  hij als twee doelen, en een IPv4-adres in een andere schrijfwijze (voorloopnul, decimaal of
  hexadecimaal, zoals `010.0.0.2`, `167772162` of `0xa.0.0.2`) ook, terwijl het transport zo'n
  vorm wel als een gewoon adres leest (een voorloopnul zelfs als een ander adres). Zet een appliance
  dus met een naam en een adres in de gewone puntnotatie (`10.0.0.2`) in het doelenbestand.

  **Hoe die weigering weer weggaat — een fase die nooit sluit.** Een fase is "open" zolang er in
  het ledger een regel `fase_gestart` staat zonder bijbehorende sluitregel. Dat is niet alleen de
  normale, korte toestand tijdens een fase: het is ook wat er achterblijft als de faserunner zijn
  werk niet eens heeft kunnen proberen af te maken (bijvoorbeeld een afgebroken overzetting), of
  als iemand het losgekoppelde proces heeft afgeschoten — dit product kan dat proces niet stoppen
  en kan er dus ook niet namens u een sluitregel voor schrijven. Zonder tijdgrens zou zo'n
  achtergebleven regel elk schrijvend gereedschap op dat doel voorgoed blokkeren. Daarom:

  - Elke fase heeft een **tijdslimiet** (R1 een uur, R2 een kwartier, R3 en R4 een halfuur, R5
    vijf minuten; R0 en R6 hebben geen eigen limiet en volgen de ruimste, een uur). Staat een fase
    langer open dan zijn tijdslimiet zonder sluitregel, dan geldt die fase als **mislukt met reden
    tijdslimiet** — hetzelfde woord dat de faserunner zelf in het ledger schrijft als een fase over
    zijn tijd gaat — en de weigering **vervalt vanzelf**.
  - Zolang de weigering staat, zegt hij er zelf bij welke fase het is, wanneer die begon en op welk
    tijdstip de weigering vervalt. Vervalt hij, dan verdwijnt hij niet stilzwijgend: het antwoord
    van het gereedschap dat dan wel doorgaat, draagt een regel `vorige fase` die zegt dat die fase
    op gestart staat zonder sluitregel en over zijn tijdslimiet heen is.
  - **Wat u in de tussentijd doet.** Wachten kan altijd; de limiet loopt vanzelf af. Eerder dan die
    tijdslimiet is er geen weg terug — ook niet door dezelfde fase met dezelfde `run` **opnieuw te
    starten**: dit product kan een losgekoppelde faserunner niet stoppen en niet eens waarnemen,
    dus een herhaling van precies die fase en run terwijl hij nog echt loopt is voor dit product
    niet te onderscheiden van een tweede schrijver tegen dezelfde doos — die herhaling weigert dus
    net zo hard als elke andere aanroep op dat doel, zonder uitzondering. Pas ZODRA de tijdslimiet
    verstreken is (vorige punt) mag u de fase opnieuw starten met dezelfde `run` (voor R0 hoeft dat
    niet — die pakt de openstaande run op dat doel vanzelf op zodra die over zijn tijdslimiet heen
    is).
  - **Het startvenster: een start die de server niet zag landen.** Na de bevestiging wacht
    `onderhoud_upgrade_fase` hoogstens 20 seconden op de regel `fase_gestart` van de faserunner.
    Komt die regel niet binnen die tijd, dan telt de fase niet als gestart — maar de faserunner is
    losgekoppeld gestart en kan nog steeds opstarten, en een TRAGE runner laat precies hetzelfde
    lege ledger achter als een runner die nooit begon (gemeten: een runner die zijn regel pas na
    het wachten schreef, liet een nieuw voorstel en een nieuwe bevestiging voor dezelfde fase en
    run een tweede runner starten). Daarom houdt de server het doel dan zelf vast: elk schrijvend
    gereedschap op dat doel — ook een nieuw voorstel, en ook een bevestiging met een code die
    eerder werd uitgegeven — weigert met *"op dit doel is de start van fase X (run Y) nog
    onbeslist ..."*, tot de regel `fase_gestart` alsnog verschijnt (dan neemt de weigering voor een
    openstaande fase het over) of de tijdslimiet van die fase verstrijkt, gerekend vanaf de start
    van de faserunner (dan vervalt de blokkade, en het antwoord dat wel doorgaat zegt dat met een
    regel `onbesliste start`). Hetzelfde geldt als het wachten zelf afbreekt, en als de aanroep
    wordt afgebroken terwijl de faserunner nog gestart wordt: het doel staat vast vanaf het moment
    dat de start wordt aangevraagd, en alleen een start die aantoonbaar geen proces opleverde, geeft
    het weer vrij. Zolang de bevestigde aanroep nog op de regel wacht, zegt de weigering dat ook:
    *"... de server wacht nog op zijn regel fase_gestart (tot ...)"*; *"brak af"* staat er alleen
    als dat wachten werd afgebroken of een fout gaf. Het doel is daarbij de doelnaam zoals de weigering voor een openstaande fase hem
    vergelijkt: een tweede geconfigureerde naam die alleen in hoofdletters of in het domeindeel van
    een FQDN verschilt, wordt net zo vastgehouden. Een naam met een ander eerste deel is een ander
    doel, voor deze blokkade net als voor die weigering; dat twee doelen niet hetzelfde adres dragen,
    borgt de startcontrole op het doelenbestand (hierboven, bij de weigering voor een openstaande
    fase), met de grens die daar staat: het adres wordt als tekst vergeleken. Het antwoord op de
    time-out noemt het tijdstip waarop de blokkade uiterlijk vervalt, en `onderhoud_upgrade_stand`
    toont een onbesliste start als eigen regel. **De grens van die blokkade:** hij leeft in het
    serverproces zelf, net als de schrijfpoort hierboven; na een herstart van de server is hij weg
    en beslist alleen het ledger weer. Daarachter staat een tweede slot dat een herstart wel
    overleeft: de faserunner laat zijn regel `fase_gestart` alleen schrijven als er in de ledgermap
    voor dat doel geen fase open staat binnen zijn tijdslimiet (dezelfde regel als hierboven, over
    alle runbestanden van het doel), en stopt anders met exitcode 2 voordat hij een sessie opent.
    Zodra een eerste faserunner zijn regel heeft geschreven, sluit een tweede op hetzelfde doel
    zichzelf dus uit — ook als die door een andere server of na een herstart werd gestart.
  - **Eén uitzondering, met opzet.** Draagt de regel `fase_gestart` geen leesbare starttijd, dan is
    er niets om de tijdslimiet tegen af te meten en blijft de weigering staan. De weigering zegt
    dat dan met zoveel woorden. Dit product schrijft die tijd zelf op elke ledgerregel, dus dat
    gebeurt alleen bij een met de hand aangepast of van elders afkomstig ledgerbestand; opruimen
    in de ledgermap is dan uw eigen beheerstap.
  - **Onleesbare ledgermap = weigeren.** Kan dit product de ledgermap of een van de regelbestanden
    daarin helemaal niet lezen, dan weigert het schrijvende gereedschap in plaats van door te
    lopen — elk schrijvend gereedschap, `onderhoud_upgrade_fase` zelf voorop: "er staat niets open" en "ik kan het niet zien" zijn niet hetzelfde antwoord. Eén
    onleesbare REGEL is dat niet — die wordt overgeslagen, zodat een lopende upgrade niet stukloopt
    op één beschadigde regel.
  - **Een andere weigering, met een andere vorm: deze fase zelf al gesloten.** Dit is niet de
    tijdslimiet-weigering hierboven en kent geen wachttijd die hem opheft. Staat er in het ledger
    van uw `run` al een SLUITREGEL voor de fase die u aanroept — `geslaagd`, `mislukt` of `poort
    dicht`, om het even welke — dan weigert `onderhoud_upgrade_fase` die aanroep meteen, vóór de
    faserunner start: een gesloten fase wordt nooit opnieuw beoordeeld. `upgrade_gate.py` bewaakt
    dezelfde regel ook zelf, als laatste redmiddel, maar pas NA het werk op de appliance en zonder
    daar een sluitregel voor te schrijven; deze weigering staat er nu VOORAF, zodat een herhaling
    de faserunner nooit meer bereikt. Er is geen tijdslimiet om op te wachten: wilt u die fase
    opnieuw proberen, dan start u een nieuwe run.
- **Namen noemen bij een halve vraag gebeurt alleen bij `openheid: volledig`.** Vraagt u naar een
  certificaat of dienst met een halve naam, dan noemt het antwoord in de stand `volledig` de namen
  die die term bevatten, zodat u de vraag kunt aanscherpen. In `beperkt` en `minimaal` doet het
  dat **niet** — geen namen, geen pseudoniemen, en ook geen aantal. Reden: in die standen zijn de
  pseudoniemen stabiel, en dan is zo'n regel een meetinstrument: wie achter elkaar `a`, `ab`,
  `abc` … vraagt, leest aan de antwoorden af hoe een echte naam verdergaat en reconstrueert hem
  zonder hem ooit te zien. Het aantal alleen is precies dezelfde meting, dus ook dat verdwijnt.
  De "bedoelt u …?"-vraag die een schrijvend gereedschap bij een onherkenbaar argument stelde,
  bestaat om diezelfde reden helemaal niet meer — in geen enkele stand. Een weigering noemt
  alleen nog een redencode en de waarde die u zelf typte, nooit een naam of een lijst waarden
  die u niet zelf gaf.
- **Configuratieregels toont alleen `config_drift`, alleen bij `openheid: volledig`, en een regel
  met een herkend geheim nooit.** Elk ander gereedschap noemt aantallen en nooit een configuratieregel,
  want een regel kan een credential dragen. `config_drift` is de ene uitzondering: het toont
  welke regels alleen in de draaiende of alleen in de opgeslagen configuratie staan, omdat dat
  precies is wat een beheerder vóór het opslaan wil zien. Die uitzondering is op vier plaatsen
  afgebakend. Openheid: de regels staan er alleen bij `volledig`; bij `beperkt` alleen het
  commandohoofd (`set lb vserver`, nooit een argument) met een telling, bij `minimaal` alleen
  tellingen. Geheimfilter: een regel die een van de kenmerken `<REDACTED>`, `password`, `passwd`,
  `encrypted`, `encryptmethod`, `passphrase`, `secret`, `privatekey`, `bindpw`, `radkey`,
  `sharedsecret`, `geredigeerd`, `keyvalue`, `passcrypt`, `passplain`, `psk`, `credential`,
  `community`, `apikey`, `token`, `scriptargs`, `bearer`, `pass=`, `key=` of
  `cookie:` draagt (hoofdletterongevoelig, ook binnen aanhalingstekens), een cookieheader met
  witruimte of een onzichtbaar teken tussen de naam en de dubbele punt (`Cookie : ...`, ook met een
  harde of ideografische spatie of met een dubbele punt in volle breedte), een URL met inloggegevens
  erin (`schema://gebruiker:wachtwoord@host`), de header Authorization zelf geschreven (in een
  rewrite- of responderactie, HTTP-callout of monitor, ook zonder dubbele punt) maar NIET wanneer
  daarop meteen `policy`, `policylabel` of `action` volgt - `add authorization policy`, `bind
  authorization policylabel` en een parameter als `-defaultAuthorizationAction` noemen een
  autorisatiepolicy-object, geen headerwaarde, en blijven zichtbaar (die uitzondering geldt nooit
  op een regel die op een van deze manieren een header schrijft: een rewrite- of responderactie
  die Authorization noemt, en een `..._http_header`-actie, de `-customHeaders`, `-send` of
  `-httpRequest` van een monitor, de `-headers` of `-fullReqExpr` van een HTTP-callout of de
  `-fullReqExpr` van een webAuth-actie die Authorization of een cookie noemt, wordt
  achtergehouden, welk woord of teken er ook op de headernaam volgt - zolang de headernaam zelf
  er in zijn geheel staat; een header die een regel op een andere manier schrijft, of waarvan de
  naam uit stukken tekst is samengesteld, valt onder de grens hieronder), een cookie
  met een vaste
  waarde in de header die een rewrite-actie of HTTP-callout invoegt (`insert_http_header Cookie
  "..."`, `-headers "Cookie(...)"`, ook tussen enkele aanhalingstekens, tussen q-scheidingstekens
  zoals `Cookie q{...}` en met de headernaam zelf tussen aanhalingstekens), een rewrite- of
  responderactie die een cookie noemt (ook als doel: `replace`, `insert_after` of `insert_before`
  op de Cookie- of Set-Cookie-header, met een expressie als waarde, of in het antwoord dat een
  responderactie schrijft), of die begint met
  `set ns encryptionParams`, `add|set system user`, `set ns rpcNode`,
  `add|set aaa user`, `add|set snmp user` of `add|set db user`, wordt in geen enkele stand getoond
  - ook niet bij `volledig`; er staat dan alleen het commandohoofd met "(regel met een geheim of
  een geredigeerde waarde; niet getoond)". Dat commandohoofd gaat zelf door hetzelfde filter:
  draagt het een kenmerk of is het een van de genoemde commando's (zoals `add system user` of
  `set ns encryptionParams`), dan wordt ook het hoofd niet herhaald. Bij `volledig` staat er dan
  alleen die melding, bij `beperkt` telt de regel mee onder "(commandohoofd met een geheim; niet
  getoond)". Het filter leest elke regel zoals hij er staat, zoals hij getoond zou worden, en zoals
  een mens hem leest (letters in volle breedte als gewone letters, zonder accenten en combinerende
  tekens, en een onzichtbaar teken - ook een teken zonder breedte tussen twee woorden - een keer
  weggelaten en een keer gelezen als spatie), en die leesvormen nog eens zonder `-` en `_`, zodat
  `api-key`, `api_key` en `X-Api-Key` onder `apikey` vallen. Een regel die daarna nog een letter buiten het
  Latijnse basisalfabet draagt, wordt evenmin getoond: een letter uit een ander schrift kan precies
  op een Latijnse lijken (een Cyrillische a in `-password`), en dat ziet geen lijst. Die regel houdt
  dus ook een regel met bijvoorbeeld een ß of Griekse tekst in een commentaar achter - zo'n regel
  draagt een eigen melding, "(regel met letters buiten ASCII; niet getoond)", in plaats van de
  gewone geheimtekst: er hoeft geen geheim in het spel te zijn, alleen een letter dit filter niet
  kan thuisbrengen. Een regel die
  de header Authorization alleen NOEMT zonder hem te schrijven (een lijst toegestane headers, een
  policy die kijkt of de header er is) verdwijnt nog wel mee - de vorm kijkt naar wat er direct
  ná `authorization` staat en, bij een regel die een header schrijft, naar het commando; niet naar
  de betekenis van de rest van de regel. Dat filter is bewust ruimer dan
  de credentialfilter die de export al toepast: liever een regel te veel achterhouden dan één te
  weinig. Vorm: een
  onzichtbaar opmaakteken (zoals een teken zonder breedte) valt weg, andere niet-afdrukbare
  tekens worden een spatie, een regel wordt na tweehonderd tekens zichtbaar afgekapt en er staan
  hoogstens veertig regels per kant in het antwoord, met de rest geteld. Commandohoofd: dat
  bestaat uit een vaste lijst werkwoorden en commandogroepen, zodat een objectnaam er niet in
  terecht kan komen in een regel zoals de appliance die schrijft; een ander woord zonder kenmerk op
  die plaats komt wel in het hoofd. Het hoofd gaat zelf door het geheimfilter. **Dit is een filter op bekende kenmerken, geen garantie over betekenis:** een
  geheim in een parameter met een naam die geen van deze kenmerken draagt, zou bij `volledig`
  zichtbaar zijn, net als een kenmerk dat met cijfers of symbolen is nagebootst (`passw0rd`, of
  een dubbele punt vervangen door een gelijkend ander teken) en een headernaam die zelf uit
  stukken tekst is samengesteld (`"Set-Coo" + "kie: ..."`, ook in het antwoord dat een
  responderactie schrijft); zet `openheid` op `beperkt` als u
  dat risico niet wilt dragen. Witruimte of een onzichtbaar teken tussen een headernaam en zijn dubbele punt valt
  daar niet onder: `Cookie : ...` wordt achtergehouden, net als `Cookie: ...`.
  Achterhouden is iets anders dan niet meetellen: de export houdt het deel van een regel dat
  een geheim kan dragen voor elke lezer achter, maar een regel die tussen de draaiende en de
  opgeslagen configuratie alleen in dat deel verschilt (een gewijzigd wachtwoord dat niet is
  opgeslagen), telt als drift - als de export die waarde draagt. `config_drift`, `ha_stand` en
  pre-flight toets 4 noemen dan alleen het aantal zulke regels per kant, in geen enkele stand de
  regel, het commandohoofd of de waarde. De export telt dat binnen één aanroep, over een
  vingerafdruk van elke regel met een sleutel die alleen voor die aanroep bestaat; de regels van
  voor het achterhouden en die vingerafdrukken verlaten de export niet en worden niet bewaard.
  De uitgebrachte collector vervangt zulke waarden al op de jumphost door `<REDACTED>`, in de
  draaiende en in de opgeslagen configuratie; een gewijzigd wachtwoord staat dan als twee gelijke
  regels in de export, en geen telling ziet het. Zulke regels telt de export in dezelfde lezing
  als "niet te vergelijken" (alleen een aantal); melden de kopregels een wijziging na de laatste
  opslag of zijn ze onleesbaar, dan zeggen `config_drift` en `ha_stand` `onbevestigd` met dat
  aantal als reden, niet `uit`, en zegt pre-flight toets 4 `niet beoordeeld` met een reden die
  begint met `config-drift is onbevestigd:`.
- **Een doelenbestand met een bekende geheim-achtige sleutelnaam wordt geweigerd.** Een doel draagt
  in het ontwerp alleen een adres en de *targetnaam* van een credential in Windows Credential
  Manager - nooit een wachtwoord of token zelf. Een doelenbestand dat toch een geheim-achtige
  sleutel bevat (stammen als `passw`, `secret`, `token`, `apikey`, `wachtwoord`, `geheim`) wordt
  geweigerd voordat er iets gescand wordt. **Dit is een namencontrole, geen waardecontrole:** niets
  houdt tegen dat iemand een echte wachtwoordwaarde in het `credentialTarget`-veld zelf zet - die
  waarde wordt niet geïnspecteerd en gaat dan ongecontroleerd mee op de command line naar het
  verzamelscript (zie `build_arguments` in `collect.py`). Is er geen doel ingesteld, dan
  beantwoordt de server alleen een aangeleverde export en verstuurt hij geen enkele referentie.
- **Naam en adres van een doel dragen geen stuurteken.** Beide gaan als `-Doel` en `-Adres` naar
  elk schrijfscript en staan in het `[TARGET]`-etiket waaraan de bevestigingscode hangt; een
  regeleinde erin drukte een eigen `[ACTIEID]`-regel af. De server start niet met een doel
  waarvan naam of adres een niet-afdrukbaar teken draagt, en de faserunner en het opslagscript
  weigeren zo'n `-Doel` of `-Adres` zelf ook, voordat er iets geladen is.
- **`status_doelen` noemt de doelen, nooit hoe de server binnenkomt.** Het antwoord leest per doel
  alleen de naam, het adres en óf er een SSH-hostsleutel gepind is; de credential-targetnaam en
  de vingerafdrukken worden er niet eens in gelezen, dus ze staan in geen enkele stand in het
  antwoord, ook niet in een foutpad. Uit de allowlist leest het alleen de namen van de
  gereedschappen, nooit een toegestane objectnaam. Wat het uit het ledger haalt, is onvertrouwde
  invoer: een run-naam alleen als hij een veilige run-naam is, een fase alleen als het een van de
  zeven is, en de uitkomst altijd in de eigen woorden van dit product. Namen en adressen volgen
  de openheidsknop: pseudoniemen bij `beperkt`, alleen tellingen bij `minimaal`. Een opsomming
  van de ingestelde doelen in een weigering (`status_ververs` met een onbekend doel) blijft alleen
  bij `volledig`. In `beperkt` is het pseudoniem uit `status_doelen` een geldig `doel` voor de
  andere gereedschappen; een onbekend pseudoniem en een onbekende naam krijgen dezelfde
  weigering, zodat de oplossing geen manier is om de vertaaltabel af te tasten.

### De grens van de socketgarantie

Zo'n claim is alleen iets waard als er bij staat hoe ver hij reikt. `tests/test_no_network.py`
weigert `socket.socket`, `socket.socketpair`, `socket.create_connection` en `socket.getaddrinfo`,
en draait daaronder:

- het inlezen van een echte export (manifest, objectbestanden, hashcontrole, bindingen) en van een
  echt kennispakket;
- de registratie van alle 27 leesgereedschappen, met onderhoudconfiguratie;
- echte MCP-sessies die alle 25 leesgereedschappen zonder netwerkuitzondering
  aanroepen: `certificaat_wat_verloopt_er`, `certificaat_wat_breekt_er`,
  `certificaat_wat_moet_ik_doen`, `status_overzicht`, `status_namen`, `status_doelen`,
  `status_cve_controle`, `status_update_advies`, `dienst_status`, `kennis_uitleg`,
  `rapport_dekking`, `rapport_vergelijk`, `rapport_wat_is_er_veranderd`, `ha_stand`, `config_drift`, `beveiliging_verstopte_regels`,
  `beveiliging_tls_baseline`, `beveiliging_beheervlak`, `beveiliging_headers`, `beveiliging_scorekaart`, `dienst_keten`,
  `status_gezondheid`, `onderhoud_upgrade_plan`, `onderhoud_upgrade_stand`
  en `rapport_na_upgrade`.

Er zijn precies twee netwerkuitzonderingen: `status_ververs` en
`status_update_preflight`. Beide starten een apart kindproces (het
verzamelscript, of voor de vrije ruimte met een `onderhoud`-sectie en een
gepinde SSH-hostsleutel het SSH-leesscript); het serverproces opent zelf
geen socket. De tests meten beide paden met een
testuitvoerder tot de procesgrens. De zeven schrijftools gebruiken eveneens
een apart proces; hun bevestigingscontract heeft eigen tests. Verkeer van
die kindprocessen valt buiten deze meting.

**Een afzonderlijke meetgrens: de event loop zelf.** Python zelf valt buiten de meting. Op Windows maakt `ProactorEventLoop` bij constructie een interne
self-pipe met `socket.socketpair()`; dat is plumbing van de standaardbibliotheek, geen
netwerkverkeer van dit product. De loop wordt in de test daarom aangemaakt vóór de bewaker wordt
gezet. Sinds `status_ververs` intern `asyncio.to_thread()` gebruikt (de scan blokkeert de event
loop van de server niet), leest `ProactorEventLoop` diezelfde self-pipe ook opnieuw uit bij elke
cross-thread wakeup - een `isinstance`-check die een echte `socket.socket`-klasse nodig heeft. De
bewaker patcht daarom sinds die ronde alleen nog `socket.socket.__init__` (niet meer de klasse
zelf): elke nieuwe socket wordt nog altijd geweigerd, maar `socket.socket` blijft een echte klasse,
dus die self-pipe-uitlezing blijft werken in plaats van vast te lopen. Alles wat na de constructie
van de loop gebeurt - dus al onze code en het volledige SDK-pad, inclusief het codepad van
`status_ververs` tot aan het kindproces - valt onder de bewaker.

## Hoe de voordeur zich verdedigt

Drie maatregelen, overgenomen uit werk waar ze live zijn gereproduceerd en met tests gedicht:

1. **De aanroeper kan niet gewisseld worden.** De MCP-SDK accepteert een tweede initialize op een
   bestaande sessie en overschrijft de clientidentiteit. Wij pinnen de eerst geziene identiteit per
   sessie en weigeren elke afwijking daarna.
2. **Foutmeldingen lekken niets.** De argumentvalidatie draait in de SDK, voordat een
   gereedschapsfunctie zelf aan de beurt komt - er is geen functiebody om de maskering in te
   leggen. Daarom omhullen we de argumentvalidatie-instantie van elk gereedschap apart, nooit de
   klasse: een klassebrede omhulling zou ook de foutmeldingen van een andere, ongerelateerde
   MCP-server in hetzelfde proces maskeren. Alles wat geen bedoelde gereedschapsfout is, wordt
   vervangen door een vaste melding.
3. **De clientnaam is vrije zelfopgave.** Geleende gezagsnamen en pad- of URL-vormen worden
   geweigerd voordat ze in de bewijsketen belanden.

Daarnaast, uit dit bouwblok: **er is een beslispunt voor rechten.** Vóór elk gereedschap draait -
alle 34, inclusief `status_ververs`, `status_update_preflight` en de zeven schrijvende
gereedschappen - wordt een
besluitfunctie aangeroepen met de vastgestelde clientnaam, de naam van het gereedschap en de
(genormaliseerde) argumenten. Vandaag laat die
functie alles door: er zit nog geen echt rechtensysteem achter. Het punt bestaat wel, en is de plek
waar een latere autorisatieregel kan landen zonder de voordeur zelf te hoeven verbouwen.

## Firmware en herstarten

Dit product zet geen firmware over en herstart niets zolang de sectie `handelen` en het hoofdstuk
`onderhoud` ontbreken; met beide bestaat één uitzondering, uitsluitend binnen een runnerfase
(`onderhoud_upgrade_fase`), en die fase loopt als apart proces met een eigen ledger.
`config_opslaan` zet geen firmware over en herstart niets: het slaat alleen de draaiende
configuratie op.

**De vloerpoort.** Welke build er komt, bepaalt alleen de ene bundel in `onderhoud.firmwaremap`.
R0 toetst die doelbuild eerst tegen de huidige build uit de export: een andere releaselijn sluit
R0 altijd, ook met acceptatie, want dit gereedschap doet geen overstap tussen releaselijnen.
Daarna tegen de vloer: de hoogste fix-build van de eigen tak van de doos in het kennispakket.
Onder de vloer sluit R0, tenzij een mens bij R0 bewust `doelbuild_geaccepteerd=true` meegeeft;
zonder bekende vloer, zonder bekende huidige build of bij een doelbuild die niet hoger is dan de
huidige build (een herinstallatie of een downgrade binnen de lijn, ook boven de vloer) geldt
hetzelfde, en bij een andere tak dan de vloer sluit R0 ook met die acceptatie. Het bewijs van R0
noemt versie en datum van het gepinde kennispakket waar de vloer uit komt, met een waarschuwing
als dat pakket ouder is dan 30 dagen: een oud pakket kan een vloer noemen die lager ligt dan wat
de leverancier nu voorschrijft, en de poort opent dan toch op bewijs. Die waarschuwing blokkeert
niet; de ouderdom van het pakket is een beheerbeslissing. De vloer van een FIPS-trein gaat niet mee naar de
faserunner en de acceptatie dan ook niet, dus daar sluit R0; een aanroep die de acceptatie daar
toch meegeeft, weigert al bij het voorstel, voordat er een code is. De server berekent
de vloer en leest de huidige build bij het voorstel en bij de uitvoering opnieuw en geeft ze de
runner alleen in een getoetste vorm mee; de runner weigert bij de binding elke andere vorm,
zonder de waarde te herhalen. Beide komen alleen uit een export die dit doel beschrijft: een
export van een ander doel, of een die geen doel vastlegt, weigert de fase voordat de runner
start. Gebeurt dat bij de uitvoering voor het inwisselen, dan meldt het antwoord dat de code
geldig blijft; verschijnt die export pas na het inwisselen, dan meldt het dat er niets gestart
is en de code verbruikt is. R1 tot en met R6 installeren alleen de bundel waarmee R0 van dezelfde run startte:
een andere bundel in de map, of een R0-regel zonder leesbare doelbuild, weigert de fase voordat
de runner start. De runner laadt precies Posh-SSH 3.2.7, de versie waartegen de controle van de
hostsleutel gemeten is; ontbreekt die versie, of is in dezelfde sessie al een andere geladen, dan
stopt hij met exitcode 3 voordat er een sessie opengaat.

**De snapshotverwijzing is een menselijke belofte.** R0 vraagt een `snapshotverwijzing`: de
hypervisor-snapshot die de beheerder vooraf maakte. De server controleert alleen dat die
verwijzing niet leeg is; vorm, bestaan en ouderdom van de snapshot toetst hij niet, en R0 raakt
geen hypervisor aan. Elke niet-lege tekst opent dus de mens-poort van R0, ook een tekst die het
model zelf invult. De bevestigingscode is gebonden aan de verwijzing en aan de schakelaars
`doelbuild_geaccepteerd`, `drift_geaccepteerd`, `standalone_geaccepteerd` en
`oude_buildbomen_opruimen`, en elk codekanaal toont ze boven de code: het venster en het bestand
onder `wat:`, het `sso`-kanaal in het veld `argumenten`. Controleer ze daar, en geef de code niet
af voor een snapshot die u niet zelf hebt gemaakt. Elk kanaal toont per waarde ten hoogste 120
tekens: een langere verwijzing staat er afgekapt, gevolgd door ` ...`, terwijl de code aan de
volledige verwijzing gebonden is. Onzichtbare tekens laat de weergave weg en witruimte voegt zij
samen tot één spatie; de gebonden verwijzing houdt ze wel. De server toetst de vorm van de
verwijzing niet, ook niet haar lengte of tekens. Houd de verwijzing dus kort en gewoon, en geef de
code niet af als de getoonde regel op ` ...` eindigt: dan ziet u niet de hele verwijzing.

Een terugrol van de firmware herstelt de build, niet de configuratie. De upgrade wijzigt de
configuratie en slaat die op; na een terugrol naar de oude build staat de gewijzigde configuratie
er nog. De inverse van een upgrade is daarom de backup of de hypervisor-snapshot, nooit de oude
firmware alleen. Een backup op de appliance is geen off-box backup; het downloaden ervan is
een aparte stap die dit product niet doet. Dit product biedt "terug naar de oude build" nergens aan als herstelpad.

## Bekende doelwaarden in foutmeldingen

Het adres, de targetnaam van een credential (nooit de credential zelf - die staat uitsluitend in
Windows Credential Manager) en de geconfigureerde vingerafdruk zijn geen geheimen, maar horen niet
ongevraagd in elke foutregel te verschijnen. Foutmeldingen van een mislukte scan halen deze drie
bekende waarden van het doel eruit voordat de tekst de aanroeper bereikt, ongeacht de schrijfwijze
(hoofd-/kleine letters) waarin het collectorscript ze in zijn foutuitvoer liet staan.

Dezelfde maskering geldt voor **alles wat het schrijfscript uitstoot en in een antwoord
terechtkomt**: de voorstelregels, het teruglees-blok, de eindstatus, het doel-etiket en de ruwe
uitvoer op het faalpad. Daar komt een regellimiet bovenop - hoogstens tien regels script-uitvoer
per blok, met een zichtbare melding hoeveel regels zijn ingekort. Zonder die limiet zou een
mislukte schrijfactie hele NITRO-payloads in de context van het taalmodel leggen.

**Dit is een maskering van bekende waarden, geen garantie over de hele foutuitvoer.** Tot tien
regels PowerShell-uitvoer gaan verder mee (zie `_short_report` in `collect.py` voor het leespad
en `_from_script` in `mcp_server.py` voor het schrijfpad). Op het leespad gaan die regels sinds
1.0.2 door het tekenfilter van elk antwoord (stuurtekens, opmaaktekens en Unicode-scheiders
worden een zichtbaar vraagteken), wordt een regel boven de 400 tekens afgekapt met een melding,
staat er hoeveel regels zijn ingekort, en sluit het faalantwoord van `status_ververs` af met de
eigen regels "Kennisbasis ..." en "Gegevens ..." van het product. Een waarde die dit
product niet als "van het doel" kent - bijvoorbeeld het werkelijke certificaat-thumbprint dat de
appliance teruggeeft bij een pin-mismatch, of een heel ander adres in een omleidings- of
DNS-foutmelding - kan dus gewoon in het antwoord verschijnen.

**Die grens geldt alleen bij `openheid: volledig`.** Beneden volledige openheid wordt vrije
scriptuitvoer onderdrukt in het antwoord aan het model - het chatvoorstel en een mislukte
uitvoering lezen dan de vaste onderdrukkingstekst, nooit de vrije regels van het script. Het EIGEN
voorstel van de operator (de `proposal_text` voor het bestands- en SSO-kanaal) blijft die regels
tonen, gemaskeerd op dezelfde manier als een weigering, op elke stand: een mens die een fysieke
handeling bevestigt moet zien wat het script zelf zei te gaan doen. Het vensterkanaal toont op
geen enkele stand voorsteltekst - alleen gereedschap, doel, doelnaam en argumenten. Voor `status_ververs`
betekent de onderdrukking aan het model concreet: in `beperkt` en `minimaal` komt de
ruwe scriptuitvoer van een mislukte scan helemaal niet in het antwoord - het vervangt haar door de
vaste tekst *"scriptuitvoer niet getoond op deze stand"* en houdt de exitcode, de fasediagnose en
de eigen, geclassificeerde redenen van dit product (een scan die al loopt, een tijdslimiet, de
soort van een bestandsfout) gewoon leesbaar. Bij `beperkt` bestaan de schrijvende gereedschappen;
bij `minimaal` worden ze niet aangemeld. Wat het verzamelscript in zijn werkmap schreef, bewaart
dit product als `.mislukt` naast de export (zie de handleiding); regels die het script alleen op
zijn console zette, zijn in die twee standen nergens meer terug te lezen - dat is de prijs van
die keuze, en hij is bewust.

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
