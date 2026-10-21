# scripts/ - de transporthelft van de firmware-upgraderoute

PowerShell 5.1, ASCII-only:

- **`GjkUpgrade-Ssh.ps1`** - het SSH/SFTP-transport. Zeven publieke functies:
  `Assert-GjkPoshSsh`, `Get-GjkCredential`, `New-GjkSshSession`, `Invoke-GjkSsh`,
  `Get-GjkVrijeRuimteVar` (vrije ruimte op /var met `df -k`, de ene meetplek voor R1 en het
  leesscript), `Copy-GjkFile`, `Wait-GjkTerug` - plus een klein, symmetrisch opruimhulpje,
  `Close-GjkSshSession`, en vier interne hulpfuncties met het voorvoegsel `_Gjk`
  (`_GjkPinHostsleutel`, `_GjkIsHostsleutelfout`, `_GjkIsOndubbelzinnigeHostsleutelfout`,
  `_GjkZonderBanner`): de hostsleutel pinnen, een hostsleutelfout herkennen en het gemeten
  waarschuwingsblok van de appliance uit de uitvoer halen. Twaalf in totaal.
- **`Invoke-GjkUpgradeFase.ps1`** - de entrypoint. Voert **EEN fase** (R0..R6) van de
  upgraderoute uit, als apart proces, per aanroep. Elke tekstparameter (`-Doel`, `-Adres`, `-Run`,
  `-Gebruiker`, `-CredentialTarget`, `-HostsleutelVingerafdruk`, `-Doelbuild`, `-Firmwaremap`,
  `-Ledger`, `-GatePython`, `-Snapshotverwijzing`, `-Vloerbuild`, `-VloerBulletin`,
  `-VloerPakket`, `-VloerPakketDatum`, `-Huidigebuild`, `-Actieregister`, `-ExportRoot`,
  `-Actieid`, `-Bevestiger`, `-Transport`) en elk verboden adres moet ASCII zijn en mag geen
  stuurteken dragen (CR, LF, tab, 0-31 en 127): die waarden komen in het `[TARGET]`- of
  `[ACTIEID]`-etiket, in een ledgerregel of in een logregel, en een regeleinde splitst die regel.
  Weigering met `[FOUT]` + `[GEWEIGERD]` en exitcode 1, voordat er iets geladen is, zonder de
  waarde te herhalen.
- **`Invoke-GjkLiveMeting.ps1`** - een losse leesmeting voor `status_update_preflight`
  (`-Meting vrije-ruimte`): opent een sessie met de gepinde hostsleutel, roept
  `Get-GjkVrijeRuimteVar` aan en drukt `[VRIJ_MB] <n>` of `[FOUT] <reden>`. Wijzigt niets en
  oordeelt niet; dezelfde ASCII- en verboden-adrescontrole als de runner, VOOR het transport
  geladen wordt. `-VerbodenAdressen` is hier EEN komma-gescheiden argument: `powershell.exe
  -File` bindt maar een van twee losse waarden aan een lijstparameter, en een losse extra waarde
  wordt geweigerd in plaats van stil aan een andere parameter gebonden.
- **`Invoke-GjkConfigOpslaan.ps1`** - de schrijfroute van `config_opslaan`: `save ns config` over
  SSH, met hetzelfde transport. Parameters `-Doel -Adres -Gebruiker -CredentialTarget
  -HostsleutelVingerafdruk -GatePython [-VerbodenAdressen] [-Actieid] [-Transport] [-WatIs]`;
  `-Transport` laadt na `GjkUpgrade-Ssh.ps1` een bestand dat de sessiefuncties vervangt (het
  nep-transport van de tests), zoals bij de runner. Net als de runner weigert het een stuurteken
  (CR, LF, tab) in `-Doel` of `-Adres` met exitcode 1, voordat er iets geladen is. `-WatIs` drukt
  `[TARGET]`, wat het zou doen en `[EINDSTATUS] WAT-IS` af en opent GEEN sessie. De echte run
  (alleen met `-Actieid`) opent een sessie met de gepinde hostsleutel, leest `show ha node` en laat
  de rol beoordelen door `python -m nsmcp.upgrade_measure` (actie `vorm`, verzoek
  `rol-voor-opslaan`); alleen bij `open` volgen `[ACTIEID]`, `save ns config` en `show ns config`.
  Die laatste gaat ruw en begrensd naar buiten als `[METING] show ns config: <regel>`, met een
  regel `[METINGSTATUS] show ns config: exitcode=<n>`; de server beoordeelt de teruglezing
  (`nsmcp.backup.save_readback_ok`). Het script oordeelt nergens zelf. Alle tekst van de appliance
  gaat alleen als afdrukbare ASCII achter een eigen voorvoegsel naar buiten.
- **`Get-GjkPoshSshManifest.ps1`** - toetst de INHOUD van een geinstalleerde Posh-SSH 3.2.7, waar
  de pin in het transport alleen de versie toetst. Methode: elk gewoon bestand onder de modulemap
  (ook verborgen bestanden; niet wat achter een directory-junction of ander reparse point ligt,
  en geen alternate data streams: die ziet het manifest niet) behalve `PSGetModuleInfo.xml` in de
  modulemap zelf (dat schrijft
  `Install-Module` per installatie: pad en tijdstip); per bestand de sha256 als kleine hex; het
  pad relatief aan de modulemap met `/`, in ordinale volgorde; per bestand een regel
  `<sha256>  <pad>`; de manifestwaarde is de sha256 over die regels, elk afgesloten met LF, als
  UTF-8. De gemeten waarde staat in het script (`$gemeten`). Zonder `-Pad` toetst het elke
  Posh-SSH 3.2.7 die `Get-Module -ListAvailable` vindt. Drukt altijd de volledige lijst af, dan
  `[MANIFEST] <waarde>` en `[OK]` of `[FOUT]`; exitcode 0 gelijk, 1 afwijkend, 3 niet gevonden of
  onverwachte fout. Leest alleen; CI draait het direct na `Install-Module`.

## Vereisten

- Windows PowerShell 5.1.
- De PowerShell-module **Posh-SSH 3.2.7**, precies die versie: de hostsleutelpin is daartegen
  gemeten. `GjkUpgrade-Ssh.ps1` controleert dat zelf (`Assert-GjkPoshSsh`), laadt de module met
  `-RequiredVersion 3.2.7` en **installeert niets** - ontbreekt die versie, dan stopt de aanroep
  met `[FOUT] Posh-SSH ontbreekt: versie 3.2.7 is niet gevonden` en exitcode 3; is er in dezelfde
  sessie al een andere versie geladen, dan ook (`[FOUT] Posh-SSH <versie> is al geladen ...`).
  Andere versies mogen ernaast geinstalleerd staan; ze worden niet geladen. Het modulepad van het
  account dat de server draait (`PSModulePath`, in het bijzonder
  `%ProgramFiles%\WindowsPowerShell\Modules` en `$PSHOME\Modules`) is daarmee een beheermap: de pin
  toetst de versie, en sinds 1.0.2 toetst `Assert-GjkPoshSsh` ook de inhoud van elke geladen of
  beschikbare 3.2.7 tegen het gemeten manifest (`[FOUT]` en exitcode 3 bij een afwijking), geen
  herkomst; wie daar mag schrijven kan een andere module dus niet stil als 3.2.7 laten laden. Dat geldt ook voor de modulemap in het eigen profiel van dat account (de
  CurrentUser-scope, `Documents\WindowsPowerShell\Modules`): die wordt als eerste doorzocht, is
  door dat account zelf te beschrijven en kan door mapomleiding in een gesynchroniseerde
  documentenmap liggen. Dezelfde toets staat los in `Get-GjkPoshSshManifest.ps1` (hieronder);
  CI draait die direct na `Install-Module`.
- Een credential in Windows Credential Manager, op de TARGETNAAM die `-CredentialTarget`
  meegeeft. Het wachtwoord verlaat `Get-GjkCredential` nooit als platte tekst en komt in geen
  enkele uitvoer, ledgerregel of logregel voor - alleen de targetnaam zelf.

## De twee helften, en waar de grens ligt

De runner MEET en HANDELT; hij OORDEELT nergens. Elke poortuitspraak, elke fase-uitkomst
(`gestart` / `poort dicht` / `geslaagd` / `mislukt` / `niet beoordeeld`) en elke ledgerregel komt
uit het Python-pakket `nsmcp`, nooit uit deze scripts. Dat loopt via twee kleine CLI's die
`Invoke-GjkUpgradeFase.ps1` per fase aanroept:

1. **`python -m nsmcp.upgrade_measure`** (actie `start`) legt de ENE `fase_gestart`-regel vast,
   met dezelfde append-only, gefsyncte schrijfactie die de oordeelshelft zelf gebruikt
   (`nsmcp.upgrade.append_line()`). Het script opent daarvoor zelf nooit het ledgerbestand.
   Staat er in de ledgermap voor hetzelfde doel al een fase open - een `fase_gestart` zonder
   sluitregel, binnen de tijdslimiet van die fase, van welke run ook (dezelfde regel als
   `blocking_phase()` in de server, over alle runbestanden van het doel) - of is de ledgermap niet
   te lezen, dan schrijft `start` NIETS en eindigt met exitcode 2 en een `[GEWEIGERD]`-reden op
   stderr; het script logt dan `[FOUT]` + `[GEWEIGERD]` en stopt met exitcode 2, voordat er een
   sessie opengaat. Zo sluit een tweede faserunner op hetzelfde doel zichzelf uit, ook als de
   server het startvenster van de eerste niet zag. Een fase met een sluitregel of over zijn
   tijdslimiet houdt niets tegen: een retry blijft mogelijk.
2. **`python -m nsmcp.upgrade_measure`** (actie `voorpoort`, R1 tot en met R4) schrijft de
   voorafgaande poorten voordat de runner een schrijfactie uitvoert. Elke poging meet opnieuw
   de lokale HA-rol en NSIP via een geslaagde SSH-aanroep; R1 meet ook vrije ruimte
   (`Get-GjkVrijeRuimteVar`), de lokale bundel tegenover de sidecar en de configuratiestand
   (`show ns config`, verzoek `configstand`): de driftpoort opent op bewijs als er sinds de laatste
   opslag niets gewijzigd is, of met `-DriftGeaccepteerd` als menselijke beslissing met de gemeten
   stand erbij. Anders begint R1 geen upload. Alleen als alle voorpoorten openstaan volgt
   schrijven. De regel
   `voorpoort` hoort bij dezelfde run, fase, actie, start en unieke poging als de sluitregel.
   Een oudere open poort bewijst geen toestemming voor een volgende poging. R1 controleert
   daarnaast na upload nog steeds de digest VAN DE DOOS. De bestaande fasevolgorde wordt ook
   vooraf getoetst: zonder geslaagde vorige fase begint de schrijfactie niet.
3. **`python -m nsmcp.upgrade_measure`** (actie `vorm`) zet de RUWE metingen die het script
   verzamelde (df -k /var, show ha node, de vendor-precheck-JSON, de sha256 VAN DE DOOS - gemeten
   NA de overzet, met `shell sha256 -q <buildboom>/<bundelnaam>` in dezelfde SSH-sessie, nooit
   `Get-FileHash` op het lokale bestand - of de sessie openging, ...) om in getypte poorten, door
   de bestaande, al geteste poortfuncties in
   `nsmcp.upgrade` aan te roepen (`disk_gate`, `secondary_gate`, `hash_gate`, `precheck_gate`)
   plus een reeks kleine functies voor wat geen eerdere taak al had: `hostkey_session_gate` (de
   EERLIJKE sessiepoort - OF de sessie openging, en zo niet, OF dat specifiek een
   hostsleutelfout was; nooit een vingerafdruk die alleen tegen zichzelf vergeleken wordt - zie
   "De hostsleutel" hieronder), `presence_gate` (een kale "is dit aangetoond"-toets),
   `backup_register_gate`/`build_tree_gate`/`export_age_gate`/`family_counts_gate` (R0's bronnen:
   het actieregister en de export - zie "`-Actieregister` en `-ExportRoot`" hieronder). Dit is de
   "caller die de stdin-vorm van de runner kent" waar de docstring van `nsmcp.upgrade_gate` het
   over heeft: het script beslist zelf geen enkele uitkomst, het roept alleen de Python-functie
   aan die dat al deed. Al deze poortfuncties staan in `nsmcp.upgrade` zelf, naast `Gate` en
   `_bounded` - `upgrade_measure.py` is de CLI-adapter (leest bestanden, dispatcht op `"soort"`),
   niet de plek waar een poort zelf beslist wordt.
4. **`python -m nsmcp.upgrade_measure`** (actie `terugrolpunt`, alleen R0) legt R0's EXTRA
   bewijsregel `terugrolpunt_vast` vast - de backupnaam, grootte en tijd, het pad van de vorige
   buildboom, de leeftijd van de export waaruit dat pad komt en de snapshotverwijzing letterlijk
   (ontwerp 3.5 noemt voor R0 TWEE regels). Dezelfde `append_line()`; geen oordeel, geen
   sluitregel: `uitkomst` blijft `gestart` en `terugrolpunt_vast` staat met opzet niet in
   `_CLOSING_EVENTS`. De regel staat TUSSEN `fase_gestart` en de sluitregel, dus "precies EEN
   `fase_gestart` en EEN sluitregel per fase" verandert er niet door. Een component die niet
   leesbaar is staat als `niet gelezen` in de regel - nooit stilzwijgend weggelaten.
5. **`python -m nsmcp.upgrade_gate`** is de ENE aanroep per fase die het sluitende oordeel geeft: de
   volgordepoort, de soakpoort, de tijdslimiet en de identiteitskoppeling komen daar zelf
   vandaan, samen met de al gevormde poorten uit stap 3. Zonder aantoonbaar voorafgaande,
   passende voorpoort wordt een schrijffase niet als geslaagd beoordeeld. Deze module schrijft de sluitende
   ledgerregel zelf (`append_line()`) en het script neemt alleen zijn exitcode over.

Zo is er precies EEN implementatie van elke poortregel, in Python, met een mutatieproef eromheen
die overal in CI draait - de SSH-route blijft waar hij hoort.

## De hostsleutel: gepind, nooit geaccepteerd

`GjkUpgrade-Ssh.ps1` gebruikt nergens een optie die een NIEUWE, nog onbekende hostsleutel
automatisch vertrouwt, en nergens een optie die de hostsleutelcontrole helemaal uitschakelt. In
plaats daarvan zet het de VERWACHTE vingerafdruk (`-HostsleutelVingerafdruk`) zelf in Posh-SSH's
in-geheugen known-hosts-opslag voor die ene verbinding, en verbindt daarna met `-ErrorOnUntrusted`:
Posh-SSH vergelijkt de ECHT aangeboden sleutel met wat er net is gezet, en weigert de verbinding
als ze verschillen. Wijkt de sleutel af, dan is er GEEN sessie, gaat er GEEN commando naar de
appliance, en sluit de fase in het ledger als `poort dicht` met de reden "hostsleutel wijkt af" -
geoordeeld door `python -m nsmcp.upgrade_gate`, niet door het script.

**De poort "hostsleutel gepind" beweert nooit een vergelijking die het script niet maakte**:
PowerShell krijgt de daadwerkelijk aangeboden vingerafdruk bij een
GESLAAGDE verbinding niet terug van Posh-SSH (dat valideert intern), dus de poort claimt bij een
open sessie ook geen bytevergelijking - alleen dat de sessie openging, wat ALLEEN kan als Posh-SSH's
eigen `-ErrorOnUntrusted` al akkoord ging. Bij een verbindingsfout gebruikt het script een
tekstherkenning. `untrusted`, `fingerprint` en `known host` gelden als ondubbelzinnige
hostsleutelfouten. De melding `Key exchange negotiation failed` is dubbelzinnig: zij kan zowel
een afwijkende sleutel als een mislukte algoritmeonderhandeling betekenen. Ook die melding
sluit bij de eerste verbinding de poort. De reden "hostsleutel wijkt af" is in dat geval een
voorzichtige classificatie en stelt de precieze oorzaak niet vast. Andere verbindingsfouten
blijven `niet beoordeeld`.

Na een reboot (fase R4) pint `Wait-GjkTerug` iedere herverbindingspoging opnieuw. Een
ondubbelzinnige hostsleutelfout stopt direct. De dubbelzinnige KEX-melding mag binnen de
wachttermijn opnieuw geprobeerd worden, omdat SSH nog kan opstarten. Blijft zij optreden,
dan sluit de poort alsnog; dit bewijst ook dan niet welke van beide oorzaken optrad.

**Bewijsstatus:** de oorspronkelijke taak-3-tekst noemde het pinpad nog niet live getoetst;
dat is een historische status. Het controllerdossier en reviewverzoek van 8 september 2026
melden een latere, afzonderlijke pinproef: juiste pin gaf een sessie, onjuiste pin werd
geweigerd met de genoemde KEX-melding. Dat bewijs betreft uitsluitend die pinproef op de
toenmalige code. Het bewijst geen volledige upgraderun en is geen nieuwe live meting van
deze hersteltak. De zeven-fasen-labrun blijft open en wacht op herstel en onafhankelijke
keuring. Deze herstelronde doet uitsluitend offline controles.

## Parameters van `Invoke-GjkUpgradeFase.ps1`

`-Doel -Adres -Fase -Run -Gebruiker -CredentialTarget -HostsleutelVingerafdruk -Doelbuild
-Firmwaremap -Ledger -GatePython -Snapshotverwijzing -Vloerbuild -VloerBulletin -VloerPakket
-VloerPakketDatum -Huidigebuild -DoelbuildGeaccepteerd -Actieregister -ExportRoot -DriftGeaccepteerd -StandaloneGeaccepteerd
-OudeBuildbomenOpruimen -SoakUren -Actieid -Bevestiger -Transport -VerbodenAdressen -WatIs`

Elke waarde komt met haar parameternaam binnen: het script bindt niets positioneel
(`PositionalBinding = $false`). Een losse waarde is een bindingsfout voordat er een ledgerregel
bestaat - gemeten: een tweede verboden adres na `-VerbodenAdressen a b` belandde vroeger stil in
de eerste vrije parameter (bij R0 de snapshotverwijzing).

**De vloer en de huidige build (R0).** `-Huidigebuild` is de build die de doos volgens de export
draait (`config/nsversion`, `nsmcp.update_advice.export_current_build`); een doelbuild in een
andere releaselijn dan deze build blijft ook met acceptatie dicht, en zonder huidige build opent de
poort alleen op de acceptatie. `-Vloerbuild` is de vloer die de server uit de export en het
kennispakket afleidt (de hoogste fix-build van de eigen tak, `nsmcp.update_advice.export_floor`),
`-VloerBulletin` het bulletin waar hij vandaan komt, `-VloerPakket` en `-VloerPakketDatum` versie
en datum van het gepinde kennispakket dat die vloer leverde, en `-DoelbuildGeaccepteerd` de
menselijke acceptatie van een doelbuild onder de vloer, zonder bekende vloer, zonder bekende huidige
build of niet hoger dan de huidige build (herinstallatie of downgrade binnen de lijn;
`doelbuild_geaccepteerd=true`); een takverschil met de vloer blijft ook met acceptatie dicht. Het
bewijs van de vloerpoort noemt het kennispakket (of "kennispakket niet meegegeven") en draagt een
WAARSCHUWING als het pakket ouder is dan 30 dagen; die waarschuwing verandert de uitkomst nooit. De
server geeft ze alleen bij R0 mee, en alleen in de vorm die hier getoetst wordt; een vloer of
huidige build zonder die vorm (bijvoorbeeld een FIPS-trein) gaat niet mee, en de acceptatie dan
ook niet. `-Vloerbuild` en `-Huidigebuild` krijgen dezelfde vormtoets als `-Doelbuild` en mogen
leeg zijn; `-VloerBulletin` alleen letters, cijfers en koppeltekens, hoogstens 32; `-VloerPakket`
letters, cijfers, punt, liggend streepje en koppelteken, hoogstens 64; `-VloerPakketDatum` leeg of
`JJJJ-MM-DD`. De server geeft het pakket alleen mee samen met een vloer. Een afgekeurde waarde
drukt `[FOUT]` en `[GEWEIGERD]` af tijdens de binding, zonder de waarde te herhalen. R0 stuurt
verzoek `doelbuild-vloer` naar `python -m nsmcp.upgrade_measure`; `floor_gate` oordeelt en de
poort `doelbuild op of boven de vloer, of bewust geaccepteerd` staat daarna in `terugrolpunt_vast`
en in de sluitregel.

**De doelbuild in `fase_gestart`.** De startregel van elke fase draagt `doelbuild`. De server
weigert R1 tot en met R6 als de bundel in de map afwijkt van die waarmee R0 van dezelfde run
startte; dat veld is ledgerinhoud en wordt alleen op vorm getoetst, nooit herhaald.

`-Transport` wijst standaard naar `GjkUpgrade-Ssh.ps1` naast dit bestand; een test kan er een
ander bestand met dezelfde functienamen voor in de plaats zetten (zie
`tests/fixtures/runner/GjkUpgrade-NepTransport.ps1` en `tests/test_runner_script.py`) om zonder
appliance te draaien. `-GatePython` is het pad naar de Python-interpreter waarmee de twee
bovenstaande CLI's worden aangeroepen (`.venv\Scripts\python.exe`).

**`-Doelbuild` is TAK-GEKWALIFICEERD en wordt gevalideerd voordat de scriptbody start.** Dit is de
enige configuratiestring die zonder toetsing in een remote shell-commando EN een remote pad
terechtkwam (`cd <buildDir> && tar ...`, `./installns -Y -n`,
het poginggebonden precheckpad onder `/var/tmp/`).

- **Toegestane vorm**: `<build>` (`72.57`) of `<tak>-<build>` (`14.1-72.57`). Alleen cijfers,
  punten en hoogstens EEN koppelteken. **Dit product geeft `14.1-72.57` mee** - dat is de vorm waarin
  de rest van dit product een buildidentiteit schrijft (`nsmcp.cve.parse_build`). Het eerdere patroon
  `^[0-9]+(\.[0-9]+)*$` weigerde precies die waarde, want het koppelteken viel erbuiten.
- **De injectieafweer blijft ongewijzigd streng**: geen puntkomma, ampersand, spatie, backtick,
  `$(...)`, schuine streep of tweede koppelteken.
- **De tak wordt GESTRIPT voor het remote pad.** Een NetScaler-buildboom heet
  `/var/nsinstall/<tak>/build_<buildnummer>` - dus `/var/nsinstall/14.1/build_72.57` en nooit
  `.../build_14.1-72.57`. De tak uit `-Doelbuild` wint van de tak die uit de bundelbestandsnaam
  af te leiden is: `-Doelbuild` staat in het `[TARGET]`-etiket waaraan de bevestigingscode hangt,
  de bundelnaam is maar een afleiding.
- **De bundel wordt op de EXACTE naam gekozen, nooit op de eerste treffer.** R1/R2/R3 kiezen de
  firmwarebundel in `-Firmwaremap` als `build-<tak>-<build>_nc_64.tgz` - is `-Doelbuild`
  tak-gekwalificeerd (het gebruikelijke geval), dan is die naam letterlijk bekend en ontbreekt hij,
  dan weigert de fase; is `-Doelbuild` bare (geen tak, de losse-scriptvorm), dan zoekt de selectie
  op hetzelfde patroon met EXACT een kandidaat - nul of meer dan een treffer is ook dan een
  weigering. Een stray `.tgz` in dezelfde map (een oude bundel, een verkeerd gekopieerd bestand)
  wordt zo nooit meer stilzwijgend geupload, uitgepakt en geinstalleerd - dezelfde regel
  (`_FIRMWARE_BUNDLE_RE`) als `handelen.py`'s `_firmware_target_build()` al aanhoudt voor
  `-Doelbuild` zelf.
- **Een bundelnaam buiten de bundelvorm komt in geen enkel commando.** Bij een bare `-Doelbuild`
  komt de naam uit een wildcard over de map, dus uit een bestandsnaam die iedereen met
  schrijfrecht op `-Firmwaremap` kiest; die naam gaat daarna letterlijk in `shell sh -c`. Elke
  kandidaat van het patroon moet daarom `build-<tak>-<build>_nc_64.tgz` zijn (tak en build alleen
  ASCII-cijfers en punten, hoofdlettergevoelig). R1, R2, R3 en R5 toetsen dat voordat het transport
  laadt (ook bij `-WatIs`) en opnieuw waar de bundel gekozen wordt; een afwijkende naam geeft
  `[FOUT]` + `[GEWEIGERD]` en exitcode 4, zonder de naam te herhalen en zonder ledgerregel (bij de
  tweede toets staat de `fase_gestart`-regel er al, zonder sluitregel). De server geeft altijd een
  tak-gekwalificeerde `-Doelbuild` mee en vormt de naam dan zelf.
- **R5 vergelijkt de volledige tak en build exact.** Alleen een geslaagde versieaanroep kan
  bewijs leveren. `nsmcp.cve.parse_build` leest bijvoorbeeld `NetScaler NS14.1: Build 72.57.nc`
  als tak `14.1` en buildtuple `(72, 57)`; `172.570`, `72.570` en een andere tak voldoen niet.
  Een tak-gekwalificeerd doel heeft hiervoor geen firmwarebestand nodig. Bij een historisch
  kaal buildnummer moet de tak eenduidig uit de exact geselecteerde bundel volgen; zonder die
  informatie blijft het oordeel `niet beoordeeld`.
- **Een geweigerde waarde meldt zichzelf.** De validatie zit in een `[ValidateScript({...})]` die
  `[FOUT]` en `[GEWEIGERD]` afdrukt voordat hij weigert: een bindingsfout produceerde voorheen
  geen enkele regel op dat kanaal, omdat de scriptbody dan nooit start. De afgekeurde waarde zelf
  wordt niet geechood.

**Verboden adressen** (adresvorm sinds een latere wijziging uit de configuratie, niet
meer uit een letterlijke waarde in dit bestand): de statische naam `lab-01` in
`$script:GjkVerbodenAdressen` wordt ALTIJD getoetst; adresvormen (IP's, FQDN's) worden er per
aanroep aan toegevoegd via de optionele parameter `-VerbodenAdressen` (standaard leeg; meerdere
adressen als EEN komma-gescheiden argument, `a,b` - het script splitst zelf op de komma, want
`powershell.exe -File` bindt maar een van twee losse waarden aan een string-array). De MCP-server
vult die parameter uit configuratieveld `handelen.verboden_adressen` (zie
`docs/klant/HANDLEIDING.md`) - het echte adres van lab-01 staat dus buiten deze repository, in de
configuratie van de operator, niet in code. Zonder die parameter (leeg) weigert de guard alleen op
de naam. Getoetst op zowel `-Adres` als `-Doel`, VOOR er ook maar een transportbestand geladen
wordt - ook bij `-WatIs`. lab-01 is voorgoed read-only; een fase erop weigert met exitcode 1 en
`[GEWEIGERD]`.

*Waarom niet gewoon een letterlijk adres in dit script.* Elke letterlijke waarde in dit bestand is
een kandidaat voor de fixture-pseudonimiseringsronde (dezelfde literaalvervanging die
testliteralen meeverschuift) - gemeten: het echte adres werd stilzwijgend vervangen door een
TEST-NET-alias, en de adreshelft van de guard bewaakte vanaf dat moment een doos die niet bestaat.
Dit is een BEWUSTE, gemotiveerde uitzondering op de regel "geen productgedrag wijzigen":
de guard is een veiligheidscontrole en moet blijven werken, dus verhuist het adres naar
configuratie in plaats van code.

*Wat die toets wel en niet dekt*, zonder mooier gemaakt te worden dan hij is. Genormaliseerd
wordt: getrimd, hoofdletterongevoelig, een `gebruiker@`-voorvoegsel eraf, een `:poort`-achtervoegsel
eraf, een afsluitende punt van een FQDN eraf; van een NAAM (nooit van een IPv4-vorm) wordt ook het
eerste DNS-label getoetst, zodat `lab-01.intern.example` net zo goed geweigerd wordt als `lab-01`.
**Niet gedekt**: een tweede DNS-naam voor dezelfde doos, een CNAME, een decimale of hexadecimale
schrijfwijze van hetzelfde IPv4-adres, een IPv6-vorm, of een NAT-adres. Een volledige
aliasresolutie zou een DNS-lookup vragen en die doet dit script bewust niet - het raakt niets aan
voordat het geweigerd heeft. Dit is dus een VANGNET tegen de voor de hand liggende schrijfwijzen,
geen bewijs dat een verboden doos onbereikbaar is; die garantie ligt bij de aanroeper die
het adres vormt.

**`-Actieid` is verplicht op een echte run.** Zonder dat argument ging een leeg `actieid` naar
`upgrade_gate` terwijl `actieid_uit_script` het zelf gegenereerde id droeg; `evaluate_phase`
vergelijkt die twee met `!=`, dus ELKE fase sloot `mislukt` - met een ledgerregel die een echt
oordeel leek. Het script weigert die aanroep nu expliciet (`[GEWEIGERD]`, exitcode 1) voordat er
een ledgerregel bestaat. Bij `-WatIs` is een leeg `-Actieid` juist normaal: er is dan nog niets
bevestigd en het script vormt zelf het etiket waaraan de mens de code straks bindt.

### `-Actieregister` en `-ExportRoot` - de aanroeper bedraadt beide

R0 raakt de appliance NIET aan (ontwerp 3.5: "NIETS op de appliance"). Zijn twee bronnen zijn:

- **`-Actieregister`** - het pad naar het actieregister: JSONL, een JSON-object per regel,
  hetzelfde formaat als het ledger.

  De aanroeper geeft dit argument mee zodra `onderhoud.actieregister` in de
  configuratie staat (`handelen.build_upgrade_arguments()`) - de PATH, niet een verzonnen locatie.
  De schrijver is `mcp_server._act()` via `nsmcp.upgrade.register_line()` (sinds 8-9-2026): een
  regel per UITGEVOERDE schrijvende handeling (nooit voor een voorstel), met `tijd`, `tool`, `doel`,
  `actieid`, `uitkomst`, `bevestiger` en voor een backup `objectnaam`. Wat hieronder staat is dus
  wat het product schrijft en wat deze runner leest. Is `onderhoud.actieregister`
  niet geconfigureerd, dan blijft `-Actieregister` net als vroeger helemaal weg - een LEEG veld in
  de configuratie is dus nog steeds eerlijk `niet beoordeeld`, geen fout.

  Velden per regel: minstens `tool`, `doel`, `uitkomst`, `actieid` en - voor
  `onderhoud_backup_maken` - **`objectnaam`** (`nsmcp.upgrade.REGISTER_OBJECT_FIELD`) met de
  backupnaam die het PRODUCT vormde (`handelen.ActionResult.object_name`, door `perform()` uit de
  argumentlijst gelezen - nooit terug-geparsed uit de stdout van het schrijfscript; het mechanisme
  dat eerder gerepareerd is). R0's backupobject-poort zoekt hierin de meest recente
  `onderhoud_backup_maken`-regel voor dit `-Doel` met `uitkomst: "geslaagd"`, en R0's
  `terugrolpunt_vast`-regel zoekt die `objectnaam` daarna op in de COLLECTIE
  `config/systembackup` van de export - voor de grootte en de tijd - nooit met een GET op de
  naam (gemeten: een verwijderd object antwoordt daar met 599 in plaats van 404, lab-meting
  `nitro-readback-599-vs-404`, dus een fout en een afwezigheid zijn op die route hetzelfde
  antwoord).
- **`-ExportRoot`** - het pad naar een NSHC-collectorexport-map (`export-manifest.json` +
  `objects/`/`parsed/`, hetzelfde formaat als `nsmcp.export.load_export()` overal elders in dit
  product leest). Hieruit komen: de vorige buildboom (`config/systemfile` met `filelocation` op
  `/var/nsinstall`, dezelfde bron als preflight-check 9), de leeftijd van die export
  (`collectedAtUtc`), de familietellingen (objecttellingen per `nsmcp.upgrade.FAMILIES`-resource) en
  het genormaliseerde configuratie-anker (`parsed/runningconfig.txt`, hash-geverifieerd).

**Beide zijn OPTIONEEL op dit script's eigen parameterlijst** (leeg is de standaardwaarde) - een
leeg of onleesbaar pad maakt de bijbehorende poort `niet beoordeeld`, NOOIT `open`
(`nsmcp.upgrade.backup_register_gate`/`build_tree_gate`/`export_age_gate`/`family_counts_gate`).
**De aanroeper die dit script echt start geeft ECHTE paden mee voor beide** - dit script
zelf verzint geen locatie: `-ExportRoot` kreeg altijd al `onderhoud`'s eigen `export_dir` mee,
en `-Actieregister` krijgt sinds een latere wijziging het geconfigureerde
`onderhoud.actieregister` mee zodra die sleutel gezet is (anders blijft het argument weg en
degradeert de bijbehorende poort eerlijk naar `niet beoordeeld`, in plaats van een verzonnen pad
te verzinnen).

## Het exitcodecontract

| exitcode | betekenis | wie geeft hem |
|---|---|---|
| 0 | de fase is GEOORDEELD en de uitkomst is `geslaagd` | `python -m nsmcp.upgrade_gate` |
| 1 | de fase is GEOORDEELD en de uitkomst is `poort dicht` of `mislukt`; OF het script heeft de aanroep zelf GEWEIGERD voordat er een ledgerregel bestond (`[GEWEIGERD]`: niet-ASCII argument, een stuurteken (CR, LF, tab) in een tekstparameter of een verboden adres, een adres/doel op de verboden lijst, een ontbrekende `-Actieid` op een echte run, een `-Doelbuild`, `-Huidigebuild`, `-Vloerbuild`, `-VloerBulletin`, `-VloerPakket` of `-VloerPakketDatum` die de vorm niet heeft) | `upgrade_gate`, of het script zelf |
| 2 | NIET BEOORDEELD: `upgrade_gate` of `upgrade_measure` kon de STDIN-invoer zelf niet lezen (kapotte JSON of een ontbrekend verplicht veld), of `upgrade_measure` (actie `start`) weigerde `fase_gestart` omdat er op hetzelfde doel al een fase open staat binnen zijn tijdslimiet of de ledgermap niet te lezen is (het script logt dan `[FOUT]` + `[GEWEIGERD]` en opent geen sessie), of de fase draagt al ELDERS in het eigen ledgerbestand van deze run een sluitregel - ELKE sluitregel voor deze fase, niet alleen de laatste (`ClosedPhaseError`, herbeoordeling geweigerd omdat een gesloten fase niet opnieuw gesloten mag worden - een retry hoort een nieuwe `run` te zijn). Er is geen fase-uitkomst. Een onleesbare REGEL in het eigen ledgerbestand van deze run (in plaats van de STDIN-invoer) is dit NIET: die telt als een eigen `niet beoordeeld`-poort ("ledger leesbaar") die de fase op `poort dicht` sluit (exitcode 1) - de gesloten stand kan dan niet volledig vastgesteld worden, maar er komt wel een sluitregel | `upgrade_gate` / `upgrade_measure` |
| 3 | de runner kon zijn werk niet eens proberen te voltooien: Posh-SSH ontbreekt, OF een ONVERWACHTE MEETFOUT (een ontbrekende firmwarebundel, een mislukte SFTP-upload, een niet-nul exitcode uit `upgrade_measure`). Gelogd als `[FOUT]` + `[GEWEIGERD]`, GEEN `[EINDSTATUS]`, en er komt geen sluitregel in het ledger | het script zelf |
| 4 | een firmwarebundel die via het patroon van een bare `-Doelbuild` gevonden wordt, heeft niet de bundelvorm `build-<tak>-<build>_nc_64.tgz`: geweigerd voordat de naam in een commando komt. Gelogd als `[FOUT]` + `[GEWEIGERD]`, GEEN `[EINDSTATUS]`, geen sluitregel | het script zelf |

Exitcode 1 is in dit contract het woord voor een GEOORDEELDE weigering. Daarom eindigt een crash
NOOIT met 1: een onverwachte meetfout is exitcode 3, zodat een aanroeper een echte poortuitspraak
nooit met een kapotte run kan verwarren.

## De twee etiketten

Elke aanroep (ook `-WatIs`) drukt af:

```
[TARGET] <doosnaam> (<adres>) - fase <Rn> naar build <doelbuild>[, oude buildbomen opruimen]
[ACTIEID] upgrade-<fase>-<jjjjmmdd-hhmmss>
```

De toevoeging ", oude buildbomen opruimen" staat er ALLEEN bij `-OudeBuildbomenOpruimen`: het
argument maakt deel uit van het etiket waaraan de bevestigingscode gebonden is, zodat een mens de
opruiming zelf bevestigt. De runner ruimt nooit uit zichzelf op.

## -WatIs

Drukt beide etiketten af en een korte beschrijving van wat de fase ZOU doen, en stopt dan
(exitcode 0). Er wordt geen transport geladen voor sessiedoeleinden, geen sessie geopend en geen
ledgerregel geschreven.

## Drie gemeten feiten die dit script hard respecteert

- de exitstatus van `shell reboot` betekent niets (gemeten: exit -1 na 30,1 s time-out, in alle
  vier de spike-runs) - R4 oordeelt uitsluitend op SSH-auth, nooit op die exitstatus;
- de exitstatus van `installns --pre_check` betekent niets - het script stuurt de JSON door, de
  oordeelshelft beslist;
- de vingerafdruk wordt na de reboot OPNIEUW gemeten, nooit aangenomen dat hij gelijk bleef.

R2 krijgt per run, bevestigde actie en unieke poging een eigen resultaatpad onder `/var/tmp/`.
De runner bewijst vooraf dat dit pad afwezig is, ook als symbolische link, voert de precheck
met dat pad uit en leest uitsluitend dat resultaat terug. Een bestaand bestand, ontbrekend
resultaat of mislukte
leesaanroep kan geen geslaagde precheck opleveren. De vendorvelden `global_status` en `checks`
bepalen vervolgens de inhoudelijke uitkomst; de exitstatus van de precheck zelf doet dat niet.

Configuratiebewijs bevat ook de status van de leesaanroep. Een mislukte of ontbrekende lezing
legt geen anker vast. Een geslaagde lezing met lege uitvoer mag wel een expliciet leeg anker
opleveren: leeg bewijs en ontbrekend bewijs zijn verschillende toestanden.

Een afsluitende herlezing vervangt geen voorafgaand bewijs en omgekeerd. Als dezelfde poort
voor en na de handeling wordt gemeten, bewaart het ledger beide: de eerdere meting krijgt
het voorvoegsel `voorpoort:`, de afsluitende meting houdt de gewone poortnaam. Beide tellen
mee in het oordeel. Een open hostsleutelpoort voor reboot kan zo een negatieve meting na
reboot nooit verbergen.

## `sso_presenter_windows.py` - de referentiepresenter voor het codekanaal `sso`

Puur-Python, alleen de standaardbibliotheek (`ctypes`, `json`, `sys`, `datetime`), geen import
van `nsmcp`: `code_channel.SsoCodeChannel` start dit bestand als EIGEN PROCES
(`[sys.executable, handelen.codekanaal.pad]`), dus het moet zelfstandig draaien op een machine
die alleen Python heeft. Windows-only, en die Python is minimaal 3.11 (`from datetime import
UTC` gebruikt dat rechtstreeks) - dezelfde ondergrens als de rest van dit product
(`pyproject.toml`, `requires-python`).

Draai dit script nooit als Windows-service of onder een ander serviceaccount: in sessie 0
geeft `MessageBoxW` geen 0 terug (het gedocumenteerde "geen interactieve sessie"-pad) maar
BLOKKEERT op een onzichtbaar bureaublad tot `SsoCodeChannel`'s eigen `wachttijd_s` dit proces
beeindigt - fail closed blijft overeind, maar via de timeout, niet via het venstergedrag hierboven.

### Wat het is

De referentie-implementatie van "goedkeuring via de beheerdersidentiteit van de interactieve
Windows-sessie": het toont de bevestigingscode in een `MessageBoxW` (OK/Annuleren, topmost) op
het bureaublad waarop dit proces draait, en meldt bij OK terug WIE er bevestigd heeft. Dat is het
verschil met de kanalen `venster` en `bestand`: die kunnen allebei een code tonen, geen van
beide kan zeggen wie er keek.

### Welke identiteit hij levert, en hoe sterk die is

`bevestiger` is de Windows-identiteit van de interactieve sessie waarin het venster getoond is,
via `secur32.GetUserNameExW`: eerst de UPN (`NameUserPrincipal`), en alleen als die er niet is
`MACHINE\gebruiker` (`NameSamCompatible`). Eerlijk gezegd: dit bewijst dat iemand met een
Windows-aanmelding op DIT bureaublad op OK geklikt heeft - het bewijst geen Entra-aanmelding, geen
MFA en geen druk op een telefoon. Sterker (Entra-gebonden, push-based) is roadmap, geen vandaag.
`bevestiger` is nooit leeg: kan geen van beide namen vastgesteld worden, dan levert dit script
niets af (exit 1), ook al is er op OK geklikt.

### Configuratie (`handelen.codekanaal`)

```json
{"soort": "sso", "pad": "C:\\pad\\naar\\sso_presenter_windows.py",
 "autoriteit": "https://...", "wachttijd_s": 120}
```

- `soort`: altijd `"sso"` voor dit kanaal.
- `pad`: absoluut pad naar dit bestand (of een ander presenterscript met hetzelfde protocol);
  moet bestaan bij het starten van de server, en mag niet in een map liggen die het product
  zelf leest of schrijft (`_check_code_path` in `start.py` weigert dat bij het starten).
- `autoriteit`: een https-URL - waar de goedkeuring vandaan komt. Verschijnt in de zin
  "goedkeuring namens `<autoriteit>`" in het venster - bij meer dan 200 tekens afgekapt met
  `...` (net als `aanduiding`; de code zelf wordt nooit afgekapt).
- `wachttijd_s`: hoe lang de server op aflevering wacht voordat hij dit proces beeindigt en de
  code als niet-afgeleverd behandelt (positief geheel getal).

### Het protocol

Een regel JSON op stdin, een regel JSON terug op stdout - nooit meer dan een van elk.

**In** (door `SsoCodeChannel.__call__` geschreven):

```json
{"vingerafdruk": "...", "code": "...", "autoriteit": "https://...",
 "aanduiding": "voorstel A", "gereedschap": "onderhoud_upgrade_fase",
 "doel": "[TARGET] node-a", "sectie": "netscaler-01", "fase": "R3", "voorstel": "Installeer de bevestigde build.",
 "argumenten": ["doelbuild_geaccepteerd: False", "drift_geaccepteerd: False", "fase: R3", "..."]}
```

`argumenten` is verplicht: een lijst (mag leeg zijn) van ten hoogste 32 regels, elk printbaar en
maximaal 4096 tekens - dezelfde `<naam>: <waarde>`-regels die het venster onder `wat:` toont,
een per argument van de handeling (elk argument van de aanroep behalve `doel` en `bevestiging`),
elke waarde afgekapt op 120 tekens. De doelnaam (de sectie in `handelen.toegestaan`) is ook aan
de code gebonden en staat er niet in, maar in het eigen veld `sectie`: `doel` is het doel-etiket
dat het schrijfscript meldt, en dat is gelijk voor twee doelnamen die dezelfde handeling toestaan.
De presenter toont ze boven de code, los van de voorsteltekst en volledig; alleen een regel boven
200 tekens wordt voor weergave afgekapt, en die vormt de server zelf nooit.

`sectie` is verplicht: de doelnaam waaraan de code gebonden is. De referentiepresenter toont haar
op een eigen regel `sectie: <doelnaam>` direct onder `doel:`, ook als doelnaam en etiket op
elkaar lijken, en weigert een verzoek zonder `sectie` voordat er een venster komt.

Een eigen presenter MOET elke regel van `argumenten` en de `sectie` tonen, zoals de
referentiepresenter: de code is aan die waarden gebonden. Een presenter van voor deze versie
weigert geen onbekend veld en toont `argumenten` en `sectie` dus niet; hij spiegelt ze ook niet
terug, en daarom levert hij geen code meer af (zie **Uit, bij OK**). Werk presenter en server
samen bij.

`code`, `aanduiding`, `autoriteit`, `gereedschap`, `doel`, `sectie` en `voorstel` zijn verplicht,
niet leeg, printbaar (`str.isprintable()`) en maximaal 4096 tekens. `doel` en `sectie` hebben een
strengere grens van 256 tekens en worden volledig getoond. Ontbrekende of ongeldige velden weigeren
het verzoek voordat er een venster komt. `vingerafdruk` wordt nooit getoond, alleen na OK
ongewijzigd teruggespiegeld. Het is een sha256 over
gereedschap, argumenten, het getoonde doel-etiket en de doelnaam: twee voorstellen voor
verschillende doelnamen met hetzelfde etiket en dezelfde argumenten krijgen een verschillende
waarde. Het is niet per se de sleutel waaronder de server de code bewaart: die rekent met het
etiket zoals het schrijfscript het meldde.
Het codekanaal valideert doel, sectie, gereedschap en fase ook voordat het de presenter start en
geeft die identiteit volledig door. Het kapt een te lang doel niet af om het alsnog passend
te maken. Voorsteltekst mag wel worden gesaneerd en begrensd voor weergave.

`gereedschap` maakt het verschil tussen een faseaanvraag en een gewone schrijfactie expliciet:
voor `onderhoud_upgrade_fase` is `fase` verplicht R0 tot en met R6; voor andere gereedschappen
moet het veld aanwezig en leeg zijn. De presenter leidt de fase niet af uit de voorsteltekst.
Doel, sectie, fase en argumentregels staan boven de code, met de voorsteltekst begrensd op 1000 tekens en een zichtbare
`...` bij afkapping. Werk de referentiepresenter samen met de server bij; de oude aanvraagvorm
zonder deze context wordt geweigerd, en een terugantwoord zonder spiegel ook (hieronder).

**Uit, bij OK** (exit 0):

```json
{"afgeleverd": true, "sectie": "netscaler-01", "vingerafdruk": "...", "bevestiger": "<identiteit>", "tijdstip": "2026-09-08T12:34:56Z"}
```

`sectie` en `vingerafdruk` zijn verplicht in het antwoord: exact de waarden uit het verzoek,
ongewijzigd teruggespiegeld, en pas na de positieve keuze van de mens. `SsoCodeChannel` telt een
aflevering alleen als beide exact gelijk zijn aan wat het kanaal stuurde - geen hoofdletterfolding,
geen spaties wegknippen. Ontbreekt een van beide, of hoort een van beide bij een ander verzoek,
dan is er niets afgeleverd: het kanaal faalt dicht met de reden "de presenter spiegelt sectie en
vingerafdruk niet terug: verouderde of onbekende presenter", de server verbruikt de code zodat
hij niet inwisselbaar is, en de reden noemt code noch sectie. Zo levert een presenter van voor het
veld `sectie` - die het veld negeert, de code zonder sectie toont en toch `afgeleverd: true`
antwoordt - geen code meer af. Er is geen apart versieveld en geen terugval naar het oude
antwoord: de spiegel is het bewijs dat de presenter de sectie gelezen heeft. Wat de presenter
werkelijk toont, bewijst de spiegel niet; die garantie geldt voor de meegeleverde
referentiepresenter of een presenter die u zelf beoordeeld hebt.

`bevestiger` moet, net als hierboven, printbaar zijn en binnen 256 tekens blijven - exact de
eisen die `SsoCodeChannel` zelf al aan de ontvangende kant stelt
(`code_channel._clean_answer_field`); een derde presenter die zich hierop baseert moet aan
dezelfde twee eisen voldoen, anders levert dit script niets af (exit 1), ook al is er op OK
geklikt. Deze ene regel wordt in EEN schrijfactie plus flush geschreven; faalt een van beide
alsnog, dan volgt NOOIT exit 0 - `SsoCodeChannel` leest stdout uitsluitend bij returncode 0, dus
inhoud die mogelijk toch (deels) in de stream staat wordt door een ontvanger die het protocol
volgt genegeerd.

**Bij Annuleren, sluiten, geen bureaublad, onleesbare invoer, een ontbrekend of niet-printbaar
veld, een identiteit die niet vastgesteld kan worden, een mislukte schrijfactie, of welke fout
dan ook**: geen stdout-regel met `afgeleverd: true`, exit 1. Een korte, vaste reden mag op
stderr - nooit de code, nooit de volledige invoerregel.

### De drie invarianten, in dit script

- De bevestigingscode staat NERGENS behalve in de venstertekst: niet in stdout (buiten het
  venster om), niet in stderr, niet in een bestand, niet in een procesargument.
- Er is geen vlag, omgevingsvariabele of "testmodus" die het venster overslaat of automatisch
  OK geeft - dat is precies het gat (het model dat zichzelf bevestigt) waarvoor dit kanaal
  bestaat. Tests injecteren de venster- en identiteitsfunctie zelf, via parameters van `main()`
  in-process, of door ze als module-attributen te vervangen voor een subprocess-aanroep - nooit
  door een kortere weg in dit script zelf.


## Offline pseudonimisering van een export

`pseudonymise_export.py` maakt een nieuwe doelmap na manifest-, hash- en
lekcontrole. Aanroep: `python scripts/pseudonymise_export.py --source <bron>
--target <nieuw-doel> --mapping <map-buiten-repos> [--extra-forbidden <bestand-buiten-repos>]`.
Bronbestanden blijven ongewijzigd; mapping.json en verboden.txt blijven prive
buiten elke repository. Ook een hergebruikte mapping blijft bij een fout in
de lekcontrole ongewijzigd. De controle wordt op de stagingbytes herhaald.

Elke geslaagde run zet `manifest["pseudonymisation"] = {"version": 1}` in het
doelmanifest voordat dat manifest wordt weggeschreven. Een BRON die deze
sleutel al draagt wordt direct na de bronvalidatie geweigerd (eigen diagnose,
geen doelmap, mapping ongewijzigd) - dus nooit stilzwijgend opnieuw
gepseudonimiseerd.

Deze marker herkent alleen een BRON die zelf al door de huidige tool liep.
Een output van VOOR de marker bestond, of elke andere historische output
zonder deze sleutel, mist hem - daarom herkent `collect_candidates()`
daarnaast elke kandidaatnaam die al de vorm draagt die dit gereedschap zelf
uitgeeft: het per-familie `FAMILIE-NNN`-patroon (afgeleid uit `NAME_SOURCES`,
dus automatisch elke familie - `LBV`, `CSV`, `VSRV`, `MON`, `CERT`, `TERM`,
enz., niet alleen de familie waarin de eerste externe proef het aantoonde),
het `host-NNN.lab.example`/`host-NNN.invalid`-patroon en de vaste
id-aliassen. Zo'n naam wordt voor elke mapping geweigerd, met een eigen
diagnose, geen doelmap, mapping ongewijzigd - ook wanneer de bron geen
marker en geen botsende hostalias draagt. Bewuste afweging: een ECHTE eerste
bron met een object dat toevallig precies zo heet (een lbvserver die een
klant zelf "LBV-001" noemde) wordt op dezelfde manier geweigerd; de operator
hernoemt dat object op de bron. De referentiefixture
`tests/fixtures/lab-export-vpx-20260826/` draagt de marker sinds de
nabehandeling van vrije tekst (zie hieronder) en wordt dus al op de marker
geweigerd.

Vervanging gebruikt naamgrenzen om protocolwaarden en JSON-veldnamen te
behouden. De eindpoort zoekt hoofdletterongevoelig naar elke oorspronkelijke
substring in bestandsnamen, tekst en gedecodeerde JSON (sleutels en waarden
rauw, zonder hercodering). Een restant binnen een langer woord, certpad of
subject-CN geeft exitcode 1 en MISLUKT, zonder nieuw doel. De aparte
identiteitspoort controleert bronhostnamen ook als de mapping een naam mist.
De diagnose noemt de familie van het origineel (uit het alias-voorvoegsel,
bijv. LBV/host/ip/CERT/TERM - altijd veilig vocabulaire, nooit het origineel
zelf) en een veilige bestandsnaam; bij een onbekende of gevoelige bestandsnaam
wordt het volgnummer in de gesorteerde bestandenlijst getoond, bepaal het
bijbehorende bestand uitsluitend lokaal. Zit de treffer uitsluitend in een
JSON-sleutel of een bestandsnaam en niet in een echte waarde, dan meldt de
diagnose dat expliciet: zo'n treffer is schema (bijv. een objectnaam die
toevallig een substring is van een NITRO-veldnaam als `netscaleruuid`) en is
niet oplosbaar via `--extra-forbidden` - alleen hernoemen op de bron helpt.

De velden sslcertkey.cert, sslcertkey.key en sslcertkey.linkcertkeyname
leveren als CERT-kandidaat: de volledige basename (inclusief extensie, zodat
de vervanger de hele naam als geheel blijft vervangen), de kale stam zonder
een herkende extensie uit FILE_SUFFIXES (zodat een sibling-bestand met een
andere of ontbrekende extensie - een `.pem`-tegenhanger, een los genoemde
stam in een logregel - ook een bekend origineel is voor de eindpoort, die geen
naamgrenzen kent), en de directe mapnaam in het pad tenzij die een standaard
NetScaler-certopslagsegment is (`nsconfig`, `ssl`, `var`, `tmp`, `flash`) -
bijvoorbeeld een klantnaam onder `/nsconfig/ssl/<map>/`. Het appliancepad
blijft een string; het script opent nooit de daarin genoemde certificaat- of
sleutelbestanden. Een kandidaat die zelf een bekende technische of publieke
term is (`protected_category`, incl. KEEP_NAMES) wordt overgeslagen met een
`[waarschuwing]`-regel, niet als fout. Een kale stam die toevallig gelijk is
aan het eigen familie-voorvoegsel (bijv. een cert letterlijk genaamd `cert`)
blijft een losstaande, bestaande fout ("botst met de verplichte
pseudoniemvorm"): dat is geen protected_category-geval en wordt niet apart
overgeslagen, maar faalt wel altijd veilig (exit 1, geen doelmap). Een
sibling die de vervanger niet kan raken (de bare stam gevolgd door een punt
blijft altijd buiten de naamgrens) laat de run falen; de operator zet die
sibling dan zelf in `--extra-forbidden`.

Een AFGELEIDE kandidaat (de kale stam of de mapnaam - nooit de volledige
basename, die blijft altijd kandidaat) wordt overgeslagen met een
`[waarschuwing]`-regel zonder de naam te noemen, alleen de reden, als hij
korter is dan vier tekens of casefold een substring is van een vaste
technische/publieke term (`PROTECTED_PUBLIC_SUFFIXES`, `KEEP_NAMES`,
`CONFIG_TERMS`, `SEMANTIC_FIELDS`, de standaard certopslagsegmenten).
Zulke fragmenten (`root`, `ca`, `old`, `ssl`, ...) zijn afkomstig uit het
pad zelf, geen door de operator gekozen naam, en botsen daardoor vaker met
schematekst (`root` in `root-servers.net`, `ssl` als protocolwaarde, een
tweeletterige map in een hex-hash) dan dat ze een echt origineel zijn. Een
generiek woord van vier tekens of meer dat toevallig NIET in die vaste
lijst staat maar wel ergens anders in de export als substring voorkomt
(bijv. een map `backup` naast een configregel met `-backupVServer`) blijft
een bestaande, losstaande fout: dat is geen lek maar een onvermijdelijk
gevolg van substring-gebaseerde detectie. Los op door de map op de bron te
hernoemen, of geef het volledige token via `--extra-forbidden` als dat kan.

Dezelfde vier-tekens-grens geldt voor een geoogste hostnaam (nshardware/
hanode/nshostname, inclusief de `set ns hostname`-configregel) en voor de
doelnaam uit scan-doel.txt: te kort wordt niet als kandidaat of identiteit
opgenomen, alleen een `[waarschuwing]`-regel (hostnaam- of doelnaam-
variant, zonder de naam te noemen). Los op door het doel of de host op de
bron te hernoemen - `--extra-forbidden` is hiervoor ongeschikt, want dat
vervangt dan een NetScaler-sleutelwoord door een klantalias en maakt de
configuratietekst onjuist. Een hergebruikte `mapping.json` van voor deze
grens kan nog een origineel korter dan vier tekens bevatten; zo'n
vermelding wordt overgeslagen (eigen `[waarschuwing]`-regel, nooit de naam)
in plaats van hergebruikt, en verdwijnt uit de herschreven mapping. Het
pseudoniem van zo'n overgeslagen vermelding (te kort, of ingebouwd - zie
hieronder) blijft alleen BINNEN DEZE RUN gereserveerd: het wordt niet aan
een andere kandidaat in dezelfde run uitgegeven, maar die reservering staat
alleen in het geheugen van deze aanroep en wordt niet weggeschreven. Een
volgende run met dezelfde teruggeschreven `mapping.json` kan dat pseudoniem
dus wel opnieuw uitgeven aan een niet-verwante kandidaat; er is bewust geen
persistente reserveringslijst gebouwd.

Een NetScaler-eigen ingebouwd object (certkeys als `ns-server-certificate`
en `ns-sftrust-certificate`, de rewrite-actie `NOREWRITE`, de
`ns_default_ssl_profile_*`-profielen, standaardmonitoren als `ping-default`
en `tcp-default`, de ingebouwde CVPN-rewriteregelset, ...) is nooit een
kandidaat of identiteit: een NITRO-rij met een niet-lege `builtin`-lijst of
een letterlijke `builtin: true` (alleen dat objecttype gebruikt de
boolean-vorm) levert nooit een kandidaat, en `VENDOR_BUILTIN_NAMES` vangt
de namen op die dat attribuut (in deze schema's objecttypen) niet dekt.
Zulke namen zijn op elke appliance gelijk en de productlogica vergelijkt
er hardcoded op; ze mogen wel in de diagnose genoemd worden,
leveranciersvocabulaire is publiek. Regel A slaat nooit de hele rij over:
een ingebouwde certkey kan nog altijd een operator-benoemd `.cert`/`.key`-
bestand dragen, en dat blijft een gewone kandidaat. Noemt een klant een
eigen object toch net zo, dan hernoemt hij het op de bron.

`builtin_names(blobs)` bundelt `VENDOR_BUILTIN_NAMES` met elke NAAM uit deze
export die zelf een ingebouwde rij draagt (regel A) maar niet in die vaste
lijst voorkomt, en geldt op drie plekken tegelijk: de verse kandidaatoogst,
een hergebruikte `mapping.json`-vermelding, en een `--extra-forbidden`-
literal. Een hergebruikte `mapping.json`-vermelding voor zo'n naam wordt net
als een te korte vermelding overgeslagen (eigen `[waarschuwing]`-regel,
alias blijft bezet) - staat de naam in de vaste `VENDOR_BUILTIN_NAMES`-lijst,
dan noemt die regel de naam (publieke vocabulaire); komt hij alleen uit
regel A van DEZE export, dan blijft de waarschuwing naamloos, want een
willekeurige attribuutnaam is niet zonder meer veilig om af te drukken. Een
`--extra-forbidden`-literal die zo'n naam is (vast of attribuutgebaseerd)
wordt geweigerd (eigen diagnose, exit 1, geen doelmap) in plaats van alsnog
kandidaat te worden.

`VENDOR_BUILTIN_NAMES` is een exacte (casefold) lijst, gemeten op een
14.1-labexport (`tests/fixtures/lab-export-vpx-20260826`) - op dit moment
200 namen, geen voorvoegselregel. Een ingebouwde naam die daar niet in
voorkomt EN geen ingebouwde rij (regel A) draagt in de huidige export (andere
firmware, een andere CVPN-generatie, afwijkende standaardmonitoren) wordt
gewoon vervangen: geen lek, wel ruis, en de productlogica die op die naam
vergelijkt is in zo'n gepseudonimiseerde fixture dan niet meer zichtbaar.
De lijst breidt uit door meten, nooit door een `ns_`/`ns-`-voorvoegsel te
vertrouwen - dat zou een klantobject met datzelfde voorvoegsel net zo goed
laten staan. Een naam met voorvoegsel `ns_cvpn_` of `ns_default_` die toch
vervangen wordt, telt mee in een eigen naamloze regel
(`[waarschuwing] N niet-gelijste namen met een leveranciersvoorvoegsel
(ns_cvpn_/ns_default_) zijn wel vervangen; controleer de mapping`), zodat
zo'n lijstgat zichtbaar is zonder dat er iets lekt.

Elke ontbrekende of lege verwachte payloadSha256 of fileSha256 krijgt een
eigen waarschuwing. Ontbrekende bewijswaarden blijven ontbreken; de uitvoer
krijgt daarvoor geen nieuw vertrouwen. LF/CRLF en een aanwezige UTF-8-BOM
blijven per bestand behouden; bestanden zonder BOM krijgen er geen. De
configpayloadhash volgt de bestaande BOM-vrije LF-normalisatie van de reader.
Overige hashes en de scan-doelstempel gebruiken de werkelijke uitvoerbytes.

Controleer voor publicatie handmatig sslcertkey subject en issuer, met name
O= (organisatie) en L= (plaats), en de vrije tekst die niet onder "Vrije tekst"
hieronder valt (beleidsregels, expressies, paden in een regel). Deze velden
hebben geen algemene automatische anonimiseringsregel; alleen reeds bekende of expliciet opgegeven
literalen worden vervangen. De operator-naampoort, de vertrouwelijke extra
termenlijst en vergelijking van semantische uitkomsten blijven vereist.
GESLAAGD bewijst de beschreven controles, geen algemene anonimiteit.

## Synthetische DoH-export: `make_doh_fixture.py`

`make_doh_fixture.py` schrijft `tests/fixtures/lab-export-vpx-doh-synthetic/`:
een export in de vorm die de verzamelaar schrijft (manifest met een hash per
resource en per bestand, `objects/`, aggregate- en lijstvormige `bindings/`,
`parsed/runningconfig.txt` en `parsed/savedconfig.txt`, `collect-log.txt`),
met uitsluitend verzonnen inhoud: namen als `LBV-DOH-001`, adressen op de
TEST-NET-reeksen, hostnamen onder `lab.example`, geen vrije tekst uit welke
echte export dan ook. Er komt geen appliance, geen netwerk en geen klok aan
te pas; dezelfde aanroep schrijft dezelfde bytes.

Aanroep vanuit de repositorywortel, in de venv van het project:
`python scripts/make_doh_fixture.py` (schrijft de fixture; weigert als de map
al bestaat) of `python scripts/make_doh_fixture.py --force` (vervangt hem).
De hashes in het manifest komen uit `nsmcp.export.payload_digest` en
`nsmcp.export.config_text_digest`, dezelfde functies waarmee het product ze
leest; na het schrijven leest het script elke bron terug via `load_export` en
eindigt het met `[eindstatus] GESLAAGD` of, bij een leesgat, met exitcode 1.
Wie de fixture wijzigt, wijzigt het script en draait het opnieuw; de
tellingen in de tests zijn op deze uitvoer gemeten.

### Vrije tekst

De aliasmapping vervangt namen en adressen; vrije tekst die een beheerder
typte valt daar niet onder. Gemeten op een echte export: tientallen
commentaarvelden en monitorteksten overleefden een geslaagde run. Daarom
neutraliseert elke run, op elke rij die geen leveranciersrij is (een
`builtin`-attribuut, `isdefault: true` of een naam uit `VENDOR_BUILTIN_NAMES`),
deze velden in `objects/` en `parsed/` en de gelijknamige vlaggen in beide
configteksten: `comment`, `send`, `recv`, `storename`, `stringbuilderexpr`
(in de configtekst: het laatste positionele argument van `add rewrite action`
met een tekstbouwer), `timezone` (behalve een tijdzonewoord zonder plaats als
`GMT_TIME`), `ntDomain`, en van `wihome`/`citrixReceiverHome` het pad achter
de host. Een EUI-64 link-local IPv6-adres verraadt het MAC-adres en wordt
vervangen door het adres van het neutrale MAC (`fe80::ff:fe00:1`). De
waarde `<REDACTED>` van de verzamelaar blijft staan. De eindpoort weigert een
uitvoer waarin zo'n veld nog niet neutraal is.

Een export die al gepseudonimiseerd werd voordat deze velden gedekt waren,
krijgt een nabehandeling zonder aliasoogst en zonder mappingmap:
`python scripts/pseudonymise_export.py --free-text-only --source <bron>
--target <nieuw-doel> [--extra-forbidden <bestand-buiten-repos>]`. Die
neutraliseert de vrije tekst, vervangt elke extra term door een
`TERM-NNN`-alias, herrekent de manifesthashes en de scanstempel en zet de
marker. Een mappingmap opgeven is dan een fout.

De familie voor extra termen heette eerder anders; een prive `mapping.json`
uit die tijd draagt pseudoniemen die deze versie niet meer als aliasvorm
erkent en wordt geweigerd. Begin dan met een lege mapping, of hernoem de
aliassen in die mapping naar `TERM-NNN`.
