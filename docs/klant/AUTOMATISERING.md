# Automatisering rond dit product

Een MCP-server is geen scheduler: hij antwoordt op aanroepen. Periodiek werk
wordt vanuit een geplande taak buiten het product gestart.

Een schrijvend gereedschap hoort niet in een geplande taak, en `config_opslaan` ook niet: opslaan
wijzigt de appliance, en de bevestigingscode is voor een mens bedoeld. Met het bestandskanaal
(`codekanaal` `"bestand"`) kan een taak de code technisch zelf lezen en dus zelf bevestigen; het
product houdt dat niet tegen. Zet `config_opslaan` daarom nooit in een geplande taak.

## Waar de bestanden staan

Bewaar de geplande taak, beheerlogs en uitkomsten van controles in
`<exportwortel>/_beheer/`, naast de exportmappen. Een server gebruikt een
exportmap voor zijn doelen. De bewaargeschiedenis blijft naast die exportmap
staan; het opruimbeleid telt de bewaarde exports afzonderlijk per doel.

## 1. De dagelijkse scan

Roep `status_ververs` per doel aan vanuit een geplande taak. Een scan duurt
minuten. Voeg `bewaren` toe aan de configuratie om de vorige export na een
geslaagde scan te bewaren:

```json
{
  "bewaren": { "exports_per_doel": 5, "vrije_ruimte_vloer_mb": 2048 }
}
```

Zonder `bewaren` blijft bewaren uit. Een leeg object kiest de standaardwaarden
5 exports en 2048 MB. `exports_per_doel: 0` zet bewaren uit. Beide velden
accepteren uitsluitend gehele getallen van 0 of hoger. Zonder bewaren of bij
`exports_per_doel: 0` wordt ook de bestaande bewaargeschiedenis niet opgeruimd.
De getalsgrens en de vrije-ruimtecontrole gelden bij het opruimbeleid hieronder.

De vorige export krijgt naast de huidige exportmap de naam
`<naam>.bewaard-<jjjjmmddThhmmssZ>`. De tijd komt uit het scanmoment van die
vorige export, omgerekend naar UTC. Bij gelijke scanmomenten krijgen extra
kopieen een unieke toevoeging; een bestaande kopie wordt niet overschreven.
Een ontbrekend of onleesbaar scanmoment krijgt `onbekend`. Zo'n map blijft
bewaard, maar geldt niet als de nieuwste export met een vastgesteld scanmoment.

Alleen een herkenbare bewaarnaam met een geldig manifest wordt als bewaarde
export gebruikt. Een ongeldig manifest of een padverwijzing levert geen vorige
export op. De vaste map `.vorig` blijft het herstelpunt van een onderbroken
omwisseling; bij een geslaagde scan wordt die map hernoemd of opgeruimd.
Mislukt het bewaren achteraf, dan blijft de nieuwe export geldig en verschijnt
een waarschuwing. Kan ook het opruimen van `.vorig` niet, dan meldt de
waarschuwing dat afzonderlijk.

Een geplande scan verandert de gegevensleeftijd. Het scanmoment bewijst geen
volledige dekking en een geslaagde scan bewijst geen gezonde appliance.

## 2. Opruimen

Na elke geslaagde omwisseling ruimt het product overtollige bewaarde exports
op. Het bewaart de nieuwste `exports_per_doel` exports met een vastgesteld
scanmoment per doel; oudere exports worden eerst verwijderd. De huidige
export telt niet mee als bewaarde export. De nieuwste bewaarde export per
doel blijft altijd staan. Exports zonder vastgesteld scanmoment blijven ook
staan en worden gemeld; hierdoor kan de ingestelde grens overschreden blijven.

De doelnaam komt alleen uit `scan-doel.txt` als de vorm geldig is en de daarin
vastgelegde hash bij het manifest hoort. Dat koppelt de twee lokale bestanden;
het is geen handtekening die de herkomst bewijst. Ontbreekt die koppeling of
is de doelnaam onleesbaar, dan krijgt de export geen gegokte doelidentiteit.
Deze exports vormen een aparte groep per exportmap, met dezelfde getalsgrens.
Het log meldt dat deze groep geen identiteitsbewijs heeft. Een vergelijking
van zulke exports bewijst dus niet dat de scans hetzelfde doel betreffen.

Voor het opruimen en opnieuw voor iedere verwijdering wordt de vrije ruimte
gemeten. Onder `vrije_ruimte_vloer_mb` wordt NIETS opgeruimd. Is de vrije ruimte
niet vast te stellen, dan stopt het opruimen eveneens. Een vloer van 0 schakelt
de ondergrens uit, maar vereist nog steeds een geldige meting. De eenheid is
1.048.576 bytes. Daalt de ruimte tijdens het opruimen onder de vloer, dan
volgen geen verdere verwijderingen; eerdere verwijderingen worden apart gelogd.
Het log meldt de stop. Zo blijft het bewijsspoor behouden wanneer de schijf
volloopt. Het opruimbeleid maakt dus geen extra ruimte vrij onder druk.

Alleen een eigen bewaarnaam met geldig manifest, direct naast deze exportmap,
kan worden verwijderd. Dat wordt vlak voor iedere verwijdering opnieuw
gecontroleerd, inclusief doelidentiteit, gewijzigd manifest en padverwijzingen.
De huidige export, `.vorig`, `_beheer`, andere exportmapnamen en ongeldige
bewaarmappen vallen buiten dit opruimbeleid. Mislukt een verwijdering, dan
stopt het opruimen met een melding en zonder een succesregel voor die poging.

Iedere geslaagde verwijdering krijgt een logregel met het gecontroleerde
eigen bewaarkenmerk, bijvoorbeeld
`bewaarbeleid: bewaarde export 20260901T080000Z verwijderd`. Een eventuele
unieke toevoeging wordt meegenomen om kopieen te onderscheiden. De regels
bevatten geen doelnamen, paden of ruwe foutdetails. Ze verschijnen standaard als waarschuwing
op `stderr`, zodat MCP-uitvoer op `stdout` schoon blijft. Laat de externe
geplande taak `stderr` opslaan onder `<exportwortel>/_beheer/`, bijvoorbeeld als
`bewaarbeleid-log.txt`. Het product schrijft daar zelf geen logbestand en
beheert de logretentie niet. Een fout in het loggen na de geslaagde omwisseling
maakt die omwisseling niet ongedaan; de nieuwe export blijft geldig.

## 3. Dekkingsbewaking

Laat na de scan een externe geplande taak controleren of een eerder gelezen
bron nu geweigerd wordt, ontbreekt of mislukt is. De overgang is van gelezen
naar niet-gelezen: zowel `OK` als `LEEG` telt als gelezen. Een rechtenwijziging,
een ontbrekend bestand of een onleesbare bronvorm kan dekking kosten. De
melding stelt de oorzaak niet vast en zegt niets over de gezondheid van de
appliance.

Voer dit commando uit vanuit de productmap, met de Python-omgeving van het
product. Vervang het voorbeeldpad door de exportmap van het doel:

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; from nsmcp.coverage import coverage_watch; [print(change.to_text()) for change in coverage_watch(Path(r'C:\exports\doel'))]"
```

Bewaar de uitvoer onder `<exportwortel>/_beheer/`. Er komt geen nieuwe
MCP-tool of scheduler bij; `status_ververs` houdt zijn bestaande antwoordvorm.
De bewaking leest uitsluitend lokale bestanden en start geen verbinding.

De vergelijking kiest de nieuwste bewaarde scan die strikt eerder is en
dezelfde geverifieerde doelidentiteit heeft als de huidige scan. Een nieuwere
bewaarde scan van een ander doel wordt overgeslagen. Dezelfde bestandskoppeling
uit hoofdstuk 2 geldt hier: dit bewijst de koppeling aan het lokale manifest,
niet de authenticiteit van een aangeleverde export. Een ontbrekende of
onduidelijke identiteit of scantijd levert `niet vastgesteld` op. Dat geldt
ook bij een onleesbaar manifest of een export die tijdens het lezen wisselt.

De bewaking controleert naast de manifeststatus ook of de gebruikte bronvorm
leesbaar is: singleton-object, lijst van objecten of een van de drie parsed-
bronnen. Ze beoordeelt geen inhoudelijke appliancevelden. De leesgrenzen zijn
32 MiB per bestand, JSON-diepte 100, 50.000 objecten per bron en 100.000 regels
per parsed tekstbron. Een overschrijding is een leesgat. Padverwijzingen
worden geweigerd.

Een melding benoemt verlies van leesdekking en vermeldt de toestand van de
appliance als `niet vastgesteld`. Een bron die weer leest, van `OK` naar
`LEEG` gaat of al onleesbaar was, geeft geen nieuwe verliesmelding. Een
optioneel afwezige bron geeft evenmin een verliesmelding.

Geen uitvoer betekent dat geen nieuw verlies is gemeld. Als er geen
herkenbare bewaarde export met geldig manifest is, wordt niets vergeleken
en blijft de uitvoer ook leeg. Stilte bewijst daarom geen gelijke dekking,
volledige scan of gezonde appliance. De bestaande dekkingsrapportage blijft
nodig om al aanwezige leesgaten te zien.

## 4. Pariteitspoort tegen de healthcheck

Voer deze controle maandelijks uit en na iedere wijziging aan de healthcheck.
De poort vergelijkt alle vier gevendorde regelsets in `tests/rulesets/` met hun
vastgelegde anker en met de NSHC-werkkopie. Voor drie JSON-regelsets moeten
versie en bytes gelijk zijn. Voor de verborgen regels leest dezelfde extractor
de volledige catalogus en statussen uit `backend/hiddenrules/NshcHiddenRules.ps1`
en de TLS-letters uit `backend/readonly/Invoke-NshcSslGrade.ps1`. Ook verdwenen
regels, gewijzigd vocabulaire, een andere lettervolgorde en een afwijkende
`appVersion` in `backend/capabilities.json` laten de controle falen.

De controle leest de NSHC-werkkopie uitsluitend. Ze schrijft geen fixtures
opnieuw. Zonder `NSMCP_NSHC_ROOT` worden precies vier broncontroles expliciet
overgeslagen; de overige pariteitstests blijven draaien. Een ingestelde maar
lege, ongeldige of onvolledige bronmap geeft een fout. Een overgeslagen
broncontrole bewijst geen actuele pariteit. De testsuite zelf dwingt deze
broncontrole dus niet af: alleen deze geplande controle, met `NSMCP_NSHC_ROOT`
gezet, doet dat.

Sla onderstaand script op als `<exportwortel>/_beheer/pariteitscontrole.ps1`.
Vervang de drie voorbeeldpaden. Gebruik PowerShell 7 en de eigen `.venv` van
deze productcheckout, waarin ook de ontwikkelafhankelijkheden (`pytest`)
geinstalleerd zijn. Het script kiest de repo als werkmap, bewaart een uniek log
onder `_beheer` en schrijft de uitkomst met logverwijzing in het beheerjournaal.
De tijdelijke testbestanden komen eveneens onder `_beheer`; beheer de retentie
van deze logs en testmappen afzonderlijk.

```powershell
$repo = 'C:\tools\netscaler-mcp'
$sourceRoot = 'C:\tools\nshc-vrijgegeven-v1.0.1'
$exportRoot = 'C:\exports'
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$exitCode = 1
$log = $null

try {
    $adminRoot = Join-Path $exportRoot '_beheer'
    New-Item -ItemType Directory -Path $adminRoot -Force | Out-Null
    $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
    $log = Join-Path $adminRoot "pariteit-$runId.log"
    $testTemp = Join-Path $adminRoot "pariteit-$runId-testbestanden"
    $python = Join-Path $repo '.venv\Scripts\python.exe'
    $env:NSMCP_NSHC_ROOT = $sourceRoot
    "START pariteitscontrole $runId" | Tee-Object -FilePath $log
    Push-Location -LiteralPath $repo
    try {
        & $python -m pytest tests/test_parity_nshc.py -q -rs -p no:cacheprovider --basetemp $testTemp 2>&1 |
            Tee-Object -FilePath $log -Append
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    $status = if ($exitCode -eq 0) { 'OK' } else { 'FOUT' }
    $summary = "$status pariteitscontrole; exitcode=$exitCode; log=$log"
    $summary | Tee-Object -FilePath $log -Append
    $event = "$( [DateTime]::UtcNow.ToString('o') ) $summary"
    Add-Content -LiteralPath (Join-Path $adminRoot 'beheerjournaal.log') -Value $event
}
catch {
    if ($exitCode -eq 0) { $exitCode = 1 }
    $failure = "FOUT pariteitscontrole niet volledig afgerond; exitcode=$exitCode"
    Write-Output $failure
    if ($log) { Add-Content -LiteralPath $log -Value $failure -ErrorAction Continue }
}
exit $exitCode
```

De externe maandelijkse taak kan dit script starten met:

```powershell
pwsh.exe -NoProfile -NonInteractive -File 'C:\exports\_beheer\pariteitscontrole.ps1'
```

Het script installeert geen geplande taak. Exitcode 0 betekent dat alle
geselecteerde controles geslaagd zijn; iedere andere exitcode vraagt opvolging.
De niet-nul exitcode van pytest blijft behouden, zodat de taak geen succes
meldt wanneer alleen de logging is gelukt. Een fout in opstarten of logging
levert eveneens een niet-nul exitcode op.

Onderzoek bij een afwijking welke bron, versie of vendored kopie is gewijzigd.
Leg oorzaak, beoordeling en vervolgactie vast in het beheerjournaal. Pas
regelsets, ankers en eventuele productlogica pas aan na inhoudelijke beoordeling
en review, met nieuwe regressiecontrole. Vendor nooit automatisch opnieuw om
een afwijking groen te maken.

## 5. De maandelijkse verversing van het kennispakket

Het kennispakket (`kennispad` in de configuratie, zie [HANDLEIDING.md](HANDLEIDING.md)) draagt de
securitybulletins, de aangeboden build per tak en de stap die na een upgrade nog volgt. Dat pakket
komt uit het kennisabonnement van GJK Partners en hoort maandelijks ververst te worden - anders
antwoordt het product met kennis die stilzwijgend veroudert.

### Wat buiten het product blijft, en waarom

Een MCP-server is geen scheduler. Drie dingen horen daarom hier, als procedure, en niet in de
productcode:

- de geplande taak zelf (Taakplanner, cron, of wat de beheeromgeving al gebruikt);
- de exportstap die een kandidaatpakket uit het kennisabonnement in het pakketformaat zet;
- de journaalregel die een geslaagde verversing vastlegt.

Wat het product WEL doet, is de kant die fout kan gaan: de kandidaat **valideren** en het huidige
pakket **nooit stilzwijgend vervangen**. Die ene regel - een kandidaat die niet door de
laadvalidatie komt, vervangt het oude pakket nooit - zit in `nsmcp.knowledge_refresh` en wordt
nergens in deze procedure herhaald of overgedaan.

### De vijf stappen

1. **Exporteer het kandidaatpakket uit de kennisbron naar het pakketformaat** - hetzelfde JSON-
   formaat als `kennispad` zelf (`versie`, `datum`, `cve`, `uitleg`, `begrippen`, optioneel
   `aangeboden` en, alleen in de nieuwe pakketlijn, `minimaleEngine`; zie
   [HANDLEIDING.md](HANDLEIDING.md)). Deze stap gebeurt buiten dit product.

2. **Draai de verversing:**

   ```
   python -m nsmcp.knowledge_refresh <kandidaat> <huidig> --beheer <exportwortel>\_beheer
   ```

   `<huidig>` is hetzelfde pad als `kennispad` in de configuratie. `nsmcp.knowledge_refresh`
   laadt de kandidaat met dezelfde validatie die het product ook bij het beantwoorden gebruikt
   (`knowledge.load_knowledge`) en weigert een kandidaat die niet laadt, of die een oudere
   `datum` draagt dan het huidige pakket - een verversing die teruggaat in de tijd is geen
   verversing.

3. **Lees de exitcode.** Nul betekent geinstalleerd. Niet-nul betekent afgekeurd: het oude
   pakket staat er nog, ongewijzigd, en de kandidaat is bewaard naast `<huidig>` als
   `<huidig>.afgekeurd-<UTC>.json` (raken twee verversingen toevallig dezelfde UTC-seconde,
   dan krijgt de tweede in plaats daarvan `<huidig>.afgekeurd-<UTC>-2.json` - een geteld
   volgnummer, nooit een overschreven eerste bestand). In beide gevallen staat er een regel in
   `<exportwortel>\_beheer\kennisverversing.log` - geslaagd of afgekeurd, er komt altijd een
   regel bij, nooit een stille uitkomst. Bij een afkeuring leest u de reden in die regel voordat
   u de kandidaat opnieuw aanbiedt.

4. **Leg de verversing vast** (alleen bij een geslaagde verversing, exitcode 0) in uw eigen
   beheerlogboek of wijzigingsregistratie: de nieuwe `<versie>` (uit het nieuw geinstalleerde
   pakket) en het pad `<huidig>`. Dit product schrijft die regel niet zelf ergens buiten
   `kennisverversing.log` weg - dat vastleggen is aan de beheerder, met het logboek dat bij uw
   eigen beheeromgeving hoort.

5. **Werk de kennispin bij** als de configuratie een `kennispin` draagt (zie
   [HANDLEIDING.md](HANDLEIDING.md), "Het kennispakket vastpinnen"): bereken de digest van het
   nieuw geinstalleerde pakket met `python -m nsmcp.knowledge --digest <huidig>` en zet het
   afgedrukte blok in de configuratie. Tot dan weigert de server het nieuwe pakket, met de
   reden dat het afwijkt van de kennispin. Dat is bewust geen automatische stap: de pin is de
   goedkeuring van de beheerder, en een verversing die zichzelf goedkeurt, keurt niets goed.

### Het exitcodecontract

| exitcode | betekenis |
|---|---|
| 0 | het kandidaatpakket is geinstalleerd; `<huidig>` draagt nu de nieuwe inhoud |
| niet-nul | het kandidaatpakket is AFGEKEURD (laadvalidatie faalde, of de datum is ouder dan het huidige pakket) of de installatie zelf is onverwacht mislukt; `<huidig>` is in beide gevallen ONGEWIJZIGD |

Een geplande taak die alleen de exitcode leest, hoeft geen onderscheid te maken tussen deze twee
niet-nul-uitkomsten: in beide gevallen is er niets veranderd en staat de reden in
`kennisverversing.log`.

### Een pakketrelease met de regressiematrix

Bij elk pakket hoort een regressiematrix: `kennis-regressie.json`, naast het pakket (hij reist
met het pakket, niet met deze repository). Per bulletin en per tak zegt de matrix welk oordeel
een build moet krijgen onder welke uitkomst van de voorwaarden, en de engine rekent elk geval na
met haar eigen regelpad. De vorm:

```json
{
  "pakketversie": "2026.11",
  "pakketdigest": "<64 hex: de canonieke digest, de uitvoer van --digest>",
  "engines": [{"versie": "1.1.0", "commit": "<40 hex>"}],
  "gevallen": [
    {
      "bulletin": "CTX...",
      "tak": "14.1",
      "build": "73.45",
      "voorwaarden": {"heeft_gateway_vserver": true},
      "verwacht": {"CVE-...": "GERAAKT"},
      "verwachteVloer": "14.1-73.46"
    }
  ]
}
```

`voorwaarden` noemt per predicaat `true`, `false` of `"onleesbaar"` (`altijd` wordt nooit
opgelegd); `verwacht` noemt precies de CVE's van het bulletin; `verwachteVloer` is de vloer van
die tak over het hele pakket, of `null`. Voordat er een geval draait, weigert de runner de matrix
als `pakketdigest` niet de canonieke digest van het aangeboden pakket is, als de draaiende engine
(versie EN de commit waarvan zij geinstalleerd is) niet in `engines` staat, of als de dekking
niet compleet is. Verplichte dekking per bulletin per tak: een build direct onder de fix, de
fix-build zelf en een build erboven; per predicaat in de voorwaarde `true`, `false` en
`onleesbaar` (onder de fix, waar dat predicaat daar geldt); beide kanten van elke
`vanaf`-drempel (de drempel zelf en de build direct eronder); en voor elke CVE met
`naconfiguratieVerplicht: true`, op of boven de fix, de voorwaarde afwezig, aanwezig en
onleesbaar. De weigering noemt elk ontbrekend geval.

Grens: de runner legt de uitkomst van de voorwaarden op; hij bewijst de keuze van de regel en de
samenvoeging, niet dat een predicaat de echte vorm van een appliance herkent. Dat blijft het werk
van de predicaattests op echte exports.

Per pakketlijn ([HANDLEIDING.md](HANDLEIDING.md), "Het kennispakket vastpinnen"):

- **Nieuwe lijn** (met `minimaleEngine`): draai de matrix op de engine die `minimaleEngine`
  noemt EN op de nieuwste engine, elk geinstalleerd vanaf een vaste commit
  (`pip install "git+<repository>@<commit>"`, of een bewerkbare checkout op die commit zonder
  wijzigingen onder `src/`), en zet beide in `engines`:

  ```
  python -m nsmcp.knowledge --regressie <pakket> <pakket-map>\kennis-regressie.json
  ```

  Beide groen (exitcode 0) voordat het pakket uitgaat. Dan eerst elke afnemer naar ten minste die
  engine, met bewijs per afnemer, en pas daarna het pakket.
- **Bestaande lijn** (zonder `minimaleEngine`, voor afnemers op 1.0.x): `--regressie` bestaat
  daar niet (een 1.0.x-engine eindigt die aanroep met exitcode 2). Daarvoor is het harnas
  `tools/regressie-1.0.x/`: het installeert engine v1.0.3 vanaf zijn tag (gepind op de volledige
  commit) in een eigen omgeving met de hash-gelockte requirements van die tag, draait dezelfde
  matrix met dezelfde digest- en enginebinding (`engines` noemt dan
  `{"versie": "1.0.3", "commit": "41c85229edb6b9f78983fef09d03ebd15ef85641"}`), en toetst
  daarnaast de vaste verwachting dat v1.0.1, v1.0.2 en v1.0.3 een pakket met `minimaleEngine`
  weigeren:

  ```
  python tools\regressie-1.0.x\opzetten.py --bron <clone met de tags> --werkmap <lege map> --pakket <pakket> --matrix <matrix>
  ```

  De laatste regel is `[EINDE] GESLAAGD` (exitcode 0) of `[EINDE] MISLUKT`.

| exitcode van `--regressie` | betekenis |
|---|---|
| 0 | de matrix hoort bij dit pakket en deze engine, de dekking is compleet en elk geval klopt |
| 1 | geweigerd voordat een geval draaide (de reden staat erbij), of een of meer gevallen wijken af |
| 2 | verkeerde aanroep |
