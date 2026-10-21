# Gevendorde NSHC-regelsets

Byte-voor-byte kopieen van `backend/rulesets/*.json` uit GJK NetScaler
Healthcheck 1.0.1, gekopieerd op 6-9-2026. Ze staan hier zodat de
pariteitstest (`tests/test_parity_nshc.py`) kan draaien zonder de
healthcheck-repo.

Deze bestanden worden hier NOOIT met de hand bewerkt. Ze veranderen alleen
door ze opnieuw uit de healthcheck te kopieren, en dan verandert het
SHA-256-anker in `src/nsmcp/rulesets.py` in dezelfde commit mee.

| bestand | rulesetName | rulesetVersion | rulesetDate | gebruikt door |
|---|---|---|---|---|
| `nshc-ssl-baseline.json` | `nshc-ssl-baseline` | 2026.08 | 2026-08-12 | `beveiliging_tls_baseline` |
| `nshc-cve-baseline.json` | `nshc-cve-baseline` | 2026.08 | 2026-08-11 | alleen de pariteitstest |
| `nshc-iprep-baseline.json` | `nshc-iprep-baseline` | 2026.07.1 | 2026-07-24 | alleen de pariteitstest |
| `nshc-hidden-rules.json` | `nshc-hidden-rules` | 1.0.1 | 2026-09-06 | alleen de pariteitstest |

Naam, versie en datum hierboven zijn op 6-9-2026 uit de bestanden zelf
gelezen, niet uit een plan overgenomen; dit is de plek waar een lezer de
herkomst controleert, dus er staat hier niets wat niet gemeten is.

## `nshc-hidden-rules.json` is een ANDER SOORT bestand

De drie regelsets hierboven zijn letterlijke kopieen van een NSHC JSON-bestand.
De verstopte-regels-catalogus van NSHC bestaat niet als JSON - hij staat in
PowerShell (`backend/hiddenrules/NshcHiddenRules.ps1`). `nshc-hidden-rules.json`
is daarom een GEGENEREERDE UITLEZING, geproduceerd door
`extract_nshc_hidden_rules.py` in deze map, niet een kopie. Sinds een latere
wijziging leest de extractor een TWEEDE PowerShell-bestand mee:
`backend/readonly/Invoke-NshcSslGrade.ps1`, voor de `$order`-literal (:381)
die de TLS-lettervocabulaire vastlegt. Dat komt in hetzelfde bestand terecht
als het veld `gradeLetters` - geen vijfde regelset ernaast, om dezelfde reden
als hieronder (een uniforme envelop, een ankerregister).

Bewuste keuze: dit bestand draagt dezelfde envelop-velden (`rulesetName`,
`rulesetVersion`, `rulesetDate`) als de drie kopieen, zodat de
mapbrede poorten in `tests/test_parity_nshc.py` (het anker, de
naam/versie-test en de datumtest) dit bestand blijven dekken zonder een
tweede, aparte registratie ernaast te bouwen - een bestand in deze map dat
buiten een van die poorten valt is precies wat niet mag. `rulesetVersion` is
hier de NSHC-productversie waaruit gelezen is, niet een regelsetversie die de
catalogus zelf draagt (die heeft NSHC niet); `readAt` en `rulesetDate` zijn
dezelfde datum onder twee namen, voor leesbaarheid.

Regeleindes: dit bestand is met opzet ALLEEN LF (`extract_nshc_hidden_rules.py`
schrijft bytes rechtstreeks, nooit via de standaard newline-vertaling van
`Path.write_text`) - in tegenstelling tot de drie kopieen hierboven is er geen
CRLF-origineel om te bewaren, dus maakt het platform dat genereert niet uit
voor het anker. `.gitattributes`' `-text` geldt voor de hele map en dus ook
hiervoor.

### Provenance-velden zijn VERPLICHTE argumenten

`rulesetVersion`, `rulesetDate`, `readAt` en (het versie-deel van) `source`
waren aanvankelijk letterlijke tekst in `build_fixture()` - een eerlijke
herdraai tegen een latere NSHC-versie zou dan stil een verouderde herkomst
blijven stempelen. `extract_nshc_hidden_rules.py` accepteert daarom nu twee
VERPLICHTE argumenten zonder standaardwaarde:

- `--nshc-version` - de NSHC-productversie van deze werkkopie (bv. `1.0.2`).
- `--read-at` - de ISO-datum (`YYYY-MM-DD`) van deze uitlezing, niet van de
  systeemklok afgeleid (anders is de uitvoer niet reproduceerbaar per
  aanroep).

Zonder deze argumenten weigert het script te draaien (`SystemExit`, een
argparse-foutmelding) in plaats van een oude stempel te hergebruiken. Het
bestandspad-deel van `source` wordt WEL afgeleid - uit de paden die het
script daadwerkelijk leest, niet als losse tekst getypt - zodat dat deel
nooit los kan raken van de werkelijke bronbestanden.

Regenereren:

```
./.venv/Scripts/python.exe tests/rulesets/extract_nshc_hidden_rules.py \
    --nshc-version <versie> --read-at <YYYY-MM-DD>
```

tegen een uitgecheckte NSHC-werkkopie, en het anker in `src/nsmcp/rulesets.py`
in dezelfde commit bijwerken. Eerste uitvoerregel hoort `29 16 13` te zijn;
wijkt dat af, dan is de catalogus verschoven sinds 6-9-2026. Tweede
uitvoerregel toont de gelezen `gradeLetters`; wijkt die af van
`A+ A B C F T`, dan is de TLS-lettervocabulaire verschoven.

## Waarom `tests/rulesets/` en niet `tests/fixtures/`

Het ontwerp (hoofdstuk 6, rij "pariteitstest tegen NSHC") noemt
`tests/rulesets/` met zoveel woorden. `tests/fixtures/` is bovendien de boom
van een andere werkstroom; een gevendorde leveranciersregelset hoort niet
tussen de exportfixtures van dit product.

## Regeleindes: niet aanraken

De NSHC-originelen dragen CRLF. Deze repo wordt met `core.autocrlf=true`
gekloond, dus git normaliseerde ze bij het toevoegen naar LF - en dan levert
een verse clone bytes met een ANDERE SHA-256 dan het anker, precies op de
runner waar het vendoren voor bestaat. `.gitattributes` zet daarom
`tests/rulesets/*.json -text`, zodat de bytes elke checkout overleven.
`tests/test_parity_nshc.py` houdt die regel op zijn plek.

## SHA-256-ankers

De ankers staan in `src/nsmcp/rulesets.py` (`VENDORED_ANCHORS`) en worden door
`tests/test_parity_nshc.py` afgedwongen. Gemeten op 6-9-2026:

```
66a9b3786231e9757f6bb0c16be00c239fba1937148b14399be6c7a3ad1b72fd  nshc-ssl-baseline.json
ff56f0a6c0113e48744eaba0c0a21f62db33e570714d63991377820ee3a97013  nshc-cve-baseline.json
6bd6a6735a333c217b914baa30aa94ffa9463d27b037b7d47d123c5f8ceada2b  nshc-iprep-baseline.json
```
