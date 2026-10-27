<#
.SYNOPSIS
    Een fase van de firmware-upgraderoute (R0..R6), EEN keer per aanroep.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. Meet en handelt voor EEN fase; oordeelt NOOIT
    zelf. Elke poortuitspraak, elke fase-uitkomst en elke ledgerregel komt uit
    'python -m nsmcp.upgrade_gate' - dit script schrijft GEEN ledgerregel, opent nooit
    een sessie zonder de gepinde hostsleutel te verifieren, en beslist nergens een
    open/dicht/geslaagd/mislukt zelf.

    Volgorde:
      1.  parameters lezen, ASCII-controle, verboden-adreslijst, Assert-GjkPoshSsh
      2.  [TARGET] en [ACTIEID] afdrukken (ook bij -WatIs)
      3.  -WatIs: afdrukken wat deze fase ZOU doen, exit 0. Geen sessie, geen wijziging.
      4.  ledgerregel 'fase_gestart' laten schrijven door de oordeelshelft
          ('python -m nsmcp.upgrade_measure', actie 'start' - dezelfde append_line()
          als de oordeelshelft zelf gebruikt; zie scripts/README.md)
      5.  transport laden (-Transport, standaard scripts\GjkUpgrade-Ssh.ps1)
      6.  R0: GEEN sessie - R0 raakt de appliance niet aan.
          Elke andere fase: sessie openen met de GEPINDE vingerafdruk.
      7.  de METINGEN van deze fase verzamelen
      8.  de metingen als JSON naar 'python -m nsmcp.upgrade_gate' sturen (EXACT een
          keer per fase-aanroep) - de eventuele poortuitspraken (schijfruimte,
          secondary, firmware-hash, vendor-precheck, hostsleutel, ...) worden EERST
          gevormd door 'python -m nsmcp.upgrade_measure' (actie 'vorm'), dat de
          bestaande, al geteste poortfuncties in nsmcp.upgrade aanroept - dit script
          beslist zelf nergens open/dicht (zie scripts/README.md, "de twee helften").
      9.  de ledgerregel die terugkomt is de waarheid; dit script drukt hem af en
          neemt zijn exitcode over
      10. sessie sluiten in een finally-blok

    DRIE GEMETEN FEITEN DIE DIT SCRIPT HARD RESPECTEERT (taakopdracht):
      - de exitstatus van 'shell reboot' betekent niets - R4 oordeelt uitsluitend op
        SSH-auth (Wait-GjkTerug), nooit op die exitstatus;
      - de exitstatus van './installns --pre_check' betekent niets - R2 stuurt de
        JSON door naar de oordeelshelft en kijkt zelf niet naar de exitcode;
      - de vingerafdruk wordt na de reboot OPNIEUW gemeten (Wait-GjkTerug pint elke
        poging opnieuw - nooit aangenomen dat hij gelijk bleef).

    WAT HIER LATER TOEGEVOEGD IS, GEMETEN:
      - een verboden-adreslijst: de naam 'lab-01' wordt VOOR elke
        transportaanraking geweigerd, ongeacht fase of -WatIs; adresvormen komen
        van de aanroeper mee via -VerbodenAdressen (het echte adres hoort niet
        als letterlijke waarde in dit bestand);
      - validatie op -Doelbuild: de enige onvalideerde
        configuratiestring die in een remote shell-commando en een remote pad
        terechtkwam;
      - een eerlijke hostsleutelpoort: het script beweert nooit meer
        dat het een vingerafdruk MAT die het alleen aannam - het meldt OF de sessie
        openging, en zo niet, OF dat specifiek een hostsleutelfout was
        (_GjkIsHostsleutelfout), nooit "hostsleutel wijkt af" voor elke andere
        verbindingsfout;
      - actieid_uit_script komt uit de ECHO van de fase_gestart-schrijfactie, niet
        uit dezelfde variabele als het label;
      - R0 doet NIETS meer op de appliance: zijn bronnen zijn het
        actieregister (-Actieregister) en de export (-ExportRoot), allebei nieuwe
        parameters die de aanroeper moet gaan vullen (zie scripts/README.md);
      - een buitenste catch om de metingen: een onverwachte meetfout
        (een ontbrekende firmwarebundel, een mislukte SFTP-upload, ...) eindigt nooit
        meer stilzwijgend met exitcode 1 (het contractwoord voor een GEOORDEELDE
        weigering) - hij wordt gelogd en eindigt met exitcode 3;
      - -Doelbuild mag TAK-GEKWALIFICEERD zijn ('14.1-72.57', wat dit product meegeeft);
        de tak wordt gestript voor het remote pad (/var/nsinstall/14.1/build_72.57),
        R5 toetst de twee delen apart, en een bindingsweigering drukt nu zelf
        [FOUT]/[GEWEIGERD] af in plaats van een kale PowerShell-bindingsfout;
      - R0 schrijft zijn EXTRA bewijsregel 'terugrolpunt_vast' (ontwerp 3.5 noemt
        voor R0 TWEE regels), VOOR de sluitregel, via dezelfde append_line();
      - -Actieid is verplicht op een echte run: zonder dat argument sloot ELKE fase
        'mislukt' op een identiteitsvergelijking die nooit kon kloppen;
      - de gepinde vingerafdruk gaat mee naar de hostsleutelpoort: GEEN pin is
        'dicht' (een vastgestelde afwezigheid), niet 'niet beoordeeld';
      - R3 stuurt de STAART van installns' uitvoer door (END_TIME staat achteraan);
      - de verboden-adreslijst dekt ook 'gebruiker@', ':poort' en het eerste
        DNS-label van een FQDN - zie scripts/README.md voor wat hij NIET dekt;
      - een bundelnaam die via het patroon (geen tak in -Doelbuild) gevonden
        wordt, moet de bundelvorm build-<tak>-<build>_nc_64.tgz hebben voordat
        hij in een remote shell-commando mag; anders exitcode 4, zie
        _GjkBundelnaamGeldig.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
# PositionalBinding uit: elke waarde komt met haar eigen parameternaam binnen.
# Een losse waarde (bijvoorbeeld een tweede verboden adres na
# -VerbodenAdressen) is dan een bindingsfout in plaats van een stille binding
# aan de eerste vrije parameter - gemeten: bij R0 werd dat de
# snapshotverwijzing, en opende de mensenpoort op een adres.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)] [string] $Doel,
    [Parameter(Mandatory = $true)] [string] $Adres,
    [Parameter(Mandatory = $true)] [ValidateSet('R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6')] [string] $Fase,
    [Parameter(Mandatory = $true)] [string] $Run,
    [Parameter(Mandatory = $true)] [string] $Gebruiker,
    [Parameter(Mandatory = $true)] [string] $CredentialTarget,
    [Parameter(Mandatory = $true)] [string] $HostsleutelVingerafdruk,
    # De ENIGE configuratiestring die zonder toetsing in een remote
    # shell-commando EN een remote pad terechtkwam ('cd <buildDir> && tar ...',
    # './installns -Y -n', '/var/tmp/gjk_pre_check_<Doelbuild>.json').
    #
    # De vorm is TAK-GEKWALIFICEERD, niet alleen het
    # kale buildnummer. De rest van dit product schrijft een buildidentiteit
    # altijd als '14.1-72.57' (nsmcp.cve.parse_build), en een gemeten upgrade draaide 66.59 -> 14.1-72.57 op de
    # labdoos. Het oude patroon '^[0-9]+(\.[0-9]+)*$' weigerde precies die
    # waarde: het koppelteken viel erbuiten.
    #
    # Toegestaan: <build> ('72.57') of <tak>-<build> ('14.1-72.57'). Alleen
    # cijfers, punten en HOOGSTENS EEN koppelteken - een puntkomma, spatie,
    # backtick, $(...) of / komt er nog steeds nooit doorheen, dus de
    # injectieafweer hierboven blijft precies zo streng als hij was.
    #
    # ValidateScript in plaats van ValidatePattern: een
    # bindingsweigering gaf voorheen een KALE PowerShell-bindingsfout, zonder
    # [FOUT]/[GEWEIGERD], omdat de scriptbody dan nooit start. Dit blok draait
    # WEL tijdens de binding en drukt de twee regels af die de operator kent -
    # en de body start nog steeds niet met een afgekeurde waarde. De waarde
    # zelf wordt NIET geechood (dat is precies de untrusted string).
    #
    # Een eerder overgenomen defect, inmiddels gesloten: '\z', niet '$', aan
    # het einde. .NET-regex laat '$' standaard ook MATCHEN vlak voor een
    # AFSLUITENDE '\n' - '72.57' + een letterlijke regeleindeteken zou dus
    # ook door deze toets komen. Assert-GjkAsciiWaarde hieronder vangt dat
    # niet op: die weigert alleen tekens boven 127, geen stuurtekens zoals
    # \n (10) of \r (13). Met '$' zou zo'n waarde de NetScaler-CLI-regel
    # splitsen die dit product bouwt (scripts/README.md). '\z' matcht
    # UITSLUITEND het echte einde van de string, zonder die uitzondering.
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -notmatch '^[0-9]+(\.[0-9]+)*(-[0-9]+(\.[0-9]+)*)?\z') {
            Write-Host '[FOUT] -Doelbuild heeft niet de vorm van een buildnummer'
            Write-Host '[GEWEIGERD] -Doelbuild moet <build> of <tak>-<build> zijn, alleen cijfers, punten en een koppelteken'
            throw '-Doelbuild moet de vorm <build> (72.57) of <tak>-<build> (14.1-72.57) hebben'
        }
        $true
    })]
    [string] $Doelbuild,
    [Parameter(Mandatory = $true)] [string] $Firmwaremap,
    [Parameter(Mandatory = $true)] [string] $Ledger,
    [Parameter(Mandatory = $true)] [string] $GatePython,
    [string] $Snapshotverwijzing = '',
    # R0: de vloer die de server uit het kennispakket afleidde (de hoogste
    # fix-build van de eigen tak) en het bulletin waar hij vandaan komt. De
    # runner oordeelt er niet zelf over: hij geeft ze door aan de
    # oordeelshelft (floor_gate). Dezelfde vormtoets als -Doelbuild, en leeg
    # is toegestaan - geen vloer, dan sluit de vloerpoort tenzij
    # -DoelbuildGeaccepteerd. Een afgekeurde waarde wordt niet geechood.
    [ValidateScript({
        if ($_ -notmatch '^([0-9]+(\.[0-9]+)*(-[0-9]+(\.[0-9]+)*)?)?\z') {
            Write-Host '[FOUT] -Vloerbuild heeft niet de vorm van een buildnummer'
            Write-Host '[GEWEIGERD] -Vloerbuild moet leeg zijn, of <build> of <tak>-<build>, alleen cijfers, punten en een koppelteken'
            throw '-Vloerbuild moet leeg zijn of de vorm <build> of <tak>-<build> hebben'
        }
        $true
    })]
    [string] $Vloerbuild = '',
    [ValidateScript({
        if ($_ -notmatch '^[A-Za-z0-9-]{0,32}\z') {
            Write-Host '[FOUT] -VloerBulletin heeft niet de vorm van een bulletin-id'
            Write-Host '[GEWEIGERD] -VloerBulletin draagt alleen letters, cijfers en koppeltekens, hoogstens 32'
            throw '-VloerBulletin heeft niet de vorm van een bulletin-id'
        }
        $true
    })]
    [string] $VloerBulletin = '',
    # R0: versie en datum van het gepinde kennispakket waar de vloer uit komt.
    # De oordeelshelft noemt ze in het bewijs van de vloerpoort en waarschuwt
    # (zonder te blokkeren) als het pakket ouder is dan 30 dagen. Leeg is
    # toegestaan; een afgekeurde waarde wordt niet geechood.
    [ValidateScript({
        if ($_ -notmatch '^([A-Za-z0-9._-]{1,64})?\z') {
            Write-Host '[FOUT] -VloerPakket heeft niet de vorm van een pakketversie'
            Write-Host '[GEWEIGERD] -VloerPakket draagt alleen letters, cijfers, punt, liggend streepje en koppelteken, hoogstens 64'
            throw '-VloerPakket heeft niet de vorm van een pakketversie'
        }
        $true
    })]
    [string] $VloerPakket = '',
    [ValidateScript({
        if ($_ -notmatch '^([0-9]{4}-[0-9]{2}-[0-9]{2})?\z') {
            Write-Host '[FOUT] -VloerPakketDatum heeft niet de vorm van een datum'
            Write-Host '[GEWEIGERD] -VloerPakketDatum moet leeg zijn of de vorm JJJJ-MM-DD hebben'
            throw '-VloerPakketDatum moet leeg zijn of de vorm JJJJ-MM-DD hebben'
        }
        $true
    })]
    [string] $VloerPakketDatum = '',
    # R0: de huidige build van de doos volgens de export (config/nsversion),
    # die de server meegeeft. De oordeelshelft (floor_gate) sluit een
    # doelbuild in een andere releaselijn dan deze build, ook met
    # -DoelbuildGeaccepteerd. Dezelfde vormtoets als -Doelbuild, en leeg is
    # toegestaan - de export droeg geen build, en dan opent de vloerpoort
    # alleen op -DoelbuildGeaccepteerd. Een afgekeurde waarde wordt niet
    # geechood.
    [ValidateScript({
        if ($_ -notmatch '^([0-9]+(\.[0-9]+)*(-[0-9]+(\.[0-9]+)*)?)?\z') {
            Write-Host '[FOUT] -Huidigebuild heeft niet de vorm van een buildnummer'
            Write-Host '[GEWEIGERD] -Huidigebuild moet leeg zijn, of <build> of <tak>-<build>, alleen cijfers, punten en een koppelteken'
            throw '-Huidigebuild moet leeg zijn of de vorm <build> of <tak>-<build> hebben'
        }
        $true
    })]
    [string] $Huidigebuild = '',
    # R0: een mens accepteert bewust een doelbuild ONDER de vloer, een
    # doelbuild zonder bekende vloer, een doelbuild zonder bekende huidige
    # build, of een doelbuild die niet hoger is dan de huidige build
    # (herinstallatie of downgrade binnen de lijn; doelbuild_geaccepteerd).
    # Dat opent alleen die vier situaties; een andere releaselijn dan de
    # huidige build en een takverschil met de vloer blijven dicht.
    [switch] $DoelbuildGeaccepteerd,
    # R0's twee bronnen hier. Allebei een pad; leeg of onleesbaar
    # is 'niet beoordeeld' in de bijbehorende poort (upgrade_measure.py), nooit
    # 'open'. De aanroeper die dit script ECHT start is verantwoordelijk
    # voor het meegeven van echte paden - zie scripts/README.md.
    [string] $Actieregister = '',
    [string] $ExportRoot = '',
    [switch] $DriftGeaccepteerd,
    # Standalone appliance (geen HA-peer): de upgrade betekent downtime; alleen een mens beslist dat.
    [switch] $StandaloneGeaccepteerd,
    [switch] $OudeBuildbomenOpruimen,
    [int] $SoakUren = 24,
    [string] $Actieid = '',
    [string] $Bevestiger = '',
    [string] $Transport = '',
    # Het WERKELIJKE adres van een voorgoed read-only doos hoort niet als
    # letterlijke waarde in dit bestand (het zou dan een
    # pseudonimiseringskandidaat worden en de guard zou een dode alias bewaken -
    # gemeten, zie scripts/README.md). Het adres komt daarom van BUITEN: de
    # aanroeper (de MCP-server, uit configuratieveld 'handelen.verboden_adressen')
    # geeft de lijst hier expliciet mee. Leeg is geldig (WatIs-achtige aanroepen
    # of een omgeving zonder bekende verboden doos); de statische naamguard
    # hieronder ('lab-01') blijft ONGEACHT deze parameter van kracht.
    # Komma-gescheiden in EEN argument ('a,b'): powershell.exe -File bindt
    # maar een van twee losse waarden aan een [string[]]-parameter. De
    # splitsing gebeurt hieronder, bij het vullen van de verboden lijst.
    [string[]] $VerbodenAdressen = @(),
    [switch] $WatIs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# What this host writes into the Python bridges' stdin. Windows PowerShell
# 5.1 on a UTF-8 console (code page 65001) was measured to prefix pipeline
# input to a native command with a byte-order mark; the bridges strip one,
# but the encoding is pinned here anyway so the bytes do not depend on the
# console's code page: UTF-8, no mark.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
# Get-FileHash (the local sha256 of the bundle) is a FUNCTION in
# Microsoft.PowerShell.Utility that Windows PowerShell 5.1 loads on demand
# by module name. A PSModulePath inherited from a PowerShell 7 parent lists
# PowerShell 7's own copy of that module first; 5.1 cannot load that copy
# and answers 'Get-FileHash is not recognized' (measured on a hosted Windows
# runner whose job shell is PowerShell 7). Loading the host's own copy by
# path makes the measurement independent of whatever started this process.
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility') -ErrorAction Stop

function Log { param([string]$Niveau, [string]$Boodschap) Write-Host ("[{0}] {1}" -f $Niveau, $Boodschap) }

# ---------------------------------------------------------------------------
# ASCII-controle. Elke argumentwaarde die op stdout, in een label of in een
# metingenveld terechtkomt moet ASCII zijn - een non-ASCII byte breekt de
# 5.1-parser niet TIJDENS deze run (het script zelf is al geparseerd), maar
# zou wel de volgende keer een no-BOM CP1252-lees breken als hij in een pad
# of een ledgerregel terechtkwam. Fail closed: exit 1, geen sessie geopend.
# Het eindstatuswoord hierbij is 'GEWEIGERD', dus met OPZET
# NIET op het [EINDSTATUS]-kanaal - dat kanaal draagt uitsluitend de vijf
# woorden uit ontwerp 2.1.1 (gestart/poort dicht/geslaagd/mislukt/niet
# beoordeeld), en dit is geen fase-uitkomst: er is nog geen fase_gestart
# geschreven.
# ---------------------------------------------------------------------------
function Assert-GjkAsciiWaarde {
    param([string] $Naam, [string] $Waarde)
    if ([string]::IsNullOrEmpty($Waarde)) { return }
    foreach ($teken in $Waarde.ToCharArray()) {
        if ([int][char]$teken -gt 127) {
            Log 'FOUT' ("argument -" + $Naam + " bevat een niet-ASCII teken; geweigerd")
            Log 'GEWEIGERD' ("-" + $Naam + " is niet ASCII")
            exit 1
        }
    }
}
foreach ($p in @('Doel', 'Adres', 'Run', 'Gebruiker', 'CredentialTarget', 'HostsleutelVingerafdruk',
                  'Doelbuild', 'Firmwaremap', 'Ledger', 'GatePython', 'Snapshotverwijzing',
                  'Vloerbuild', 'VloerBulletin', 'VloerPakket', 'VloerPakketDatum', 'Huidigebuild', 'Actieregister',
                  'ExportRoot', 'Actieid', 'Bevestiger',
                  'Transport')) {
    Assert-GjkAsciiWaarde -Naam $p -Waarde (Get-Variable -Name $p -ValueOnly)
}
foreach ($v in @($VerbodenAdressen)) { Assert-GjkAsciiWaarde -Naam 'VerbodenAdressen' -Waarde $v }

# ---------------------------------------------------------------------------
# -Doel en -Adres staan in het [TARGET]-etiket waaraan de bevestigingscode
# hangt, en in de logregels over de doos. De ASCII-toets hierboven hield een
# CR, LF of tab niet tegen: een waarde met een regeleinde drukte een tweede,
# eigen [ACTIEID]-regel af, voor de echte (gemeten met -WatIs). Geen
# stuurteken dus (0 tot en met 31, en 127); de waarde wordt niet herhaald.
#
# Niet alleen die twee: -Actieid staat in de [ACTIEID]-regel, -Doelbuild in
# het [TARGET]-etiket, -Run in een logregel en in elke ledgerregel,
# -Bevestiger en -Snapshotverwijzing in ledgerregels, en de paden en namen
# in [FOUT]-regels. Daarom dezelfde lijst als de ASCII-toets: ELKE
# tekstparameter, plus elk verboden adres. Een pad, een run-id of een
# actie-id draagt nooit legitiem een stuurteken.
# ---------------------------------------------------------------------------
function Assert-GjkGeenStuurteken {
    param([string] $Naam, [string] $Waarde)
    if ([string]::IsNullOrEmpty($Waarde)) { return }
    foreach ($teken in $Waarde.ToCharArray()) {
        $code = [int][char]$teken
        if ($code -lt 32 -or $code -eq 127) {
            Log 'FOUT' ("argument -" + $Naam + " bevat een stuurteken; geweigerd")
            Log 'GEWEIGERD' ("-" + $Naam + " mag geen regeleinde, tab of ander stuurteken dragen")
            exit 1
        }
    }
}
foreach ($p in @('Doel', 'Adres', 'Run', 'Gebruiker', 'CredentialTarget', 'HostsleutelVingerafdruk',
                  'Doelbuild', 'Firmwaremap', 'Ledger', 'GatePython', 'Snapshotverwijzing',
                  'Vloerbuild', 'VloerBulletin', 'VloerPakket', 'VloerPakketDatum', 'Huidigebuild', 'Actieregister',
                  'ExportRoot', 'Actieid', 'Bevestiger',
                  'Transport')) {
    Assert-GjkGeenStuurteken -Naam $p -Waarde (Get-Variable -Name $p -ValueOnly)
}
foreach ($v in @($VerbodenAdressen)) { Assert-GjkGeenStuurteken -Naam 'VerbodenAdressen' -Waarde $v }

# ---------------------------------------------------------------------------
# lab-01 (en zijn IP) staan op GEEN enkele verboden lijst, en
# -Adres wordt verder alleen op ASCII getoetst. -Adres <het echte lab-01-adres>
# -Fase R3 zou zonder deze toets 'installns' draaien op de doos die voorgoed
# read-only is. Getoetst VOORDAT er ook maar een transportbestand geladen
# wordt - dus voor Assert-GjkPoshSsh en ruim voor enige sessie - op zowel
# -Adres als -Doel.
#
# Het adres zelf stond hier ooit als letterlijke waarde in de statische
# lijst. Dat is een pseudonimiseringskandidaat zoals elke andere literal in
# dit bestand - de fixture-pseudonimiseringsronde verving hem stilzwijgend
# door een TEST-NET-alias, en de adreshelft van deze guard bewaakte vanaf
# dat moment een doos die niet bestaat (gemeten). Bewuste, gemotiveerde
# uitzondering op "geen productgedrag": het echte adres hoort niet in de
# repo EN de guard moet blijven werken, dus komt het adres voortaan van
# BUITEN dit bestand - de optionele parameter -VerbodenAdressen hieronder.
# De NAAM 'lab-01' blijft
# hier wel statisch (namen zijn geen geheim en identificeren de doos niet op
# zichzelf); alleen adresvormen verhuizen naar de aanroeper.
#
# WAT DEZE TOETS WEL EN NIET DEKT, zonder mooier
# gemaakt te worden dan hij is. Genormaliseerd wordt: getrimd,
# hoofdletterongevoelig, een 'gebruiker@'-voorvoegsel eraf, een ':poort'-
# achtervoegsel eraf, een afsluitende punt van een FQDN eraf. Van een
# NAAM (geen IP-vorm) wordt ook het EERSTE DNS-label getoetst, zodat
# 'lab-01.intern.example' net zo goed geweigerd wordt als 'lab-01'.
#
# NIET gedekt, en dat wordt hier ook niet beweerd: een tweede DNS-naam voor
# dezelfde doos, een CNAME, een decimale of hexadecimale schrijfwijze van
# hetzelfde IPv4-adres, een IPv6-vorm, of een NAT-adres. Een volledige
# aliasresolutie zou een DNS-lookup vragen en die doet dit script niet -
# het raakt bewust niets aan voordat het geweigerd heeft. Dit is dus een
# VANGNET tegen de voor de hand liggende schrijfwijzen, geen bewijs dat een
# verboden doos onbereikbaar is; die garantie ligt bij de aanroeper
# die het adres vormt.
# ---------------------------------------------------------------------------
$script:GjkVerbodenAdressen = @('lab-01')
foreach ($v in @($VerbodenAdressen)) {
    foreach ($deel in ([string]$v).Split(',')) {
        if (-not [string]::IsNullOrWhiteSpace($deel)) { $script:GjkVerbodenAdressen += $deel.Trim() }
    }
}
function _GjkNormaliseerDoosnaam {
    param([string] $Waarde)
    if ($null -eq $Waarde) { return '' }
    $kaal = $Waarde.Trim().ToLowerInvariant()
    if ($kaal.Contains('@')) { $kaal = $kaal.Substring($kaal.LastIndexOf('@') + 1) }
    if ($kaal -match '^(?<host>[^:]+):[0-9]+$') { $kaal = $Matches['host'] }
    return $kaal.TrimEnd('.')
}
function _GjkDoosVarianten {
    <#  De genormaliseerde waarde, plus - alleen voor een NAAM, nooit voor een
        IPv4-vorm - het eerste DNS-label. '203.0.113.42' levert dus nooit
        '203' op; 'lab-01.intern.example' levert wel 'lab-01' op. #>
    param([string] $Waarde)
    $kaal = _GjkNormaliseerDoosnaam -Waarde $Waarde
    $varianten = @($kaal)
    if ($kaal -notmatch '^[0-9]+(\.[0-9]+){3}$' -and $kaal.Contains('.')) {
        $varianten += $kaal.Split('.')[0]
    }
    return @($varianten | Where-Object { -not [string]::IsNullOrEmpty($_) })
}
function Test-GjkVerbodenDoel {
    param([string] $Adres, [string] $Doel)
    $kandidaten = @()
    $kandidaten += _GjkDoosVarianten -Waarde $Adres
    $kandidaten += _GjkDoosVarianten -Waarde $Doel
    foreach ($verboden in $script:GjkVerbodenAdressen) {
        $kaalVerboden = _GjkNormaliseerDoosnaam -Waarde $verboden
        foreach ($kandidaat in $kandidaten) {
            if ($kandidaat -eq $kaalVerboden) { return $true }
        }
    }
    return $false
}
if (Test-GjkVerbodenDoel -Adres $Adres -Doel $Doel) {
    Log 'FOUT' ("adres of doel staat op de verboden lijst (voorgoed read-only): " + $Adres + " / " + $Doel)
    Log 'GEWEIGERD' 'dit adres/doel staat op de verboden lijst; geen transport geladen'
    exit 1
}

# ---------------------------------------------------------------------------
# -Actieid weglaten was STILZWIJGEND fataal. Het lege
# argument ging als 'actieid' naar upgrade_gate, terwijl 'actieid_uit_script'
# het zelf gegenereerde id droeg; evaluate_phase vergelijkt die twee met !=,
# dus ELKE fase sloot 'mislukt' - met een ledgerregel die een echt oordeel
# lijkt. Dat is nu EXPLICIET: een echte (niet -WatIs) aanroep zonder -Actieid
# wordt geweigerd voordat er een ledgerregel bestaat. Bij -WatIs is een leeg
# -Actieid juist normaal (er is nog niets bevestigd; het script vormt dan
# zelf het etiket waaraan de mens de code straks bindt).
# ---------------------------------------------------------------------------
if (-not $WatIs -and [string]::IsNullOrWhiteSpace($Actieid)) {
    Log 'FOUT' '-Actieid ontbreekt op een echte fase-aanroep; het bevestigde actie-id is de identiteitskoppeling met het ledger'
    Log 'GEWEIGERD' 'geef -Actieid mee (of gebruik -WatIs voor een voorvertoning); zonder actie-id sluit elke fase mislukt'
    exit 1
}

# ---------------------------------------------------------------------------
# -Doelbuild mag TAK-GEKWALIFICEERD zijn ('14.1-72.57',
# de vorm die de rest van dit product gebruikt). Het
# REMOTE PAD kent die vorm niet: een NetScaler-buildboom heet
# /var/nsinstall/<tak>/build_<buildnummer> - dus /var/nsinstall/14.1/build_72.57
# en NOOIT /var/nsinstall/14.1/build_14.1-72.57. De tak en het buildnummer
# worden hier EEN keer gesplitst en overal hergebruikt.
#
# De tak uit -Doelbuild wint van de tak uit de bundelbestandsnaam: -Doelbuild
# is het BEVESTIGDE argument (het staat in het [TARGET]-etiket waaraan de code
# hangt), de bundelnaam is een afleiding. Draagt -Doelbuild geen tak, dan valt
# het terug op de oude regex over de bundelnaam.
# ---------------------------------------------------------------------------
if ($Doelbuild.Contains('-')) {
    $script:GjkDoelbuildTak = $Doelbuild.Substring(0, $Doelbuild.IndexOf('-'))
    $script:GjkDoelbuildNummer = $Doelbuild.Substring($Doelbuild.IndexOf('-') + 1)
}
else {
    $script:GjkDoelbuildTak = ''
    $script:GjkDoelbuildNummer = $Doelbuild
}
function _GjkBuildPad {
    param([string] $BundelNaam)
    $tak = $script:GjkDoelbuildTak
    if ([string]::IsNullOrEmpty($tak)) {
        $m = [regex]::Match($BundelNaam, 'build-(?<tak>\d+\.\d+)-')
        $tak = if ($m.Success) { $m.Groups['tak'].Value } else { 'onbekend' }
    }
    return ('/var/nsinstall/' + $tak + '/build_' + $script:GjkDoelbuildNummer)
}

# ---------------------------------------------------------------------------
# DE ENE plek waar dit script een
# firmwarebundel in -Firmwaremap kiest. Drie eerdere aanroepplekken (R1, R2,
# R3) deden elk hun EIGEN 'Get-ChildItem -Filter *.tgz | Select-Object
# -First 1' - een stray .tgz in de map (een oude bundel, een per ongeluk
# gekopieerd bestand) werd dan stilzwijgend gekozen: geupload, uitgepakt en
# GEINSTALLEERD, zonder dat -Doelbuild daar iets tegen deed. Kiest nu op de
# EXACTE, verwachte naam wanneer -Doelbuild een tak draagt
# (build-<tak>-<build>_nc_64.tgz - dezelfde vorm en dezelfde regex-vorm
# handelen.py's _firmware_target_build()/_FIRMWARE_BUNDLE_RE ook aanhoudt,
# zodat beide helften van dit product dezelfde regel toepassen). Draagt
# -Doelbuild geen tak (de losse-scriptvorm), dan is de tak nog
# onbekend en zoekt dit op hetzelfde patroon met EXACT EEN kandidaat - nooit
# een eerste treffer bij nul of meer dan een match, hetzelfde regime als
# _firmware_target_build() voor "geen eenduidige doelbuild".
# ---------------------------------------------------------------------------
function _GjkVerwachteBundelnaam {
    if (-not [string]::IsNullOrEmpty($script:GjkDoelbuildTak)) {
        return ('build-' + $script:GjkDoelbuildTak + '-' + $script:GjkDoelbuildNummer + '_nc_64.tgz')
    }
    return $null
}

# ---------------------------------------------------------------------------
# De bundelnaam gaat letterlijk in remote shell-commando's ('shell sh -c ''cd
# <buildboom> && tar -xvzf <naam>''', 'test -f', 'sha256 -q') en in een remote
# pad. Met een tak in -Doelbuild vormt dit script die naam zelf uit het
# gevalideerde argument. ZONDER tak komt hij uit een wildcard over de map, en
# dan is het een BESTANDSNAAM die iedereen met schrijfrecht op de firmwaremap
# kiest: een aanhalingsteken, puntkomma of spatie in die naam past op het
# patroon build-*-<build>_nc_64.tgz en werd een tweede commando op de doos
# (gemeten met het NEP-transport). Daarom moet elke gevonden naam de
# bundelvorm hebben die de server ook eist (handelen._FIRMWARE_BUNDLE_RE):
# build-<tak>-<build>_nc_64.tgz, tak en build alleen ASCII-cijfers en punten,
# hoofdlettergevoelig, en de build gelijk aan die van -Doelbuild.
#
# Getoetst op TWEE plekken: voor de sessie opengaat (elke kandidaat van het
# patroon, zodat geen enkel commando de doos bereikt - ook niet bij -WatIs),
# en opnieuw waar de bundel gekozen wordt (_GjkVindBundel), voor een naam die
# tussen die twee momenten in de map verscheen. Een afwijkende naam: [FOUT] +
# [GEWEIGERD] en exitcode 4, zonder de naam te herhalen. Een eigen exitcode:
# dit is geen geoordeelde fase (1), geen onleesbare invoer (2) en geen
# onverwachte meetfout (3), maar een firmwaremap die iemand anders dan dit
# product heeft ingericht.
# ---------------------------------------------------------------------------
function _GjkBundelpatroon { return ('build-*-' + $script:GjkDoelbuildNummer + '_nc_64.tgz') }

function _GjkBundelnaamGeldig {
    param([string] $Naam)
    $vorm = '^build-[0-9]+(\.[0-9]+)*-' + [regex]::Escape($script:GjkDoelbuildNummer) + '_nc_64\.tgz\z'
    return ($Naam -cmatch $vorm)
}

function _GjkWeigerBundelnaam {
    Log 'FOUT' 'een firmwarebundel in -Firmwaremap heeft niet de vorm build-<tak>-<build>_nc_64.tgz'
    Log 'GEWEIGERD' 'de bundelnaam gaat in geen enkel commando naar de appliance; hernoem of verwijder het bestand, of geef -Doelbuild met tak mee'
    exit 4
}

function _GjkVindBundel {
    param([Parameter(Mandatory = $true)] [string] $Firmwaremap)
    $verwacht = _GjkVerwachteBundelnaam
    if ($null -ne $verwacht) {
        $pad = Join-Path $Firmwaremap $verwacht
        if (-not (Test-Path -LiteralPath $pad -PathType Leaf)) {
            throw ('geen firmwarebundel gevonden: verwacht ' + $verwacht + ' in ' + $Firmwaremap)
        }
        $gekozen = Get-Item -LiteralPath $pad
    }
    else {
        $patroon = _GjkBundelpatroon
        $kandidaten = @(Get-ChildItem -LiteralPath $Firmwaremap -Filter $patroon -File -ErrorAction SilentlyContinue)
        if ($kandidaten.Count -eq 0) {
            throw ('geen firmwarebundel gevonden die voldoet aan ' + $patroon + ' in ' + $Firmwaremap)
        }
        if ($kandidaten.Count -gt 1) {
            throw ('meer dan een firmwarebundel voldoet aan ' + $patroon + ' in ' + $Firmwaremap + ': geen eenduidige doelbuild')
        }
        $gekozen = $kandidaten[0]
    }
    if (-not (_GjkBundelnaamGeldig -Naam $gekozen.Name)) { _GjkWeigerBundelnaam }
    return $gekozen
}

# De eerste toets: voor het transport, de sessie en fase_gestart, alleen waar
# de naam uit het patroon komt (geen tak in -Doelbuild) en alleen in de fasen
# die de bundel kiezen.
if ([string]::IsNullOrEmpty($script:GjkDoelbuildTak) -and $Fase -in @('R1', 'R2', 'R3', 'R5')) {
    foreach ($kandidaat in @(Get-ChildItem -LiteralPath $Firmwaremap -Filter (_GjkBundelpatroon) -File -ErrorAction SilentlyContinue)) {
        if (-not (_GjkBundelnaamGeldig -Naam $kandidaat.Name)) { _GjkWeigerBundelnaam }
    }
}

$eigenMap = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($eigenMap)) { $eigenMap = Split-Path -Parent $MyInvocation.MyCommand.Path }
$echteTransport = Join-Path $eigenMap 'GjkUpgrade-Ssh.ps1'
. $echteTransport
Assert-GjkPoshSsh

# ---------------------------------------------------------------------------
# STAP 2: de twee etiketten, letterlijk (runnercontract hoofdstuk 8). De
# bevestigingscode wordt hieraan gebonden - ALTIJD afgedrukt, ook bij -WatIs.
# ---------------------------------------------------------------------------
$opruimtoevoeging = ''
if ($OudeBuildbomenOpruimen) { $opruimtoevoeging = ', oude buildbomen opruimen' }
$targetLabel = ('[TARGET] ' + $Doel + ' (' + $Adres + ') - fase ' + $Fase + ' naar build ' + $Doelbuild + $opruimtoevoeging)

if ([string]::IsNullOrWhiteSpace($Actieid)) {
    # Nog niets bevestigd (een -WatIs-voorstel): dit script vormt het etiket
    # waaraan de mens straks de code bindt. Op de ECHTE (bevestigde) run geeft
    # de aanroeper -Actieid altijd mee, en dan wordt dat etiket hier herhaald -
    # nooit een nieuwe klok, anders zou het etiket van de bevestigde run niet
    # meer overeenkomen met wat de mens zag.
    $actieidVoorLabel = ('upgrade-' + $Fase + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
}
else {
    $actieidVoorLabel = $Actieid
}
$actieidLabel = ('[ACTIEID] ' + $actieidVoorLabel)

Write-Host $targetLabel
Write-Host $actieidLabel

# ---------------------------------------------------------------------------
# STAP 3: -WatIs. Geen sessie, geen wijziging - alleen tekst over wat deze
# fase ZOU doen. Het eindwoord hier ('er is niets
# gewijzigd') staat op een EIGEN kanaal ([VOORVERTONING]), niet op
# [EINDSTATUS] - er is nog geen fase gestart en dus geen fase-uitkomst.
# ---------------------------------------------------------------------------
$fasePreview = @{
    'R0' = 'zou meten: de backupregel uit het actieregister, de vorige buildboom en zijn leeftijd uit de export, de snapshotverwijzing, de familietellingen en het genormaliseerde anker uit de export, en de doelbuild tegenover de huidige build en de vloer. Wijzigt niets en raakt de appliance niet aan.'
    'R1' = 'zou meten: HA-rol, vrije ruimte op /var, de configuratiestand (show ns config), sha256 van de doos. Zou doen: mkdir op de buildboom en de bundel via SFTP overzetten.'
    'R2' = 'zou meten: de vendor-precheck-uitkomst. Zou doen: de buildboom uitpakken en installns --pre_check draaien (de exitcode telt niet mee).'
    'R3' = 'zou doen: installns -Y -n draaien.'
    'R4' = 'zou doen: shell reboot (de exitcode telt niet mee). Zou meten: poort 22, dan SSH-auth, dan de hostsleutel opnieuw.'
    'R5' = 'zou meten: de nieuwe build, de HA-rol en het anker (live gelezen). Meet GEEN familietellingen: die komen in R0 uit de export en R5 heeft geen export. Wijzigt niets.'
    'R6' = 'wijzigt niets en meet niets; opent alleen het soakvenster.'
}
if ($WatIs) {
    Write-Host ('[OK] ' + $fasePreview[$Fase])
    Write-Host '[VOORVERTONING] er is niets gewijzigd'
    exit 0
}

# ---------------------------------------------------------------------------
# Python-bruggen. TWEE, en niet meer: 'upgrade_measure' (vormt poorten uit
# ruwe metingen, en schrijft de ENE fase_gestart-markeerregel) en
# 'upgrade_gate' (het oordeel, EXACT een keer per fase-aanroep). Dit script
# beslist zelf geen enkele poort - het roept alleen de functies aan die dat
# al deden (nsmcp.upgrade.disk_gate/secondary_gate/hash_gate/precheck_gate/...)
# via die brug.
# ---------------------------------------------------------------------------
function _GjkAanroepPython {
    param([Parameter(Mandatory = $true)] [string] $Module, [Parameter(Mandatory = $true)] [string] $JsonIn)
    $foutBestand = [System.IO.Path]::GetTempFileName()
    try {
        $stdout = $JsonIn | & $GatePython -I -m $Module 2>$foutBestand
        $code = $LASTEXITCODE
        $stderrTekst = ''
        if (Test-Path -LiteralPath $foutBestand) { $stderrTekst = Get-Content -LiteralPath $foutBestand -Raw -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Stdout = ($stdout -join [Environment]::NewLine); Stderr = $stderrTekst; ExitCode = $code }
    }
    finally {
        Remove-Item -LiteralPath $foutBestand -ErrorAction SilentlyContinue
    }
}

function _GjkVormPoorten {
    <#  Stuurt VERZOEKEN naar 'python -m nsmcp.upgrade_measure' (actie 'vorm') en
        geeft de gevormde poortlijst terug. Dit is de ENE plek waar dit script
        "elke poortuitspraak komt uit Python" naleeft voor de metingen-gebonden
        poorten (schijfruimte, secondary, firmware-hash, vendor-precheck,
        hostsleutel, aanwezigheidstoetsen, het configuratie-anker, R0's
        actieregister-/exportpoorten). #>
    param([array] $Verzoeken)
    if (-not $Verzoeken -or $Verzoeken.Count -eq 0) { return @() }
    $json = (@{ actie = 'vorm'; verzoeken = $Verzoeken } | ConvertTo-Json -Depth 12 -Compress)
    $uit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $json
    if ($uit.ExitCode -ne 0) {
        throw ('upgrade_measure (vorm) gaf exitcode ' + $uit.ExitCode + ': ' + $uit.Stderr)
    }
    $geparsed = $uit.Stdout | ConvertFrom-Json
    return @($geparsed.poort)
}

function _GjkNu { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

# ---------------------------------------------------------------------------
# STAP 4: de ONE fase_gestart-regel, geschreven DOOR de oordeelshelft
# ('python -m nsmcp.upgrade_measure', actie 'start' - dezelfde append_line()
# als upgrade_gate.py zelf gebruikt). Dit script opent hiervoor GEEN ledger
# zelf en schrijft er nooit direct in.
#
# 'actieid_uit_script' hieronder (stap 8) komt uit de
# ECHO van DEZE schrijfactie ($actieidUitLedger), niet uit dezelfde variabele
# als het [ACTIEID]-label ($actieidVoorLabel). Dat is een ECHTE, andere bron:
# een fout in de JSON-omzetting tussen dit script en Python, of tussen Python
# en het geschreven ledgerbestand, zou hier zichtbaar worden; met de oude
# wiring (dezelfde variabele aan beide kanten van evaluate_phase()'s
# vergelijking) kon dat nooit.
# ---------------------------------------------------------------------------
$gestart = _GjkNu
$poging = [guid]::NewGuid().ToString("N")
# 'doelbuild' in de startregel: R1..R6 weigeren in de server een bundel die
# afwijkt van die waarmee R0 van dezelfde run startte (de runbinding).
$startJson = (@{
    actie = 'start'; run = $Run; doel = $Doel; fase = $Fase
    actieid = $actieidVoorLabel; bevestiger = $Bevestiger; gestart = $gestart; ledger = $Ledger; poging = $poging
    doelbuild = $Doelbuild
} | ConvertTo-Json -Compress)
$startUit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $startJson
if ($startUit.ExitCode -ne 0) {
    Log 'FOUT' ('kon fase_gestart niet laten vastleggen: ' + $startUit.Stderr)
    Log 'GEWEIGERD' 'fase_gestart is niet vastgelegd'
    exit 2
}
$gestartRegel = $startUit.Stdout | ConvertFrom-Json
$actieidUitLedger = [string]$gestartRegel.actieid
Log 'OK' ('fase_gestart vastgelegd voor ' + $Run + '/' + $Fase)

# ---------------------------------------------------------------------------
# STAP 5: transport laden. Standaard scripts\GjkUpgrade-Ssh.ps1 (al geladen
# hierboven voor Assert-GjkPoshSsh); -Transport kan de sessie-functies
# overschrijven (een NEP-transport in de tests - zie tests/test_runner_script.py).
# ---------------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($Transport)) {
    . $Transport
}

# ---------------------------------------------------------------------------
# STAP 6-8: R0 opent GEEN sessie (R0 raakt de appliance NIET aan).
# Elke andere fase: sessie openen (GEPINDE vingerafdruk), metingen verzamelen,
# poorten laten vormen, en het geheel naar upgrade_gate sturen. EEN
# try/finally: de sessie gaat altijd dicht (stap 10), ook als er onderweg
# iets misgaat.
#
# De METINGEN (stap 7, en het vormen/oordelen in stap 8) vallen
# onder de outer catch verderop in dit bestand (net voor de finally). Een
# onverwachte fout daar (een ontbrekende firmwarebundel, `.Name` op een lege
# Get-ChildItem-uitkomst, een mislukte SFTP-upload, een niet-nul exitcode uit
# _GjkVormPoorten, ...) mag NOOIT stilzwijgend eindigen met exitcode 1 - dat
# is in dit contract het woord voor een GEOORDEELDE weigering (upgrade_
# gate.py's eigen docstring). Zo'n fout wordt gelogd en eindigt met exitcode
# 3 (hetzelfde "de runner kon zijn werk niet eens proberen te voltooien"-
# register als "Posh-SSH ontbreekt"). Het sessie-openen hieronder heeft zijn
# EIGEN, aparte catch en behandelt zijn fouten zelf - die
# gooit niet verder naar de outer catch.
# ---------------------------------------------------------------------------
$sessie = $null
$ruweMetingen = @{}
$verzoeken = @()
$sessieGeopend = $false

try {
    if ($Fase -eq 'R0') {
        # ---------------------------------------------------------------
        # R0: GEEN SSH. Zijn bronnen zijn het actieregister (de backupregel
        # die onderhoud_backup_maken al vastlegde, met zijn eigen teruglezing
        # op de collectie config/systembackup - een eerder gerepareerd mechanisme)
        # en de export (de vorige buildboom, zijn leeftijd, de
        # familietellingen en het genormaliseerde anker). De snapshot-
        # verwijzing komt zoals altijd van de mens (-Snapshotverwijzing).
        # ---------------------------------------------------------------
        $ruweMetingen['snapshotverwijzing'] = $Snapshotverwijzing
        $ruweMetingen['actieregister_pad'] = $Actieregister
        $ruweMetingen['export_root'] = $ExportRoot

        $verzoeken += @{ soort = 'backupregister'; pad = $Actieregister; doel = $Doel }
        $verzoeken += @{ soort = 'export-buildboom'; export_root = $ExportRoot }
        $verzoeken += @{ soort = 'export-leeftijd'; export_root = $ExportRoot }
        $verzoeken += @{ soort = 'familietellingen'; export_root = $ExportRoot }
        $verzoeken += @{ soort = 'configuratie-anker-export'; export_root = $ExportRoot }
        $verzoeken += @{
            soort = 'aanwezig'; naam = 'hypervisor-snapshotverwijzing ingevoerd'; poorttype = 'mens'
            aanwezig = (-not [string]::IsNullOrWhiteSpace($Snapshotverwijzing))
            bewijs = ('snapshotverwijzing: ' + $Snapshotverwijzing)
            reden_dicht = 'geen snapshotverwijzing meegegeven; een mens moet die intypen'
        }
        # De doelbuild tegenover de huidige build en de vloer. De server gaf
        # ze mee (-Huidigebuild, -Vloerbuild, -VloerBulletin); de oordeelshelft
        # (floor_gate) beslist, met -DoelbuildGeaccepteerd als menselijke
        # uitweg onder de vloer, zonder vloer, zonder huidige build of bij
        # een doelbuild die niet hoger is dan de huidige build.
        $verzoeken += @{
            soort = 'doelbuild-vloer'; doelbuild = $Doelbuild; huidig = $Huidigebuild; vloer = $Vloerbuild
            bulletin = $VloerBulletin; geaccepteerd = [bool]$DoelbuildGeaccepteerd
            pakket = $VloerPakket; pakket_datum = $VloerPakketDatum
        }
    }
    else {
        try {
            $sessie = New-GjkSshSession -Adres $Adres -Gebruiker $Gebruiker -CredentialTarget $CredentialTarget -Vingerafdruk $HostsleutelVingerafdruk -TimeoutSec 30
            Log 'OK' ('SSH-sessie geopend naar ' + $Adres)
            $sessieGeopend = $true
            $verzoeken += @{ soort = 'hostsleutel'; sessie_geopend = $true; gepinde_vingerafdruk = $HostsleutelVingerafdruk }
        }
        catch {
            $boodschap = [string]$_.Exception.Message
            Log 'FOUT' ('kon geen SSH-sessie openen: ' + $boodschap)
            # NIET elke verbindingsfout is een hostsleutelfout. De
            # discriminator (_GjkIsHostsleutelfout, uit het transport)
            # beslist - een timeout/verkeerd wachtwoord/host-down wordt nooit
            # meer als "hostsleutel wijkt af" in het ledger gezet.
            $isHostsleutelfout = _GjkIsHostsleutelfout $boodschap
            $verzoeken += @{
                soort = 'hostsleutel'; sessie_geopend = $false
                hostsleutelfout = $isHostsleutelfout; foutmelding = $boodschap
                gepinde_vingerafdruk = $HostsleutelVingerafdruk
            }
        }

        $voorpoortOpen = $true
        if ($Fase -in @('R1', 'R2', 'R3', 'R4')) {
            $voorVerzoeken = @($verzoeken)
            if ($sessieGeopend) {
                $ha = Invoke-GjkSsh -Sessie $sessie -Commando 'show ha node' -TimeoutSec 60
                $voorVerzoeken += @{ soort = 'secondary'; ha_node_uitvoer = $ha.stdout; doel_adres = $Adres; exitcode = $ha.exitcode; stderr = $ha.stderr; standalone_geaccepteerd = [bool]$StandaloneGeaccepteerd }
                if ($Fase -eq 'R2') {
                    $padJson = (@{ actie = 'precheck-pad'; run = $Run; actieid = $actieidUitLedger; poging = $poging } | ConvertTo-Json -Compress)
                    $padUit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $padJson
                    if ($padUit.ExitCode -ne 0) { throw ('precheck-pad kon niet worden gevormd: ' + $padUit.Stderr) }
                    $precheckPad = [string](($padUit.Stdout | ConvertFrom-Json).pad)
                    $afwezig = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sh -c ''test ! -e ' + $precheckPad + ' && test ! -L ' + $precheckPad + ' && echo AFWEZIG''') -TimeoutSec 60
                    $voorVerzoeken += @{ soort = 'precheck-pad'; pad = $precheckPad; exitcode = $afwezig.exitcode; stdout = $afwezig.stdout }
                }
                if ($Fase -eq 'R1') {
                    # De meting en de parse staan in het transport
                    # (Get-GjkVrijeRuimteVar): dezelfde functie die het losse
                    # leesscript voor de preflight gebruikt.
                    $df = Get-GjkVrijeRuimteVar -Sessie $sessie
                    $vrijMb = $df.vrijMb

                    $bundelBestand = _GjkVindBundel -Firmwaremap $Firmwaremap
                    $buildDir = _GjkBuildPad -BundelNaam $bundelBestand.Name

                    # Voor upload vergelijkt Python de lokale hash met de vendor-sidecar.
                    # Na upload blijft firmware-hash een afzonderlijke SHA256-meting OP DE DOOS.
                    $lokaleSha = (Get-FileHash -LiteralPath $bundelBestand.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                    $vendorSha = ''
                    $shaBestand = $bundelBestand.FullName + '.sha256'
                    if (Test-Path -LiteralPath $shaBestand) {
                        $eersteRegel = Get-Content -LiteralPath $shaBestand -TotalCount 1 -ErrorAction SilentlyContinue
                        if ($eersteRegel) { $vendorSha = (@($eersteRegel -split '\s+' | Where-Object { $_ -ne '' }))[0] }
                    }
                    $bundelMb = [math]::Round($bundelBestand.Length / 1MB)

                    # Gemeten: een hertest van R1 uploadde de
                    # bundel altijd opnieuw, ook als een vorige poging hem al met de
                    # juiste hash op de doos had staan; een hertest vereiste dan
                    # handmatig opruimen van de buildboom. Staat de bundel al op het
                    # doelpad EN klopt de SHA-256 op de doos met de vendor-SHA
                    # (dezelfde hashpoort R1 hieronder al heeft voor firmware-hash),
                    # dan slaat de uitvoering de upload over. Een NIEUW commando
                    # (geen 'sha256' erin) zodat een test zonder expliciete
                    # respons-override hier gewoon "afwezig" leest en de bestaande
                    # upload ongewijzigd blijft.
                    $aanwezigheid = Invoke-GjkSsh -Sessie $sessie -Commando (
                        'shell sh -c ''test -f ' + $buildDir + '/' + $bundelBestand.Name +
                        ' && echo AANWEZIG || echo AFWEZIG'''
                    ) -TimeoutSec 60
                    $bundelAlOpDoos = ($aanwezigheid.exitcode -eq 0 -and $aanwezigheid.stdout -match 'AANWEZIG')
                    $doosShaVooraf = ''
                    if ($bundelAlOpDoos) {
                        $shaVooraf = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sha256 -q ' + $buildDir + '/' + $bundelBestand.Name) -TimeoutSec 120
                        if ($shaVooraf.exitcode -eq 0) {
                            $shaVoorafMatch = [regex]::Match($shaVooraf.stdout, '(?<hash>[0-9a-fA-F]{64})')
                            if ($shaVoorafMatch.Success) { $doosShaVooraf = $shaVoorafMatch.Groups['hash'].Value.ToLowerInvariant() }
                        }
                    }
                    $uploadOverslaan = (
                        $bundelAlOpDoos -and $vendorSha -ne '' -and $doosShaVooraf -ne '' -and $doosShaVooraf -eq $vendorSha
                    )

                    # bundel_mb blijft de ECHTE gemeten
                    # grootte (nooit een verzonnen 0) - bundel_al_aanwezig zegt
                    # de Python-kant dat de bundelterm bij het overslaan een
                    # BEWUSTE nul is (geen tweede kopie meer over SFTP), nooit
                    # een ONGEMETEN waarde. disk_gate() beslist zelf hoe die term
                    # meetelt; dit script raadt de rekensom niet na.
                    $voorVerzoeken += @{
                        soort = 'schijfruimte-live'; vrij_mb = $vrijMb; bundel_mb = $bundelMb
                        uitpak_mb = $null; exitcode = $df.exitcode; stderr = $df.stderr
                        bundel_al_aanwezig = $uploadOverslaan
                    }
                    $voorVerzoeken += @{ soort = 'lokale-bundel'; vendor_sha = $vendorSha; lokale_sha = $lokaleSha }
                    # De driftpoort meet zelf: show ns config in deze sessie. De
                    # oordeelshelft (drift_live_gate) opent op bewijs als er sinds de
                    # laatste opslag niets gewijzigd is, of op de menselijke
                    # acceptatie (-DriftGeaccepteerd) met de gemeten stand erbij.
                    $configStand = Invoke-GjkSsh -Sessie $sessie -Commando 'show ns config' -TimeoutSec 60
                    $voorVerzoeken += @{
                        soort = 'configstand'; uitvoer = [string]$configStand.stdout
                        exitcode = $configStand.exitcode; stderr = [string]$configStand.stderr
                        drift_geaccepteerd = [bool]$DriftGeaccepteerd
                    }
                }
            }
            $voorJson = (@{
                actie = 'voorpoort'; fase = $Fase; run = $Run; doel = $Doel; ledger = $Ledger
                actieid = $actieidUitLedger; bevestiger = $Bevestiger; gestart = $gestart; poging = $poging
                verzoeken = $voorVerzoeken
            } | ConvertTo-Json -Depth 12 -Compress)
            $voorUit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $voorJson
            if ($voorUit.ExitCode -ne 0) { throw ('voorpoort kon niet worden vastgelegd: ' + $voorUit.Stderr) }
            $voorRegel = $voorUit.Stdout | ConvertFrom-Json
            $voorpoortOpen = ($voorRegel.uitkomst -eq 'open')
            Log 'OK' ('voorpoort vastgelegd: ' + $voorRegel.uitkomst)
        }
        if ($sessieGeopend -and $voorpoortOpen) {
            switch ($Fase) {
                'R1' {
                        $mk = Invoke-GjkSsh -Sessie $sessie -Commando ('shell mkdir -p ' + $buildDir) -TimeoutSec 60
                        # Alleen de upload zelf wordt overgeslagen (mkdir blijft
                        # onvoorwaardelijk draaien - idempotent, en zo blijft
                        # mkdir_exitcode hieronder een ECHTE meting in plaats van
                        # een verzonnen waarde voor een commando dat nooit liep).
                        if ($uploadOverslaan) {
                            $upload = [pscustomobject]@{ duurSec = 0 }
                        } else {
                            $upload = Copy-GjkFile -Sessie $sessie -Bron $bundelBestand.FullName -Doel $buildDir -TimeoutSec 3000
                        }
                        $ls = Invoke-GjkSsh -Sessie $sessie -Commando ('shell ls -la ' + $buildDir) -TimeoutSec 60
                        $shaOpDeDoos = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sha256 -q ' + $buildDir + '/' + $bundelBestand.Name) -TimeoutSec 120

                        $doosSha = ''
                        if ($shaOpDeDoos.exitcode -eq 0) {
                            $shaMatch = [regex]::Match($shaOpDeDoos.stdout, '(?<hash>[0-9a-fA-F]{64})')
                            if ($shaMatch.Success) { $doosSha = $shaMatch.Groups['hash'].Value.ToLowerInvariant() }
                        }

                        # De "buildboom staat er nog" poort krijgt
                        # er een GROOTTEVERGELIJKING bij: de naam alleen in de
                        # 'ls -la'-uitvoer terugzien bewijst niet dat de bytes
                        # ook echt allemaal aankwamen (een afgebroken transfer
                        # kan dezelfde naam met een kortere lengte achterlaten).
                        $doosGrootteBytes = $null
                        $regelMetBestand = @($ls.stdout -split "`r?`n") | Where-Object { $_ -match [regex]::Escape($bundelBestand.Name) } | Select-Object -First 1
                        if ($regelMetBestand) {
                            $velden = @($regelMetBestand -split '\s+' | Where-Object { $_ -ne '' })
                            if ($velden.Count -ge 5) {
                                $mogelijkeGrootte = [int64]0
                                if ([int64]::TryParse($velden[4], [ref]$mogelijkeGrootte)) { $doosGrootteBytes = $mogelijkeGrootte }
                            }
                        }
                        $grootteKomtOvereen = ($null -ne $doosGrootteBytes -and $doosGrootteBytes -eq $bundelBestand.Length)

                        $ruweMetingen['mkdir_exitcode'] = $mk.exitcode
                        $ruweMetingen['buildboom'] = $buildDir
                        $ruweMetingen['upload_duur_sec'] = $upload.duurSec

                        $verzoeken += @{ soort = 'firmware-hash'; vendor_sha = $vendorSha; doos_sha = $doosSha; lokale_sha = $lokaleSha }
                        $verzoeken += @{
                            soort = 'aanwezig'; naam = 'lokale bundel-sha256 (informatief)'; poorttype = 'bewijs'
                            aanwezig = $true
                            bewijs = ('lokaal sha256 ' + $lokaleSha + '; bestand ' + $bundelBestand.FullName)
                            reden_dicht = ''
                        }
                        if ($uploadOverslaan) {
                            # Informatief bewijs, geen eigen poort die kan sluiten -
                            # zelfde vorm als 'lokale bundel-sha256' hierboven.
                            $verzoeken += @{
                                soort = 'aanwezig'; naam = 'upload overgeslagen'; poorttype = 'bewijs'
                                aanwezig = $true
                                bewijs = 'bundel aanwezig met gelijke SHA: upload overgeslagen'
                                reden_dicht = ''
                            }
                        }
                        $verzoeken += @{
                            soort = 'aanwezig'; naam = 'buildboom staat er nog'; poorttype = 'bewijs'
                            aanwezig = ($ls.exitcode -eq 0 -and $ls.stdout -match [regex]::Escape($bundelBestand.Name) -and $grootteKomtOvereen)
                            bewijs = (
                                'ls ' + $buildDir + ': ' + $ls.stdout + '; lokale grootte ' + $bundelBestand.Length +
                                ' bytes, op de doos ' + $(if ($null -ne $doosGrootteBytes) { [string]$doosGrootteBytes + ' bytes' } else { 'onbekend' })
                            )
                            reden_dicht = 'de overgezette bundel staat niet (meer) in de buildboom, of de grootte op de doos wijkt af van de lokale bundel'
                        }
                    }
                    'R2' {
                        $bundelBestand = _GjkVindBundel -Firmwaremap $Firmwaremap
                        $buildDir = _GjkBuildPad -BundelNaam $bundelBestand.Name

                        # A later fix removed the wildcard from
                        # every OTHER selection site in this file (the exact bundle
                        # name is already known here, from _GjkVindBundel above) -
                        # this was the one left over. '*.tgz' would silently pick up
                        # ANY leftover .tgz in the build directory from a previous,
                        # unrelated upgrade run, not necessarily the bundle this run
                        # just uploaded.
                        $uitpakken = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sh -c ''cd ' + $buildDir + ' && tar -xvzf ' + $bundelBestand.Name + '''') -TimeoutSec 600
                        $ondersteund = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sh -c ''test -f ' + $buildDir + '/.pre-check-supported && echo JA || echo NEE''') -TimeoutSec 60
                        # Gemeten op lab-02: de doos zet voor elke shell-uitvoer een waarschuwingsbanner
                        # (RPC default passwords); het antwoord is dus een HELE REGEL 'JA', niet de hele uitvoer.
                        $regelsOnd = @(($ondersteund.stdout -split "`r?`n") | ForEach-Object { $_.Trim() })
                        $isOndersteund = ($ondersteund.exitcode -eq 0 -and $regelsOnd -contains 'JA')

                        $precheckTekst = ''
                        if ($isOndersteund) {
                            Invoke-GjkSsh -Sessie $sessie -Commando ('shell sh -c ''cd ' + $buildDir + ' && ./installns --pre_check --pre_check_output ' + $precheckPad + '''') -TimeoutSec 900 | Out-Null
                            $lees = Invoke-GjkSsh -Sessie $sessie -Commando ('shell cat ' + $precheckPad) -TimeoutSec 60
                            $precheckTekst = $lees.stdout
                        }

                        $ruweMetingen['uitpakken_exitcode'] = $uitpakken.exitcode
                        $ruweMetingen['precheck_ondersteund'] = $isOndersteund

                        $verzoeken += @{
                            soort = 'aanwezig'; naam = 'pre-check-ondersteuning aanwezig'; poorttype = 'bewijs'
                            aanwezig = $isOndersteund
                            bewijs = ('.pre-check-supported: ' + $ondersteund.stdout)
                            reden_dicht = 'deze buildboom draagt geen .pre-check-supported'
                        }
                        if ($isOndersteund) {
                            $verzoeken += @{ soort = 'precheck-poging'; precheck_json = $precheckTekst; exitcode = $lees.exitcode; pad = $precheckPad }
                        }
                    }
                    'R3' {
                        $bundelBestand = _GjkVindBundel -Firmwaremap $Firmwaremap
                        $buildDir = _GjkBuildPad -BundelNaam $bundelBestand.Name
                        $inst = Invoke-GjkSsh -Sessie $sessie -Commando ('shell sh -c ''cd ' + $buildDir + ' && ./installns -Y -n''') -TimeoutSec 1700

                        $ruweMetingen['installns_exitcode'] = $inst.exitcode
                        # NIET meer met de hand afgekapt in PowerShell
                        # (Substring(len-200)) - presence_gate (Python, nsmcp.upgrade)
                        # bindt UNTRUSTED bewijs nu op EEN plek, voor elke aanroeper.
                        # Gemeten op lab-02 (8-9-2026): installns schrijft BEGIN_TIME en END_TIME
                        # naar STDERR, niet naar stdout. Beide stromen tellen dus mee voor het
                        # feit en voor het bewijs; alleen op stdout kijken sloot R3 na een
                        # geslaagde installatie.
                        $instTekst = [string]$inst.stdout + "`n" + [string]$inst.stderr
                        # Retain the measured deciding line explicitly; its location
                        # in either stream is not assumed to be the end of the output.
                        $eindRegel = @($instTekst -split "`r?`n" | Where-Object { $_ -match 'END_TIME' } | Select-Object -Last 1)
                        $markerBewijs = ''
                        if ($eindRegel.Count -eq 1) {
                            $markerBewijs = $eindRegel[0].Substring($eindRegel[0].IndexOf('END_TIME', [System.StringComparison]::OrdinalIgnoreCase))
                        }
                        $verzoeken += @{
                            soort = 'aanwezig'; naam = 'installatie voltooid (END_TIME)'; poorttype = 'bewijs'
                            aanwezig = ($instTekst -match 'END_TIME')
                            bewijs = ('installns -Y -n; gemeten markerfragment: ' + $markerBewijs)
                            reden_dicht = 'installns meldt geen END_TIME in zijn uitvoer'
                            bewijs_kant = 'kop'
                        }
                    }
                    'R4' {
                        $rebootUit = Invoke-GjkSsh -Sessie $sessie -Commando 'shell reboot' -TimeoutSec 30
                        Close-GjkSshSession $sessie
                        $sessie = $null
                        $terug = Wait-GjkTerug -Adres $Adres -Gebruiker $Gebruiker -CredentialTarget $CredentialTarget -Vingerafdruk $HostsleutelVingerafdruk -TimeoutSec 1700

                        $ruweMetingen['reboot_exitcode'] = $rebootUit.exitcode
                        $ruweMetingen['auth_terug'] = $terug.ok
                        $ruweMetingen['versie_na_reboot'] = $terug.versie
                        if ($terug.poort22Terug) { $ruweMetingen['poort22_terug'] = $terug.poort22Terug.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                        if ($terug.authTerug) { $ruweMetingen['auth_terug_tijd'] = $terug.authTerug.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

                        # GEEN vingerafdruk meer die alleen
                        # wordt AANGENOMEN gelijk te zijn. Wait-GjkTerug pint elke
                        # herverbindingspoging opnieuw via New-GjkSshSession; het
                        # RESULTAAT daarvan (geslaagd of niet, en of dat specifiek
                        # een hostsleutelfout was) is het enige dat hier telt.
                        $verzoeken = @($verzoeken | Where-Object { $_.soort -ne 'hostsleutel' })
                        if ($terug.ok) {
                            $verzoeken += @{ soort = 'hostsleutel'; sessie_geopend = $true; gepinde_vingerafdruk = $HostsleutelVingerafdruk }
                            # Meting 5 van het labbewijs: R4 draagt BEIDE tijden en oordeelt op de tweede.
                            $p22 = if ($terug.poort22Terug) { $terug.poort22Terug.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '(niet gemeten)' }
                            $pauth = if ($terug.authTerug) { $terug.authTerug.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '(niet gemeten)' }
                            $verzoeken += @{
                                soort = 'aanwezig'; naam = 'SSH-auth terug na reboot'; poorttype = 'bewijs'
                                aanwezig = $true
                                bewijs = ('poort 22 terug ' + $p22 + '; SSH-auth terug ' + $pauth + '; het oordeel valt op de auth, niet op poort 22')
                                reden_dicht = ''
                            }
                        }
                        else {
                            $postRebootIsHostsleutelfout = ($terug.reden -like 'hostsleutel wijkt af*')
                            $verzoeken += @{
                                soort = 'hostsleutel'; sessie_geopend = $false
                                hostsleutelfout = $postRebootIsHostsleutelfout; foutmelding = $terug.reden
                                gepinde_vingerafdruk = $HostsleutelVingerafdruk
                            }
                            $verzoeken += @{
                                soort = 'aanwezig'; naam = 'SSH-auth terug na reboot'; poorttype = 'bewijs'
                                aanwezig = $false; bewijs = $terug.reden; reden_dicht = $terug.reden
                            }
                        }
                    }
                    'R5' {
                        $ha = Invoke-GjkSsh -Sessie $sessie -Commando 'show ha node' -TimeoutSec 60
                        $versie = Invoke-GjkSsh -Sessie $sessie -Commando 'show ns version' -TimeoutSec 60
                        $config = Invoke-GjkSsh -Sessie $sessie -Commando 'show ns runningConfig' -TimeoutSec 180
                        $configRegels = @()
                        if (-not [string]::IsNullOrEmpty($config.stdout)) { $configRegels = @($config.stdout -split "`r?`n") }

                        $ruweMetingen['versie_uitvoer'] = $versie.stdout

                        $verzoeken += @{ soort = 'secondary'; ha_node_uitvoer = $ha.stdout; doel_adres = $Adres; exitcode = $ha.exitcode; stderr = $ha.stderr; standalone_geaccepteerd = [bool]$StandaloneGeaccepteerd }
                        $verzoeken += @{ soort = 'configuratie-anker'; regels = $configRegels; exitcode = $config.exitcode; stderr = $config.stderr }
                        $bevestigdeBuild = $Doelbuild
                        if ([string]::IsNullOrEmpty($script:GjkDoelbuildTak)) {
                            # The legacy bare build needs a uniquely selected bundle to establish its branch.
                            $bevestigdeBuild = ''
                            try {
                                $doelBundel = _GjkVindBundel -Firmwaremap $Firmwaremap
                                if ($doelBundel.Name -match '^build-(\d+\.\d+-\d+\.\d+)_') { $bevestigdeBuild = $Matches[1] }
                            } catch { $bevestigdeBuild = '' }
                        }
                        $verzoeken += @{
                            soort = 'doelbuild'; doelbuild = $bevestigdeBuild
                            versie_uitvoer = $versie.stdout; exitcode = $versie.exitcode; stderr = $versie.stderr
                        }
                    }
                'R6' {
                    # Meet niets, doet niets - opent alleen het soakvenster. De
                    # sessie hierboven bewijst alleen dat de gepinde hostsleutel nog
                    # klopt; er gaat verder geen commando naar de appliance.
                }
            }
        }
    }

    $geeindigd = _GjkNu
    # @() is niet decoratief: 'return @(...)' garandeert GEEN array over een
    # PowerShell-functiegrens heen - bij precies EEN geschreven object wordt de
    # aanroeper stilzwijgend een scalar, en dan zou 'poort' als een los OBJECT
    # in de JSON belanden in plaats van een lijst van EEN element (gemeten:
    # brak upgrade_gate met "string indices must be integers" bij een fase met
    # precies een poort - de hostsleutelpoort). Hier, aan de aanroepkant,
    # wordt de array dus opnieuw afgedwongen.
    $poort = @(_GjkVormPoorten -Verzoeken $verzoeken)

    # -----------------------------------------------------------------------
    # R0's EXTRA bewijsregel 'terugrolpunt_vast', VOOR
    # de sluitregel. Ontwerp 3.5 noemt voor R0 TWEE regels; alleen de tweede
    # (voormeting_vast) werd geschreven, dus de IDENTITEIT van het ding dat een
    # beheerder zou terugzetten - backupnaam, grootte, tijd, het pad van de
    # vorige buildboom, de leeftijd van de export waaruit dat pad komt, en de
    # snapshotverwijzing letterlijk - stond nergens in het ledger.
    #
    # Geschreven door de OORDEELSHELFT, via dezelfde append_line() als elke
    # andere regel ('python -m nsmcp.upgrade_measure', actie 'terugrolpunt') -
    # dit script opent nog steeds nooit zelf een ledgerbestand. Het is GEEN
    # sluitregel: 'terugrolpunt_vast' staat met opzet niet in _CLOSING_EVENTS
    # en de uitkomst blijft 'gestart', dus "precies EEN fase_gestart en EEN
    # sluitregel per fase" verandert niet - deze regel staat ertussen.
    #
    # De poorten die meegaan zijn de poorten die HIERBOVEN al gevormd zijn;
    # ze worden geechood, niet opnieuw geoordeeld, zodat de bewijsregel en de
    # sluitregel nooit iets anders over R0 kunnen zeggen.
    # -----------------------------------------------------------------------
    if ($Fase -eq 'R0') {
        $terugrolJson = (@{
            actie = 'terugrolpunt'; run = $Run; doel = $Doel; ledger = $Ledger
            actieid = $actieidUitLedger; bevestiger = $Bevestiger; gestart = $gestart
            actieregister = $Actieregister; export_root = $ExportRoot
            snapshotverwijzing = $Snapshotverwijzing; poort = $poort
        } | ConvertTo-Json -Depth 12 -Compress)
        $terugrolUit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $terugrolJson
        if ($terugrolUit.ExitCode -ne 0) {
            throw ('kon het terugrolpunt niet laten vastleggen: ' + $terugrolUit.Stderr)
        }
        Log 'OK' 'terugrolpunt vastgelegd (terugrolpunt_vast)'
    }

    $ruweMetingen['poort'] = $poort
    $ruweMetingen['actieid_uit_script'] = $actieidUitLedger

    $gateJson = (@{
        fase = $Fase; run = $Run; doel = $Doel; actieid = $Actieid; bevestiger = $Bevestiger
        gestart = $gestart; geeindigd = $geeindigd; ledger = $Ledger; soak_uren = $SoakUren; poging = $poging
        metingen = $ruweMetingen
    } | ConvertTo-Json -Depth 12 -Compress)

    $oordeel = _GjkAanroepPython -Module 'nsmcp.upgrade_gate' -JsonIn $gateJson
    if ($oordeel.ExitCode -eq 2 -and [string]::IsNullOrWhiteSpace($oordeel.Stdout)) {
        Log 'FOUT' ('upgrade_gate kon de invoer niet beoordelen: ' + $oordeel.Stderr)
        Log 'EINDSTATUS' 'NIET BEOORDEELD: de oordeelshelft kon deze meting niet lezen'
        exit 2
    }
    Write-Host $oordeel.Stdout
    $ledgerregel = $oordeel.Stdout | ConvertFrom-Json
    Log 'EINDSTATUS' ('fase ' + $Fase + ': ' + [string]$ledgerregel.uitkomst)
    exit $oordeel.ExitCode
}
catch {
    # Dit vangt ELKE onverwachte fout in de meting/oordeelspijplijn
    # hierboven - een ontbrekende firmwarebundel, '.Name' op een lege
    # Get-ChildItem-uitkomst, een mislukte SFTP-upload (elke throw uit
    # Copy-GjkFile), een niet-nul exitcode uit '_GjkVormPoorten' - NOOIT het
    # sessie-openen zelf (die catch hierboven vangt en behandelt zijn eigen
    # fouten en gooit niet verder). 'exit' in het try-blok hierboven wordt
    # NOOIT door deze catch gevangen (PowerShell behandelt 'exit' niet als
    # een throw), dus een normaal geoordeelde uitkomst (exitcode 0/1/2) komt
    # hier nooit terecht - alleen een ECHTE crash. Exitcode 1 is in dit
    # contract het woord voor een GEOORDEELDE weigering (upgrade_gate.py's
    # eigen docstring: "never exit 1 for a crash"), dus deze tak eindigt met
    # exitcode 3 - hetzelfde register als "Posh-SSH ontbreekt": de runner kon
    # zijn werk niet eens voltooien, en dat is geen fase-uitkomst.
    $boodschap = [string]$_.Exception.Message
    Log 'FOUT' ('onverwachte meetfout in fase ' + $Fase + ': ' + $boodschap)
    Log 'GEWEIGERD' ('geen oordeel gegeven: de meting van fase ' + $Fase + ' mislukte onverwacht')
    exit 3
}
finally {
    Close-GjkSshSession $sessie
}
