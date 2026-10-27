<#
.SYNOPSIS
    Laat de NetScaler de draaiende configuratie opslaan (save ns config), over SSH,
    na een rolcontrole, en drukt de ruwe teruglezing (show ns config) af.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. De schrijfroute van config_opslaan, met het
    transport van de faserunner (scripts\GjkUpgrade-Ssh.ps1: gepinde hostsleutel,
    credential uit Windows Credential Manager, bannerfilter).

    Dit script OORDEELT NERGENS ZELF:
      - de rol komt uit 'python -m nsmcp.upgrade_measure' (actie 'vorm', verzoek
        'rol-voor-opslaan'); alleen de uitkomst 'open' leidt tot save ns config;
      - de teruglezing beoordeelt het serverproces (nsmcp.backup.save_readback_ok)
        uit de [METING]-regels die dit script afdrukt.

    Volgorde:
      1. parameters lezen, ASCII-controle, verboden-adreslijst - VOOR er een
         transportbestand geladen wordt (ook bij -WatIs)
      2. een echte aanroep zonder -Actieid wordt geweigerd
      3. transport laden, Assert-GjkPoshSsh, [TARGET] afdrukken
      4. -WatIs: afdrukken wat dit ZOU doen en stoppen - geen sessie
      5. sessie openen MET de gepinde hostsleutel
      6. show ha node -> upgrade_measure (rol-voor-opslaan) -> alleen bij 'open' verder
      7. [ACTIEID] vlak voor de schrijfactie, dan save ns config
      8. show ns config, regel voor regel als '[METING] show ns config: <regel>'
         (begrensd), en een regel '[METINGSTATUS] show ns config: exitcode=<n>'
      9. [EINDSTATUS]; sessie sluiten in een finally-blok

    Alles wat van de appliance komt, gaat alleen als afdrukbare ASCII achter een
    eigen voorvoegsel naar buiten: een regeleinde of stuurteken in die tekst kan
    zo nooit een eigen regel vormen die op een [METING]- of [ACTIEID]-regel lijkt.

    Exitcodes: 0 opgeslagen en teruggelezen (het oordeel volgt in de server),
    1 geweigerd of niets gedaan, 3 onverwachte fout of Posh-SSH ontbreekt.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)] [string] $Doel,
    [Parameter(Mandatory = $true)] [string] $Adres,
    [Parameter(Mandatory = $true)] [string] $Gebruiker,
    [Parameter(Mandatory = $true)] [string] $CredentialTarget,
    [Parameter(Mandatory = $true)] [string] $HostsleutelVingerafdruk,
    [Parameter(Mandatory = $true)] [string] $GatePython,
    # Adresvormen van een voorgoed read-only doos, van de aanroeper
    # (configuratieveld handelen.verboden_adressen). Komma-gescheiden in EEN
    # argument: powershell.exe -File bindt maar een van twee losse waarden aan
    # een [string[]]-parameter.
    [string[]] $VerbodenAdressen = @(),
    [string] $Actieid = '',
    [string] $Transport = '',
    [switch] $WatIs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Zelfde vaste codering als de runner voor wat naar de Python-brug gaat:
# UTF-8 zonder BOM.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Log { param([string]$Niveau, [string]$Boodschap) Write-Host ("[{0}] {1}" -f $Niveau, $Boodschap) }

# Tekst van buiten (appliance, foutmelding) op EEN regel, alleen afdrukbare ASCII,
# begrensd. Een tab wordt een spatie; elk ander stuurteken (ook een losse CR) en
# elk niet-ASCII teken een vraagteken.
function _GjkVeiligeTekst {
    param($Tekst, [int] $Max = 200)
    if ($null -eq $Tekst) { return '' }
    $plat = ([string]$Tekst).Replace("`t", ' ')
    $plat = [regex]::Replace($plat, '[^\x20-\x7E]', '?')
    if ($plat.Length -gt $Max) { $plat = $plat.Substring(0, $Max) + '...(afgekapt)' }
    return $plat
}

# ---------------------------------------------------------------------------
# ASCII-controle, zoals de runner. Fail closed: exit 1, geen transport geladen.
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
foreach ($p in @('Doel', 'Adres', 'Gebruiker', 'CredentialTarget', 'HostsleutelVingerafdruk', 'GatePython', 'Actieid', 'Transport')) {
    Assert-GjkAsciiWaarde -Naam $p -Waarde (Get-Variable -Name $p -ValueOnly)
}
foreach ($v in @($VerbodenAdressen)) { Assert-GjkAsciiWaarde -Naam 'VerbodenAdressen' -Waarde $v }

# ---------------------------------------------------------------------------
# -Doel en -Adres staan in het [TARGET]-etiket, zoals bij de runner: geen CR,
# LF, tab of ander stuurteken (0 tot en met 31, en 127), anders zou een waarde
# een eigen markeerregel kunnen afdrukken. Fail closed: exit 1, niet herhaald.
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
foreach ($p in @('Doel', 'Adres')) {
    Assert-GjkGeenStuurteken -Naam $p -Waarde (Get-Variable -Name $p -ValueOnly)
}

# ---------------------------------------------------------------------------
# Verboden-adreslijst, dezelfde normalisatie als de runner: getrimd,
# hoofdletterongevoelig, 'gebruiker@' en ':poort' eraf, afsluitende punt eraf,
# en van een NAAM ook het eerste DNS-label. Een vangnet tegen de voor de hand
# liggende schrijfwijzen, geen aliasresolutie (geen DNS-lookup hier).
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
# Een echte aanroep draagt het actie-id dat de server vormde; het script
# herhaalt het vlak voor de schrijfactie. Zonder, of in een andere vorm:
# geweigerd voordat er iets geladen is.
# ---------------------------------------------------------------------------
if (-not $WatIs) {
    if ([string]::IsNullOrWhiteSpace($Actieid)) {
        Log 'FOUT' '-Actieid ontbreekt op een echte aanroep'
        Log 'GEWEIGERD' 'geef -Actieid mee (of gebruik -WatIs voor een voorstel); er is niets opgeslagen'
        exit 1
    }
    if ($Actieid -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') {
        Log 'FOUT' '-Actieid heeft niet de vorm van een actie-id'
        Log 'GEWEIGERD' '-Actieid mag alleen letters, cijfers, punt, streepje en underscore dragen'
        exit 1
    }
}

$eigenMap = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($eigenMap)) { $eigenMap = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $eigenMap 'GjkUpgrade-Ssh.ps1')
Assert-GjkPoshSsh

# Het etiket waaraan de bevestigingscode wordt gebonden: bij het voorstel en bij
# de echte run gelijk, zonder tijdstempel.
Write-Host ('[TARGET] nsconfig/' + $Doel + ' (' + $Adres + ') - config opslaan')

if ($WatIs) {
    Write-Host ('[OK] zou doen: save ns config op ' + $Doel + ' na een rolcontrole')
    Write-Host '[EINDSTATUS] WAT-IS: er is niets gewijzigd'
    exit 0
}

if (-not [string]::IsNullOrWhiteSpace($Transport)) {
    . $Transport
}

function _GjkAanroepPython {
    param([Parameter(Mandatory = $true)] [string] $Module, [Parameter(Mandatory = $true)] [string] $JsonIn)
    # 1.1: stderr door een pijp (2>&1), niet via een tijdelijk bestand op
    # naam, en 'Continue' alleen binnen deze functie: onder 'Stop' maakt
    # Windows PowerShell 5.1 van de eerste stderr-regel van een native kind
    # een afbrekende fout (gemeten) - een onschuldige waarschuwing van de brug
    # blokkeerde zo de opslag met "onverwachte fout". Dezelfde functie als de
    # faserunner.
    $ErrorActionPreference = 'Continue'
    $alles = @($JsonIn | & $GatePython -I -m $Module 2>&1)
    $code = $LASTEXITCODE
    $uit = @($alles | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { [string]$_ })
    $fout = @($alles | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() })
    return [pscustomobject]@{ Stdout = ($uit -join [Environment]::NewLine); Stderr = ($fout -join [Environment]::NewLine); ExitCode = $code }
}

$sessie = $null
$saveGegeven = $false
try {
    try {
        $sessie = New-GjkSshSession -Adres $Adres -Gebruiker $Gebruiker -CredentialTarget $CredentialTarget -Vingerafdruk $HostsleutelVingerafdruk -TimeoutSec 30
    }
    catch {
        Log 'FOUT' ('kon geen SSH-sessie openen: ' + (_GjkVeiligeTekst $_.Exception.Message))
        Log 'EINDSTATUS' 'NIET UITGEVOERD: er is geen sessie geopend en niets opgeslagen'
        exit 1
    }
    Log 'OK' 'SSH-sessie geopend met de gepinde hostsleutel'

    # Rolcontrole: de oordeelshelft beslist, dit script leest alleen 'open'.
    $ha = Invoke-GjkSsh -Sessie $sessie -Commando 'show ha node' -TimeoutSec 60
    $verzoek = @{
        soort = 'rol-voor-opslaan'; ha_node_uitvoer = [string]$ha.stdout; doel_adres = $Adres
        exitcode = [int]$ha.exitcode; stderr = [string]$ha.stderr
    }
    $vormJson = (@{ actie = 'vorm'; verzoeken = @($verzoek) } | ConvertTo-Json -Depth 6 -Compress)
    $vormUit = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn $vormJson
    if ($vormUit.ExitCode -ne 0) { throw ('upgrade_measure (vorm) gaf exitcode ' + $vormUit.ExitCode + ': ' + $vormUit.Stderr) }
    $poorten = @(($vormUit.Stdout | ConvertFrom-Json).poort)
    if ($poorten.Count -ne 1) { throw 'upgrade_measure gaf niet precies een rolpoort terug' }
    $rol = $poorten[0]
    Write-Host ('[ROL] ' + (_GjkVeiligeTekst $rol.uitkomst 40) + ': ' + (_GjkVeiligeTekst $rol.bewijs 300))
    if ([string]$rol.uitkomst -cne 'open') {
        Log 'GEWEIGERD' (_GjkVeiligeTekst $rol.reden 300)
        Log 'EINDSTATUS' 'GEWEIGERD: niet opgeslagen (rolcontrole)'
        exit 1
    }

    # De schrijfactie. De exitstatus van een CLI-commando over SSH is geen
    # bewijs; de teruglezing hieronder is dat wel, en die beoordeelt de server.
    Write-Host ('[ACTIEID] ' + $Actieid)
    $saveGegeven = $true
    $save = Invoke-GjkSsh -Sessie $sessie -Commando 'save ns config' -TimeoutSec 120
    Write-Host ('[SAVE] save ns config: exitcode=' + $save.exitcode)
    $saveRegels = @(([string]$save.stdout) -split "`n")
    foreach ($regel in ($saveRegels | Select-Object -First 20)) {
        Write-Host ('[SAVE] save ns config: ' + (_GjkVeiligeTekst ([string]$regel).TrimEnd("`r")))
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$save.stderr)) {
        Write-Host ('[SAVE] save ns config stderr: ' + (_GjkVeiligeTekst $save.stderr))
    }

    # De teruglezing, in dezelfde sessie, direct na het opslaan: ruw en begrensd.
    $config = Invoke-GjkSsh -Sessie $sessie -Commando 'show ns config' -TimeoutSec 60
    $maxRegels = 60
    $configRegels = @(([string]$config.stdout) -split "`n")
    foreach ($regel in ($configRegels | Select-Object -First $maxRegels)) {
        Write-Host ('[METING] show ns config: ' + (_GjkVeiligeTekst ([string]$regel).TrimEnd("`r")))
    }
    if ($configRegels.Count -gt $maxRegels) {
        Write-Host ('[METING-AFGEKAPT] show ns config: ' + ($configRegels.Count - $maxRegels) + ' regels niet getoond')
    }
    Write-Host ('[METINGSTATUS] show ns config: exitcode=' + $config.exitcode)
    Log 'EINDSTATUS' 'OPGESLAGEN: save ns config gegeven; de teruglezing beoordeelt de server'
    exit 0
}
catch {
    Log 'FOUT' ('onverwachte fout: ' + (_GjkVeiligeTekst $_.Exception.Message))
    if ($saveGegeven) {
        Log 'EINDSTATUS' 'NIET VASTGESTELD: save ns config is gegeven maar de teruglezing liep mis; lees de stand terug'
    }
    else {
        Log 'EINDSTATUS' 'NIET UITGEVOERD: er is niets opgeslagen'
    }
    exit 3
}
finally {
    Close-GjkSshSession $sessie
}
