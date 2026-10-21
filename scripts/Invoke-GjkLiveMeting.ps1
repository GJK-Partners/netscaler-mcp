<#
.SYNOPSIS
    EEN live leesmeting over SSH voor de preflight: de vrije ruimte op /var.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. Leest alleen; wijzigt niets op de
    appliance en oordeelt nergens zelf. De server (nsmcp.preflight) leest de
    ENE regel '[VRIJ_MB] <geheel getal>' en toetst die tegen de vloeren.

    Volgorde:
      1. parameters lezen, ASCII-controle, verboden-adreslijst - VOOR er een
         transportbestand geladen wordt
      2. transport laden (scripts\GjkUpgrade-Ssh.ps1, zelfde als de runner),
         Assert-GjkPoshSsh; -Transport kan de sessiefuncties vervangen (een
         NEP-transport in de tests)
      3. sessie openen MET de gepinde hostsleutel (New-GjkSshSession)
      4. Get-GjkVrijeRuimteVar - dezelfde meting en parse als R1 van de runner
      5. '[VRIJ_MB] <n>' alleen bij een geslaagde meting met een getal;
         anders '[FOUT] <reden>' en exitcode 1. Nooit een getal zonder meting.
      6. sessie sluiten in een finally-blok

    Exitcodes: 0 gemeten, 1 niet gemeten of geweigerd, 3 onverwachte fout of
    Posh-SSH ontbreekt.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('vrije-ruimte')] [string] $Meting,
    [Parameter(Mandatory = $true)] [string] $Doel,
    [Parameter(Mandatory = $true)] [string] $Adres,
    [Parameter(Mandatory = $true)] [string] $Gebruiker,
    [Parameter(Mandatory = $true)] [string] $CredentialTarget,
    [Parameter(Mandatory = $true)] [string] $HostsleutelVingerafdruk,
    # Adresvormen van een voorgoed read-only doos, van de aanroeper
    # (configuratieveld handelen.verboden_adressen). Komma-gescheiden in EEN
    # argument: powershell.exe -File bindt maar een van twee losse waarden aan
    # een [string[]]-parameter.
    [string[]] $VerbodenAdressen = @(),
    [string] $Transport = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Zelfde vaste uitvoercodering als de runner: UTF-8 zonder BOM.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Log { param([string]$Niveau, [string]$Boodschap) Write-Host ("[{0}] {1}" -f $Niveau, $Boodschap) }

# Tekst die van buiten komt (een foutmelding, stderr van de appliance) gaat
# alleen als afdrukbare ASCII op EEN regel naar buiten, en begrensd: een
# regeleinde of stuurteken erin zou een eigen regel kunnen vormen.
function _GjkVeiligeTekst {
    param([string] $Tekst, [int] $Max = 200)
    if ($null -eq $Tekst) { return '' }
    $plat = [regex]::Replace($Tekst, '[^\x20-\x7E]', '?').Trim()
    if ($plat.Length -gt $Max) { $plat = $plat.Substring(0, $Max) + '...(afgekapt)' }
    return $plat
}

# ---------------------------------------------------------------------------
# ASCII-controle op elke argumentwaarde, zoals de runner. Fail closed: exit 1,
# geen transport geladen.
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
foreach ($p in @('Meting', 'Doel', 'Adres', 'Gebruiker', 'CredentialTarget', 'HostsleutelVingerafdruk', 'Transport')) {
    Assert-GjkAsciiWaarde -Naam $p -Waarde (Get-Variable -Name $p -ValueOnly)
}
foreach ($v in @($VerbodenAdressen)) { Assert-GjkAsciiWaarde -Naam 'VerbodenAdressen' -Waarde $v }

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
# Transport: hetzelfde bestand als de runner (gepinde hostsleutel, credential
# uit Windows Credential Manager, bannerfilter, de df-parse).
# ---------------------------------------------------------------------------
$eigenMap = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($eigenMap)) { $eigenMap = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $eigenMap 'GjkUpgrade-Ssh.ps1')
Assert-GjkPoshSsh
if (-not [string]::IsNullOrWhiteSpace($Transport)) {
    . $Transport
}

$sessie = $null
try {
    try {
        $sessie = New-GjkSshSession -Adres $Adres -Gebruiker $Gebruiker -CredentialTarget $CredentialTarget -Vingerafdruk $HostsleutelVingerafdruk -TimeoutSec 30
    }
    catch {
        Log 'FOUT' ('kon geen SSH-sessie openen: ' + (_GjkVeiligeTekst ([string]$_.Exception.Message)))
        Log 'EINDSTATUS' 'NIET GEMETEN: er is geen sessie geopend'
        exit 1
    }
    Log 'OK' 'SSH-sessie geopend met de gepinde hostsleutel'

    # Niet '$meting': PowerShell-variabelen zijn hoofdletterongevoelig en
    # '-Meting' draagt een ValidateSet.
    $ruimte = Get-GjkVrijeRuimteVar -Sessie $sessie
    if ($ruimte.exitcode -ne 0) {
        Log 'FOUT' ('df -k /var gaf exitcode ' + $ruimte.exitcode + ': ' + (_GjkVeiligeTekst ([string]$ruimte.stderr)))
        Log 'EINDSTATUS' 'NIET GEMETEN: df -k /var is niet geslaagd'
        exit 1
    }
    if ($null -eq $ruimte.vrijMb) {
        Log 'FOUT' 'df -k /var gaf geen leesbare regel met een geheel getal voor /var'
        Log 'EINDSTATUS' 'NIET GEMETEN: geen getal gelezen'
        exit 1
    }
    Write-Host ('[VRIJ_MB] ' + ([int64]$ruimte.vrijMb).ToString([System.Globalization.CultureInfo]::InvariantCulture))
    Log 'EINDSTATUS' 'GEMETEN: vrije ruimte op /var gelezen'
    exit 0
}
catch {
    Log 'FOUT' ('onverwachte meetfout: ' + (_GjkVeiligeTekst ([string]$_.Exception.Message)))
    Log 'EINDSTATUS' 'NIET GEMETEN: de meting mislukte onverwacht'
    exit 3
}
finally {
    Close-GjkSshSession $sessie
}
