<#
.SYNOPSIS
    Toetst de INHOUD van een geinstalleerde Posh-SSH 3.2.7 tegen een gemeten sha256-manifest.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. Leest alleen; wijzigt niets en
    installeert niets.

    De pin in GjkUpgrade-Ssh.ps1 toetst de VERSIE van Posh-SSH, niet de
    inhoud of de herkomst. Dit script toetst de inhoud, met deze methode:
      1. elk bestand onder de modulemap, ook verborgen bestanden, BEHALVE
         PSGetModuleInfo.xml in de modulemap zelf (dat schrijft
         Install-Module bij elke installatie opnieuw: installatiepad en
         -tijdstip);
      2. per bestand de sha256 over de bytes op schijf, als kleine hex;
      3. het pad relatief aan de modulemap, met '/' als scheidingsteken,
         gesorteerd in ordinale volgorde (niet taalafhankelijk);
      4. per bestand een regel '<sha256>  <relatief pad>' (twee spaties);
      5. de manifestwaarde: de sha256 over die regels, elk afgesloten met
         LF, als UTF-8 zonder BOM.
    De waarde in $gemeten is zo gemeten over een Posh-SSH 3.2.7 uit de
    PowerShell Gallery (Install-Module -RequiredVersion 3.2.7).

    Zonder -Pad toetst het script elke geinstalleerde Posh-SSH 3.2.7 die
    Get-Module -ListAvailable vindt: Import-Module laadt de eerste op het
    modulepad, dus elke kopie telt.

    Uitvoer: per modulemap '[INFO]', dan ELKE manifestregel, dan
    '[MANIFEST] <waarde>' en '[OK]' of '[FOUT]'; tot slot '[EINDSTATUS]'.
    De volledige lijst staat altijd in de uitvoer, zodat een afwijking in een
    log te lezen is.

    Exitcodes: 0 elke kopie gelijk aan de gemeten waarde, 1 een kopie wijkt
    af (of de map is leeg), 3 Posh-SSH 3.2.7 niet gevonden of een
    onverwachte fout.
.PARAMETER Pad
    Een modulemap om te toetsen (de map met Posh-SSH.psd1). Leeg: elke
    geinstalleerde Posh-SSH 3.2.7.
.PARAMETER Verwacht
    Een andere verwachte manifestwaarde dan de gemeten waarde (64 hex). Voor
    tests; leeg: $gemeten.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $Pad = '',
    [string] $Verwacht = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The version the transport pins (GjkUpgrade-Ssh.ps1, $vereist) and the
# manifest value measured over that version from the PowerShell Gallery.
# tests/test_posh_ssh_manifest_script.py holds $versie to the transport's pin.
$versie = '3.2.7'
$gemeten = '0f92952a5d8e156c40c1831f8a9d4fe7e8c58252d9b40ff3bf6895ef29f3e3d1'

function Log { param([string]$Niveau, [string]$Boodschap) Write-Host ("[{0}] {1}" -f $Niveau, $Boodschap) }

# A path comes from disk: printed only as printable ASCII on one line, so a
# file name with a line break cannot form a line of its own in a log.
function _GjkVeiligeTekst {
    param([string] $Tekst)
    if ($null -eq $Tekst) { return '' }
    return [regex]::Replace($Tekst, '[^\x20-\x7E]', '?')
}

function _GjkSha256Hex {
    param([byte[]] $Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function _GjkSha256Bestand {
    param([string] $Bestand)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stroom = [System.IO.File]::Open($Bestand, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try { $digest = $sha.ComputeHash($stroom) } finally { $stroom.Dispose(); $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

# Returns @{ Regels = [string[]]; Waarde = [string] } for one module map.
function Get-GjkPoshSshManifest {
    param([Parameter(Mandatory = $true)] [string] $Modulemap)
    $basis = [System.IO.Path]::GetFullPath($Modulemap).TrimEnd('\')
    $paden = New-Object System.Collections.Generic.List[string]
    $volledig = @{}
    foreach ($item in @(Get-ChildItem -LiteralPath $basis -Recurse -Force | Where-Object { -not $_.PSIsContainer })) {
        $relatief = $item.FullName.Substring($basis.Length).TrimStart('\').Replace('\', '/')
        if ([string]::Equals($relatief, 'PSGetModuleInfo.xml', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $paden.Add($relatief)
        $volledig[$relatief] = $item.FullName
    }
    $gesorteerd = $paden.ToArray()
    [System.Array]::Sort($gesorteerd, [System.StringComparer]::Ordinal)
    $regels = New-Object System.Collections.Generic.List[string]
    $tekst = New-Object System.Text.StringBuilder
    foreach ($relatief in $gesorteerd) {
        $regel = (_GjkSha256Bestand -Bestand $volledig[$relatief]) + '  ' + $relatief
        $regels.Add($regel)
        $null = $tekst.Append($regel).Append("`n")
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    return @{ Regels = $regels.ToArray(); Waarde = (_GjkSha256Hex -Bytes $utf8.GetBytes($tekst.ToString())) }
}

try {
    $doel = $gemeten
    if (-not [string]::IsNullOrEmpty($Verwacht)) {
        if ($Verwacht -notmatch '\A[0-9a-f]{64}\z') {
            Log 'FOUT' '-Verwacht is geen sha256-waarde (64 kleine hex-tekens); geweigerd'
            exit 3
        }
        $doel = $Verwacht
    }

    $mappen = @()
    if (-not [string]::IsNullOrEmpty($Pad)) {
        if (-not (Test-Path -LiteralPath $Pad -PathType Container)) {
            Log 'FOUT' ('modulemap niet gevonden: ' + (_GjkVeiligeTekst $Pad))
            exit 3
        }
        $mappen = @($Pad)
    } else {
        $gevonden = @(Get-Module -ListAvailable -Name Posh-SSH | Where-Object { $_.Version -eq [version]$versie })
        if ($gevonden.Count -eq 0) {
            Log 'FOUT' ('Posh-SSH ontbreekt: versie ' + $versie + ' is niet gevonden')
            exit 3
        }
        $mappen = @($gevonden | ForEach-Object { $_.ModuleBase })
    }

    $afwijkend = 0
    foreach ($map in $mappen) {
        $manifest = Get-GjkPoshSshManifest -Modulemap $map
        Log 'INFO' ('Posh-SSH-manifest over ' + $manifest.Regels.Count + ' bestanden in ' + (_GjkVeiligeTekst $map) + ' (PSGetModuleInfo.xml uitgesloten)')
        foreach ($regel in $manifest.Regels) { Write-Host (_GjkVeiligeTekst $regel) }
        Log 'MANIFEST' $manifest.Waarde
        if ($manifest.Regels.Count -gt 0 -and $manifest.Waarde -eq $doel) {
            Log 'OK' ('manifest gelijk aan de gemeten waarde voor Posh-SSH ' + $versie)
        } else {
            Log 'FOUT' ('manifest wijkt af van de gemeten waarde voor Posh-SSH ' + $versie + ': verwacht ' + $doel + ', gemeten ' + $manifest.Waarde)
            $afwijkend++
        }
    }
    if ($afwijkend -gt 0) {
        Log 'EINDSTATUS' ('AFWIJKEND (' + $afwijkend + ' van ' + $mappen.Count + ')')
        exit 1
    }
    Log 'EINDSTATUS' ('GELIJK (' + $mappen.Count + ')')
    exit 0
} catch {
    Log 'FOUT' ('onverwachte fout: ' + (_GjkVeiligeTekst $_.Exception.Message))
    exit 3
}
