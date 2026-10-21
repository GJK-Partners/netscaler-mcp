<#
.SYNOPSIS
    KAPOT nep-transport voor tests/test_runner_script.py.
.DESCRIPTION
    De goede nep-transport (GjkUpgrade-NepTransport.ps1) laat exact EEN
    negatief scriptpad zien (een afwijkende hostsleutel). Dit bestand voegt
    er twee toe, zonder een appliance nodig te hebben:

      - New-GjkSshSession gooit een GENERIEKE verbindingsfout (geen
        hostsleutel-gerelateerd woord erin) wanneer -Vingerafdruk de sentinel
        'KAPOT-VERBINDING' is - dit toont aan dat een
        niet-hostsleutelfout NOOIT als "hostsleutel wijkt af" in het
        ledger mag komen.
      - Copy-GjkFile gooit ALTIJD een fout (een "mislukte SFTP-upload"),
        ongeacht de vingerafdruk, zodra de sessie wel opengaat - dit toont
        aan dat een onverwachte fout TIJDENS het meten (niet
        het sessie-openen) nooit stilzwijgend mag eindigen met exitcode 1.
      - Invoke-GjkSsh geeft exitcode -1 en lege
        stdout voor ELK commando - de vorm die de echte Invoke-GjkSsh ook
        gebruikt voor een genuine meetfout (geen throw, een METING).
#>
Set-StrictMode -Version Latest

$script:NepGoedeVingerafdruk = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
$script:NepGebruikersnaam = 'GJK-Test-Gebruiker'
$script:NepWachtwoord = 'TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a'

function _NepMarkeer {
    param([string] $Naam)
    if ([string]::IsNullOrWhiteSpace($env:GJK_TEST_MARKERDIR)) { return }
    if (-not (Test-Path -LiteralPath $env:GJK_TEST_MARKERDIR)) {
        New-Item -ItemType Directory -Path $env:GJK_TEST_MARKERDIR -Force | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $env:GJK_TEST_MARKERDIR $Naam) -Value 'x' -Encoding ASCII
}

function Get-GjkCredential {
    param([Parameter(Mandatory = $true)] [string] $Target)
    _NepMarkeer 'credential-gelezen.txt'
    $veilig = ConvertTo-SecureString $script:NepWachtwoord -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($script:NepGebruikersnaam, $veilig)
}

function New-GjkSshSession {
    param(
        [Parameter(Mandatory = $true)] [string] $Adres,
        [Parameter(Mandatory = $true)] [string] $Gebruiker,
        [Parameter(Mandatory = $true)] [string] $CredentialTarget,
        [Parameter(Mandatory = $true)] [string] $Vingerafdruk,
        [int] $TimeoutSec = 30
    )
    if ($Vingerafdruk -eq 'KAPOT-VERBINDING') {
        # GEEN hostsleutelwoord hierin - dit simuleert een doos die gewoon
        # niet reageert (time-out), niet een afwijkende sleutel.
        throw 'Verbinding time-out: kon geen route naar het nep-adres vinden (nep-kapot, geen hostsleutelfout)'
    }
    if ($Vingerafdruk -ne $script:NepGoedeVingerafdruk) {
        throw ('hostsleutel wijkt af: nep-doos bood ' + $script:NepGoedeVingerafdruk + ' aan, verwacht was ' + $Vingerafdruk + ' (untrusted)')
    }
    _NepMarkeer 'ssh-sessie-geopend.txt'
    return [pscustomobject]@{
        SSHSession       = $null
        Adres            = $Adres
        Gebruiker        = $Gebruiker
        CredentialTarget = $CredentialTarget
        Vingerafdruk     = $Vingerafdruk
    }
}

function Close-GjkSshSession {
    param($Sessie)
    _NepMarkeer 'ssh-sessie-gesloten.txt'
}

function Invoke-GjkSsh {
    param(
        [Parameter(Mandatory = $true)] $Sessie,
        [Parameter(Mandatory = $true)] [string] $Commando,
        [int] $TimeoutSec = 120
    )
    _NepMarkeer 'ssh-commando.txt'
    $t = Get-Date
    return [pscustomobject]@{
        commando = $Commando; exitcode = -1; stdout = ''; stderr = '(nep-kapot, geen uitvoer)'
        gestart = $t; geeindigd = (Get-Date); duurSec = 0.1
    }
}

function Copy-GjkFile {
    param(
        [Parameter(Mandatory = $true)] $Sessie,
        [Parameter(Mandatory = $true)] [string] $Bron,
        [Parameter(Mandatory = $true)] [string] $Doel,
        [int] $TimeoutSec = 600
    )
    _NepMarkeer 'sftp-upload.txt'
    throw 'Copy-GjkFile (nep-kapot): SFTP-upload mislukte onverwacht - dit is GEEN geoordeelde weigering'
}

function Wait-GjkTerug {
    param(
        [Parameter(Mandatory = $true)] [string] $Adres,
        [Parameter(Mandatory = $true)] [string] $Gebruiker,
        [Parameter(Mandatory = $true)] [string] $CredentialTarget,
        [Parameter(Mandatory = $true)] [string] $Vingerafdruk,
        [int] $TimeoutSec = 900,
        [int] $IntervalSec = 5
    )
    # Carried defect, since closed: 'vingerafdrukGemeten'
    # bestaat niet meer in het ECHTE transport (scripts/GjkUpgrade-Ssh.ps1,
    # Wait-GjkTerug) - zie GjkUpgrade-NepTransport.ps1 voor de volledige
    # reden. Deze nep-kapot-transport spiegelt het ECHTE object dus ook
    # zonder dat veld.
    _NepMarkeer 'wait-gjkterug.txt'
    return [pscustomobject]@{
        ok = $false; reden = 'SSH-auth kwam niet terug (nep-kapot)'; poort22Terug = (Get-Date); authTerug = $null
        versie = ''; vingerafdrukKomtOvereen = $false
    }
}
