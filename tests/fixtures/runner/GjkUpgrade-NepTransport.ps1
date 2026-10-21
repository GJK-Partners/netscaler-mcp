<#
.SYNOPSIS
    NEP-transport voor tests/test_runner_script.py - overschrijft de sessie-functies
    van scripts\GjkUpgrade-Ssh.ps1 zonder een echte SSH-verbinding te maken.
.DESCRIPTION
    Raakt Assert-GjkPoshSsh niet aan (die komt altijd uit de echte
    scripts\GjkUpgrade-Ssh.ps1 - Posh-SSH staat echt op deze werkbank). Dit bestand
    overschrijft sessie- en SFTP-functies. Commandometingen lopen door de
    ECHTE Invoke-GjkSsh-adapter, met een fake Invoke-SSHCommand die dezelfde
    Output-array, Error-string en ExitStatus geeft als Posh-SSH:
      - New-GjkSshSession vergelijkt -Vingerafdruk met een VASTE "juiste" waarde en
        gooit "hostsleutel wijkt af: ..." bij een verschil - exact het gedrag dat
        MUTATIEPROEF 9 (scriptkant) bewijst, zonder een appliance nodig te hebben.
      - Get-GjkCredential geeft een NEP-PSCredential terug met een HERKENBAAR
        testwachtwoord, zodat een test kan bewijzen dat het nooit op stdout of in
        het ledger belandt (GJK/Test/... naam, nooit een echte Credential
        Manager-target).
      - Elke aanroep schrijft, ALS $env:GJK_TEST_MARKERDIR gezet is, een leeg
        markeerbestand ("ssh-sessie-geopend.txt", "ssh-commando.txt", ...) zodat een
        test kan bewijzen dat er WEL of GEEN commando naar "de appliance" ging.
      - 'shell sha256 -q ...' antwoordt met
        $script:NepDoosSha, of - als $env:GJK_TEST_DOOS_SHA is gezet - met DIE
        waarde, zodat een test een afwijkende hash "op de doos" kan simuleren
        zonder de echte transportkant aan te raken. Copy-GjkFile schrijft er,
        ALS $env:GJK_TEST_MARKERDIR gezet is, ook het BRONBESTAND bij
        ("sftp-upload-bron.txt") zodat een test kan bewijzen WELK bestand
        echt is "geupload" - de kern van finding C2 (exacte naam, geen
        eerste treffer).
#>
Set-StrictMode -Version Latest

$script:NepGoedeVingerafdruk = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
$script:NepGebruikersnaam = 'GJK-Test-Gebruiker'
$script:NepWachtwoord = 'TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a'
# Moet letterlijk gelijk zijn aan NEP_DOOS_SHA in tests/test_runner_script.py
# (de vendorwaarde die _firmwaremap() daar in het .sha256-bestand schrijft).
$script:NepDoosSha = '1997e2585c3ea0e412f90b343c4e9d90f1f96d02f54cdbe9a024fb5c89e4fb22'

function _NepMarkeer {
    param([string] $Naam, [string] $Waarde = 'x')
    if ([string]::IsNullOrWhiteSpace($env:GJK_TEST_MARKERDIR)) { return }
    if (-not (Test-Path -LiteralPath $env:GJK_TEST_MARKERDIR)) {
        New-Item -ItemType Directory -Path $env:GJK_TEST_MARKERDIR -Force | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $env:GJK_TEST_MARKERDIR $Naam) -Value $Waarde -Encoding ASCII
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
    if ($Vingerafdruk -ne $script:NepGoedeVingerafdruk) {
        # De melding draagt hetzelfde Engelse trefwoord
        # ('untrusted') als een echte Posh-SSH -ErrorOnUntrusted-fout, zodat
        # deze nep-fout door _GjkIsHostsleutelfout (het transport) ECHT als
        # hostsleutelfout wordt herkend - net als de echte transportkant, en
        # niet alleen doordat de tekst toevallig met "hostsleutel wijkt af"
        # begint.
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

function Invoke-SSHCommand {
    param(
        $SSHSession, [string] $Command, [int] $TimeOut, $ErrorAction
    )
    $Commando = $Command
    _NepMarkeer 'ssh-commando.txt'
    if ($env:GJK_TEST_MARKERDIR) {
        Add-Content -LiteralPath (Join-Path $env:GJK_TEST_MARKERDIR 'commands.txt') -Value $Commando -Encoding ASCII
        if ($Commando -match 'mkdir|tar -xvzf|installns|shell reboot|save ns config') {
            Add-Content -LiteralPath (Join-Path $env:GJK_TEST_MARKERDIR 'writes.txt') -Value $Commando -Encoding ASCII
        }
    }
    # Captures the FULL command text for a
    # 'tar -xvzf' extraction (R2), the same way Copy-GjkFile below already
    # captures the SFTP upload's own source path ('sftp-upload-bron.txt') -
    # so a test can prove the exact bundle name reached the shell command,
    # never a wildcard.
    if ($Commando -like '*tar -xvzf*') {
        _NepMarkeer -Naam 'ssh-tar-commando.txt' -Waarde $Commando
    }
    $t = Get-Date
    $uit = ''
    if ($Commando -like '*show ha node*') {
        # secondary_gate() toetst voortaan ook
        # de IP van Node ID 0 tegen -Adres wanneer die is meegegeven (wat de
        # echte runner nu altijd doet) - draagt de nep-uitvoer geen 'IP:'
        # die met de standaard testadressen (127.0.0.1) overeenkomt, dan
        # wordt deze poort in elke R1/R5-test 'niet beoordeeld' in plaats
        # van 'open', ongeacht wat de test eigenlijk wil bewijzen.
        $uit = "Node ID: 0`n IP: 127.0.0.1`n Master State: Secondary`n"
    }
    elseif ($Commando -like '*df -k*') { $uit = "Filesystem  1K-blocks Used Avail Use% Mounted on`n/dev/x     10000000 100000 9000000  2% /var`n" }
    elseif ($Commando -like '*test ! -e*') { $uit = 'AFWEZIG' }
    elseif ($Commando -like '*shell cat /var/tmp/gjk_pre_check*') { $uit = '{"global_status":"SUCCESS","checks":[]}' }
    elseif ($Commando -like '*ls -la*') { $uit = "total 4`n-rw-r--r-- 1 root wheel 17 Sep 8 00:00 build-14.1-72.57_nc_64.tgz" }
    elseif ($Commando -like '*show ns runningConfig*') { $uit = "add lb vserver example SSL 192.0.2.1 443`nset ns param -timezone GMT" }
    elseif ($Commando -like '*show ns config*') {
        # Synthetisch, in de veldvormen van tests/fixtures/configstand: een
        # wijziging na de laatste opslag, zodat R1's driftpoort zonder
        # -DriftGeaccepteerd dicht blijft (de eerdere, puur menselijke poort
        # gedroeg zich in de tests net zo).
        $uit = "`tNode: Standalone`n`t      Last Config Changed Time: Sun Sep  6 10:50:08 2026`n`t        Last Config Saved Time: Sun Sep  6 10:49:58 2026`n`tConfig Changed since Last Saved Config: TRUE`n Done"
    }
    elseif ($Commando -like '*show ns version*') { $uit = 'NetScaler NS14.1: Build 72.57.nc, Date: Jan  1 2026, 00:00:00' }
    elseif ($Commando -like '*show system backup*') { $uit = 'Filename: backup_lab-02_20260906.tgz Level: full' }
    elseif ($Commando -like '*ls -1 /var/nsinstall*') { $uit = "14.1`n" }
    elseif ($Commando -like '*sha256*') {
        $waarde = if (-not [string]::IsNullOrWhiteSpace($env:GJK_TEST_DOOS_SHA)) { $env:GJK_TEST_DOOS_SHA } else { $script:NepDoosSha }
        $uit = $waarde + "`n"
    }
    elseif ($Commando -like '*.pre-check-supported*') { $uit = 'JA' }
    # Zoals de echte installns (gemeten op lab-02): de tijdmarkers gaan naar STDERR, stdout draagt de tekst.
    elseif ($Commando -like '*END_TIME*' -or $Commando -like '*installns -Y*') { $uit = 'Install started ... done.' }
    else { $uit = '(nep-uitvoer)' }
    $status = 0
    if ($env:GJK_TEST_RESPONSES) {
        $responses = Get-Content -LiteralPath $env:GJK_TEST_RESPONSES -Raw | ConvertFrom-Json
        foreach ($response in $responses) {
            if ($Commando.Contains([string]$response.match)) {
                $uit = [string]$response.stdout
                $status = [int]$response.exitcode
                break
            }
        }
    }
    return [pscustomobject]@{
        Output = [string[]]@($uit -replace '\n$' -split '\n')
        Error = $(if ($Commando -like '*installns -Y*') { 'installns: [1]: BEGIN_TIME 1 x' + "`n" + 'installns: [1]: END_TIME 2 y' } else { '' })
        ExitStatus = $status
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
    if ($env:GJK_TEST_MARKERDIR) { Add-Content -LiteralPath (Join-Path $env:GJK_TEST_MARKERDIR 'writes.txt') -Value 'SFTP upload' -Encoding ASCII }
    _NepMarkeer -Naam 'sftp-upload-bron.txt' -Waarde $Bron
    return [pscustomobject]@{ bron = $Bron; doel = $Doel; gestart = (Get-Date); geeindigd = (Get-Date); duurSec = 0.1 }
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
    # Wait-GjkTerug) - het droeg de VERWACHTE waarde ($Vingerafdruk, het
    # argument) onder een naam die 'gemeten' zei, een landmijn voor een lezer
    # die er een onafhankelijke meting in zou lezen. Deze nep-transport
    # spiegelt het ECHTE object dus zonder dat veld.
    _NepMarkeer 'wait-gjkterug.txt'
    if ($Vingerafdruk -ne $script:NepGoedeVingerafdruk) {
        return [pscustomobject]@{
            ok = $false; reden = 'hostsleutel wijkt af: nep-doos'; poort22Terug = (Get-Date); authTerug = $null
            versie = ''; vingerafdrukKomtOvereen = $false
        }
    }
    return [pscustomobject]@{
        ok = $true; reden = ''; poort22Terug = (Get-Date); authTerug = (Get-Date)
        versie = 'NetScaler NS14.1: Build 72.57.nc'; vingerafdrukKomtOvereen = $true
    }
}
