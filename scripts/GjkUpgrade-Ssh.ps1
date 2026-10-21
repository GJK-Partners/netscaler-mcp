<#
.SYNOPSIS
    Het SSH/SFTP-transport voor de upgraderunner: PINNED hostsleutel, Posh-SSH 3.2.7.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. Dot-source dit bestand (of een vervanger via
    Invoke-GjkUpgradeFase.ps1's -Transport - zie scripts\README.md).

    ZEVEN verantwoordelijkheden, en niet meer dan deze:
      Assert-GjkPoshSsh      - is de module er?
      Get-GjkCredential      - PSCredential uit Windows Credential Manager
      New-GjkSshSession      - sessie openen MET vingerafdrukcontrole
      Invoke-GjkSsh          - een commando, met exitcode/stdout/stderr terug
      Get-GjkVrijeRuimteVar  - vrije ruimte op /var (df -k), de ene meetplek
      Copy-GjkFile           - SFTP-upload
      Wait-GjkTerug          - poort 22, dan SSH-AUTH, na een reboot
    Plus een klein, symmetrisch opruimhulpje: Close-GjkSshSession (Remove-SSHSession),
    zodat de aanroeper een sessie kan sluiten zonder Posh-SSH's eigen cmdlet-naam te
    hoeven kennen.

    DE HOSTSLEUTEL WORDT GEPIND, NOOIT GEACCEPTEERD.
    De optie die Posh-SSH's New-SSHSession/New-SFTPSession een NIEUWE, nog onbekende
    sleutel automatisch laat vertrouwen komt in dit bestand niet voor, en de optie die
    ELKE hostsleutelcontrole uitschakelt ook niet. In plaats daarvan zet dit bestand de
    VERWACHTE vingerafdruk zelf in Posh-SSH's eigen known-hosts-opslag (New-SSHTrustedHost)
    voordat er verbonden wordt, en verbindt daarna met -ErrorOnUntrusted: Posh-SSH
    vergelijkt de ECHT aangeboden sleutel met wat hier net is gezet, en weigert de
    verbinding als ze verschillen. Dat is dezelfde strictheid als een ssh_known_hosts-
    bestand dat een afwijkende sleutel altijd weigert - er is hier geen instelling die
    dat afzwakt.

    Waarom Posh-SSH en niet de OpenSSH-client van Windows: de NetScaler doet
    wachtwoordauthenticatie en ssh.exe/scp.exe kunnen een wachtwoord niet
    niet-interactief aannemen (gemeten op het lab). Posh-SSH neemt een PSCredential
    aan en levert SFTP in hetzelfde model.

    Het wachtwoord komt uit Windows Credential Manager, blijft in het geheugen van deze
    sessie en verlaat Get-GjkCredential nooit als platte tekst. In uitvoer, ledger en
    logregels staat uitsluitend de TARGETNAAM - nooit het wachtwoord zelf.

    GEVERIFIEERD (tegen lab-02, 203.0.113.11):
    dit bestand zet -HostKeyName niet mee bij New-SSHTrustedHost (Posh-SSH accepteert
    dat: de waarde valt terug op een lege tekst) en dat laat de vergelijking tijdens
    het echt verbinden ongemoeid - een sessie opent op de juiste gepinde vingerafdruk
    en wordt geweigerd op een verkeerde, allebei tegen de echte appliance, met een
    read-only 'show ns version' als bewijs voor de geslaagde kant. Dit was tot nu toe
    een ONGEVERIFIEERDE AANNAME (dat bestand raakte toen bewust geen
    echte appliance aan); dit is de eerste keer dat dit tegen een echte
    doos liep.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
Set-StrictMode -Version Latest

# SR-6 (1.0.2): de INHOUD van Posh-SSH 3.2.7, niet alleen de versie. Dezelfde
# methode en dezelfde gemeten waarde als scripts\Get-GjkPoshSshManifest.ps1
# ($gemeten daar); tests\test_runner_script.py houdt de twee waarden gelijk.
$script:GjkPoshSshManifestGemeten = '0f92952a5d8e156c40c1831f8a9d4fe7e8c58252d9b40ff3bf6895ef29f3e3d1'

function _GjkPoshSshManifest {
    <#  De manifestwaarde van een modulemap: elk bestand (ook verborgen) behalve
        PSGetModuleInfo.xml in de map zelf, sha256 per bestand, relatief pad met
        '/', ordinaal gesorteerd, regels '<sha256>  <pad>' met LF, en de sha256
        over die regels als UTF-8 zonder BOM. Leeg bij een lege map. #>
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
    if ($paden.Count -eq 0) { return '' }
    $gesorteerd = $paden.ToArray()
    [System.Array]::Sort($gesorteerd, [System.StringComparer]::Ordinal)
    $tekst = New-Object System.Text.StringBuilder
    foreach ($relatief in $gesorteerd) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $stroom = [System.IO.File]::Open($volledig[$relatief], [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try { $digest = $sha.ComputeHash($stroom) } finally { $stroom.Dispose(); $sha.Dispose() }
        $hex = ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        $null = $tekst.Append($hex + '  ' + $relatief).Append("`n")
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($utf8.GetBytes($tekst.ToString())) } finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function _GjkToetsPoshSshInhoud {
    <#  [FOUT] en exit 3 als een van de gegeven modulemappen niet de gemeten
        inhoud van Posh-SSH 3.2.7 draagt. Noemt alleen de versie en de twee
        waarden, nooit een pad uit het gebruikersprofiel. #>
    param([string[]] $Mappen)
    foreach ($map in $Mappen) {
        $waarde = ''
        try { $waarde = _GjkPoshSshManifest -Modulemap $map } catch { $waarde = '' }
        if ($waarde -ne $script:GjkPoshSshManifestGemeten) {
            Write-Host ('[FOUT] de inhoud van Posh-SSH 3.2.7 wijkt af van het gemeten manifest (verwacht ' + $script:GjkPoshSshManifestGemeten + ', gemeten ' + $(if ($waarde) { $waarde } else { 'niet te berekenen' }) + '); dit transport laadt deze module niet')
            exit 3
        }
    }
}

function Assert-GjkPoshSsh {
    <#  Laadt PRECIES Posh-SSH 3.2.7: de versie waartegen de hostsleutelpin
        hieronder gemeten is (New-SSHMemoryKnownHost, -KnownHost,
        -ErrorOnUntrusted). Op naam laden koos de eerste of hoogste versie in
        het modulepad, en een al geladen module van elke versie ging door
        (gemeten met een nep-module 9.9.9). Ontbreekt 3.2.7, of is er al een
        andere versie geladen: [FOUT] en exit 3.
        Sinds 1.0.2 (SR-6) ook de INHOUD: elke kopie van 3.2.7 die geladen is
        of op het modulepad staat (Import-Module laadt de eerste) moet het
        gemeten manifest dragen; anders [FOUT] en exit 3, voor er iets laadt.
        Deze functie installeert NIETS - dat is niet het werk van de runner. #>
    $vereist = '3.2.7'
    $geladen = @(Get-Module -Name 'Posh-SSH')
    if ($geladen.Count -gt 0) {
        $anders = @($geladen | Where-Object { $_.Version -ne [version]$vereist })
        if ($anders.Count -gt 0) {
            Write-Host ('[FOUT] Posh-SSH ' + (($anders | ForEach-Object { $_.Version.ToString() }) -join ', ') + ' is al geladen; dit transport vraagt precies Posh-SSH ' + $vereist)
            exit 3
        }
        _GjkToetsPoshSshInhoud -Mappen @($geladen | ForEach-Object { $_.ModuleBase })
        return
    }
    $kopieen = @(Get-Module -ListAvailable -Name 'Posh-SSH' | Where-Object { $_.Version -eq [version]$vereist })
    if ($kopieen.Count -eq 0) {
        Write-Host ('[FOUT] Posh-SSH ontbreekt: versie ' + $vereist + ' is niet gevonden')
        exit 3
    }
    _GjkToetsPoshSshInhoud -Mappen @($kopieen | ForEach-Object { $_.ModuleBase })
    Import-Module -Name 'Posh-SSH' -RequiredVersion $vereist -ErrorAction Stop | Out-Null
}

function Get-GjkCredential {
    <#  Haalt gebruikersnaam en wachtwoord uit Windows Credential Manager op de
        TARGETNAAM en levert een PSCredential. Het wachtwoord verlaat deze functie
        NOOIT als platte tekst: het wordt hier meteen in een SecureString gezet en
        de platte kopie wordt losgelaten voordat de functie teruggeeft. #>
    param([Parameter(Mandatory = $true)] [string] $Target)

    if (-not ([System.Management.Automation.PSTypeName]'GjkUpgradeCredLezer').Type) {
        Add-Type -Namespace '' -Name 'GjkUpgradeCredLezer' -MemberDefinition @'
            [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool CredRead(string target, int type, int flags, out IntPtr credential);
            [DllImport("advapi32.dll")] public static extern bool CredFree(IntPtr cred);
            [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
                public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
'@ -ErrorAction Stop
    }

    $ptr = [IntPtr]::Zero
    if (-not [GjkUpgradeCredLezer]::CredRead($Target, 1, 0, [ref]$ptr)) {
        throw ("Credential-target '" + $Target + "' niet gevonden in Windows Credential Manager van deze gebruiker.")
    }
    try {
        $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type]'GjkUpgradeCredLezer+CREDENTIAL')
        $gebruikersnaam = [string]$cred.UserName
        $veilig = New-Object System.Security.SecureString
        if ($cred.CredentialBlobSize -gt 0) {
            $platteTekst = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, $cred.CredentialBlobSize / 2)
            foreach ($teken in $platteTekst.ToCharArray()) { $veilig.AppendChar($teken) }
            # Dit overschrijft de plaintext NIET in het geheugen - .NET
            # strings zijn immutable, dus de vermenigvuldiging hierboven bindt een NIEUWE
            # string aan deze variabele en de ORIGINELE platte tekst blijft op de managed
            # heap staan tot de garbage collector hem opruimt (geen vaste termijn). Er is
            # in standaard PowerShell/.NET geen ondersteunde manier om de backing-array
            # van een levende System.String in-place te overschrijven zonder unsafe/pinned
            # geheugentrucs, die hier meer risico toevoegen dan ze oplossen. Dit is dus
            # BEST-EFFORT opruiming van de REFERENTIE (de variabele wijst niet meer naar de
            # platte tekst), geen garantie dat de bytes zelf weg zijn - en de SecureString
            # hierboven beschermt uitsluitend de kopie die er NU in staat.
            $platteTekst = $null
        }
        $veilig.MakeReadOnly()
        if ([string]::IsNullOrWhiteSpace($gebruikersnaam)) {
            throw ("Credential-target '" + $Target + "' heeft geen gebruikersnaam.")
        }
        return New-Object System.Management.Automation.PSCredential($gebruikersnaam, $veilig)
    }
    finally {
        [GjkUpgradeCredLezer]::CredFree($ptr) | Out-Null
    }
}

function _GjkPinHostsleutel {
    <#  INTERN. Bouwt een IN-GEHEUGEN known-hosts-opslag (New-SSHMemoryKnownHost)
        met UITSLUITEND de VERWACHTE vingerafdruk voor dit adres erin - geen
        gemeten waarde, alleen wat is meegegeven - en geeft die opslag terug.
        De aanroeper geeft haar mee aan New-SSHSession/New-SFTPSession via
        -KnownHost, zodat -ErrorOnUntrusted tegen DEZE opslag vergelijkt.

        Een latere fix: deze functie schreef
        eerder RECHTSTREEKS in de OPERATOR'S GLOBALE known-hosts-opslag
        (New-SSHTrustedHost zonder -KnownHostStore schrijft in
        ~/.poshssh/hosts.json) - een Remove+New tegen een bestand van de
        operator, op ELKE verbinding, ook al gaat het deze runner niets aan.
        Met een verse in-geheugen opslag per verbinding (New-SSHMemoryKnownHost
        + -KnownHostStore hier, -KnownHost bij het echte verbinden) raakt deze
        functie dat bestand niet meer aan: de opslag bestaat alleen zolang de
        aanroepende functie de teruggegeven waarde vasthoudt. #>
    param([Parameter(Mandatory = $true)] [string] $Adres, [Parameter(Mandatory = $true)] [string] $Vingerafdruk)
    $opslag = New-SSHMemoryKnownHost
    New-SSHTrustedHost -HostName $Adres -FingerPrint $Vingerafdruk -KnownHostStore $opslag -ErrorAction Stop | Out-Null
    return $opslag
}

function _GjkIsHostsleutelfout {
    <#  INTERN. Is deze fout een AFWIJKENDE HOSTSLEUTEL (in plaats van een
        netwerkfout/timeout)? Posh-SSH is een compiled cmdlet zonder eigen
        foutcode voor dit geval, dus dit is een tekstmatch op de Engelse melding
        die -ErrorOnUntrusted geeft. Bij twijfel (de tekst matcht niet): FALSE, en
        de aanroeper behandelt het dan als een gewone verbindingsfout - nooit
        andersom, want een fout die WEL een hostsleutelfout is maar hier niet
        herkend wordt, moet nog steeds hard stoppen bij New-GjkSshSession (die
        nergens een nieuwe sleutel automatisch vertrouwt en dus so wie so geen
        sessie oplevert). #>
    param([string] $Boodschap)
    if ([string]::IsNullOrWhiteSpace($Boodschap)) { return $false }
    $laag = $Boodschap.ToLowerInvariant()
    # 'trusted' is met opzet NIET apart getoetst: elke
    # tekst die 'untrusted' bevat bevat het woord 'trusted' ook al, dus die
    # tweede toets was altijd overbodig naast de eerste.
    #
    # 'key exchange negotiation failed':
    # SSH.NET gooit exact deze tekst wanneer CanTrust false teruggeeft na
    # -ErrorOnUntrusted - de vorm waarin een afwijkende hostsleutel zich in
    # de praktijk meldt, niet 'untrusted'/'fingerprint'/'known host'.
    # EERLIJK GEZEGD is deze detector daarmee BREDER dan strikt correct:
    # SSH.NET gebruikt dezelfde tekst ook voor een PUUR algoritme-
    # onderhandelingsfalen (geen gedeeld kex/cipher/mac-algoritme), dat niets
    # met de hostsleutel te maken heeft. Dat is een bewuste, benoemde
    # afweging: bij twijfel liever te vaak 'hostsleutel wijkt af' melden dan
    # een echte mismatch laten wegvallen naar 'niet beoordeeld' (zie
    # hostkey_session_gate in upgrade.py) - precisie die dit bestand niet
    # claimt te hebben.
    return ($laag.Contains('untrusted') -or $laag.Contains('fingerprint') -or $laag.Contains('known host') `
        -or $laag.Contains('key exchange negotiation failed'))
}

function _GjkIsOndubbelzinnigeHostsleutelfout {
    <#  INTERN. Dezelfde tekstmatch als
        _GjkIsHostsleutelfout hierboven, maar ZONDER de 'key exchange
        negotiation failed'-tak - die tak is, zoals _GjkIsHostsleutelfout's
        eigen commentaar al eerlijk toegeeft, BREDER dan strikt correct: SSH.NET
        gooit exact diezelfde tekst ook voor een PUUR algoritme-
        onderhandelingsfalen, dat niets met de hostsleutel te maken heeft - en
        dat is precies wat een net gerebootte appliance kan geven terwijl sshd
        nog opstart, ruim voor de gebruikelijke algoritmeset weer beschikbaar
        is.

        Deze functie bestaat voor Wait-GjkTerug's hervat-lus (na een reboot,
        R4): die lus mag op de AMBIGUE tekst niet meteen stoppen (dat was de
        bug), maar moet nog steeds METEEN stoppen op een tekst die ondubbelzinnig
        een afwijkende hostsleutel betekent. New-GjkSshSession zelf blijft de
        BREDE _GjkIsHostsleutelfout gebruiken: daar is er geen hervat-lus die
        de kans krijgt op te klaren, dus geldt nog steeds "bij twijfel liever
        te vaak melden dan een echte mismatch missen". #>
    param([string] $Boodschap)
    if ([string]::IsNullOrWhiteSpace($Boodschap)) { return $false }
    $laag = $Boodschap.ToLowerInvariant()
    return ($laag.Contains('untrusted') -or $laag.Contains('fingerprint') -or $laag.Contains('known host'))
}

function New-GjkSshSession {
    <#  Opent een SSH-sessie MET vingerafdrukcontrole. Geen optie die een nieuwe
        sleutel automatisch vertrouwt en geen optie die de hostsleutelcontrole
        uitschakelt komt hier voor: de vingerafdruk wordt EERST gepind
        (_GjkPinHostsleutel) en pas DAARNA wordt verbonden, met -ErrorOnUntrusted. Wijkt de aangeboden
        sleutel af, dan gooit dit een fout MET de tekst "hostsleutel wijkt af" erin
        en is er GEEN sessie - de aanroeper mag dat nooit als een sessie behandelen. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Adres,
        [Parameter(Mandatory = $true)] [string] $Gebruiker,
        [Parameter(Mandatory = $true)] [string] $CredentialTarget,
        [Parameter(Mandatory = $true)] [string] $Vingerafdruk,
        [int] $TimeoutSec = 30
    )
    if ([string]::IsNullOrWhiteSpace($Vingerafdruk)) {
        throw 'hostsleutel wijkt af: geen gepinde vingerafdruk meegegeven'
    }
    $cred = Get-GjkCredential -Target $CredentialTarget
    $sshCred = New-Object System.Management.Automation.PSCredential($Gebruiker, $cred.Password)
    $opslag = _GjkPinHostsleutel -Adres $Adres -Vingerafdruk $Vingerafdruk
    try {
        $ssh = New-SSHSession -ComputerName $Adres -Credential $sshCred -ConnectionTimeout $TimeoutSec -KnownHost $opslag -ErrorOnUntrusted -ErrorAction Stop
    }
    catch {
        $boodschap = [string]$_.Exception.Message
        if (_GjkIsHostsleutelfout $boodschap) {
            throw ('hostsleutel wijkt af: ' + $boodschap)
        }
        throw
    }
    return [pscustomobject]@{
        SSHSession       = $ssh
        Adres            = $Adres
        Gebruiker        = $Gebruiker
        CredentialTarget = $CredentialTarget
        Vingerafdruk     = $Vingerafdruk
    }
}

function Close-GjkSshSession {
    <#  Sluit een sessie van New-GjkSshSession. Best-effort: een sessie die al weg
        is (bijvoorbeeld na 'shell reboot') mag hier geen fout geven. #>
    param($Sessie)
    if ($null -eq $Sessie) { return }
    try { Remove-SSHSession -SSHSession $Sessie.SSHSession -ErrorAction SilentlyContinue | Out-Null } catch { }
}

# Gemeten op lab-02 (8-9-2026): de appliance zet voor ELKE shell-uitvoer een waarschuwingsblok
# ('Warning: [' ... ']' gevolgd door ' Done'). Dat is vendorruis, geen meting: het wordt hier aan
# de transportgrens verwijderd zodat poorten en bewijs alleen de uitvoer van het commando dragen.
function _GjkZonderBanner {
    param([string] $Tekst)
    # Only the MEASURED RPC warning is transport decoration (lab-02, 8-9-2026:
    # 'Warning: [ One or more RPC nodes are configured with default passwords.
    # For enhanced security, you must change the default RPC node password. ]'
    # and then ' Done'). Anchored on the first sentence, tolerant up to the
    # closing bracket: the second sentence has been seen with and without line
    # breaks. Any OTHER warning remains command output, including its closing
    # bracket and Done lines.
    $patroon = '(?s)\AWarning:\s*\[\s*One or more RPC nodes are configured with default passwords\..*?\](?:\r?\n[ \t]*Done[ \t]*)?(?:\r?\n|\z)'
    $banner = [regex]::Match($Tekst, $patroon)
    if (-not $banner.Success) { return $Tekst }
    return $Tekst.Substring($banner.Length)
}

function Invoke-GjkSsh {
    <#  Voert EEN commando uit en geeft ALTIJD een object terug - een niet-nul
        exitstatus is een METING, geen uitzondering: sommige commando's (reboot)
        verbreken de sessie voordat er een status komt, en de drie gemeten feiten
        in de taakopdracht zeggen dat de exitstatus van 'shell reboot' en van
        './installns --pre_check' NIETS betekenen. Deze functie oordeelt daar
        niet over - ze meet en geeft door. #>
    param(
        [Parameter(Mandatory = $true)] $Sessie,
        [Parameter(Mandatory = $true)] [string] $Commando,
        [int] $TimeoutSec = 120
    )
    $t0 = Get-Date
    $uit = ''
    $fout = ''
    $status = -1
    try {
        $r = Invoke-SSHCommand -SSHSession $Sessie.SSHSession -Command $Commando -TimeOut $TimeoutSec -ErrorAction Stop
        $uit = _GjkZonderBanner (@($r.Output) -join "`n")
        $fout = [string]$r.Error
        $status = [int]$r.ExitStatus
    }
    catch {
        $fout = [string]$_.Exception.Message
        $status = -1
    }
    $t1 = Get-Date
    return [pscustomobject]@{
        commando  = $Commando
        exitcode  = $status
        stdout    = $uit
        stderr    = $fout
        gestart   = $t0
        geeindigd = $t1
        duurSec   = [math]::Round(($t1 - $t0).TotalSeconds, 1)
    }
}

function Get-GjkVrijeRuimteVar {
    <#  Meet de vrije ruimte op /var met 'shell df -k /var' in een geopende
        sessie. DE ENE meetplek: de runner (R1) en het losse leesscript
        (Invoke-GjkLiveMeting.ps1) roepen allebei deze functie aan, zodat er
        een parse bestaat en niet twee.

        Oordeelt niet: geeft een object terug met vrijMb (een geheel getal in
        MB, of $null als er geen bruikbaar getal was), de exitcode en stderr
        van het commando, en de df-regel waar het getal uit kwam. Een
        niet-nul exitcode levert nooit een getal op: de uitvoer van een
        mislukt commando is geen meting. #>
    param([Parameter(Mandatory = $true)] $Sessie)
    $df = Invoke-GjkSsh -Sessie $Sessie -Commando 'shell df -k /var' -TimeoutSec 60
    $vrijMb = $null
    $gevondenRegel = ''
    $uitvoer = ''
    if ($df.exitcode -eq 0 -and $null -ne $df.stdout) { $uitvoer = [string]$df.stdout }
    foreach ($regel in ($uitvoer -split "`r?`n")) {
        if ($regel -match '/var\s*$' -or $regel -match '/var\b') {
            $delen = @($regel -split '\s+' | Where-Object { $_ -ne '' })
            if ($delen.Count -ge 4) {
                $kb = [int64]0
                if ([int64]::TryParse($delen[3], [ref]$kb)) {
                    $vrijMb = [int64][math]::Round($kb / 1024)
                    $gevondenRegel = $regel
                }
            }
        }
    }
    return [pscustomobject]@{
        vrijMb   = $vrijMb
        exitcode = $df.exitcode
        stderr   = [string]$df.stderr
        regel    = $gevondenRegel
    }
}

function Copy-GjkFile {
    <#  SFTP-upload van EEN lokaal bestand naar een remote map. Posh-SSH gebruikt
        voor SFTP een EIGEN sessietype (SftpSession, niet SSHSession), dus deze
        functie opent er zelf een - MET dezelfde vingerafdrukcontrole als
        New-GjkSshSession, nooit een automatisch vertrouwde nieuwe sleutel - en sluit hem weer in een
        finally-blok. $Sessie is het object dat New-GjkSshSession teruggeeft: het
        draagt genoeg (Adres/Gebruiker/CredentialTarget/Vingerafdruk) om een eigen
        SFTP-sessie te openen zonder de aanroeper opnieuw te laten kiezen. #>
    param(
        [Parameter(Mandatory = $true)] $Sessie,
        [Parameter(Mandatory = $true)] [string] $Bron,
        [Parameter(Mandatory = $true)] [string] $Doel,
        [int] $TimeoutSec = 600
    )
    if (-not (Test-Path -LiteralPath $Bron -PathType Leaf)) {
        throw ('Copy-GjkFile: bronbestand niet gevonden: ' + $Bron)
    }
    $cred = Get-GjkCredential -Target $Sessie.CredentialTarget
    $sftpCred = New-Object System.Management.Automation.PSCredential($Sessie.Gebruiker, $cred.Password)
    $opslag = _GjkPinHostsleutel -Adres $Sessie.Adres -Vingerafdruk $Sessie.Vingerafdruk
    $sftp = $null
    try {
        try {
            $sftp = New-SFTPSession -ComputerName $Sessie.Adres -Credential $sftpCred -ConnectionTimeout 30 -OperationTimeout $TimeoutSec -KnownHost $opslag -ErrorOnUntrusted -ErrorAction Stop
        }
        catch {
            $boodschap = [string]$_.Exception.Message
            if (_GjkIsHostsleutelfout $boodschap) { throw ('hostsleutel wijkt af: ' + $boodschap) }
            throw
        }
        $t0 = Get-Date
        Set-SFTPItem -SFTPSession $sftp -Path $Bron -Destination $Doel -Force -ErrorAction Stop
        $t1 = Get-Date
        return [pscustomobject]@{ bron = $Bron; doel = $Doel; gestart = $t0; geeindigd = $t1; duurSec = [math]::Round(($t1 - $t0).TotalSeconds, 1) }
    }
    finally {
        if ($null -ne $sftp) { try { Remove-SFTPSession -SFTPSession $sftp -ErrorAction SilentlyContinue | Out-Null } catch { } }
    }
}

function Wait-GjkTerug {
    <#  Wacht na een reboot EERST op TCP-poort 22, en DAARNA op een
        GEAUTHENTICEERDE 'show ns version' - poort 22 is geen bewijs (lab-meting
        post-reboot-ssh-auth-readiness; gemeten in de spike: poort terug na 66 s,
        auth pas na 76 s). Elke poging pint de vingerafdruk opnieuw (nooit
        aannemen dat hij gelijk bleef): wijkt hij af, dan stopt deze functie
        METEEN met een fout - geen waarschuwing die doorloopt met de nieuw
        aangeboden sleutel (dat was het openstaande punt van de spike; dit
        ontwerp sluit het, besluit 2).

        WAT DIT TERUGGEEFT, en wat NIET: het veld
        'vingerafdrukGemeten' bestaat niet meer. Het droeg de VERWACHTE
        waarde ($Vingerafdruk, het argument) onder een naam die 'gemeten'
        zei - dood voor de aanroeper van vandaag, maar een landmijn voor
        later werk dat er een onafhankelijke meting in zou lezen. Deze
        functie MEET geen vingerafdruk: ze laat Posh-SSH's -ErrorOnUntrusted
        de aangeboden sleutel tegen de gepinde vergelijken en stelt daarmee
        vast OF die verbinding tot stand kwam. Dat feit staat in
        'vingerafdrukKomtOvereen', en de reden bij een mislukking in 'reden'
        (met het voorvoegsel 'hostsleutel wijkt af' als het daar echt om
        ging). Wie een echte, onafhankelijk gemeten bytewaarde nodig heeft
        moet die alsnog bouwen - hier staat er geen. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Adres,
        [Parameter(Mandatory = $true)] [string] $Gebruiker,
        [Parameter(Mandatory = $true)] [string] $CredentialTarget,
        [Parameter(Mandatory = $true)] [string] $Vingerafdruk,
        [int] $TimeoutSec = 900,
        [int] $IntervalSec = 5
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $poort22Terug = $null
    while ((Get-Date) -lt $deadline) {
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $c.BeginConnect($Adres, 22, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(2000, $false)) {
                $c.EndConnect($iar)
                $poort22Terug = Get-Date
                break
            }
        }
        catch { }
        finally { try { $c.Close() } catch { } }
        Start-Sleep -Seconds $IntervalSec
    }
    if ($null -eq $poort22Terug) {
        return [pscustomobject]@{ ok = $false; reden = 'poort 22 kwam niet terug'; poort22Terug = $null; authTerug = $null; versie = ''; vingerafdrukKomtOvereen = $false }
    }

    # De auth-lus kreeg voorheen het RESTANT van dezelfde
    # deadline als de poort-22-lus. Kwam poort 22 vlak voor die deadline
    # terug, dan draaide de auth-lus NUL keer en las de melding hierboven
    # "Laatste fout: " (leeg) - faalt veilig, maar meldt niets bruikbaars.
    # De auth-fase krijgt daarom een EIGEN, VERSE termijn van $TimeoutSec
    # vanaf het moment dat poort 22 terug was, ongeacht hoe lang dat wachten
    # al duurde.
    $authDeadline = (Get-Date).AddSeconds($TimeoutSec)
    $laatsteFout = ''
    while ((Get-Date) -lt $authDeadline) {
        try {
            $sessie = New-GjkSshSession -Adres $Adres -Gebruiker $Gebruiker -CredentialTarget $CredentialTarget -Vingerafdruk $Vingerafdruk -TimeoutSec 15
            try {
                $r = Invoke-GjkSsh -Sessie $sessie -Commando 'show ns version' -TimeoutSec 30
                if ($r.exitcode -eq 0 -and -not [string]::IsNullOrWhiteSpace($r.stdout)) {
                    return [pscustomobject]@{
                        ok = $true; reden = ''; poort22Terug = $poort22Terug; authTerug = (Get-Date)
                        versie = $r.stdout.Trim(); vingerafdrukKomtOvereen = $true
                    }
                }
                $laatsteFout = 'show ns version exit ' + $r.exitcode
            }
            finally { Close-GjkSshSession $sessie }
        }
        catch {
            $laatsteFout = [string]$_.Exception.Message
            if (_GjkIsOndubbelzinnigeHostsleutelfout $laatsteFout) {
                # Decision 2: geen waarschuwing die doorloopt. De vingerafdruk is
                # NA de reboot opnieuw gemeten en wijkt ONDUBBELZINNIG af - dit
                # stopt meteen.
                return [pscustomobject]@{
                    ok = $false; reden = $laatsteFout; poort22Terug = $poort22Terug; authTerug = $null
                    versie = ''; vingerafdrukKomtOvereen = $false
                }
            }
            # Een latere fix: een tekst die ALLEEN via de brede
            # 'key exchange negotiation failed'-tak van _GjkIsHostsleutelfout
            # als hostsleutelfout gold (of helemaal geen hostsleutelfout is)
            # stopt deze lus NIET meer meteen - dat kon een puur, voorbijgaand
            # algoritme-onderhandelingsfalen zijn, precies wat sshd van een net
            # gerebootte appliance geeft terwijl het nog opstart. $laatsteFout
            # blijft staan, zodat de reden - als dit tot de deadline aanhoudt -
            # alsnog in het uiteindelijke antwoord verschijnt (hieronder).
        }
        Start-Sleep -Seconds $IntervalSec
    }
    if ([string]::IsNullOrWhiteSpace($laatsteFout)) {
        # Met de eigen auth-deadline hierboven
        # loopt de lus normaliter minstens een keer, maar een pathologisch
        # kleine -TimeoutSec/-IntervalSec kan hem nog steeds nul keer laten
        # draaien - dan is een duidelijke tekst beter dan "Laatste fout: ".
        $laatsteFout = 'geen enkele auth-poging is voltooid binnen het tijdvenster'
    }
    if (_GjkIsHostsleutelfout $laatsteFout) {
        # Een latere fix: de lus hierboven liet de AMBIGUE 'key
        # exchange negotiation failed'-tekst nu wel doorlopen (nooit meer
        # meteen stoppen erop), maar als die tekst tot aan de EIGEN
        # auth-deadline is blijven terugkomen, telt dat alsnog als een
        # hostsleutelfout - een puur, voorbijgaand algoritme-
        # onderhandelingsfalen hoort allang verdwenen te zijn ruim binnen
        # $TimeoutSec seconden. 'hostsleutel wijkt af' vooraan houdt
        # Invoke-GjkUpgradeFase.ps1's eigen "-like 'hostsleutel wijkt af*'"
        # toets kloppend - dezelfde brede _GjkIsHostsleutelfout hier gebruikt
        # omdat een ONDUBBELZINNIGE tekst dit punt nooit bereikt (de lus
        # hierboven stopte daar al meteen op).
        return [pscustomobject]@{
            ok = $false
            reden = (
                'hostsleutel wijkt af: dit bleef ' + $TimeoutSec + ' s optreden na de reboot (' +
                $laatsteFout + ')'
            )
            poort22Terug = $poort22Terug; authTerug = $null; versie = ''; vingerafdrukKomtOvereen = $false
        }
    }
    return [pscustomobject]@{
        ok = $false; reden = ('SSH-auth kwam niet terug binnen ' + $TimeoutSec + ' s. Laatste fout: ' + $laatsteFout)
        poort22Terug = $poort22Terug; authTerug = $null; versie = ''; vingerafdrukKomtOvereen = $false
    }
}
