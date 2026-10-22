#requires -Version 5.1
<#
Read-only local snapshot, indicators dated 2026-10-22. NOT a safety verdict.
Only writes new report files. No network requests, chain building, private-key
access, certificate changes, updates, or policy changes. No external modules.
Sources: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
https://emudhra.we-have-a-problem.com/impacted-intermediates.json
https://emudhra.we-have-a-problem.com/roots.json
#>
[CmdletBinding()]
param([string]$OutputDirectory = (Get-Location).Path, [switch]$SkipHttpSys)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run on Windows using Windows PowerShell 5.1.' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run with Windows PowerShell 5.1 (powershell.exe), not PowerShell Core.'
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    throw 'Use 64-bit Windows PowerShell to avoid registry and executable redirection.'
}
function Assert-LocalDirectory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\') { throw 'Choose a local output directory, not a UNC or device path.' }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable, [IO.DriveType]::Ram)) {
        throw 'Choose a local output directory, not a network or unavailable drive.'
    }
    # Check each ancestor before visiting its child; never traverse a junction.
    $cursor = [IO.Path]::GetPathRoot($full)
    foreach ($part in @('') + @($full.Substring($cursor.Length).Split('\') | Where-Object { $_ })) {
        if ($part) { $cursor = Join-Path $cursor $part }
        $item = Get-Item -LiteralPath $cursor -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Output directory must exist locally without junctions or symbolic links.'
        }
    }
    return $full
}
$base = Assert-LocalDirectory $OutputDirectory
$issues = New-Object 'System.Collections.Generic.List[object]'
$certs = New-Object 'System.Collections.Generic.List[object]'
$stores = New-Object 'System.Collections.Generic.List[object]'
function Add-Issue($Scope, $Problem) { $issues.Add([pscustomobject]@{ Scope=$Scope; Problem=$Problem }) }
function Get-HexHash([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-', '') } finally { $h.Dispose() }
}
function Read-DerElement([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) { throw 'DER header bounds.' }
    $start=$Offset; $tag=[int]$Bytes[$Offset]; $Offset++; $length=[long]$Bytes[$Offset]; $Offset++
    if ($length -ge 128) {
        $n=[int]($length -band 127)
        if ($n -lt 1 -or $n -gt 4 -or $Offset+$n -gt $Bytes.Length) { throw 'DER length invalid.' }
        $length=0
        for ($i=0; $i -lt $n; $i++) { $length=($length*256)+$Bytes[$Offset]; $Offset++ }
    }
    $end=$Offset+$length
    if ($end -gt $Bytes.Length) { throw 'DER content bounds.' }
    return [pscustomobject]@{ Tag=$tag; Start=$start; Content=$Offset; End=[int]$end }
}
function Get-SpkiHash([byte[]]$Der) {
    $outer=Read-DerElement $Der 0; $tbs=Read-DerElement $Der $outer.Content
    if ($outer.Tag -ne 48 -or $tbs.Tag -ne 48 -or $outer.End -ne $Der.Length -or $tbs.End -gt $outer.End) { throw 'Not an X.509 sequence.' }
    $pos=$tbs.Content; $first=Read-DerElement $Der $pos
    if ($first.End -gt $tbs.End) { throw 'Version bounds invalid.' }
    if ($first.Tag -eq 160) { $pos=$first.End } # optional explicit version
    for ($i=0; $i -lt 5; $i++) {
        $e=Read-DerElement $Der $pos
        if ($e.End -gt $tbs.End) { throw 'TBS field bounds invalid.' }; $pos=$e.End
    }
    $spki=Read-DerElement $Der $pos
    if ($spki.Tag -ne 48 -or $spki.End -gt $tbs.End) { throw 'SPKI bounds invalid.' }
    [byte[]]$bytes=$Der[$spki.Start..($spki.End-1)]
    return Get-HexHash $bytes
}
$indicatorText = @'
EM DV TLS CA - G3B|42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493|EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105
EM DV TLS CA - G3B|45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE|EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105
EM OV TLS CA - G3B|98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B|43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B
EM OV TLS CA - G3B|5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699|43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B
EM EV TLS CA - G3B|E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838|E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41
EM EV TLS CA - G3B|579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512|E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41
EM DV TLS CA - G3C|0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19|49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F
EM DV TLS CA - G3C|62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72|49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F
EM OV TLS CA - G3C|CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F|63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8
EM OV TLS CA - G3C|7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489|63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8
EM EV TLS CA - G3C|432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3|5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0
EM EV TLS CA - G3C|FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F|5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0
EM OV CS CA - G3B|9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4|EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6
EM OV CS CA - G3B|A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8|EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6
EM OV CS CA - G3C|4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1|92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30
EM OV CS CA - G3C|84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD|92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30
'@
$byCert=@{}; $byKey=@{}
foreach ($line in ($indicatorText -split '\r?\n')) {
    $v=$line.Split('|'); $byCert[$v[1]]=$v[0]; $byKey[$v[2]]=$v[0]
}
$rootText = @'
emSign Root TLS CA - G3|7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D
emSign Root CS CA - G3|F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5
AAA Certificate Services|D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
emSign ECC Root CA - G3|86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
'@
$knownRoots=@{}
foreach ($line in ($rootText -split '\r?\n')) { $v=$line.Split('|'); $knownRoots[$v[1]]=$v[0] }

# Stop before scanning if a future edit corrupts the indicator snapshot.
if ($byCert.Count -ne 16 -or $byKey.Count -ne 8 -or $knownRoots.Count -ne 4) { throw 'Unexpected indicator counts.' }
foreach ($hash in @($byCert.Keys) + @($byKey.Keys) + @($knownRoots.Keys)) {
    if ($hash -cnotmatch '^[0-9A-F]{64}$') { throw 'Malformed SHA-256 indicator.' }
}
$namePattern = '(?i)(emudhra|emsign|\bEM\s+(DV|OV|EV)\s+(TLS|CS)\s+CA\b)'

function Get-CertificateRecord($Certificate, [string]$Location, [string]$StoreName) {
    $derHash = Get-HexHash $Certificate.RawData
    $spkiHash = $null; $spkiError = $null
    try { $spkiHash = Get-SpkiHash $Certificate.RawData }
    catch { $spkiError = $_.Exception.Message; Add-Issue ($Location + '\' + $StoreName + '\' + $Certificate.Thumbprint) ('SPKI: ' + $spkiError) }
    $matchKinds = New-Object 'System.Collections.Generic.List[string]'
    $labels = New-Object 'System.Collections.Generic.List[string]'
    if ($byCert.ContainsKey($derHash)) { $matchKinds.Add('ExactCompromisedCertificate'); $labels.Add($byCert[$derHash]) }
    if ($spkiHash -and $byKey.ContainsKey($spkiHash)) { $matchKinds.Add('CompromisedPublicKey'); $labels.Add($byKey[$spkiHash]) }
    if ($knownRoots.ContainsKey($derHash)) { $matchKinds.Add('KnownRelatedRootNotProofOfCompromise'); $labels.Add($knownRoots[$derHash]) }
    if ($matchKinds.Count -eq 0 -and ($Certificate.Subject -match $namePattern -or $Certificate.Issuer -match $namePattern)) {
        $matchKinds.Add('NameOnlyNeedsChainReview')
    }
    # Never serialize the X509Certificate2 object: no raw certificate or key fields.
    [pscustomobject][ordered]@{
        Location=$Location; Store=$StoreName; InDisallowed=($StoreName -eq 'Disallowed')
        Subject=$Certificate.Subject; Issuer=$Certificate.Issuer; SerialNumber=$Certificate.SerialNumber
        NotBeforeUtc=$Certificate.NotBefore.ToUniversalTime().ToString('o')
        NotAfterUtc=$Certificate.NotAfter.ToUniversalTime().ToString('o')
        ThumbprintSHA1=$Certificate.Thumbprint; CertificateSHA256=$derHash; SpkiSHA256=$spkiHash
        SpkiParseError=$spkiError; Matches=$matchKinds.ToArray(); IndicatorNames=@($labels.ToArray() | Select-Object -Unique)
    }
}

$started = [DateTime]::UtcNow
foreach ($location in @('CurrentUser', 'LocalMachine')) {
    foreach ($storeName in @('Root', 'CA', 'Disallowed', 'My', 'WebHosting', 'TrustedPeople', 'TrustedPublisher')) {
        $store = $null; $status = 'Read'; $count = 0; $processed = 0; $problem = $null
        try {
            $store = [Security.Cryptography.X509Certificates.X509Store]::new($storeName, [Security.Cryptography.X509Certificates.StoreLocation]$location)
            $flags = [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::IncludeArchived
            $store.Open($flags)
            $collection = $store.Certificates
            $count = $collection.Count
            foreach ($certificate in $collection) {
                try { $certs.Add((Get-CertificateRecord $certificate $location $storeName)); $processed++ }
                catch { $status = 'Partial'; Add-Issue ($location + '\' + $storeName) ('Certificate read failed: ' + $_.Exception.Message) }
                finally { $certificate.Dispose() }
            }
        } catch {
            $status = 'MissingOrInaccessible'; $problem = $_.Exception.Message
            Add-Issue ($location + '\' + $storeName) $problem
        } finally { if ($null -ne $store) { $store.Close(); $store.Dispose() } }
        $stores.Add([pscustomobject]@{Location=$location; Store=$storeName; Status=$status; EnumeratedCount=$count; RecordedCount=$processed; Problem=$problem})
    }
}

function Get-RedactedRootUrl($Value) {
    # A custom URL might contain credentials or query tokens. Do not report them.
    try {
        $uri = [Uri]::new([string]$Value, [UriKind]::Absolute)
        if ($uri.Scheme -notin @('http','https','file')) { return '<configured; unsupported scheme omitted>' }
        $builder = [UriBuilder]::new($uri)
        $builder.UserName=''; $builder.Password=''; $builder.Query=''; $builder.Fragment=''
        return $builder.Uri.AbsoluteUri
    } catch { return '<configured; unparseable value omitted>' }
}

function Read-TrustRegistry([string]$Path, [string[]]$Names, [string[]]$PresenceOnly) {
    $root = $null; $key = $null; $values = New-Object 'System.Collections.Generic.List[object]'
    $status='Read'; $problem=$null
    try {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $root.OpenSubKey($Path, $false)
        if ($null -eq $key) { $status='Missing' }
        $presentNames = @(); if ($null -ne $key) { $presentNames = @($key.GetValueNames()) }
        foreach ($name in $Names) {
            $present = $presentNames -contains $name
            $kind=$null; $value=$null
            if ($present) {
                $kind=$key.GetValueKind($name).ToString()
                if ($PresenceOnly -notcontains $name) {
                    $value=$key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ($name -eq 'RootDirUrl') { $value=Get-RedactedRootUrl $value }
                    elseif ($kind -ne 'DWord') { $value='<unexpected registry type; value omitted>' }
                }
            }
            $values.Add([pscustomobject]@{Name=$name; Present=$present; Kind=$kind; Value=$value; PresenceOnly=($PresenceOnly -contains $name)})
        }
    } catch { $status='Inaccessible'; $problem=$_.Exception.Message; Add-Issue ('HKLM\'+$Path) $problem }
    finally { if ($null -ne $key) { $key.Dispose() }; if ($null -ne $root) { $root.Dispose() } }
    [pscustomobject]@{Path=('HKLM\'+$Path); View='Registry64'; Status=$status; Values=$values.ToArray(); Problem=$problem}
}
$trust = @(
    Read-TrustRegistry 'SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' @('DisableRootAutoUpdate','EnableDisallowedCertAutoUpdate') @()
    Read-TrustRegistry 'SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate' @('RootDirUrl','EncodedCtl','DisallowedCertEncodedCtl','LastSyncTime','DisallowedCertLastSyncTime') @('EncodedCtl','DisallowedCertEncodedCtl','LastSyncTime','DisallowedCertLastSyncTime')
)

$servicePattern='(?i)(memoq|emudhra|emsign|apache|nginx|tomcat|java|node|openssl|^W3SVC$|^WAS$|^HTTP$|^CryptSvc$|^wuauserv$|^WinHttpAutoProxySvc$)'
$services=@(); $serviceStatus='Read'
try {
    $services=@(Get-Service | Where-Object { $_.Name -match $servicePattern -or $_.DisplayName -match $servicePattern } | ForEach-Object {
        [pscustomobject]@{Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.Status.ToString()}
    })
} catch { $serviceStatus='Inaccessible'; Add-Issue 'Local services' $_.Exception.Message }

$software = New-Object 'System.Collections.Generic.List[object]'
$softwareCoverage = New-Object 'System.Collections.Generic.List[object]'
$softwarePattern='(?i)(memoq|emudhra|emsign|python|java|jdk|jre|openjdk|temurin|corretto|zulu|node\.?(js)?\b|\bgit\b|openssl|apache|nginx|tomcat|\.net|chrome|chromium|firefox|microsoft edge|internet information|\bIIS\b|\bcurl\b|\bPHP\b|\bRuby\b)'
foreach ($hive in @('LocalMachine','CurrentUser')) {
    foreach ($view in @('Registry64','Registry32')) {
        $root=$null; $key=$null; $status='Read'; $readCount=0; $matchedCount=0
        $path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        try {
            $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$hive, [Microsoft.Win32.RegistryView]$view)
            $key=$root.OpenSubKey($path, $false)
            if ($null -eq $key) { $status='Missing' }
            else {
                foreach ($childName in $key.GetSubKeyNames()) {
                    $child=$null
                    try {
                        $child=$key.OpenSubKey($childName, $false)
                        if ($null -eq $child) { throw 'Uninstall entry disappeared or could not be opened.' }
                        $readCount++
                        $name=[string]$child.GetValue('DisplayName', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        if ($name -notmatch $softwarePattern) { continue }
                        $software.Add([pscustomobject]@{
                            Hive=$hive; View=$view; DisplayName=$name
                            DisplayVersion=[string]$child.GetValue('DisplayVersion', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            Publisher=[string]$child.GetValue('Publisher', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        }); $matchedCount++
                    } catch { $status='Partial'; Add-Issue ($hive+'\'+$view+'\Uninstall\'+$childName) $_.Exception.Message }
                    finally { if ($null -ne $child) { $child.Dispose() } }
                }
            }
        } catch { $status='Inaccessible'; Add-Issue ($hive+'\'+$view+'\Uninstall') $_.Exception.Message }
        finally { if ($null -ne $key) { $key.Dispose() }; if ($null -ne $root) { $root.Dispose() } }
        $softwareCoverage.Add([pscustomobject]@{Hive=$hive; View=$view; Status=$status; EntriesRead=$readCount; MatchedEntries=$matchedCount})
    }
}

function Read-HttpSys {
    $result=[ordered]@{Status='Skipped'; Command=$null; ExitCode=$null; OutputEncoding=$null; ErrorEncoding=$null; Stdout=''; Stderr=''; StdoutBytesBase64=''; StderrBytesBase64=''; Problem=$null}
    if ($SkipHttpSys) { return [pscustomobject]$result }
    $process=$null; $outBytes=$null; $errBytes=$null
    try {
        $exe=Join-Path ([Environment]::GetFolderPath('System')) 'netsh.exe'
        $result.Command=$exe+' http show sslcert'
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName=$exe; $info.Arguments='http show sslcert'; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
        if (-not $process.Start()) { throw 'Could not start the system netsh.exe.' }
        $outBytes=[IO.MemoryStream]::new(); $errBytes=[IO.MemoryStream]::new()
        $stdout=$process.StandardOutput.BaseStream.CopyToAsync($outBytes)
        $stderr=$process.StandardError.BaseStream.CopyToAsync($errBytes)
        if (-not $process.WaitForExit(30000)) {
            # Only stop the child netsh process started here, never a service.
            $process.Kill(); $null=$process.WaitForExit(5000)
            throw 'HTTP.sys read timed out after 30 seconds.'
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'netsh output capture timed out.' }
        # Preserve exact bytes. SSH/console code page can differ from the locale OEM code page.
        $rawOut=$outBytes.ToArray(); $rawErr=$errBytes.ToArray()
        $result.StdoutBytesBase64=[Convert]::ToBase64String($rawOut)
        $result.StderrBytesBase64=[Convert]::ToBase64String($rawErr)
        $strictUtf8=[Text.UTF8Encoding]::new($false,$true)
        $fallback=[Console]::OutputEncoding
        try { $result.Stdout=$strictUtf8.GetString($rawOut); $result.OutputEncoding='utf-8' }
        catch { $result.Stdout=$fallback.GetString($rawOut); $result.OutputEncoding=$fallback.WebName }
        try { $result.Stderr=$strictUtf8.GetString($rawErr); $result.ErrorEncoding='utf-8' }
        catch { $result.Stderr=$fallback.GetString($rawErr); $result.ErrorEncoding=$fallback.WebName }
        $result.ExitCode=$process.ExitCode
        if ($process.ExitCode -ne 0) { throw ('netsh exited with code '+$process.ExitCode) }
        $result.Status='Read'
    } catch { $result.Status='Failed'; $result.Problem=$_.Exception.Message; Add-Issue 'HTTP.sys' $result.Problem }
    finally { if ($null -ne $process) { $process.Dispose() }; if ($null -ne $outBytes) { $outBytes.Dispose() }; if ($null -ne $errBytes) { $errBytes.Dispose() } }
    [pscustomobject]$result
}
$httpSys=Read-HttpSys

$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$sourceHash=$null
try { $sourceHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash }
catch { Add-Issue 'Script hash' $_.Exception.Message }
$entries=$certs.ToArray()
$compromised=@($entries | Where-Object { $_.Matches -contains 'ExactCompromisedCertificate' -or $_.Matches -contains 'CompromisedPublicKey' })
$summary=[ordered]@{
    CertificateEntries=$entries.Count; StoresRequested=$stores.Count
    StoresRead=@($stores.ToArray() | Where-Object { $_.Status -eq 'Read' }).Count
    ExactCompromisedCertificate=@($entries | Where-Object { $_.Matches -contains 'ExactCompromisedCertificate' }).Count
    CompromisedPublicKey=@($entries | Where-Object { $_.Matches -contains 'CompromisedPublicKey' }).Count
    CompromisedEntries=$compromised.Count
    CompromisedEntriesOutsideDisallowed=@($compromised | Where-Object { -not $_.InDisallowed }).Count
    KnownRelatedRootNotProofOfCompromise=@($entries | Where-Object { $_.Matches -contains 'KnownRelatedRootNotProofOfCompromise' }).Count
    NameOnlyNeedsChainReview=@($entries | Where-Object { $_.Matches -contains 'NameOnlyNeedsChainReview' }).Count
    CoverageIssueCount=$issues.Count
}
$limitations=@(
    'A local inventory only. Zero matches are NOT proof of safety. No certificate chain or revocation validation was performed.'
    'Counts are store entries, not unique certificates or keys. Logical stores can inherit entries. Exact and SPKI match counts can overlap.'
    'A related root or name match does not prove compromise, a signature relationship, trust, or active use.'
    'CurrentUser covers only this process identity, not other users or service identities.'
    'Disallowed applies to the reported certificate entry; it does not prove all same-key paths and applications are blocked.'
    'Policy values and cached CTL presence do not prove successful updates, freshness, revocation or application enforcement. CTLs were not decoded.'
    'No Java keystores, application CA bundles, containers, other user profiles, portable tools or centralized certificate stores were searched.'
    'HTTP.sys is not an inventory of every TLS listener. Installed software versions are clues, not patch verification.'
    'Reports contain operational information. Redact internal domains, names, addresses, ports and software versions before sharing.'
)
$report=[ordered]@{
    SchemaVersion='1.2'; ScriptVersion='1.1.0'; IndicatorDate='2026-10-22'; SafetyConclusion='NOT_ASSESSED'
    ScanStatus=$(if ($issues.Count -gt 0) { 'CompletedWithCoverageIssues' } else { 'Completed' })
    StartedUtc=$started.ToString('o'); FinishedUtc=[DateTime]::UtcNow.ToString('o')
    ComputerName=$env:COMPUTERNAME; Identity=$identity.Name; IsAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    OSVersion=[Environment]::OSVersion.VersionString; PowerShellVersion=$PSVersionTable.PSVersion.ToString(); PowerShellEdition=$PSVersionTable.PSEdition; Is64BitProcess=[Environment]::Is64BitProcess
    ScriptSHA256=$sourceHash; Summary=$summary
    Indicators=[ordered]@{CertificateCount=$byCert.Count; SpkiCount=$byKey.Count; RelatedRootCount=$knownRoots.Count; SourceVerification='Provided snapshot retained; no online refresh or independent PEM recalculation by this script.'}
    Stores=$stores.ToArray(); Certificates=$entries; TrustUpdateRegistry=$trust
    ServiceInventory=[ordered]@{Status=$serviceStatus; Services=$services}
    SoftwareInventory=[ordered]@{Coverage=$softwareCoverage.ToArray(); Software=$software.ToArray()}
    HttpSys=$httpSys; CoverageIssues=$issues.ToArray(); Limitations=$limitations
    Sources=@('https://bugzilla.mozilla.org/show_bug.cgi?id=2083449','https://emudhra.we-have-a-problem.com/impacted-intermediates.json','https://emudhra.we-have-a-problem.com/roots.json','https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates')
}

$lines=New-Object 'System.Collections.Generic.List[string]'
$lines.Add('Windows eMudhra / emSign local read-only snapshot')
$lines.Add('SafetyConclusion=NOT_ASSESSED -- ZERO MATCHES DO NOT PROVE SAFETY.')
$lines.Add('Indicator snapshot: 2026-10-22; no online refresh or chain/revocation check.')
$lines.Add('Host: '+$report.ComputerName+'; identity: '+$report.Identity+'; admin: '+$report.IsAdministrator)
$lines.Add('PowerShell: '+$report.PowerShellVersion+'; edition: '+$report.PowerShellEdition+'; 64-bit: '+$report.Is64BitProcess)
$lines.Add('Started UTC: '+$report.StartedUtc+'; finished UTC: '+$report.FinishedUtc)
$lines.Add('Scan status: '+$report.ScanStatus)
$lines.Add('')
$lines.Add('SUMMARY (store entries; categories can overlap)')
foreach ($name in $summary.Keys) { $lines.Add($name+'='+$summary[$name]) }
$lines.Add('')
$lines.Add('STORE COVERAGE')
foreach ($store in $stores.ToArray()) { $lines.Add(('{0}\{1}: {2}; enumerated={3}; recorded={4}' -f $store.Location,$store.Store,$store.Status,$store.EnumeratedCount,$store.RecordedCount)) }
$lines.Add('')
$lines.Add('MATCHED ENTRIES (related roots/names are NOT proof of compromise)')
$matched=@($entries | Where-Object { $_.Matches.Count -gt 0 })
if ($matched.Count -eq 0) { $lines.Add('No indicator or name matches in the entries successfully read. See coverage and limitations.') }
foreach ($entry in $matched) {
    $lines.Add(('[{0}\{1}] {2}; InDisallowed={3}' -f $entry.Location,$entry.Store,($entry.Matches -join ', '),$entry.InDisallowed))
    $lines.Add('  Subject: '+$entry.Subject); $lines.Add('  Issuer: '+$entry.Issuer)
    $lines.Add('  DER SHA256: '+$entry.CertificateSHA256); $lines.Add('  SPKI SHA256: '+$entry.SpkiSHA256)
}
$lines.Add(''); $lines.Add('TRUST UPDATE CONFIGURATION AND CACHE PRESENCE (NOT freshness or enforcement proof)')
foreach ($section in $trust) {
    $lines.Add($section.Path+': '+$section.Status)
    foreach ($value in $section.Values) {
        $display='<not configured / absent>'
        if ($value.Present) { if ($value.PresenceOnly) { $display='<present; content not read or decoded>' } else { $display=[string]$value.Value } }
        $lines.Add('  '+$value.Name+'='+$display)
    }
}
$lines.Add('DisableRootAutoUpdate=1 disables automatic trusted root updates; EnableDisallowedCertAutoUpdate=0 disables automatic disallowed CTL updates.')
$lines.Add('Missing values normally use default behavior. Configuration alone does not establish protection.')
$lines.Add(''); $lines.Add('RELATED SOFTWARE / SERVICES')
$lines.Add('Service read status: '+$serviceStatus+'; matching services: '+$services.Count+'; matching uninstall entries: '+$software.Count)
$lines.Add('HTTP.sys: '+$httpSys.Status+'; exit code: '+$httpSys.ExitCode+' (raw stdout/stderr in report.json)')
$lines.Add(''); $lines.Add('COVERAGE ISSUES -- do not interpret failures as zero risk')
if ($issues.Count -eq 0) { $lines.Add('None reported within the declared scope.') }
foreach ($issue in $issues.ToArray()) { $lines.Add('['+$issue.Scope+'] '+$issue.Problem) }
$lines.Add(''); $lines.Add('LIMITATIONS')
foreach ($limitation in $limitations) { $lines.Add('- '+$limitation) }
$lines.Add(''); $lines.Add('Full metadata, software clues and raw HTTP.sys output: report.json')

function Write-NewUtf8File([string]$Path, [string]$Content) {
    $stream=$null; $writer=$null
    try {
        $stream=[IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $writer=[IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($true))
        $writer.Write($Content)
    } finally { if ($null -ne $writer) { $writer.Dispose() } elseif ($null -ne $stream) { $stream.Dispose() } }
}
# Recheck the output path after collecting; create a fresh folder and never overwrite.
$null=Assert-LocalDirectory $base
$destination=Join-Path $base ('EmudhraAudit-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $destination
$null=Assert-LocalDirectory $destination
$json=$report | ConvertTo-Json -Depth 10
Write-NewUtf8File (Join-Path $destination 'report.json') $json
Write-NewUtf8File (Join-Path $destination 'report.txt') ($lines.ToArray() -join [Environment]::NewLine)
Write-Output ('Report TXT: '+(Join-Path $destination 'report.txt'))
Write-Output ('Report JSON: '+(Join-Path $destination 'report.json'))
Write-Output ('SafetyConclusion=NOT_ASSESSED; CoverageIssues='+$issues.Count)
