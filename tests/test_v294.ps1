# tests\test_v294.ps1 - v2.94 D-group: joins, parsers, normalizers, honesty
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $repo 'Ophira.ps1'
$src = [IO.File]::ReadAllText($srcPath)

$script:pass = 0; $script:fail = 0
function Check($name, $ok) {
    if ($ok) { $script:pass++; Write-Host "[PASS] $name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "[FAIL] $name" -ForegroundColor Red }
}
function Get-Extracted($fn) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { throw "cannot extract $fn" }
    return $m.Value
}

# ---- P1: Convert-ToWinPath (shared normalizer, D2)
$sb1 = [scriptblock]::Create((Get-Extracted 'Convert-ToWinPath'))
. $sb1
Check 'C2P: \\?\ prefix stripped' ((Convert-ToWinPath '\\?\C:\Windows\x.exe') -eq 'C:\Windows\x.exe')
Check 'C2P: device path joined' ((Convert-ToWinPath '\Device\HarddiskVolume3\Windows\notepad.exe') -eq 'C:\Windows\notepad.exe')
Check 'C2P: doubled device path' ((Convert-ToWinPath '\\DEVICE\\HARDDISKVOLUME2\Program Files\a.dll') -eq 'C:\Program Files\a.dll')
Check 'C2P: volume GUID stripped' ((Convert-ToWinPath '\VOLUME{01a2b3c4-0000-0000-0000-000000000000}\Users\x.exe') -eq '\Users\x.exe')
Check 'C2P: forward slashes unified' ((Convert-ToWinPath 'C:/Program Files/x/sys.exe') -eq 'C:\Program Files\x\sys.exe')
Check 'C2P: empty stays empty' ((Convert-ToWinPath '  ') -eq '')

# ---- P2: Get-SidName (D4)
$sb2 = [scriptblock]::Create((Get-Extracted 'Get-SidName'))
. $sb2
$sysName = Get-SidName 'S-1-5-18'
Check 'D4: S-1-5-18 resolves' ("$sysName" -match 'SYSTEM')
Check 'D4: unresolvable SID returns empty' ((Get-SidName 'S-1-5-21-9999999999-9999999999-9999999999-999999') -eq '')
Check 'D4: non-SID passes through' ((Get-SidName 'Aryan') -eq 'Aryan')

# ---- P3: recyclebin $I binary parse (D7a) via module 8.1 extraction
$m81 = [regex]::Match($src, "(?s)Id = '8\.1';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '8\.2'")
Check 'D7a: module 8.1 extracted' ($m81.Success)
if ($m81.Success) {
    $tmp = Join-Path $env:TEMP ("oph_v294_" + (Get-Date -Format 'HHmmss'))
    $rbRoot = Join-Path $tmp 'drive'
    $rbDir = Join-Path $rbRoot '$Recycle.Bin\S-1-5-21-100-200-300-1001'
    New-Item -ItemType Directory -Path $rbDir -Force | Out-Null
    $iFile = Join-Path $rbDir '$I3E4F5A6B.dat'
    # v2 layout: ver=2(8) size=4096(8) filetime(8) namelen=11(4) name UTF16
    $name = 'C:\evil.exe'
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([long]2); $bw.Write([long]4096)
    $ft = [DateTime]::Parse('2026-01-15 12:00:00', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal).ToFileTime()
    $bw.Write([long]$ft); $bw.Write([int]$name.Length)
    $bw.Write([Text.Encoding]::Unicode.GetBytes($name))
    $bw.Flush(); [IO.File]::WriteAllBytes($iFile, $ms.ToArray()); $bw.Close()

    # stubs for the module body
    function Save-Rows { param($Name, $Rows) $script:saved831 = @($Rows) }
    function Write-CaseLog { param($m, [object]$c) }
    function Get-LogStart { return $null }
    function Get-UserProfileList { return @() }
    function Get-LocalProfiles { return @() }
    $RawDir = Join-Path $tmp 'raw'
    New-Item -ItemType Directory -Path $RawDir -Force | Out-Null
    $fakeDrv = [pscustomobject]@{ Name = 'Q'; Root = "$rbRoot\"; Free = 1 }
    # drive-stub + real filesystem for the rest
    $global:GetPSDrive_Orig = Get-Content function:Get-PSDrive -ErrorAction SilentlyContinue
    function Get-PSDrive { param($PSProvider) return @($fakeDrv) }
    $runBody = [scriptblock]::Create($m81.Groups[1].Value)
    try { & $runBody } catch { Check 'D7a: module body ran' $false; Write-Host "      err: $($_.Exception.Message)" -ForegroundColor Red }
    $rows = $script:saved831
    Check 'D7a: one row emitted' (@($rows).Count -eq 1)
    if (@($rows).Count -eq 1) {
        $r0 = $rows[0]
        Check 'D7a: original size parsed' ("$($r0.Bytes)" -eq '4096')
        Check 'D7a: delete time = UTC wall clock' ("$($r0.DeletedUTC)" -eq '2026-01-15 12:00:00')
        Check 'D7a: original path parsed' ("$($r0.OriginalPath)" -eq 'C:\evil.exe')
        Check 'D7a: owner sid kept' ("$($r0.OwnerSid)" -eq 'S-1-5-21-100-200-300-1001')
    }
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ---- P4: Get-FilteredEvents invariant stamp (D8c)
$sb4 = [scriptblock]::Create((Get-Extracted 'Get-FilteredEvents'))
. $sb4
function Get-WinEvent { param($FilterHashtable, $ErrorAction)
    return @([pscustomobject]@{ TimeCreated = [datetime]'2026-11-01 13:45:00'; Id = 4624; ProviderName = 'Microsoft-Windows-Security-Auditing'; LevelDisplayName = 'Information'; Message = 'log on  x' })
}
$fe = Get-FilteredEvents -LogName Security -Ids 4624
Check 'D8c: TimeCreated emitted as invariant ISO' (@($fe).Count -eq 1 -and "$($fe[0].TimeCreated)" -eq '2026-11-01 13:45:00')
Check 'D8c: message whitespace collapsed' ("$($fe[0].Message)" -eq 'log on x')

# ---- P5: Get-ConnectionTable ::ffff: strip (D7f)
$sb5 = [scriptblock]::Create((Get-Extracted 'Test-IsPublicIp'))
. $sb5
$sb5b = [scriptblock]::Create((Get-Extracted 'Get-ConnectionTable'))
. $sb5b
function Get-Process { return @() }
function Get-NetTCPConnection { param($ErrorAction)
    return @([pscustomobject]@{ LocalAddress = '::ffff:127.0.0.1'; LocalPort = 1234; RemoteAddress = '::ffff:4.213.25.242'; RemotePort = 443; State = 'Established'; OwningProcess = 6440 })
}
$ct = Get-ConnectionTable
Check 'D7f: remote ::ffff: stripped' (@($ct).Count -eq 1 -and "$($ct[0].RemoteAddress)" -eq '4.213.25.242')
Check 'D7f: local ::ffff: stripped' ("$($ct[0].LocalAddress)" -eq '127.0.0.1')
Check 'D7f: public still classified on stripped ip' ("$($ct[0].Public)" -eq 'True')

# ---- P6: structure pins
Check 'D1: sysmon_network weave carries hostname' ($src.Contains('host='))
Check 'D1: sysmon_network weave marks INBOUND' ($src.Contains(" INBOUND'"))
Check 'D1: sysmon_registry weave carries Details' ($src.Contains('| $($r.Details)'))
Check 'D1: sysmon_proc_create hash join in entities' ($src.Contains('sysmon-exec') -and $src.Contains('process created (Sysmon 1)'))
Check 'D3: services entity scan present' ($src.Contains("rowsOf 'services'") -and $src.Contains('service-persist'))
Check 'D3: binFromRow argged-path branch' ($src.Contains('(?i)([a-z]:\\[^\s]+\.(exe|dll|sys|ps1|bat|js|vbs|hta|com|ocx|drv))(\s|$)'))
Check 'D4: acctGet resolves SIDs' ($src.Contains('if ($a2 -match ' + "'" + '^S-1-5-' + "'" + ')'))
Check 'D5: recyclebin coverage voice' ($src.Contains("Deleted-file index (recycle bin `$I)"))
Check 'D5: shellbags coverage voice' ($src.Contains("'ShellBags folder history'"))
Check 'D5: jumplist coverage voice' ($src.Contains("'JumpLists'"))
Check 'D7a: weave reads OriginalPath' ($src.Contains("PSObject.Properties['OriginalPath']"))
Check 'D7c: exec stacks prefetch 0..7' ($src.Contains("foreach (`$pn in 0..7) {"))
Check 'D8b: winpmem via Invoke-NativeTool' ($src.Contains('-ExePath $tool.FullName -ToolArgs @("$dump") -CaptureOut'))
Check 'D8c: Get-EventDataRows invariant' ($src.Contains("Time = `$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'"))
Check 'D8c: Get-FilteredEvents invariant' ($src.Contains("TimeCreated = `$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'"))
Check 'D7f: mapped-prefix strip count' (([regex]::Matches($src, [regex]::Escape('(?i)^::ffff:'))).Count -ge 3)

# ---- P7: version
Check 'version: header bumped' ($src.Contains('Ophira v2.94'))
Check 'version: ScriptVersion 2.94' ($src.Contains('$ScriptVersion = "2.94"'))

Write-Host ''
Write-Host "v294: $script:pass passed, $script:fail failed" -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
