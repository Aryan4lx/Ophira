$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.76 - hunt precision: R4 download-exec full-path/parent+leaf matching + severity matrix,
# R15 EID2 copy/extract-tool skip + per-target dedupe before the cap,
# R22 timestamp rules keyed by full path + three-way split, R4 no-dir -> medium rider,
# R28 injection severity ladder + R13 discovery storm -> low with machine/system note;
# PART 2: hunt table render - counts line, high/medium main table, low/info details block
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# PART 1 - R4 + R15 through the real function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_h276_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'W1'

# real signed binary staged in a real Downloads-shaped dir (R4 signed-in-Downloads -> medium)
$dl = Join-Path $env:TEMP "v276_dl_$stamp\Downloads"
New-Item -ItemType Directory -Path $dl -Force | Out-Null
$signedPath = Join-Path $dl 'signed.exe'
Copy-Item -LiteralPath "$env:SystemRoot\System32\notepad.exe" -Destination $signedPath -Force

# execution evidence (amcache): full-path rows for the real matches; tool.exe shares the leaf
# of a Downloads download but lives in a different dir (the v2.76 polarity case). KeyTimeStamp
# rows feed the R22 timestamp rules (empty = R4-only row).
$future = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-dd HH:mm:ss')
$old400 = (Get-Date).ToUniversalTime().AddDays(-400).ToString('yyyy-MM-dd HH:mm:ss')
$old500 = (Get-Date).ToUniversalTime().AddDays(-500).ToString('yyyy-MM-dd HH:mm:ss')
$recent = (Get-Date).ToUniversalTime().AddDays(-5).ToString('yyyy-MM-dd HH:mm:ss')
# v2.76 round 2: REAL AmcacheParser header shape (ApplicationName..FullPath..Name - NO Path
# column): proves the R4 exec probe reads FullPath and R22 keys by it (Path fallback is
# covered by the mft fixture below).
New-Csv (Join-Path $CsvDir 'amcache.csv') '"ApplicationName","ProgramId","FileKeyLastWriteTimestamp","SHA1","IsOsComponent","FullPath","Name","FileExtension"' @(
    '"7z2603-x64.exe","pid1","","9eff75f1","False","C:\Users\ary\Downloads\7z2603-x64.exe","7z2603-x64.exe",".exe"',
    '"tool.exe","pid2","","aa","False","C:\Windows\Temp\tool.exe","tool.exe",".exe"',
    '"portable.exe","pid3","","ab","False","C:\Users\ary\Tools\portable.exe","portable.exe",".exe"',
    '"stage.exe","pid4","","ac","False","C:\Users\ary\AppData\Local\Temp\stage.exe","stage.exe",".exe"',
    ('"signed.exe","pid5","","ad","False","{0}","signed.exe",".exe"' -f $signedPath),
    # R22 leaf-collision polarity: execution row whose LEAF matches the OS MpCmdRun below but
    # whose FULL PATH does not - must NOT produce a finding for the OS binary
    ('"MpCmdRun.exe","pid6","{0}","ae","False","C:\Tools\DefenderPlatform\MpCmdRun.exe","MpCmdRun.exe",".exe"' -f $old500),
    ('"anom.exe","pid7","{0}","af","False","c:\users\public\anom.exe","anom.exe",".exe"' -f $old500),
    ('"fpexe.exe","pid8","{0}","b0","False","c:\full\key\fpexe.exe","fpexe.exe",".exe"' -f $old500),
    # v2.76 round 2 checks: FullPath-only probe polarity (real-case shape)
    '"fetch.exe","pid9","","b1","False","C:\Users\ary\Downloads\fetch.exe","fetch.exe",".exe"',
    '"loser.exe","pid10","","b2","False","C:\Windows\Temp\loser.exe","loser.exe",".exe"'
)
# R22 mft rows (no FullPath except fpexe -> Path-column fallback covered by the others):
# anom.exe = future $Si + ancient FILE_NAME + old execution evidence (all three rules);
# skewonly.exe = $Si-vs-FN skew only (the extracted-archive shape) -> only the low rule;
# MpCmdRun.exe = OS binary, consistent births, no amcache match at its own path;
# fpexe.exe = keyable ONLY via the FullPath column (Path empty)
New-Csv (Join-Path $CsvDir 'mft_recent.csv') '"Drive","Entry","Created","CreatedFN","LastModified","Size","Name","Path","FullPath","Flags"' @(
    ('"C:","200001","{0}","{1}","{0}","4096","anom.exe","C:\Users\public\anom.exe","","exec;user-path"' -f $future, $old400),
    ('"C:","200002","{0}","{1}","{0}","4096","skewonly.exe","C:\Users\public\skewonly.exe","","exec;user-path"' -f $old400, $recent),
    ('"C:","200003","{0}","{0}","{0}","4096","MpCmdRun.exe","C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpCmdRun.exe","",""' -f $recent),
    ('"C:","200004","{0}","{0}","{0}","4096","fpexe.exe","","c:\full\key\fpexe.exe",""' -f $old400)
)
# downloads: the 7-Zip carried twice (real-case duplicate shape)
New-Csv (Join-Path $CsvDir 'browser_downloads.csv') '"TargetFilePath","URL"' @(
    '"C:\Users\ary\Downloads\7z2603-x64.exe","https://www.7-zip.org/a/7z2603-x64.exe"',
    '"C:\Users\ary\Downloads\7z2603-x64.exe","https://mirror.example.com/a/7z2603-x64.exe"',
    '"C:\Users\ary\Downloads\tool.exe","http://evil.example.com/tool.exe"',
    '"portable.exe","-"',
    '"C:\Users\ary\AppData\Local\Temp\stage.exe","http://evil.example.com/stage.exe"',
    '"C:\Users\ary\Downloads\fetch.exe","http://soft.example.com/fetch.exe"',
    '"C:\Users\ary\Downloads\loser.exe","http://soft.example.com/loser.exe"',
    ('"{0}","http://vendor.example.com/signed.exe"' -f $signedPath)
)
# R15: EID 2 - copy/extract images must skip; same target twice dedupes; other images fire
New-Csv (Join-Path $CsvDir 'sysmon_file_time.csv') '"Time","EventId","Image","TargetFilename","CreationUtcTime","PreviousCreationUtcTime"' @(
    '"2026-10-22 10:00:00","2","C:\Windows\explorer.exe","C:\Users\dev\docs\report.docx","2019-01-01 00:00:00","2026-10-22 09:59:59"',
    '"2026-10-22 10:01:00","2","C:\Tools\7-Zip\7z2603-x64.exe","C:\Users\dev\archive.7z","2019-01-01 00:00:00","2026-10-22 10:00:59"',
    '"2026-10-22 10:02:00","2","C:\Program Files\WinRAR\winrar.exe","C:\Users\dev\backup.rar","2019-01-01 00:00:00","2026-10-22 10:01:59"',
    '"2026-10-22 10:03:00","2","C:\Windows\System32\Robocopy.exe","C:\Users\dev\mirror\file.txt","2019-01-01 00:00:00","2026-10-22 10:02:59"',
    '"2026-10-22 10:04:00","2","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Users\dev\secret.xlsx","2019-01-01 00:00:00","2026-10-22 10:03:59"',
    '"2026-10-22 10:04:01","2","C:\Windows\System32\cmd.exe","C:\Users\dev\secret.xlsx","2019-01-01 00:00:00","2026-10-22 10:03:59"',
    '"2026-10-22 10:05:00","2","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Users\dev\normal.pdf","2019-01-01 00:00:00","2026-10-22 10:04:59"',
    # v2.76 round 2: msiexec preserves package-embedded timestamps on install - benign, skipped
    '"2026-10-22 10:05:30","2","C:\WINDOWS\system32\msiexec.exe","C:\Program Files\App\app.exe","2019-01-01 00:00:00","2026-10-22 10:05:29"',
    # R22: EID 2 corroboration for anom.exe (full-path TargetFilename must reach the skew rule)
    '"2026-10-22 10:06:00","2","C:\Windows\System32\cmd.exe","C:\Users\public\anom.exe","2019-01-01 00:00:00","2026-10-22 10:05:59"'
)
# R28: severity ladder - protected pair low, unknown target low, lsass/user-path high,
# cross-boundary medium (the real-case dwm->csrss / dwm-><unknown process> FP shapes)
New-Csv (Join-Path $CsvDir 'sysmon_remote_thread.csv') '"Time","EventId","SourceImage","TargetImage","StartModule","StartFunction","User"' @(
    '"2026-10-22 11:00:00","8","C:\Windows\System32\dwm.exe","C:\Windows\System32\csrss.exe","","-","SYSTEM"',
    '"2026-10-22 11:00:01","8","C:\Windows\System32\dwm.exe","<unknown process>","","-","SYSTEM"',
    '"2026-10-22 11:00:02","8","C:\Windows\System32\svchost.exe","C:\Windows\System32\lsass.exe","","-","SYSTEM"',
    '"2026-10-22 11:00:03","8","C:\Users\evil\AppData\Roaming\implant.exe","C:\Windows\explorer.exe","","LoadLibraryA","DEV\evil"',
    '"2026-10-22 11:00:04","8","C:\Windows\System32\svchost.exe","C:\Program Files\Vendor\app.exe","","-","SYSTEM"'
)
# R13: machine-account storm (Ophira's own collection shape) + gate (single whoami suppressed)
New-Csv (Join-Path $CsvDir 'security_proc_events.csv') '"Time","EventId","Account","NewProcess","CommandLine","ParentProcess"' @(
    '"2026-10-22 12:00:00","4688","W1\WIN11$","C:\Windows\System32\whoami.exe","whoami.exe","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:01","4688","W1\WIN11$","C:\Windows\System32\net.exe","net view","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:02","4688","W1\WIN11$","C:\Windows\System32\nltest.exe","nltest /dclist:corp","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:03","4688","W1\WIN11$","C:\Windows\System32\systeminfo.exe","systeminfo","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:04","4688","W1\WIN11$","C:\Windows\System32\ipconfig.exe","ipconfig /all","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:05","4688","W1\WIN11$","C:\Windows\System32\quser.exe","quser","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:00:06","4688","W1\WIN11$","C:\Windows\System32\netstat.exe","netstat -ano","C:\Windows\System32\cmd.exe"',
    '"2026-10-22 12:01:00","4688","dev","C:\Windows\System32\whoami.exe","whoami.exe","C:\Windows\System32\cmd.exe"'
)

New-HuntFindings

$hf = @($saved['hunt_findings'])
# ---- R4 ----
$r4 = @($hf | Where-Object { $_.Rule -match 'Downloaded then executed' })
Check "R4: full-path match fires for Downloads 7-Zip, exactly once despite dup download row" (@($r4 | Where-Object { "$($_.Entity)" -eq 'C:\Users\ary\Downloads\7z2603-x64.exe' }).Count -eq 1)
Check "R4: Downloads + missing file -> medium ('signature not checkable' in evidence)" (@($r4 | Where-Object { "$($_.Entity)" -eq 'C:\Users\ary\Downloads\7z2603-x64.exe' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'signature not checkable' }).Count -eq 1)
Check "R4: polarity - leaf-only evidence in another dir does NOT match a full-path download" (@($r4 | Where-Object { "$($_.Entity)" -match 'Downloads\\tool\.exe' }).Count -eq 0)
Check "R4: no-directory download row falls back to leaf match" (@($r4 | Where-Object { "$($_.Entity)" -eq 'portable.exe' }).Count -eq 1)
Check "R4: staged outside Downloads -> high ('staged outside' in evidence)" (@($r4 | Where-Object { "$($_.Entity)" -eq 'C:\Users\ary\AppData\Local\Temp\stage.exe' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'staged outside' }).Count -eq 1)
Check "R4: signed binary in Downloads -> medium ('signed' case in evidence)" (@($r4 | Where-Object { "$($_.Entity)" -eq "$signedPath" -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'signed \(' }).Count -eq 1)
Check "R4 round 2: amcache FullPath probe (no Path column) drives the full-path match" (@($r4 | Where-Object { "$($_.Entity)" -eq 'C:\Users\ary\Downloads\fetch.exe' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'signature not checkable' }).Count -eq 1)
Check "R4 round 2: same leaf in another dir -> Name probe cannot satisfy a full-path download" (@($r4 | Where-Object { "$($_.Entity)" -eq 'C:\Users\ary\Downloads\loser.exe' }).Count -eq 0)
# ---- R15 ----
$r15 = @($hf | Where-Object { $_.Rule -match 'File creation time changed' })
Check "R15: explorer.exe image skipped" (@($r15 | Where-Object { "$($_.Entity)" -match 'report\.docx' }).Count -eq 0)
Check "R15: 7z image skipped" (@($r15 | Where-Object { "$($_.Entity)" -match 'archive\.7z' }).Count -eq 0)
Check "R15: winrar image skipped" (@($r15 | Where-Object { "$($_.Entity)" -match 'backup\.rar' }).Count -eq 0)
Check "R15: robocopy image skipped" (@($r15 | Where-Object { "$($_.Entity)" -match 'mirror\\file\.txt' }).Count -eq 0)
Check "R15: same target from two images dedupes to ONE finding" (@($r15 | Where-Object { "$($_.Entity)" -match 'secret\.xlsx' }).Count -eq 1)
Check "R15: non-copy-tool image still fires medium" (@($r15 | Where-Object { "$($_.Entity)" -match 'normal\.pdf' -and $_.Severity -eq 'medium' }).Count -eq 1)
Check "R15: msiexec image skipped (MSI package-embedded timestamps)" (@($r15 | Where-Object { "$($_.Evidence)" -match 'msiexec\.exe' }).Count -eq 0)
Check "R15: evidence names the acting image" (@($r15 | Where-Object { "$($_.Entity)" -match 'normal\.pdf' -and "$($_.Evidence)" -match 'powershell\.exe' }).Count -eq 1)
# ---- R22 (v2.76: full-path keys + three-way split) ----
$r22 = @($hf | Where-Object { "$($_.Rule)" -like 'Timestamp anomaly*' })
Check "R22: MpCmdRun leaf collision -> NO finding (full-path amcache key)" (@($r22 | Where-Object { "$($_.Entity)" -match 'MpCmdRun\.exe' }).Count -eq 0)
Check "R22: three rule names present" (@($r22 | Where-Object { $_.Rule -eq 'Timestamp anomaly - future file birth' }).Count -ge 1 -and @($r22 | Where-Object { $_.Rule -eq 'Timestamp anomaly - execution predates birth' }).Count -ge 1 -and @($r22 | Where-Object { $_.Rule -eq 'Timestamp anomaly - birth attribute skew' }).Count -ge 1)
Check "R22: anom.exe future file birth -> medium" (@($r22 | Where-Object { "$($_.Entity)" -match 'anom\.exe' -and $_.Rule -eq 'Timestamp anomaly - future file birth' -and $_.Severity -eq 'medium' }).Count -eq 1)
Check "R22: anom.exe execution predates birth -> medium (Path-column fallback key)" (@($r22 | Where-Object { "$($_.Entity)" -match 'anom\.exe' -and $_.Rule -eq 'Timestamp anomaly - execution predates birth' -and $_.Severity -eq 'medium' }).Count -eq 1)
Check "R22: anom.exe birth attribute skew -> low with EID 2 corroboration" (@($r22 | Where-Object { "$($_.Entity)" -match 'anom\.exe' -and $_.Rule -eq 'Timestamp anomaly - birth attribute skew' -and $_.Severity -eq 'low' -and "$($_.Evidence)" -match 'EID 2' }).Count -eq 1)
Check "R22: skew-only file -> exactly one low finding, no medium" (@($r22 | Where-Object { "$($_.Entity)" -match 'skewonly\.exe' -and $_.Severity -eq 'low' }).Count -eq 1 -and @($r22 | Where-Object { "$($_.Entity)" -match 'skewonly\.exe' -and $_.Severity -eq 'medium' }).Count -eq 0)
Check "R22: FullPath column preferred when Path empty (fpexe.exe ran-before)" (@($r22 | Where-Object { "$($_.Entity)" -match 'fpexe\.exe' -and $_.Rule -eq 'Timestamp anomaly - execution predates birth' -and $_.Severity -eq 'medium' }).Count -eq 1)
# ---- R4 rider (no-directory download row must not probe the analyst's CWD) ----
Check "R4 rider: no-directory download row -> medium ('no directory' in evidence)" (@($r4 | Where-Object { "$($_.Entity)" -eq 'portable.exe' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'no directory' }).Count -eq 1)
# ---- R28 (v2.76 severity ladder) ----
$r28 = @($hf | Where-Object { $_.Rule -eq 'Cross-process injection (remote thread)' })
Check "R28: dwm -> csrss (both under \Windows\) -> low" (@($r28 | Where-Object { "$($_.Entity)" -match 'dwm\.exe -> C:\\Windows\\System32\\csrss\.exe$' -and $_.Severity -eq 'low' -and "$($_.Evidence)" -match 'protected Windows pair' }).Count -eq 1)
Check "R28: unknown target -> low" (@($r28 | Where-Object { "$($_.Entity)" -match 'dwm\.exe -> <unknown process>$' -and $_.Severity -eq 'low' }).Count -eq 1)
Check "R28: lsass target -> high even from a Windows source (carve-out beats protected pair)" (@($r28 | Where-Object { "$($_.Entity)" -match 'svchost\.exe -> C:\\Windows\\System32\\lsass\.exe$' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'credential-dump tell' }).Count -eq 1)
Check "R28: user-path source -> high" (@($r28 | Where-Object { "$($_.Entity)" -match 'implant\.exe -> C:\\Windows\\explorer\.exe$' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'user-writable path' }).Count -eq 1)
Check "R28: cross-boundary pair with no privilege context -> medium" (@($r28 | Where-Object { "$($_.Entity)" -match 'svchost\.exe -> C:\\Program Files\\Vendor\\app\.exe$' -and $_.Severity -eq 'medium' }).Count -eq 1)
# ---- R13 (v2.76: low + machine/system context note) ----
$r13 = @($hf | Where-Object { $_.Rule -match 'Discovery command storm' })
Check "R13: machine-account storm -> low with machine/system context note" (@($r13 | Where-Object { "$($_.Entity)" -match 'WIN11\$$' -and $_.Severity -eq 'low' -and "$($_.Evidence)" -match 'machine/system context - likely its own collection tooling' }).Count -eq 1)
Check "R13: gate still suppresses a single whoami" (@($r13 | Where-Object { "$($_.Entity)" -eq 'dev' }).Count -eq 0)

Remove-Item -LiteralPath $case1 -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Split-Path $dl -Parent) -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================================
# PART 2 - hunt table render (v2.76 task 4): high/medium in the main table,
# low/info collapsed into a details block. Render harness mirrors the
# test_v270 full-report pattern: real New-HtmlReport on a hand-built fixture.
# ============================================================================
foreach ($n2 in @('ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass', 'Get-TriageLeads', 'New-VtLink', 'Split-TagList', 'Get-TacticLabel', 'New-HtmlReport')) {
    $m2 = [regex]::Match($src, "(?s)function $n2\b.*?\r?\n\}")
    if (-not $m2.Success) { throw "render extract failed: $n2" }
    Invoke-Expression $m2.Value
}
$rcase = Join-Path $env:TEMP ("ophira_h276r_$stamp")
$rcsv = Join-Path $rcase 'csv'
New-Item -ItemType Directory -Path $rcsv, (Join-Path $rcase 'raw\evtx'), (Join-Path $rcase 'focus') -Force | Out-Null
$CaseDir = $rcase; $CsvDir = $rcsv; $RawDir = Join-Path $rcase 'raw'; $MemDir = Join-Path $rcase 'mem'
$Computer = 'V276HOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-276'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Get-LogRangeText { 'analysis window' }
'{"Indicator":"x.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $rcase 'focus\focus_terms.json') -Encoding UTF8
foreach ($empty in @('flash_process_scored', 'flash_ioc_hits', 'yara_hits', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'entities_accounts', 'entities_remotes', 'entities_binaries', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'security_bruteforce_candidates', 'flash_public_connections', 'supertimeline', 'posture', 'credential_sweep', 'hunt_findings', 'process_chains', 'ioc_hits_amcache', 'ps_decoded_commands', 'session_activity', 'sysmon_process_access', 'sysmon_remote_thread', 'sysmon_pipes')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $rcsv "$empty.csv") -Encoding UTF8
}
$mkV = {
    param($sigs)
    [pscustomobject]@{
        Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 60; OwnerLine = 'fixture owner'
        Signals = $sigs; Caveats = @(); Coverage = @(); CoveragePercentUnadjusted = 60
        CoverageSourcesCollected = 3; CoverageSourcesTotal = 4; Counts = $null; GeneratedUTC = 'x'
    }
}
$script:Verdict = & $mkV @([pscustomobject]@{ Signal = 'Hunt techniques (1 fired)'; Weight = 2; Count = 1; Detail = 'LSASS access x1' })

# render A: 1 high + 1 medium (main table) + 1 low + 1 info (collapsed); XSS payload in the high Entity
@"
"Found","Rule","Severity","Entity","Attck","Evidence"
"2026-10-14 12:00:00","LSASS access","high","C:\Users\evil<script>alert(1)</script>.exe","T1003.001","handle requested"
"2026-10-14 12:01:00","UAC bypass pattern","medium","C:\Users\u\app.exe","T1548.002","pattern matched"
"2026-10-14 12:02:00","Timestamp anomaly - birth attribute skew","low","C:\Users\public\skew.exe","T1070.006","birth attributes disagree"
"2026-10-14 12:03:00","USB execution trail","info","C:\Users\u\usb.ps1","T1091","mounted"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlR = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$huntIdx = $htmlR.IndexOf("name='hunt'")
$sumIdx = $htmlR.IndexOf('<details><summary>Low / informational findings (2)</summary>')
$mainSlice = if ($sumIdx -gt $huntIdx) { $htmlR.Substring($huntIdx, $sumIdx - $huntIdx) } else { '' }
$detEnd = if ($sumIdx -ge 0) { $htmlR.IndexOf('</table></details>', $sumIdx) } else { -1 }
$detSlice = if ($detEnd -gt $sumIdx) { $htmlR.Substring($sumIdx, $detEnd - $sumIdx) } else { '' }
Check "render A: counts line exact (1 high / 1 medium / 2 informational)" ($htmlR.Contains('<h2>Hunt technique findings - 1 high / 1 medium / 2 informational</h2>'))
Check "render A: high row stays in the main table" ($mainSlice.Contains('LSASS access'))
Check "render A: medium row in the main table (same renderer, med class)" ($mainSlice.Contains("<td class='med'><b>medium</b></td><td>UAC bypass pattern</td>"))
Check "render A: low row NOT in the main table" (-not $mainSlice.Contains('skew.exe'))
Check "render A: details summary counts low+info (2)" ($sumIdx -gt $huntIdx)
Check "render A: low row inside the details block (same renderer)" ($detSlice.Contains("<td class='info'><b>low</b></td><td>Timestamp anomaly - birth attribute skew</td>") -and $detSlice.Contains('skew.exe'))
Check "render A: info row inside the details block" ($detSlice.Contains("<td class='info'><b>info</b></td><td>USB execution trail</td>"))
Check "render A: details table shares the main header row" ($detSlice.Contains('<th>Severity</th><th>Rule</th><th>ATT&amp;CK</th><th>Entity</th><th>Evidence</th>'))
Check "xss: raw script payload absent from the whole report" (-not $htmlR.Contains('evil<script>alert(1)'))
Check "xss: payload Entity rendered escaped in the hunt row" ($htmlR.Contains('evil&lt;script&gt;alert(1)&lt;/script&gt;.exe'))

# render B: high-only fixture -> zero buckets render as 0, details block ABSENT
@"
"Found","Rule","Severity","Entity","Attck","Evidence"
"2026-10-14 12:00:00","LSASS access","high","C:\Windows\System32\lsass.exe","T1003.001","handle requested"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlR2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "render B: zero buckets render as 0 in the counts line" ($htmlR2.Contains('<h2>Hunt technique findings - 1 high / 0 medium / 0 informational</h2>'))
Check "render B: details block ABSENT when no low/info rows" (-not $htmlR2.Contains('<details><summary>Low / informational findings'))
Check "render B: the lone high row still renders in the main table" ($htmlR2.Contains('LSASS access'))

# render C: no findings at all -> counts line all zeros + clean note kept
"# no entries" | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlR3 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "render C: no findings -> counts line all zeros" ($htmlR3.Contains('<h2>Hunt technique findings - 0 high / 0 medium / 0 informational</h2>'))
Check "render C: no findings -> no details block, clean note kept" ((-not $htmlR3.Contains('<details><summary>Low / informational findings')) -and $htmlR3.Contains('No hunt findings - all techniques clean'))

Remove-Item -LiteralPath $rcase -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
