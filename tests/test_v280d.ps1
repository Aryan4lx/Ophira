$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.80d (T5) - rule hardening + XSS seam:
#   F4 R29 separate high/medium cap counters (high pass not starved by medium noise)
#   F5 R4 Authenticode HashMismatch = dedicated branch (HIGH outside Downloads / MEDIUM inside,
#      wording 'binary MODIFIED after signing'); NotSigned + 'signed (...)' unchanged
#   F6 Test-IsPublicIp: CGNAT 100.64.0.0/10 = not public (mobile hotspots)
#   F7 R8 LSASS allowlist leaf-only -> leaf AND Windows system dir (name-spoof + path check)
#   F8 R3 inSys regex drive-agnostic (multi-boot/D: artifacts)
#   I4 ConvertTo-HtmlEsc escapes single quotes; New-VtLink href stays quote-safe
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - F6: Test-IsPublicIp CGNAT
# ============================================================================
$f6 = ''
foreach ($n in @('Test-IsPublicIp')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $f6 += $m.Value + "`r`n"
}
Invoke-Expression $f6
Check "F6: 100.64.1.1 (CGNAT) = not public" (-not (Test-IsPublicIp '100.64.1.1'))
Check "F6: 100.127.255.255 (CGNAT top) = not public" (-not (Test-IsPublicIp '100.127.255.255'))
Check "F6: 100.63.255.255 (below CGNAT) still public" (Test-IsPublicIp '100.63.255.255')
Check "F6: 100.128.0.1 (above CGNAT) still public" (Test-IsPublicIp '100.128.0.1')
Check "F6: real public 203.0.113.5 still public" (Test-IsPublicIp '203.0.113.5')
Check "F6: RFC1918 10.0.0.5 still private" (-not (Test-IsPublicIp '10.0.0.5'))

# ============================================================================
# PART 2 - F4 + F5 + F7 + F8 through the real New-HuntFindings
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$savedHF = @()
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:savedHF = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
# F5: controllable Authenticode verdicts by exact path
$script:sigByPath = @{}
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $script:sigByPath[$LiteralPath.ToLower()] }

# ---- F4: 45 medium pipe rows FIRST, then a HIGH C2-family row ----
$f5dir = Join-Path $env:TEMP "ophira_v280d_$stamp"
New-Item -ItemType Directory -Path $f5dir -Force | Out-Null
$medPipes = @()
for ($i = 1; $i -le 45; $i++) {
    $medPipes += [pscustomobject]@{ Time = '2026-10-05 14:00:00.000'; EventId = 17; Image = "C:\Users\dev\app\tool$i.exe"; PipeName = "\toolpipe_$i"; EventType = 'CreatePipe'; User = 'DEV\dev'; ProcessId = "$i"; ProcessGuid = "{$i}" }
}
$caseCsv = @{
    'sysmon_pipes' = @($medPipes + @(
        [pscustomobject]@{ Time = '2026-10-05 15:00:00.000'; EventId = 17; Image = 'C:\Users\Public\beacon.exe'; PipeName = '\msagent_beef'; EventType = 'CreatePipe'; User = 'DEV\dev'; ProcessId = '999'; ProcessGuid = '{beef}' }
    ))
}
New-HuntFindings
$r29hi = @($savedHF | Where-Object { $_.Rule -eq 'C2-style named pipe (known C2 family)' })
$r29med = @($savedHF | Where-Object { $_.Rule -eq 'Named pipe created from user-writable path' })
Check "F4: HIGH C2 pipe row after 40+ medium rows still classified" (@($r29hi | Where-Object { "$($_.Entity)" -eq '\msagent_beef' -and $_.Severity -eq 'high' }).Count -eq 1)
Check "F4: medium cap still honest (40 emitted of 45)" ($r29med.Count -eq 40)

# ---- F5: R4 HashMismatch / NotSigned / signed severity matrix ----
$dlDir = Join-Path $f5dir 'Downloads'
New-Item -ItemType Directory -Path $dlDir, (Join-Path $f5dir 'stage') -Force | Out-Null
foreach ($n in @('hm_in.exe', 'unsigned_in.exe', 'valid_in.exe')) { Set-Content -LiteralPath (Join-Path $dlDir $n) -Value 'x' -Encoding ASCII }
Set-Content -LiteralPath (Join-Path $f5dir 'stage\hm_out.exe') -Value 'x' -Encoding ASCII
$script:sigByPath = @{}
$script:sigByPath[(Join-Path $dlDir 'hm_in.exe').ToLower()] = [pscustomobject]@{ Status = 'HashMismatch' }
$script:sigByPath[(Join-Path $dlDir 'unsigned_in.exe').ToLower()] = [pscustomobject]@{ Status = 'NotSigned' }
$script:sigByPath[(Join-Path $dlDir 'valid_in.exe').ToLower()] = [pscustomobject]@{ Status = 'Valid' }
$script:sigByPath[(Join-Path $f5dir 'stage\hm_out.exe').ToLower()] = [pscustomobject]@{ Status = 'HashMismatch' }
$caseCsv = @{
    'amcache' = @(
        [pscustomobject]@{ Name = 'hm_in.exe'; Path = (Join-Path $dlDir 'hm_in.exe') },
        [pscustomobject]@{ Name = 'unsigned_in.exe'; Path = (Join-Path $dlDir 'unsigned_in.exe') },
        [pscustomobject]@{ Name = 'valid_in.exe'; Path = (Join-Path $dlDir 'valid_in.exe') },
        [pscustomobject]@{ Name = 'hm_out.exe'; Path = (Join-Path $f5dir 'stage\hm_out.exe') }
    )
    'browser_downloads' = @(
        [pscustomobject]@{ TargetFilePath = (Join-Path $dlDir 'hm_in.exe'); URL = 'http://evil.example.com/hm_in' },
        [pscustomobject]@{ TargetFilePath = (Join-Path $dlDir 'unsigned_in.exe'); URL = 'http://evil.example.com/unsigned' },
        [pscustomobject]@{ TargetFilePath = (Join-Path $dlDir 'valid_in.exe'); URL = 'http://vendor.example.com/valid' },
        [pscustomobject]@{ TargetFilePath = (Join-Path $f5dir 'stage\hm_out.exe'); URL = 'http://evil.example.com/hm_out' }
    )
}
New-HuntFindings
$r4 = @($savedHF | Where-Object { $_.Rule -match 'Downloaded then executed' })
Check "F5: HashMismatch inside Downloads -> medium + 'binary MODIFIED after signing'" (@($r4 | Where-Object { "$($_.Entity)" -match 'hm_in\.exe$' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'binary MODIFIED after signing' }).Count -eq 1)
Check "F5: HashMismatch outside Downloads -> HIGH + 'binary MODIFIED after signing'" (@($r4 | Where-Object { "$($_.Entity)" -match 'hm_out\.exe$' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'binary MODIFIED after signing' }).Count -eq 1)
Check "F5: NotSigned in Downloads unchanged (high, unsigned wording)" (@($r4 | Where-Object { "$($_.Entity)" -match 'unsigned_in\.exe$' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'unsigned binary in Downloads' }).Count -eq 1)
Check "F5: signed Valid in Downloads unchanged (medium, 'signed (' wording)" (@($r4 | Where-Object { "$($_.Entity)" -match 'valid_in\.exe$' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'signed \(' }).Count -eq 1)

# ---- F7: R8 allowlist needs leaf AND system dir ----
$caseCsv = @{
    'sysmon_process_access' = @(
        [pscustomobject]@{ Time = '2026-10-05 16:00:00.000'; EventId = 10; SourceImage = 'C:\Users\Public\svchost.exe'; TargetImage = 'C:\Windows\system32\lsass.exe'; GrantedAccess = '0x1010'; CallTrace = 'UNKNOWN' },
        [pscustomobject]@{ Time = '2026-10-05 16:01:00.000'; EventId = 10; SourceImage = 'C:\Windows\System32\svchost.exe'; TargetImage = 'C:\Windows\system32\lsass.exe'; GrantedAccess = '0x1010'; CallTrace = 'ok' }
    )
}
New-HuntFindings
$r8 = @($savedHF | Where-Object { $_.Rule -match 'LSASS access' })
Check "F7: C:\Users\Public\svchost.exe opening lsass -> finding" (@($r8 | Where-Object { "$($_.Entity)" -match 'Public\\svchost\.exe$' }).Count -eq 1)
Check "F7: C:\Windows\System32\svchost.exe opening lsass -> allowed" (@($r8 | Where-Object { "$($_.Entity)" -match 'System32\\svchost\.exe$' }).Count -eq 0)

# ---- F8: R3 side-load system-dir match is drive-agnostic (D:) ----
$caseCsv = @{
    'amcache' = @(
        [pscustomobject]@{ Name = 'version.dll'; Path = 'D:\Windows\System32\version.dll' },
        [pscustomobject]@{ Name = 'version.dll'; Path = 'C:\Users\u\AppData\Roaming\version.dll' }
    )
}
New-HuntFindings
Check "F8: version.dll planted next to D:\Windows\System32 -> high finding" (@($savedHF | Where-Object { $_.Rule -match 'DLL side-load - planted' -and "$($_.Evidence)" -match 'D:\\Windows\\System32\\version\.dll' }).Count -eq 1)

# ============================================================================
# PART 3 - I4: escaper + New-VtLink single-quote seam
# ============================================================================
$i4 = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $i4 += $m.Value + "`r`n"
}
Invoke-Expression $i4
$esc = ConvertTo-HtmlEsc "x' onmouseover='evil"
Check "I4: escaper emits &#39; for single quotes" ($esc -match '&#39;')
Check "I4: escaper leaves no raw single quote" (-not ($esc -match "'"))
Check 'I4: escaper basics regression (angle, ampersand, double quote)' ((ConvertTo-HtmlEsc '<a>&"') -eq '&lt;a&gt;&amp;&quot;')
$link = New-VtLink "evil.com'.aabb"
Check "I4: quote payload reaches the VT href branch" ($link -match "^<a target='_blank' href='https://www\.virustotal\.com/gui/search/evil\.com&#39;\.aabb'>VT&nearr;</a>$")
$hrefVal = [regex]::Match($link, "href='([^']*)'").Groups[1].Value
Check "I4: href attribute value contains no unescaped quote" (-not ($hrefVal -match "'"))
Check "I4: escaper double-escape safe (&amp; stays &amp;)" ((ConvertTo-HtmlEsc 'a&b') -eq 'a&amp;b')

# ============================================================================
# PART 4 - static pins
# ============================================================================
Check "static F8: no C:-only windows regex remains" (-not ($src -match [regex]::Escape('^c:\\windows')))
$hits = [regex]::Matches($src, [regex]::Escape('(?i)^[a-z]:\\windows\\(system32|syswow64|sysnative)\\')).Count
Check "static F8+F7: drive-agnostic windows regex present at all sites (R3 + R8 + R36)" ($hits -eq 3)
Check "static F4: R29 uses separate dedupe tables" (($src.Contains('$r29SeenHi')) -and ($src.Contains('$r29SeenMed')) -and (-not ($src.Contains('$r29Seen ')))) 

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $f5dir -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
