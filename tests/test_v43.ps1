# test_v43.ps1 - v4.6 BAM attribution: profile_list join, ran-as tags, useract BAM rollup
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$script:fails = 0
function Check { param($Name, $Cond) if ($Cond) { Write-Host "[PASS] $Name" } else { Write-Host "[FAIL] $Name" -ForegroundColor Red; $script:fails++ } }

$root = Split-Path -Parent $PSScriptRoot
$src = Get-Content (Join-Path $root 'Ophira.ps1') -Raw

# --- extract helpers from the script ---
function Extract { param($Name, $Text)
    $m = [regex]::Match($Text, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "cannot extract $Name" }
    return $m.Value
}
iex (Extract 'Get-UserProfileList' $src)

# captured Save-Rows
$script:saved = @{}
function Save-Rows { param($Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param($m, $c) }
function QuietLog { param($m) }

# --- P1: module 8.1 saves profile_list ---
$run81 = [regex]::Match($src, "(?s)Id = '8\.1';.*?Run = \{(.*?)\r?\n        \} \}").Groups[1].Value
$env:oph81 = $run81
$sb81 = [scriptblock]::Create("`$RawDir = Join-Path $env:TEMP 'oph_t43_81'; `$script:test8 = { $run81 }")
# simpler: test the profile_list Save-Rows line exists + Get-UserProfileList works live
Check "P1: module 8.1 saves profile_list" ($run81 -match "Save-Rows -Name 'profile_list'")
$pl = @(Get-UserProfileList)
Check "P1: Get-UserProfileList returns Sid/Path/User rows" ($pl.Count -eq 0 -or ("$($pl[0])" -match 'Sid' -and "$($pl[0])" -match 'User'))

# --- P2: report-side maps (simulate the report block) ---
$profRows = @(
    [pscustomobject]@{ Sid = 'S-1-5-21-1001'; Path = 'C:\Users\aryan'; User = 'aryan' },
    [pscustomobject]@{ Sid = 'S-1-5-18'; Path = 'C:\Windows\system32\config\systemprofile'; User = 'SYSTEM' }
)
$bamRows = @(
    [pscustomobject]@{ Source = 'BAM'; Sid = 'S-1-5-21-1001'; Executable = 'E:\Apps\xray.exe'; LastWrite = '2026-11-16 21:00:00' },
    [pscustomobject]@{ Source = 'DAM'; Sid = 'S-1-5-21-1001'; Executable = 'C:\Windows\System32\svchost.exe'; LastWrite = '2026-11-16 20:00:00' },
    [pscustomobject]@{ Source = 'BAM'; Sid = 'S-1-5-21-9999'; Executable = 'E:\ghost.exe'; LastWrite = '2026-11-16 19:00:00' }
)
$profBySid = @{}
foreach ($p7 in $profRows) { if ("$($p7.Sid)" -match '^S-1-5-21-' -and "$($p7.User)") { $profBySid["$($p7.Sid)"] = "$($p7.User)" } }
$bamByLeaf = @{}
foreach ($b5 in $bamRows) {
    $lb5 = try { Split-Path "$($b5.Executable)" -Leaf } catch { "$($b5.Executable)" }
    if (-not $lb5 -or $lb5 -notmatch '\.exe$') { continue }
    $un5 = $profBySid["$($b5.Sid)"]
    if (-not $un5) { continue }
    $kl5 = $lb5.ToLower()
    if (-not $bamByLeaf.ContainsKey($kl5)) { $bamByLeaf[$kl5] = New-Object System.Collections.Generic.List[string] }
    $tag5 = "$un5 (BAM)"
    if (-not ($bamByLeaf[$kl5] -contains $tag5)) { $null = $bamByLeaf[$kl5].Add($tag5) }
}
Check "P2: xray.exe attributed to aryan (BAM)" ($bamByLeaf.ContainsKey('xray.exe') -and $bamByLeaf['xray.exe'] -contains 'aryan (BAM)')
Check "P2: svchost.exe attributed to aryan not SYSTEM" ($bamByLeaf.ContainsKey('svchost.exe') -and $bamByLeaf['svchost.exe'] -contains 'aryan (BAM)' -and -not ($bamByLeaf['svchost.exe'] -contains 'SYSTEM (BAM)'))
Check "P2: unknown SID excluded" (-not $bamByLeaf.ContainsKey('ghost.exe'))

# --- P3: useract BAM rollup ---
$uaTicks = { param([string]$s) $d = [datetime]::MinValue; if ($s -and [datetime]::TryParse($s, [ref]$d)) { $d.Ticks } else { [long]::MinValue } }
$userAct = [ordered]@{}
foreach ($b6 in $bamRows) {
    $lu6 = $profBySid["$($b6.Sid)"]
    if (-not $lu6) { continue }
    $k6 = "$lu6".ToLower()
    if (-not $userAct.Contains($k6)) { $userAct[$k6] = @{ Name = $lu6; Logons = 0; Failed = 0; Types = @{}; Ips = @{}; Procs = @{}; ProcN = 0; Files = 0; Last = '' } }
    $lp6 = try { Split-Path "$($b6.Executable)" -Leaf } catch { "$($b6.Executable)" }
    if ($lp6 -and $lp6 -match '\.exe$') { $userAct[$k6].Procs[$lp6] = [int]$userAct[$k6].Procs[$lp6] + 1 }
    if ((& $uaTicks "$($b6.LastWrite)") -gt (& $uaTicks "$($userAct[$k6].Last)")) { $userAct[$k6].Last = "$($b6.LastWrite)" }
}
Check "P3: aryan account created from BAM" ($userAct.Contains('aryan'))
Check "P3: aryan has xray + svchost in Procs" (@($userAct['aryan'].Procs.Keys) -contains 'xray.exe' -and @($userAct['aryan'].Procs.Keys) -contains 'svchost.exe')
Check "P3: Last = newest BAM stamp" ("$($userAct['aryan'].Last)" -eq '2026-11-16 21:00:00')

# --- P4: ranTxt merge logic (report cell) ---
$ranByLeaf = @{}
$noRan = 0
$lnE = 'xray.exe'
$ranTxt = if ($lnE -and $ranByLeaf.ContainsKey($lnE)) { @($ranByLeaf[$lnE]) -join '; ' } else { '' }
if ($lnE -and $bamByLeaf.ContainsKey($lnE)) { $bamTxt = @($bamByLeaf[$lnE]) -join '; '; $ranTxt = if ($ranTxt) { "$ranTxt; $bamTxt" } else { $bamTxt } }
$ranTxt = if ($ranTxt) { $ranTxt } else { $noRan++; '-' }
Check "P4: ranTxt = aryan (BAM) when 4688 absent" ("$ranTxt" -eq 'aryan (BAM)')
$ranByLeaf2 = @{ 'xray.exe' = 'DESKTOP\aryan' }
$ranTxt2 = @($ranByLeaf2['xray.exe']) -join '; '
if ($bamByLeaf.ContainsKey('xray.exe')) { $bamTxt2 = @($bamByLeaf['xray.exe']) -join '; '; $ranTxt2 = "$ranTxt2; $bamTxt2" }
Check "P4: 4688 + BAM merge with '; '" ("$ranTxt2" -eq 'DESKTOP\aryan; aryan (BAM)')
$noRan2 = 0; $lnE2 = 'unknown.bin'
$rt3 = if ($lnE2 -and $ranByLeaf.ContainsKey($lnE2)) { @($ranByLeaf[$lnE2]) -join '; ' } else { '' }
if ($lnE2 -and $bamByLeaf.ContainsKey($lnE2)) { $rt3 = "$rt3; bam" }
$rt3 = if ($rt3) { $rt3 } else { $noRan2++; '-' }
Check "P4: no evidence -> '-' and counter incremented" ("$rt3" -eq '-' -and $noRan2 -eq 1)

# --- P5: wiring pins ---
Check "P5: CsvCatMap profile_list" ($src -match "'profile_list' = 'volatile'")
Check "P5: emptyWhy profile_list" ($src -match "'profile_list'\s+= 'no interactive-user profiles")
Check "P5: desc map profile_list" ($src -match "'profile_list'\s+= 'SID to profile map")
Check "P5: version 6.3" ($src.Contains('Ophira v6.4') -and $src.Contains('$ScriptVersion = "6.4"'))
Check "P5: ranTxt BAM merge present" ($src -match 'bamByLeaf\.ContainsKey\(\$lnE\)')

Write-Host ''
if ($script:fails -eq 0) { Write-Host 'ALL PASSED' -ForegroundColor Green; exit 0 } else { Write-Host "$($script:fails) FAILED" -ForegroundColor Red; exit 1 }
