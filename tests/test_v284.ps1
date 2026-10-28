# test_v284.ps1 - v2.84: execution stacking (byName/byPath) + known-bad regex pack + time-window ratio
# Part 1: Get-KnownBadRegexes pack sanity (parses, severity, why).
# Part 2: New-ExecStacks - byName multi-path stacking, byPath staging view, prefetch
#         no-extension normalization, '(unknown path)' bucketing, window ratio + skip path.
# Part 3: New-HuntFindings R49 (misplaced system binary via stacks) + R50 (regex pack hits,
#         cross-source dedupe).
# Part 4: structural wiring (regen order, CsvCatMap, anchor, verdict catch-all, maps, report).
$ErrorActionPreference = 'Stop'
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
$src = Get-Content -LiteralPath $repoScript -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function QuietLog { param($Message) }
$script:saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }

# ---- extract the real functions ----
foreach ($n in @('Get-InvariantDate', 'Get-KnownBadRegexes', 'New-ExecStacks')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) if ("$Name" -match '\.csv$') { $Name = "$Name" -replace '\.csv$', '' }; if ($null -eq $script:caseCsv[$Name]) { return @() }; return @($script:caseCsv[$Name]) }

# ============================================================================
# PART 1 - Get-KnownBadRegexes pack sanity
# ============================================================================
$pack = @(Get-KnownBadRegexes)
Check "kbpack: at least 20 patterns" ($pack.Count -ge 20)
$kbParseOk = $true
foreach ($p in $pack) {
    try { [void][regex]::Match('probe', $p.Pat) } catch { $kbParseOk = $false }
}
Check "kbpack: every pattern compiles" ($kbParseOk)
Check "kbpack: severities limited to high/medium" (@($pack | Where-Object { @('high', 'medium') -notcontains "$($_.Sev)" }).Count -eq 0)
Check "kbpack: every pattern carries a why" (@($pack | Where-Object { -not "$($_.Why)" }).Count -eq 0)
Check "kbpack: has the talk's svchost.exe.NNN catch" (@($pack | Where-Object { $_.Pat -match 'svchost\\\.exe\\\.' }).Count -ge 1)
Check "kbpack: double-extension rule present" (@($pack | Where-Object { $_.Pat -match 'jpe\?g\|png\|gif\|pdf' }).Count -ge 1)

# ============================================================================
# PART 2 - New-ExecStacks
# ============================================================================
$script:caseCsv = @{}
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ FullPath = 'C:\Windows\System32\svchost.exe'; Name = 'svchost.exe'; FileKeyLastWriteTimestamp = '2026-10-27 21:00:00' }
    [pscustomobject]@{ FullPath = 'C:\Program Files\Mozilla Firefox\firefox.exe'; Name = 'firefox.exe'; FileKeyLastWriteTimestamp = '2026-10-26 12:00:00' }
)
$script:caseCsv['shimcache_exec'] = @(
    [pscustomobject]@{ Path = 'C:\Recycle\svchost.exe'; Executed = 'yes'; LastModified = '2026-10-27 21:30:00' }
    [pscustomobject]@{ Path = '\device\harddiskvolume3\users\aryan\appdata\local\temp\tool.exe'; Executed = 'no'; LastModified = '2026-10-27 22:00:00' }
    [pscustomobject]@{ Path = 'C:\Recycle\dump.exe'; Executed = 'yes'; LastModified = '2026-10-27 21:40:00' }
)
$script:caseCsv['prefetch_parsed'] = @(
    [pscustomobject]@{ ExecutableName = 'TOTALLY-LEGIT'; RunCount = '3'; LastRun = '2026-10-27 21:15:00'; PreviousRun0 = '2026-10-01 09:00:00'; PreviousRun1 = ''; PreviousRun2 = ''; PreviousRun3 = ''; PreviousRun4 = ''; PreviousRun5 = ''; PreviousRun6 = '' }
)
$After = '2026-10-27 20:00'
$Before = '2026-10-27 23:00'
$script:CaseDir = Join-Path $env:TEMP "ophira_v284_case_$stamp"
New-ExecStacks
$bn = $script:saved['exec_stacks_byname']
$bp = $script:saved['exec_stacks_bypath']
$wr = $script:saved['exec_window_ratio']
$bnSvc = @($bn | Where-Object { $_.Name -eq 'svchost.exe' })[0]
Check "byname: svchost stacked from 2 locations" ($null -ne $bnSvc -and [int]$bnSvc.PathCount -eq 2)
Check "byname: device path normalized to C:" ("$($bnSvc.Paths)" -match '^C:\\Recycle' -and "$($bnSvc.Paths)" -match 'System32')
$bnTool = @($bn | Where-Object { $_.Name -eq 'tool.exe' })[0]
Check "byname: device-path row lands under normalized C: folder" ($null -ne $bnTool -and "$($bnTool.Paths)" -match '^C:\\users')
$bnLegit = @($bn | Where-Object { $_.Name -eq 'totally-legit.exe' })[0]
Check "byname: prefetch no-ext leaf gets .exe + unknown-path bucket" ($null -ne $bnLegit -and [int]$bnLegit.ExecCount -eq 2 -and "$($bnLegit.Paths)" -match 'unknown path')
$bpRec = @($bp | Where-Object { $_.Folder -match '^C:\\Recycle$' })[0]
Check "bypath: recycle folder carries 2 distinct names" ($null -ne $bpRec -and [int]$bpRec.NameCount -eq 2 -and "$($bpRec.Names)" -match 'dump\.exe' -and "$($bpRec.Names)" -match 'svchost\.exe')
$wrSvc = @($wr | Where-Object { $_.Name -eq 'svchost.exe' })[0]
Check "ratio: svchost in-window count 2 (amcache+shimcache stamps)" ($null -ne $wrSvc -and [int]$wrSvc.InWindow -eq 2)
$wrLegit = @($wr | Where-Object { $_.Name -eq 'totally-legit.exe' })[0]
Check "ratio: prefetch LastRun in-window + PreviousRun0 out-window" ($null -ne $wrLegit -and [int]$wrLegit.InWindow -eq 1 -and [int]$wrLegit.OutWindow -eq 1)
$wrFire = @($wr | Where-Object { $_.Name -eq 'firefox.exe' })
Check "ratio: out-of-window-only file excluded" ($wrFire.Count -eq 0)
$wrTool = @($wr | Where-Object { $_.Name -eq 'tool.exe' })[0]
Check "ratio: window-exclusive row gets Ratio = InWindow" ($null -ne $wrTool -and [int]$wrTool.OutWindow -eq 0 -and [double]$wrTool.Ratio -eq [double]$wrTool.InWindow)

# no window -> ratio skipped, stacks still built
$After = ''; $Before = ''
$script:saved = @{}
New-ExecStacks
Check "ratio: no window -> no exec_window_ratio output" ($null -eq $script:saved['exec_window_ratio'])
Check "ratio: stacks still saved without window" ($script:saved['exec_stacks_byname'].Count -gt 0)

# focus dossier window fallback
$ftDir = Join-Path $env:TEMP "ophira_v284_ft_$stamp"
New-Item -ItemType Directory -Path (Join-Path $ftDir 'focus') -Force | Out-Null
@{ TimeWindow = @{ From = '2026-10-27 20:00'; To = '2026-10-27 23:00' } } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ftDir 'focus\focus_terms.json')
$script:CaseDir = $ftDir
$script:saved = @{}
New-ExecStacks
Check "ratio: focus dossier TimeWindow used as fallback" ($null -ne $script:saved['exec_window_ratio'] -and $script:saved['exec_window_ratio'].Count -gt 0)

# ============================================================================
# PART 3 - New-HuntFindings R49 + R50
# ============================================================================
foreach ($n in @('Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}
$script:Verbosity = 2
$script:caseCsv = @{}
$script:caseCsv['exec_stacks_byname'] = @(
    [pscustomobject]@{ Name = 'svchost.exe'; ExecCount = 9; PathCount = 2; Paths = 'C:\Windows\System32; C:\Recycle'; Sources = '' }
    [pscustomobject]@{ Name = 'lsass.exe'; ExecCount = 4; PathCount = 1; Paths = 'C:\Windows\System32'; Sources = '' }
    [pscustomobject]@{ Name = 'notepad.exe'; ExecCount = 3; PathCount = 2; Paths = 'C:\Windows\System32; C:\Windows'; Sources = '' }
    [pscustomobject]@{ Name = 'dllhost.exe'; ExecCount = 6; PathCount = 1; Paths = '(unknown path)'; Sources = '' }
    [pscustomobject]@{ Name = 'explorer.exe'; ExecCount = 5; PathCount = 2; Paths = 'C:\Windows; C:\Windows\System32'; Sources = '' }
    [pscustomobject]@{ Name = 'csrss.exe'; ExecCount = 1; PathCount = 2; Paths = 'C:\Windows\System32; (unknown path)'; Sources = '' }
)
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ FullPath = 'C:\evil\mimikatz.exe'; Name = 'mimikatz.exe'; FileKeyLastWriteTimestamp = '' }
    [pscustomobject]@{ FullPath = 'C:\users\a\downloads\invoice.pdf.exe'; Name = 'invoice.pdf.exe'; FileKeyLastWriteTimestamp = '' }
    [pscustomobject]@{ FullPath = 'C:\evil\svchost.exe.rs'; Name = 'svchost.exe.rs'; FileKeyLastWriteTimestamp = '' }
    [pscustomobject]@{ FullPath = 'C:\tools\procdump.exe'; Name = 'procdump.exe'; FileKeyLastWriteTimestamp = '' }
)
$script:caseCsv['prefetch_parsed'] = @(
    [pscustomobject]@{ ExecutableName = 'MIMIKATZ'; RunCount = '1'; LastRun = ''; PreviousRun0 = ''; PreviousRun1 = ''; PreviousRun2 = ''; PreviousRun3 = ''; PreviousRun4 = ''; PreviousRun5 = ''; PreviousRun6 = '' }
)
$script:caseCsv['shimcache_exec'] = @(
    [pscustomobject]@{ Path = 'C:\clean\cleanapp.exe'; Executed = 'yes'; LastModified = '' }
)
$script:saved = @{}
New-HuntFindings
$hf = $script:saved['hunt_findings']
$r49 = @($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' })
Check "R49: svchost from non-system32 -> high finding" ($r49.Count -eq 1 -and "$($r49[0].Severity)" -eq 'high' -and "$($r49[0].Entity)" -eq 'svchost.exe')
Check "R49: evidence lists the misplaced path(s)" ("$($r49[0].Evidence)" -match 'C:\\Recycle')
Check "R49: system32-only lsass -> no finding" (@($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' -and "$($_.Entity)" -eq 'lsass.exe' }).Count -eq 0)
Check "R49: non-critical notepad multi-path -> no finding" (@($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' -and "$($_.Entity)" -eq 'notepad.exe' }).Count -eq 0)
Check "R49: prefetch-only system binary (unknown path) -> no finding" (@($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' -and "$($_.Entity)" -eq 'dllhost.exe' }).Count -eq 0)
Check "R49: unknown path never listed as misplaced evidence" (@($hf | Where-Object { "$($_.Evidence)" -match 'unknown path' }).Count -eq 0)
Check "R49: explorer.exe from C:\Windows root (its real home) -> no finding" (@($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' -and "$($_.Entity)" -eq 'explorer.exe' }).Count -eq 0)
Check "R49: mixed known+unknown paths still judged on the KNOWN one" (@($hf | Where-Object { "$($_.Rule)" -eq 'Misplaced system binary (stack view)' -and "$($_.Entity)" -eq 'csrss.exe' }).Count -eq 0)
$r50 = @($hf | Where-Object { "$($_.Rule)" -eq 'Known-bad name pattern' })
$r50Mimi = @($r50 | Where-Object { "$($_.Entity)" -eq 'mimikatz.exe' })
Check "R50: mimikatz.exe -> one deduped high finding" ($r50Mimi.Count -eq 1 -and "$($r50Mimi[0].Severity)" -eq 'high')
Check "R50: prefetch MIMIKATZ dedupes into the same row" ($r50Mimi.Count -eq 1)
$r50Pdf = @($r50 | Where-Object { "$($_.Entity)" -eq 'invoice.pdf.exe' })
Check "R50: double extension caught high" ($r50Pdf.Count -eq 1 -and "$($r50Pdf[0].Severity)" -eq 'high')
$r50Rs = @($r50 | Where-Object { "$($_.Entity)" -eq 'svchost.exe.rs' })
Check "R50: talk's svchost.exe.rs suffix caught high" ($r50Rs.Count -eq 1 -and "$($r50Rs[0].Severity)" -eq 'high')
$r50Pd = @($r50 | Where-Object { "$($_.Entity)" -eq 'procdump.exe' })
Check "R50: procdump medium (dual-use)" ($r50Pd.Count -eq 1 -and "$($r50Pd[0].Severity)" -eq 'medium')
Check "R50: clean name -> no finding" (@($r50 | Where-Object { "$($_.Entity)" -eq 'cleanapp.exe' }).Count -eq 0)
Check "R49/R50: ATT&CK T1036 tagged" (@($r49 + $r50 | Where-Object { "$($_.Attck)" -eq 'T1036' }).Count -ge 5)

# ============================================================================
# PART 4 - structural wiring
# ============================================================================
$rgIdx = $src.IndexOf("rgStep 'execution stacks' 'New-ExecStacks'")
$hfIdx = $src.IndexOf("rgStep 'hunt findings' 'New-HuntFindings'")
Check "wire: regen step registered" ($rgIdx -gt 0)
Check "wire: stacks step runs BEFORE hunt findings (R49 reads its csv)" ($rgIdx -gt 0 -and $hfIdx -gt $rgIdx)
Check "wire: CsvCatMap - three new derived artifacts" ($src.Contains("'exec_stacks_byname' = 'derived'; 'exec_stacks_bypath' = 'derived'; 'exec_window_ratio' = 'derived'"))
Check "wire: anchor switch - stacks -> hunt" ($src.Contains("'^(hunt_findings|exec_stacks|exec_window|recon_sessions|exec_tcorr)'"))
Check "wire: verdict catch-all carries both new high rules" ($src.Contains('|Misplaced system binary|Known-bad name pattern'))
Check "wire: R49 reads exec_stacks_byname" ($src.Contains("Import-CaseCsv 'exec_stacks_byname')"))
foreach ($k in @('exec_stacks_byname', 'exec_stacks_bypath', 'exec_window_ratio')) {
    Check "wire: desc + emptyWhy maps carry $k (2 spots)" (([regex]::Matches($src, "(?m)^\s+'$k'\s*=\s*'")).Count -ge 2)
}
Check "wire: report stacking h3 present" ($src.Contains('Execution stacks - one name, many paths (stack view)'))
Check "wire: report window h3 present" ($src.Contains('Investigation-window time-stacking (what ran ONLY inside the window)'))
Check "wire: report no-window note stays honest" ($src.Contains('a made-up window would fabricate signal'))
Check "wire: report imports for the three artifacts" ($src.Contains("Import-CaseCsv 'exec_stacks_byname.csv'") -and $src.Contains("Import-CaseCsv 'exec_stacks_bypath.csv'") -and $src.Contains("Import-CaseCsv 'exec_window_ratio.csv'"))
Check "wire: version bumped to 2.85" ($src.Contains('$ScriptVersion = "2.85"'))

# ============================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host "v2.84: all $pass checks passed" -ForegroundColor Green; exit 0 }
Write-Host "v2.84: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1
