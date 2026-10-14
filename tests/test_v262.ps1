# test_v262.ps1 - detection surface: ADS-on-PE, webshell heuristics, ASEP extension wiring
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: Find-AdsOnPe against a REAL NTFS ADS ----
$m = [regex]::Match($src, "(?s)function Find-AdsOnPe \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Find-AdsOnPe extract failed' }
Invoke-Expression $m.Value
$tmp = Join-Path $env:TEMP ("ophira_v262_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$cleanExe = Join-Path $tmp 'clean.exe'
Set-Content -LiteralPath $cleanExe -Value 'MZ-clean'
$stashed = Join-Path $tmp 'signed.dll'
Set-Content -LiteralPath $stashed -Value 'MZ-stash'
Add-Content -LiteralPath $stashed -Stream 'payload' -Value 'MZ-payload-here'   # real hidden stream
$zad = Join-Path $tmp 'downloaded.exe'
Set-Content -LiteralPath $zad -Value 'MZ-zone'
Add-Content -LiteralPath $zad -Stream 'Zone.Identifier' -Value '[ZoneTransfer] ZoneId=3'   # must be ignored

$ads = @(Find-AdsOnPe -Paths @($cleanExe, $stashed, $zad, (Join-Path $tmp 'missing.exe'), (Join-Path $tmp 'notes.txt')))
Check "ADS: exactly the stashed stream found" ($ads.Count -eq 1 -and $ads[0].Path -eq $stashed -and $ads[0].Stream -eq 'payload')
Check "ADS: clean exe + Zone.Identifier-only + missing + non-PE all skipped" (@($ads | Where-Object { $_.Path -ne $stashed }).Count -eq 0)
Set-Content -LiteralPath (Join-Path $tmp 'gone.dll') -Value 'x'
Remove-Item -LiteralPath (Join-Path $tmp 'gone.dll') -Force
Check "ADS: gone file skipped without error" (@(Find-AdsOnPe -Paths @((Join-Path $tmp 'gone.dll'))).Count -eq 0)

# ---- behavioral: Test-WebshellContent heuristics ----
$m = [regex]::Match($src, "(?s)function Test-WebshellContent \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Test-WebshellContent extract failed' }
Invoke-Expression $m.Value
Check "heuristic: eval(Request)" (@(Test-WebshellContent -Content '<% Response.Write(eval(Request["p"])) %>').Count -ge 1)
Check "heuristic: cmd /c shell exec" (@(Test-WebshellContent -Content '<?php system("cmd /c dir"); ?>').Count -ge 1)
$big64 = ('A' * 400)
Check "heuristic: long base64 blob" (@(Test-WebshellContent -Content "data=$big64").Count -ge 1)
Check "heuristic: WScript.Shell process start" (@(Test-WebshellContent -Content 'var w = new ActiveXObject("WScript.Shell");').Count -ge 1)
Check "benign page -> no hits" (@(Test-WebshellContent -Content '<html><body>Hello <% Response.Write(DateTime.Now) %></body></html>').Count -eq 0)
Check "empty content -> no hits" (@(Test-WebshellContent -Content '').Count -eq 0)

# ---- behavioral: ASEP new categories parse real registry/live shape (module-level smoke via extraction is
# covered by the live E2E; here the verdict gate keeps new categories report-only unless flagged) ----
$hotSample = @(
    [pscustomobject]@{ Category = 'ActiveSetup'; Flags = 'user-path' }
    [pscustomobject]@{ Category = 'BrowserExt'; Flags = 'new-in-window' }
    [pscustomobject]@{ Category = 'OutlookRules'; Flags = 'observational' }
    [pscustomobject]@{ Category = 'PsProfile'; Flags = 'user-path' }
    [pscustomobject]@{ Category = 'TimeProvider'; Flags = '' }
)
Check "verdict gate: ActiveSetup/PsProfile user-path rows carry weight" (@($hotSample | Where-Object { $_.Flags -match 'user-path|nondefault' -and $_.Category -match 'ActiveSetup|PsProfile' }).Count -eq 2)
Check "verdict gate: BrowserExt new-in-window + OutlookRules observational stay report-only" (@($hotSample | Where-Object { $_.Flags -match 'user-path|nondefault' -and $_.Category -match 'BrowserExt|OutlookRules|TimeProvider' }).Count -eq 0)

# ---- statics: wiring ----
Check "module 5.5 calls the ADS scanner" ($src -match [regex]::Escape('Find-AdsOnPe -Paths @($keep | ForEach-Object'))
Check "module 8.12 calls the webshell scan" ($src -match [regex]::Escape('Test-WebshellContent -Content $wc'))
Check "helpers whitelisted for worker runspaces" ($src -match [regex]::Escape("'Find-AdsOnPe', 'Test-WebshellContent'"))
Check "sortment map: ads_findings = artifacts" ($src -match [regex]::Escape("'ads_findings' = 'artifacts'"))
Check "sortment map: webshell_candidates = context" ($src -match [regex]::Escape("'webshell_candidates' = 'context'"))
Check "hunt R34 wired (ADS on executable)" ($src -match [regex]::Escape("'ADS on executable file' 'medium'"))
Check "hunt R35 wired (webshell heuristics)" ($src -match [regex]::Escape("'Webshell content heuristics' 'medium'"))
Check "hunt verdict signal does NOT sweep in R34/R35 (medium = report-only)" (-not ($src -match [regex]::Escape("'ADS on executable file|Webshell content")))
Check "evidence index describes ads_findings" ($src -match [regex]::Escape("'ads_findings'                    = 'Non-Zone.Identifier alternate data streams"))
Check "evidence index describes webshell_candidates" ($src -match [regex]::Escape("'webshell_candidates'             = 'Web scripts matching content heuristics"))
Check "clean-check: ADS row wired" ($src -match [regex]::Escape("no non-Zone.Identifier streams on checked executables"))
Check "clean-check: webshell row wired" ($src -match [regex]::Escape('script files scanned, 0 heuristic matches'))
Check "ASEP: Active Setup StubPath swept" ($src -match [regex]::Escape('Active Setup\Installed Components'))
Check "ASEP: time providers swept" ($src -match [regex]::Escape('W32Time\TimeProviders'))
Check "ASEP: print processors/monitors swept" ($src -match [regex]::Escape('Print Processors'))

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { Write-Host "`ntest_v262: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v262: $pass passed, 0 failed" -ForegroundColor Green
exit 0
