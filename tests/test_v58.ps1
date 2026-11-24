# Test v5.8: lateral-movement hunt rules R57 (PsExec-family 7045), R58 (Impacket/wmiexec
# signatures), R59 (remote privileged logon T3+4672) + verdict doors.
# House style: extract New-HuntFindings + helpers, stub the case CSV layer, Check().
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$Check = { param($name, $ok) $script:n++; if ($ok) { $script:pass++; Write-Host "[PASS] $name" } else { $script:fail++; Write-Host "[FAIL] $name" } }
$script:n = 0; $script:pass = 0; $script:fail = 0

function Get-Fn { param([string]$name)
    $m = [regex]::Match($src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $name failed" }
    return $m.Value
}
Invoke-Expression (Get-Fn 'Get-KnownBadRegexes')
Invoke-Expression (Get-Fn 'Get-LevenshteinDistance')
Invoke-Expression (Get-Fn 'Test-IsUserWritablePath')
Invoke-Expression (Get-Fn 'Get-InvariantDate')
Invoke-Expression (Get-Fn 'New-HuntFindings')

# ---- stub the case layer ----
$script:caseCsv = @{}
$script:saved = New-Object System.Collections.Generic.List[object]
function Import-CaseCsv { param($Name) $v = $script:caseCsv[$Name]; if ($null -eq $v) { return @() }; return @($v) }
function Test-CaseCsv { param($Name) return $null -ne $script:caseCsv[$Name] }
function Save-Rows { [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Name, $Rows) foreach ($r in $Rows) { $script:saved.Add($r) } }
function Write-CaseLog { [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($m, $c) }
function QuietLog { [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($m) }

function F { param($rule, $sev, $entity, $evidence, $attack) [pscustomobject]@{ Found = (Get-Date).ToString('u'); Rule = $rule; Severity = $sev; Entity = $entity; Attck = $attack; Evidence = $evidence } }

# ---- P1: R57 PsExec-family service installs ----
$script:caseCsv = @{
    'system_new_services' = @(
        [pscustomobject]@{ Time = '2026-11-21 10:00:00'; EventId = 7045; Service = 'PSEXESVC'; Binary = 'C:\PSTools\PSEXESVC.exe'; Account = 'CORP\admin'; StartType = 'auto' },
        [pscustomobject]@{ Time = '2026-11-21 10:05:00'; EventId = 7045; Service = 'PAExec'; Binary = 'C:\Windows\paexec.exe'; Account = 'CORP\admin'; StartType = 'auto' },
        [pscustomobject]@{ Time = '2026-11-21 10:10:00'; EventId = 7045; Service = 'Sysmon'; Binary = 'C:\Program Files\Sysmon\sysmon64.exe'; Account = 'SYSTEM'; StartType = 'auto' }
    )
}
$script:saved.Clear()
New-HuntFindings
$r57 = @($script:saved | Where-Object { $_.Rule -match 'PsExec-family' })
& $Check 'R57: PSEXESVC + PAExec flagged high (2 findings)' ($r57.Count -eq 2 -and -not (@($r57 | Where-Object { $_.Severity -ne 'high' })).Count)
& $Check 'R57: benign service install not flagged' (-not (@($script:saved | Where-Object { "$($_.Entity)" -eq 'Sysmon' })).Count)

# ---- P2: R58 Impacket/wmiexec signatures ----
$script:caseCsv = @{
    'security_proc_events' = @(
        [pscustomobject]@{ Time = '2026-11-21 11:00:00'; EventId = 4688; Account = 'CORP\admin'; NewProcess = 'cmd.exe'; CommandLine = 'cmd.exe  /Q /c whoami /all > C:\Windows\Temp\out.txt 2>&1'; ParentProcess = 'wmiprvse.exe' },
        [pscustomobject]@{ Time = '2026-11-21 11:05:00'; EventId = 4688; Account = 'SYSTEM'; NewProcess = 'rundll32.exe'; CommandLine = 'C:\Windows\TEMP\1A2B3C4D.bat'; ParentProcess = 'schtasks.exe' },
        [pscustomobject]@{ Time = '2026-11-21 11:10:00'; EventId = 4688; Account = 'CORP\admin'; NewProcess = 'powershell.exe'; CommandLine = 'powershell -c Get-Process'; ParentProcess = 'wmiprvse.exe' },
        [pscustomobject]@{ Time = '2026-11-21 11:15:00'; EventId = 4688; Account = 'Aryan'; NewProcess = 'cmd.exe'; CommandLine = 'cmd /c echo hello'; ParentProcess = 'explorer.exe' }
    )
}
$script:saved.Clear()
New-HuntFindings
$r58w = @($script:saved | Where-Object { $_.Rule -match 'Impacket wmiexec' })
$r58a = @($script:saved | Where-Object { $_.Rule -match 'Impacket atexec' })
$r58s = @($script:saved | Where-Object { $_.Rule -match 'WMI-spawned shell' })
& $Check 'R58: /Q /c cmdline flagged wmiexec high' ($r58w.Count -eq 1 -and $r58w[0].Severity -eq 'high')
& $Check 'R58: TEMP 8-hex .bat via schtasks flagged atexec high' ($r58a.Count -eq 1 -and $r58a[0].Severity -eq 'high')
& $Check 'R58: wmiprvse parent + shell flagged medium' ($r58s.Count -eq 1 -and $r58s[0].Severity -eq 'medium')
& $Check 'R58: plain local cmd not flagged' (-not (@($script:saved | Where-Object { "$($_.Entity)" -eq 'cmd.exe' -and $_.Rule -notmatch 'Impacket|WMI' })).Count)

# ---- P3: R59 remote privileged logon (4624 T3 + 4672 same LogonId) ----
$script:caseCsv = @{
    'security_auth_events' = @(
        [pscustomobject]@{ Time = '2026-11-21 12:00:00'; EventId = 4624; Account = 'CORP\admin'; AccountDomain = 'CORP'; SubjectAccount = '-'; SourceIp = '10.0.0.50'; LogonType = '3'; LogonId = '0xABC123' },
        [pscustomobject]@{ Time = '2026-11-21 12:00:01'; EventId = 4672; Account = 'CORP\admin'; AccountDomain = 'CORP'; SubjectAccount = 'CORP\admin'; SourceIp = ''; LogonType = ''; LogonId = '0xABC123' },
        [pscustomobject]@{ Time = '2026-11-21 12:05:00'; EventId = 4624; Account = 'CORP\guest'; AccountDomain = 'CORP'; SubjectAccount = '-'; SourceIp = '10.0.0.51'; LogonType = '3'; LogonId = '0xDEF456' },
        [pscustomobject]@{ Time = '2026-11-21 12:06:00'; EventId = 4624; Account = 'Aryan'; AccountDomain = 'DESKTOP'; SubjectAccount = '-'; SourceIp = ''; LogonType = '2'; LogonId = '0x111222' }
    )
}
$script:saved.Clear()
New-HuntFindings
$r59 = @($script:saved | Where-Object { $_.Rule -match 'Remote privileged logon' })
& $Check 'R59: T3 logon with matching 4672 flagged once' ($r59.Count -eq 1 -and $r59[0].Severity -eq 'medium')
& $Check 'R59: exactly 1 remote-privileged finding (T3-without-4672 and T2-local not flagged)' ($r59.Count -eq 1)

# ---- P4: verdict doors wired ----
& $Check 'door: PsExec-family floor 3' ($src.Contains("Add-Signal 'PsExec-family service install (EID 7045)' 3"))
& $Check 'door: Impacket floor 3' ($src.Contains("Add-Signal 'Impacket/wmiexec execution signature (4688)' 3"))
& $Check 'door: WMI-spawned shell floor 2' ($src.Contains("Add-Signal 'WMI-spawned shell (wmiprvse parent)' 2"))
& $Check 'door: remote privileged logon floor 2' ($src.Contains("Add-Signal 'Remote privileged logon (T3 + 4672)' 2"))
& $Check 'traces: R57/R58/R59 present' ($src.Contains('& $trace ''R57''') -and $src.Contains('& $trace ''R58''') -and $src.Contains('& $trace ''R59'''))

# ---- P5: rule names use HIGH literal (v280a literal-high extraction counts them) ----
& $Check 'R57 uses literal high' ($src.Contains("& `$find 'PsExec-family service install (EID 7045)' 'high'"))
& $Check 'R58 wmiexec uses literal high' ($src.Contains("& `$find 'Impacket wmiexec execution signature' 'high'"))
& $Check 'R58 atexec uses literal high' ($src.Contains("& `$find 'Impacket atexec execution signature' 'high'"))

Write-Host ""
Write-Host ("v5.8 checks: {0}/{1} passed, {2} failed" -f $script:pass, $script:n, $script:fail)
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
