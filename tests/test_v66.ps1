# test_v66.ps1 - v6.5 hunt rules R68 (7045 service binary) + R69 (run-key LOLBin+tell) + R70 (DCOM lateral surface).
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check { param($name, $ok, $extra = '') if ($ok) { Write-Host "  [ok] $name" } else { Write-Host "  [FAIL] $name $extra" -ForegroundColor Red; $script:fails++ } }

# extract New-HuntFindings body (house pattern)
$m = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
Check 'extract New-HuntFindings' ($m.Success)

# stubs
$script:caseCsv = @{}
$script:savedRows = New-Object System.Collections.Generic.List[object]
$script:logLines = New-Object System.Collections.Generic.List[string]
function Import-CaseCsv { param($Name) if ($null -eq $script:caseCsv[$Name]) { return @() } return $script:caseCsv[$Name] }
function Save-Rows { param($Name, $Rows) foreach ($r in @($Rows)) { $script:savedRows.Add([pscustomobject]@{ Name = $Name; Row = $r }) } }
function Write-CaseLog { param($m) $script:logLines.Add("$m") }   # extra color arg lands in $args
function Test-IsUserWritablePath { param($p) return ($p -match '(?i)^c:\\users\\') }
function Get-KnownBadRegexes { return @() }
$script:Verbosity = 2

Invoke-Expression $m.Value

# --- fixtures ---
# R68: 7045 service installs (Time/Service/Binary/Type)
$script:caseCsv['system_new_services'] = @(
    # LOLBin binary -> high
    [pscustomobject]@{ Time = '2026-11-26 10:00:00'; Service = 'CmdSvc'; Binary = 'C:\Windows\System32\cmd.exe /c powershell -enc AAAA'; Type = 'NewService' }
    # user-writable binary -> medium
    [pscustomobject]@{ Time = '2026-11-26 10:01:00'; Service = 'EvSvc'; Binary = 'C:\Users\aryan\AppData\evil.exe -k net'; Type = 'NewService' }
    # legit System32 binary -> silent
    [pscustomobject]@{ Time = '2026-11-26 10:02:00'; Service = 'LegitSvc'; Binary = 'C:\Windows\System32\svchost.exe -k netsvcs'; Type = 'NewService' }
    # vendor path, quoted -> silent (not user-writable per stub)
    [pscustomobject]@{ Time = '2026-11-26 10:03:00'; Service = 'QuotedSvc'; Binary = '"C:\Program Files\Vendor\svc.exe" -run'; Type = 'NewService' }
    # duplicate CmdSvc -> deduped per service name
    [pscustomobject]@{ Time = '2026-11-26 10:04:00'; Service = 'CmdSvc'; Binary = 'C:\Windows\System32\cmd.exe /c powershell -enc AAAA'; Type = 'NewService' }
    # empty binary -> skipped
    [pscustomobject]@{ Time = '2026-11-26 10:05:00'; Service = 'EmptySvc'; Binary = ''; Type = 'NewService' }
)
# R69: run keys (Location/Hive/User/Name/Value)
$script:caseCsv['autoruns_runkeys'] = @(
    # LOLBin head + hidden/encoded tells -> flagged
    [pscustomobject]@{ Location = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run'; Hive = 'HKU'; User = 'S-1-5-21-1'; Name = 'Updater'; Value = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -nop -enc SQBFAFgA' }
    # LOLBin head + UNC payload tell -> flagged
    [pscustomobject]@{ Location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Hive = 'HKLM'; User = ''; Name = 'UncPs'; Value = 'powershell.exe -nop \\dc1\share\x.ps1' }
    # LOLBin head, NO tell -> silent (the cmd /c sc delete vendor shape)
    [pscustomobject]@{ Location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Hive = 'HKLM'; User = ''; Name = 'PlainCmd'; Value = 'cmd.exe /c sc delete APSPDriver' }
    # user path but not a LOLBin head -> silent (the OneDrive FP case)
    [pscustomobject]@{ Location = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run'; Hive = 'HKU'; User = 'S-1-5-21-1'; Name = 'OneDrive'; Value = 'C:\Users\aryan\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background' }
    # duplicate Updater -> deduped per Location|Name
    [pscustomobject]@{ Location = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run'; Hive = 'HKU'; User = 'S-1-5-21-1'; Name = 'Updater'; Value = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -nop -enc SQBFAFgA' }
)
# R70: DCOM lateral command surface
$script:caseCsv['security_proc_events'] = @(
    [pscustomobject]@{ Time = '2026-11-26 11:00:00'; Account = 'aryan'; NewProcess = 'C:\Windows\System32\rundll32.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'rundll32.exe doc.RunHTA payload' }
    [pscustomobject]@{ Time = '2026-11-26 11:01:00'; Account = 'aryan'; NewProcess = 'C:\Windows\System32\notepad.exe'; ParentProcess = 'C:\Windows\System32\explorer.exe'; CommandLine = 'notepad.exe' }
    # duplicate RunHTA in the same source -> deduped per pattern|source
    [pscustomobject]@{ Time = '2026-11-26 11:02:00'; Account = 'aryan'; NewProcess = 'C:\Windows\System32\rundll32.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'rundll32.exe doc.RunHTA again' }
)
$script:caseCsv['sysmon_proc_create'] = @(
    [pscustomobject]@{ Time = '2026-11-26 11:05:00'; Image = 'C:\Windows\System32\cmd.exe'; ParentImage = 'C:\Windows\System32\wmiprvse.exe'; OriginalFileName = 'cmd.exe'; CommandLine = 'cmd.exe /c tool ExecuteShellCommand whoami' }
)
$script:caseCsv['powershell_events'] = @(
    # 4104 with MMC20.Application -> flagged
    [pscustomobject]@{ TimeCreated = '2026-11-26 11:10:00'; Id = 4104; Level = 'Information'; Message = '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.0.0.5"))' }
    # non-4104 row with the same string -> skipped (kind filter)
    [pscustomobject]@{ TimeCreated = '2026-11-26 11:11:00'; Id = 4103; Level = 'Information'; Message = 'module load MMC20.Application' }
    # duplicate MMC20 4104 -> deduped per pattern|source
    [pscustomobject]@{ TimeCreated = '2026-11-26 11:12:00'; Id = 4104; Level = 'Information'; Message = 'again MMC20.Application remote 10.0.0.6' }
)

New-HuntFindings

$rows = @($script:savedRows.ToArray() | Where-Object { $_.Name -eq 'hunt_findings' } | ForEach-Object { $_.Row })

# --- R68 ---
$r68 = @($rows | Where-Object { "$($_.Rule)" -match '\(7045\)' })
Check 'R68: exactly 2 findings (LOLBin high + writable medium, rest silent, deduped)' ($r68.Count -eq 2) "got $($r68.Count)"
$r68hi = @($r68 | Where-Object { "$($_.Rule)" -eq 'LOLBin service binary (7045)' })
Check 'R68: cmd.exe binary -> high LOLBin finding on CmdSvc' ($r68hi.Count -eq 1 -and $r68hi[0].Entity -eq 'CmdSvc' -and "$($r68hi[0].Severity)" -eq 'high') "got $($r68hi.Count)"
Check 'R68: attack T1543.003 + evidence carries the binary' ("$($r68hi[0].Attck)" -eq 'T1543.003' -and "$($r68hi[0].Evidence)" -match 'cmd\.exe /c powershell')
$r68med = @($r68 | Where-Object { "$($_.Rule)" -eq 'Service binary from user-writable path (7045)' })
Check 'R68: user-writable binary -> medium on EvSvc' ($r68med.Count -eq 1 -and $r68med[0].Entity -eq 'EvSvc' -and "$($r68med[0].Severity)" -eq 'medium')
Check 'R68: svchost/vendor/empty never flag' (@($r68 | Where-Object { $_.Entity -match 'LegitSvc|QuotedSvc|EmptySvc' }).Count -eq 0)

# --- R69 ---
$r69 = @($rows | Where-Object { "$($_.Rule)" -eq 'Autostart Run key with suspicious command' })
Check 'R69: exactly 2 findings (tells only)' ($r69.Count -eq 2) "got $($r69.Count)"
Check 'R69: entity = LOLBin leaf lowercase' (@($r69 | Where-Object { $_.Entity -eq 'powershell.exe' }).Count -eq 2)
Check 'R69: evidence carries value name + location' (@($r69 | Where-Object { "$($_.Evidence)" -match 'Updater' -and "$($_.Evidence)" -match 'CurrentVersion\\Run' }).Count -eq 1)
Check 'R69: UNC tell flagged' (@($r69 | Where-Object { "$($_.Evidence)" -match 'dc1\\share' }).Count -eq 1)
Check 'R69: no-tell cmd /c sc delete silent' (@($r69 | Where-Object { "$($_.Evidence)" -match 'sc delete' }).Count -eq 0)
Check 'R69: OneDrive user path not LOLBin -> silent' (@($r69 | Where-Object { "$($_.Evidence)" -match 'OneDrive' }).Count -eq 0)
Check 'R69: attack T1547.001 medium' (@($r69 | Where-Object { "$($_.Attck)" -eq 'T1547.001' -and "$($_.Severity)" -eq 'medium' }).Count -eq 2)

# --- R70 ---
$r70 = @($rows | Where-Object { "$($_.Rule)" -match 'DCOM ' })
Check 'R70: exactly 3 findings (one per pattern, deduped per source)' ($r70.Count -eq 3) "got $($r70.Count)"
Check 'R70: MMC20 from 4104' (@($r70 | Where-Object { "$($_.Rule)" -match 'MMC20' -and $_.Entity -eq 'powershell_events' -and "$($_.Evidence)" -match 'GetTypeFromProgID' }).Count -eq 1)
Check 'R70: RunHTA from 4688 proc' (@($r70 | Where-Object { "$($_.Rule)" -match 'RunHTA' -and $_.Entity -eq 'security_proc_events' }).Count -eq 1)
Check 'R70: ExecuteShellCommand from sysmon' (@($r70 | Where-Object { "$($_.Rule)" -match 'ExecuteShellCommand' -and $_.Entity -eq 'sysmon_proc_create' }).Count -eq 1)
Check 'R70: all medium T1021.003' (@($r70 | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1021.003' }).Count -eq 3)
Check 'R70: non-4104 powershell row skipped' (@($r70 | Where-Object { "$($_.Evidence)" -match 'module load' }).Count -eq 0)

# --- trace lines ---
$tr68 = @($script:logLines | Where-Object { $_ -match '^R68 ' })
$tr69 = @($script:logLines | Where-Object { $_ -match '^R69 ' })
$tr70 = @($script:logLines | Where-Object { $_ -match '^R70 ' })
Check 'trace: R68 line with counts' ($tr68.Count -eq 1 -and "$tr68" -match '2 service')
Check 'trace: R69 line with counts' ($tr69.Count -eq 1 -and "$tr69" -match '2 entry')
Check 'trace: R70 line with counts' ($tr70.Count -eq 1 -and "$tr70" -match '3 pattern/source')

# --- wiring pins in the script source ---
Check 'wiring: huntHi regex carries the R68 high' ($src -match 'LOLBin service binary\|')
Check 'wiring: R68 literal high + medium rule names' ($src.Contains('& $find ''LOLBin service binary (7045)'' ''high''') -and $src.Contains('& $find ''Service binary from user-writable path (7045)'' ''medium'''))
Check 'wiring: R69 tell regex present' ($src -match '-w hidden\|-nop')
Check 'wiring: no new CSV sources (sources stay 34)' (-not ($src -match "Save-Rows -Name '(r68|r69|r70)"))

Write-Host ''
if ($fails -eq 0) { Write-Host 'test_v66: ALL CHECKS PASSED' -ForegroundColor Green } else { Write-Host "test_v66: $fails CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
