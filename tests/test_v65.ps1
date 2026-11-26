# test_v65.ps1 - v6.4 hunt rules R63 (USB first-seen -> execution window), R64 (LSASS dump
# file created), R65 (hive dump / NTDS command heads), R66 (Defender / LSA PPL disabled via
# registry), R67 (scheduled task with suspicious action).
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check { param($name, $ok, $extra = '') if ($ok) { Write-Host "  [ok] $name" } else { Write-Host "  [FAIL] $name $extra" -ForegroundColor Red; $script:fails++ } }

# extract New-HuntFindings + Get-InvariantDate (R63 parses usb/prefetch/userassist times)
$mH = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
$mD = [regex]::Match($src, "(?s)function Get-InvariantDate \{.*?\r?\n\}")
Check 'extract New-HuntFindings' ($mH.Success)
Check 'extract Get-InvariantDate' ($mD.Success)

# stubs (house pattern)
$script:caseCsv = @{}
$script:savedRows = New-Object System.Collections.Generic.List[object]
$script:logLines = New-Object System.Collections.Generic.List[string]
function Import-CaseCsv { param($Name) if ($null -eq $script:caseCsv[$Name]) { return @() } return $script:caseCsv[$Name] }
function Save-Rows { param($Name, $Rows) foreach ($r in @($Rows)) { $script:savedRows.Add([pscustomobject]@{ Name = $Name; Row = $r }) } }
function Write-CaseLog { param($m) $script:logLines.Add("$m") }   # extra color arg lands in $args
function Test-IsUserWritablePath { param($p) return ($p -match '(?i)^c:\\users\\') }
function Get-KnownBadRegexes { return @() }   # R50 pack not under test here
$script:Verbosity = 2   # trace goes through Write-CaseLog stub (capturable)

Invoke-Expression $mD.Value
Invoke-Expression $mH.Value

# --- fixtures ---
$script:caseCsv['usb_devices'] = @(
    [pscustomobject]@{ DeviceKey = 'Disk\Ven_X'; FriendlyName = 'Evil Stick'; Serial = 'USBSER1'; LastWrite = '2026-11-26 12:00:00' }
    [pscustomobject]@{ DeviceKey = 'Disk\Ven_Y'; FriendlyName = 'Quiet Stick'; Serial = 'USBSER2'; LastWrite = '2026-11-26 13:00:00' }
    [pscustomobject]@{ DeviceKey = 'Disk\Ven_Z'; FriendlyName = 'Bad Time'; Serial = 'USBSER3'; LastWrite = 'not a date' }
)
$script:caseCsv['prefetch_parsed'] = @(
    # in window (Delta +5 min vs USBSER1)
    [pscustomobject]@{ File = 'a.pf'; App = 'evil.exe'; ExecutableName = 'evil.exe'; Count = '1'; LastRun = '2026-11-26 12:05:00' }
    # in window via a PREVIOUS run column (Delta +1 min)
    [pscustomobject]@{ File = 'b.pf'; App = 'other.exe'; ExecutableName = 'other.exe'; Count = '9'; LastRun = '2026-11-26 18:00:00'; PreviousRun0 = ''; PreviousRun1 = ''; PreviousRun2 = ''; PreviousRun3 = '2026-11-26 12:01:00' }
    # in window via the -2 min tolerance (Delta -1.5 min)
    [pscustomobject]@{ File = 'c.pf'; App = 'edge.exe'; ExecutableName = 'edge.exe'; Count = '1'; LastRun = '2026-11-26 11:58:30' }
    # out of window (nothing near USBSER1 or USBSER2)
    [pscustomobject]@{ File = 'd.pf'; App = 'far.exe'; ExecutableName = 'far.exe'; Count = '1'; LastRun = '2026-11-26 18:00:00' }
)
$script:caseCsv['userassist'] = @(
    [pscustomobject]@{ User = 'aryan'; Guid = 'x'; Kind = 'executable'; Entry = 'tool.exe'; RunCount = '3'; LastRun = '2026-11-26 12:10:00' }
    # non-executable kind must be ignored even inside the window
    [pscustomobject]@{ User = 'aryan'; Guid = 'y'; Kind = 'folder'; Entry = 'stuff'; RunCount = '0'; LastRun = '2026-11-26 12:09:00' }
)
$script:caseCsv['sysmon_file_create'] = @(
    [pscustomobject]@{ Time = '2026-11-26 10:00:00'; Image = 'C:\Temp\dumpit.exe'; TargetFilename = 'C:\Temp\lsass_1234.dmp'; Hash = '' }
    # benign file
    [pscustomobject]@{ Time = '2026-11-26 10:01:00'; Image = 'C:\Windows\System32\notepad.exe'; TargetFilename = 'C:\Users\aryan\Documents\report.docx'; Hash = '' }
    # duplicate lsass dump leaf (deduped)
    [pscustomobject]@{ Time = '2026-11-26 10:02:00'; Image = 'C:\Temp\dumpit.exe'; TargetFilename = 'C:\Windows\Temp\lsass_1234.dmp'; Hash = '' }
)
$script:caseCsv['security_proc_events'] = @(
    # R64 command surface: comsvcs MiniDump
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\rundll32.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 666 C:\Temp\d.bin full' }
    # R65: reg save
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\cmd.exe'; ParentProcess = 'C:\Users\aryan\evil.exe'; CommandLine = 'cmd.exe /c reg save HKLM\SAM C:\Temp\sam.hive' }
    # R65: secretsdump (the PROCESS is python - the tool name is only on the command line)
    [pscustomobject]@{ NewProcess = 'C:\Python\python.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'python.exe C:\Users\aryan\impacket\examples\secretsdump.py DOMAIN/user@dc1' }
    # R65: ntdsutil
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\ntdsutil.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'ntdsutil "ac i ntds" "ifm" "cr f C:\Temp\ntds" q q' }
    # R65 duplicate (same pattern + source -> deduped)
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\cmd.exe'; ParentProcess = 'C:\Users\aryan\evil.exe'; CommandLine = 'cmd.exe /c reg save HKLM\SECURITY C:\Temp\sec.hive' }
)
$script:caseCsv['sysmon_proc_create'] = @(
    [pscustomobject]@{ Time = '2026-11-26 10:03:00'; Image = 'C:\Windows\System32\rundll32.exe'; ParentImage = 'C:\Windows\System32\cmd.exe'; CommandLine = ''; OriginalFileName = 'rundll32.exe' }
)
$script:caseCsv['powershell_events'] = @(
    # R65 via 4104 script block
    [pscustomobject]@{ TimeCreated = '2026-11-26 10:04:00'; Id = 4104; Level = 'Verbose'; Message = '$null = reg.exe save hklm\system C:\backup\sys.hive' }
    # R64 via 4104 script block
    [pscustomobject]@{ TimeCreated = '2026-11-26 10:05:00'; Id = 4104; Level = 'Verbose'; Message = 'rundll32 comsvcs.dll, MiniDump 702 C:\Temp\p.dmp full' }
    # engine event - not a script block
    [pscustomobject]@{ TimeCreated = '2026-11-26 10:06:00'; Id = 400; Level = 'Info'; Message = 'Engine state changed' }
)
$script:caseCsv['sysmon_registry'] = @(
    # R66 hit: Defender disable write, value 1
    [pscustomobject]@{ Time = '2026-11-26 10:10:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware'; Details = 'DWORD (0x00000001)'; Image = 'C:\Temp\evil.exe' }
    # skip: value 0 = re-enable (GPO refresh writes these)
    [pscustomobject]@{ Time = '2026-11-26 10:11:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring'; Details = 'DWORD (0x00000000)'; Image = 'C:\Windows\system32\svchost.exe' }
    # R66 hit: RunAsPPL zeroed
    [pscustomobject]@{ Time = '2026-11-26 10:12:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'; Details = 'DWORD (0x00000000)'; Image = 'C:\Temp\evil.exe' }
    # skip: RunAsPPL set to 1 = enabling protection
    [pscustomobject]@{ Time = '2026-11-26 10:13:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\RunAsPPL'; Details = 'DWORD (0x00000001)'; Image = 'C:\Windows\system32\svchost.exe' }
    # skip: unparseable (empty) Details - direction unknown, never guessed
    [pscustomobject]@{ Time = '2026-11-26 10:14:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware'; Details = ''; Image = 'C:\Temp\evil.exe' }
    # skip: unrelated key
    [pscustomobject]@{ Time = '2026-11-26 10:15:00'; EventType = 'SetValue'; TargetObject = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideIcons'; Details = 'DWORD (0x00000001)'; Image = 'C:\Windows\explorer.exe' }
)
$script:caseCsv['security_task_install'] = @(
    # R67 hit: user-writable action path
    [pscustomobject]@{ Time = '2026-11-26 10:20:00'; Account = 'aryan'; TaskName = 'SysUpdateB'; Command = 'C:\Users\aryan\AppData\update.exe /q' }
    # R67 hit: LOLBin head
    [pscustomobject]@{ Time = '2026-11-26 10:21:00'; Account = 'SYSTEM'; TaskName = 'Enc'; Command = 'powershell.exe -nop -enc AAAAxxxx' }
    # skip: system32 binary
    [pscustomobject]@{ Time = '2026-11-26 10:22:00'; Account = 'SYSTEM'; TaskName = 'Legit'; Command = 'C:\Windows\System32\svchost.exe -k netsvcs' }
    # skip: empty action
    [pscustomobject]@{ Time = '2026-11-26 10:23:00'; Account = 'SYSTEM'; TaskName = 'NoCmd'; Command = '' }
    # R67 hit: rundll32 LOLBin, then same TaskName again (4702 update -> deduped)
    [pscustomobject]@{ Time = '2026-11-26 10:24:00'; Account = 'SYSTEM'; TaskName = 'Loader'; Command = 'rundll32.exe C:\Users\aryan\pay.dll,Start' }
    [pscustomobject]@{ Time = '2026-11-26 10:25:00'; Account = 'SYSTEM'; TaskName = 'Loader'; Command = 'rundll32.exe C:\Users\aryan\pay2.dll,Start' }
)
# every other Import-CaseCsv name returns @() from the stub - earlier rules stay quiet.

New-HuntFindings

$rows = @($script:savedRows.ToArray() | Where-Object { $_.Name -eq 'hunt_findings' } | ForEach-Object { $_.Row })

# --- R63 ---
$r63 = @($rows | Where-Object { "$($_.Rule)" -eq 'USB first-seen then execution trail' })
Check 'R63: exactly one finding (USBSER1 only)' ($r63.Count -eq 1) "got $($r63.Count)"
Check 'R63: medium severity + T1091' ("$($r63[0].Severity)" -eq 'medium' -and "$($r63[0].Attck)" -eq 'T1091')
Check 'R63: entity carries the serial' ("$($r63[0].Entity)" -eq 'USB USBSER1')
Check 'R63: 4 binaries in window' ("$($r63[0].Evidence)" -match '4 binary/binary binaries ran' -or "$($r63[0].Evidence)" -match '^4 binary')
Check 'R63: evidence lists top-3 nearest binaries' ("$($r63[0].Evidence)" -match 'other\.exe' -and "$($r63[0].Evidence)" -match 'edge\.exe' -and "$($r63[0].Evidence)" -match 'evil\.exe')
Check 'R63: 4th-nearest binary correctly truncated from evidence' ("$($r63[0].Evidence)" -notmatch 'tool\.exe')
Check 'R63: trace line' (@($script:logLines | Where-Object { $_ -match 'R63.*usb_devices: 1 device' }).Count -gt 0)

# --- R64 ---
$r64f = @($rows | Where-Object { "$($_.Rule)" -eq 'LSASS dump file created (Sysmon EID 11)' })
Check 'R64: one file finding (dup leaf deduped)' ($r64f.Count -eq 1) "got $($r64f.Count)"
Check 'R64: high + T1003.001 + dumping process in evidence' ("$($r64f[0].Severity)" -eq 'high' -and "$($r64f[0].Attck)" -eq 'T1003.001' -and "$($r64f[0].Evidence)" -match 'dumpit\.exe')
$r64c = @($rows | Where-Object { "$($_.Rule)" -eq 'LSASS dump via comsvcs MiniDump (command line)' })
Check 'R64: command surface 4688 + 4104 (2 findings)' ($r64c.Count -eq 2) "got $($r64c.Count)"
Check 'R64: command findings high T1003.001' (@($r64c | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Attck)" -eq 'T1003.001' }).Count -eq 2)
Check 'R64: trace line' (@($script:logLines | Where-Object { $_ -match 'R64.*-> 3 artifact' }).Count -gt 0)

# --- R65 ---
$r65rs = @($rows | Where-Object { "$($_.Rule)" -eq 'reg save hive dump command' })
Check 'R65: reg save 4688 + 4104 (2 findings, dup source deduped)' ($r65rs.Count -eq 2) "got $($r65rs.Count)"
Check 'R65: reg save medium T1003.002' (@($r65rs | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1003.002' }).Count -eq 2)
$r65sd = @($rows | Where-Object { "$($_.Rule)" -eq 'secretsdump command surface' })
Check 'R65: secretsdump high T1003' ($r65sd.Count -eq 1 -and "$($r65sd[0].Severity)" -eq 'high' -and "$($r65sd[0].Attck)" -eq 'T1003')
$r65nt = @($rows | Where-Object { "$($_.Rule)" -eq 'ntdsutil command surface' })
Check 'R65: ntdsutil high T1003.003' ($r65nt.Count -eq 1 -and "$($r65nt[0].Severity)" -eq 'high' -and "$($r65nt[0].Attck)" -eq 'T1003.003')
Check 'R65: trace line' (@($script:logLines | Where-Object { $_ -match 'R65.*-> 4 pattern/source hit' }).Count -gt 0)

# --- R66 ---
$r66 = @($rows | Where-Object { "$($_.Rule)" -match 'disabled via registry' })
Check 'R66: exactly 2 findings (defender + PPL)' ($r66.Count -eq 2) "got $($r66.Count): $(($r66 | ForEach-Object { $_.Rule }) -join '; ')"
Check 'R66: high + T1562.001' (@($r66 | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Attck)" -eq 'T1562.001' }).Count -eq 2)
Check 'R66: defender entity + PPL entity' (@($r66 | Where-Object { "$($_.Entity)" -eq 'DisableAntiSpyware' }).Count -eq 1 -and @($r66 | Where-Object { "$($_.Entity)" -eq 'RunAsPPL' }).Count -eq 1)
Check 'R66: evidence carries the written value' (@($r66 | Where-Object { "$($_.Evidence)" -match 'set to 1' }).Count -eq 1 -and @($r66 | Where-Object { "$($_.Evidence)" -match 'set to 0' }).Count -eq 1)
Check 'R66: trace line' (@($script:logLines | Where-Object { $_ -match 'R66.*2 disable write' }).Count -gt 0)

# --- R67 ---
$r67 = @($rows | Where-Object { "$($_.Rule)" -eq 'Scheduled task with suspicious action' })
Check 'R67: 3 findings (user-path + LOLBin + rundll32, Loader deduped)' ($r67.Count -eq 3) "got $($r67.Count)"
Check 'R67: medium + T1053.005' (@($r67 | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1053.005' }).Count -eq 3)
Check 'R67: why-texts present' (@($r67 | Where-Object { "$($_.Evidence)" -match 'user-writable path' }).Count -ge 1 -and @($r67 | Where-Object { "$($_.Evidence)" -match 'LOLBin' }).Count -ge 2)
Check 'R67: trace line' (@($script:logLines | Where-Object { $_ -match 'R67.*3 task' }).Count -gt 0)

# --- wiring: new rules visible in the storm-guard + report surfaces is covered by the
# shared suite pins (test_v279/v280a count trace blocks + literal highs from the same source)

Write-Host "test_v65: $(if ($fails -eq 0) { 'all checks passed' } else { 'FAILURES' }), $fails failed"
if ($fails -gt 0) { exit 1 }
