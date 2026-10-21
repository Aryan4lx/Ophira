$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.50 - EID pack (Sysmon 25 tamper / 9 raw access / 19-21 WMI / 26 delete-detected / 16 config
# change -> hunt rules R30-R33) + the no-Sysmon conclusion spine (shimcache via AppCompatParser,
# per-instance execution artifacts: prefetch/amcache/BAM/shimcache, honest no-Sysmon messaging).
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
$fix = Join-Path ([IO.Path]::GetTempPath()) "ophira_v250_$stamp"
New-Item -ItemType Directory -Path $fix -Force | Out-Null

# ============================================================================
# PART 1 - static wiring
# ============================================================================
Check "collect: EID id list includes 9/16/19/26" ($src -match [regex]::Escape('$ids = @(1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25, 26)'))
Check "collect: EID 25 parse saved as sysmon_proc_tamper" (($src -match [regex]::Escape("Save-Rows -Name 'sysmon_proc_tamper' -Rows")) -and ($src -match [regex]::Escape('-Id @(25)')))
Check "collect: EID 9 parse saved as sysmon_raw_access" (($src -match [regex]::Escape("Save-Rows -Name 'sysmon_raw_access' -Rows")) -and ($src -match [regex]::Escape('-Id @(9)')))
Check "collect: EID 19/20/21 parse saved as sysmon_wmi" (($src -match [regex]::Escape("Save-Rows -Name 'sysmon_wmi' -Rows")) -and ($src -match [regex]::Escape('-Id @(19, 20, 21)')))
Check "collect: file-delete parse covers 23 AND 26" (($src -match [regex]::Escape('-Id @(23, 26)')) -and ($src -match 'EID 23/26 file deletions'))
Check "sortment: tamper/raw/wmi -> logs, shimcache -> artifacts" ((($src -match [regex]::Escape("'sysmon_proc_tamper' = 'logs'"))) -and ($src -match [regex]::Escape("'sysmon_raw_access' = 'logs'")) -and ($src -match [regex]::Escape("'sysmon_wmi' = 'logs'")) -and ($src -match [regex]::Escape("'shimcache' = 'artifacts'")))
Check "evidence index: entries for the three new CSVs + shimcache" ((($src -match [regex]::Escape("'sysmon_proc_tamper'              ="))) -and ($src -match [regex]::Escape("'sysmon_raw_access'               =")) -and ($src -match [regex]::Escape("'sysmon_wmi'                      =")) -and ($src -match [regex]::Escape("'shimcache'                       =")))
Check "verdict: high-rule regex includes R30/R31/R32 + hunt signal renders (v2.70 name)" (($src -match 'image tampering\|Direct volume access\|WMI event subscription') -and ($src -match [regex]::Escape('"Hunt techniques ($($huntHiRules.Count) fired)"')))
Check "weave: tamper + raw-access rows in the master timeline" (($src -match [regex]::Escape("weave 'sysmon_proc_tamper'")) -and ($src -match [regex]::Escape("weave 'sysmon_raw_access'")))
Check "coverage: execution-artifact spine row" ($src -match "Add-Cov 'Execution artifact spine \(prefetch/amcache/BAM/shimcache\)'")
Check "report: no-Sysmon recommendation follows the zero-footprint policy" (($src -match 'the conclusion is built from the execution-artifact spine') -and ($src -notmatch 'Deploy Sysmon with a community configuration'))
Check "setup: AppCompatParser in the catalog" ($src -match [regex]::Escape("Name = 'AppCompatParser'"))
Check "parse: shimcache + recentfilecache run via AppCompatParser" (($src -match [regex]::Escape("'AppCompatParser: shimcache (SYSTEM hive)'")) -and ($src -match [regex]::Escape('AppCompatParser: RecentFileCache')))
Check "parse_needed: shimcache row present" ($src -match "Artifact = 'shimcache\.csv'")

# focus engine
Check "focus: Tamper/RawDisk/Exec per-instance joins" ((($src -match [regex]::Escape("Tamper = @(& `$guidFilter 'sysmon_proc_tamper' `$gl `$pl)"))) -and ($src -match [regex]::Escape("RawDisk = @(& `$guidFilter 'sysmon_raw_access' `$gl `$pl)")) -and ($src -match [regex]::Escape("Exec = @(& `$execJoin)")))
Check "focus: execJoin sources = prefetch/amcache/bam/shimcache (no guid needed)" ($src -match [regex]::Escape("@('prefetch_index', 'prefetch_parsed', 'amcache', 'bam_lastexec', 'shimcache')"))
Check "focus: WMI subscriptions join per-instance persistence by guid" (($src -match [regex]::Escape("'autoruns_startup_folders', 'sysmon_wmi'")) -and ($src -match [regex]::Escape("sysmon_wmi' { 'WMI event subscription' }")))
Check "focus: red TAMPER chip before INJECT + dossier sections" ((($src -match [regex]::Escape('"TAMPER $('))) -and ($src -match 'if \(\$chip -match ''\^\(INJECT\|TAMPER\)''') -and ($src -match 'Process tampering detected by Sysmon') -and ($src -match [regex]::Escape('Execution artifacts ($($pd.Exec.Count')))
Check "focus: detail json persists Tamper/RawDisk/Exec" ((($src -match [regex]::Escape('Tamper = @($_.Tamper | Select-Object -First 25)'))) -and ($src -match [regex]::Escape('RawDisk = @($_.RawDisk | Select-Object -First 25)')) -and ($src -match [regex]::Escape('Exec = @($_.Exec | Select-Object -First 25)')))
Check "report: embed sections include tamper/raw/execution artifacts" ((($src -match [regex]::Escape("@('Process tampering (Sysmon EID 25)', 'Tamper'"))) -and ($src -match [regex]::Escape("@('Execution artifacts (prefetch/amcache/BAM/shimcache)', 'Exec'")))

# ============================================================================
# PART 2 - R30-R33 through the real New-HuntFindings
# ============================================================================
$mhf = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
$muwp = [regex]::Match($src, "(?s)function Test-IsUserWritablePath \{.*?\r?\n\}")
if (-not $mhf.Success -or -not $muwp.Success) { throw 'extract failed: New-HuntFindings/Test-IsUserWritablePath' }
$caseCsv = @{
    'sysmon_proc_tamper' = @(
        [pscustomobject]@{ Time = '2026-10-05 14:02:45.000'; Image = 'C:\Users\dev\AppData\Roaming\malware.exe'; Type = '1'; FileVersion = ''; Description = ''; Product = ''; User = 'DEV\dev'; ProcessId = '4812'; ProcessGuid = '{7a1f-aaaa}' }
    )
    'sysmon_raw_access' = @(
        [pscustomobject]@{ Time = '2026-10-05 14:03:00.000'; Image = 'C:\Users\Public\dumper.exe'; Device = '\Device\HarddiskVolume2'; User = 'DEV\dev'; ProcessId = '4242'; ProcessGuid = '{cccc}' },
        [pscustomobject]@{ Time = '2026-10-05 14:03:10.000'; Image = 'C:\Program Files\BackupTool\backup.exe'; Device = '\Device\HarddiskVolume1'; User = 'SYSTEM'; ProcessId = '900'; ProcessGuid = '{eeee}' },
        [pscustomobject]@{ Time = '2026-10-05 14:03:20.000'; Image = 'C:\Users\Public\dumper.exe'; Device = '\Device\HarddiskVolume2'; User = 'DEV\dev'; ProcessId = '4242'; ProcessGuid = '{cccc}' }
    )
    'sysmon_wmi' = @(
        [pscustomobject]@{ Image = 'C:\Users\dev\AppData\Roaming\malware.exe'; Name = 'EvilFilter'; Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60'; Destination = ''; Consumer = ''; Filter = ''; User = 'DEV\dev'; ProcessId = '4812'; ProcessGuid = '{7a1f-aaaa}' },
        [pscustomobject]@{ Image = 'C:\Users\dev\AppData\Roaming\malware.exe'; Name = ''; Query = ''; Destination = 'ActiveScriptEventConsumer'; Consumer = 'EvilConsumer'; Filter = ''; User = 'DEV\dev'; ProcessId = '4812'; ProcessGuid = '{7a1f-aaaa}' },
        [pscustomobject]@{ Image = 'C:\Windows\System32\svchost.exe'; Name = ''; Query = ''; Destination = ''; Consumer = 'EvilConsumer'; Filter = 'EvilFilter'; User = 'SYSTEM'; ProcessId = '900'; ProcessGuid = '{9abc}' }
    )
    'sysmon_events' = @(
        [pscustomobject]@{ TimeCreated = '2026-10-05 15:00:00'; Id = 16; Message = 'Sysmon configuration state changed' },
        [pscustomobject]@{ TimeCreated = '2026-10-05 15:00:01'; Id = 1; Message = 'process create ...' }
    )
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
$savedHF = @()
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:savedHF = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression ($muwp.Value + "`r`n" + $mhf.Value)
New-HuntFindings
$hf = $script:savedHF

$r30 = @($hf | Where-Object { $_.Rule -eq 'Process image tampering (hollowing)' })
Check "R30: high - Sysmon-detected image swap" (@($r30 | Where-Object { "$($_.Entity)" -match 'malware\.exe' -and $_.Severity -eq 'high' -and "$($_.Attck)" -eq 'T1055.012' }).Count -eq 1)

$r31 = @($hf | Where-Object { $_.Rule -eq 'Direct volume access (raw \\.\ read)' })
Check "R31: high - user-path reader" (@($r31 | Where-Object { "$($_.Entity)" -match 'dumper\.exe' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'credential theft' }).Count -eq 1)
Check "R31: deduped per image+device (repeat row gone)" (@($r31 | Where-Object { "$($_.Entity)" -match 'dumper\.exe' }).Count -eq 1)
Check "R31: medium - system-path backup tool" (@($r31 | Where-Object { "$($_.Entity)" -match 'backup\.exe' -and $_.Severity -eq 'medium' -and "$($_.Evidence)" -match 'verify expectation' }).Count -eq 1)

$r32 = @($hf | Where-Object { $_.Rule -eq 'WMI event subscription persistence' })
Check "R32: high - filter + consumer registered, deduped per name" (@($r32 | Where-Object { "$($_.Entity)" -eq 'EvilFilter' }).Count -eq 1 -and @($r32 | Where-Object { "$($_.Entity)" -eq 'EvilConsumer' }).Count -eq 1 -and $r32.Count -eq 2)
Check "R32: filter query + consumer destination in evidence" ((@($r32 | Where-Object { "$($_.Evidence)" -match 'InstanceModificationEvent' }).Count -eq 1) -and (@($r32 | Where-Object { "$($_.Evidence)" -match 'ActiveScriptEventConsumer' }).Count -eq 1))

$r33 = @($hf | Where-Object { $_.Rule -eq 'Sysmon configuration changed' })
Check "R33: high - EID 16 config change, emitted once" (@($r33 | Where-Object { $_.Severity -eq 'high' -and "$($_.Attck)" -eq 'T1562.001' }).Count -eq 1)

# ============================================================================
# PART 3 - Parse-mode wiring through static checks (functional run is a static
# match: the block reuses the real $runTool/$findTool helpers tested in v225)
# ============================================================================
Check "parse: shimcache guarded on SYSTEM.hiv presence + existing-CSV skip" (($src -match [regex]::Escape("Join-Path (Join-Path `$script:RawDir 'registry') 'SYSTEM.hiv'")) -and ($src -match [regex]::Escape("(Test-Path `$sysHiv) -and -not (Test-CaseCsv 'shimcache')")))

Write-Host ""
Write-Host "test_v250: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $fix -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 }
