# v6.9 design - three cheap hunt rules (existing data only)

User-approved scope: Kerberos per-account join, run-key breadth, testsigning/CodeIntegrity
scan. All read CSVs Ophira already collects; no collector changes, no new CSVs, no
verdict-weight changes beyond the existing hunt-high catch-all.

## R74 - Run-key write during collection window (+ hidden valuename)
Elastic: `persistence_run_key_and_startup_broad` (medium-ish 47) +
`persistence_via_hidden_run_key_valuename` (high 73, path-ends-with-backslash shape).
- Source: `sysmon_registry` (EID 13; EventType/TargetObject/Details/Image).
- Run-path match on TargetObject:
  `\\(Microsoft\\Windows\\CurrentVersion\\Run(Once)?|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?|Policies\\Explorer\\Run)\\`
- Broad write (EventType set|create): finding
  **'Run-key write during collection window'** medium T1547.001 - attribution = Image.
- Hidden shape (TargetObject ends with `\` or contains `\0` - the null-terminated
  valuename trick regedit cannot display properly): finding
  **'Hidden run-key valuename write'** high T1547.001.
- Dedup per TargetObject|Image; storm guard caps floods.
- FP note: legitimate installers write Run values - medium report-only is deliberate
  (honesty-over-signal-volume); only the hidden shape weighs high and nothing benign
  uses it.

## R75 - Non-Kerberos process to port 88 followed by ticket issue
Elastic: `lateral_movement_credential_access_kerberos_correlation` (high 73, EQL
sequence by source.ip maxspan 3s).
- Sources: `sysmon_network` (DestPort/DestPortName/SourceIp/Image) +
  `security_kerberos` (4768/4769; Account/IpAddress; DC-only data).
- Network side: DestPort 88 (or DestPortName 'kerberos'), process leaf not
  lsass.exe/svchost.exe/wininit.exe, destination/source not loopback/link-local.
- Auth side: 4768/4769 with same IpAddress within 5 min of the connection (relaxed from
  Elastic's 3s for log-granularity + collector caps).
- Finding: **'Kerberos ticket issued after non-standard process connection'** medium
  T1558, evidence names the process, account, DC IP and the gap.
- Honest-zero on workstations (4768/4769 live on DCs - existing coverage text says so).

## R76 - Test-signing / integrity checks disabled (command surface)
Elastic: `code_signing_policy_modification_registry` family; the concrete gap is that
`bcdedit ... testsigning|nointegritychecks` is scanned nowhere today (R72 only covers
VulnerableDriverBlocklistEnable).
- Sources: `security_proc_events` + `sysmon_proc_create` CommandLine,
  `powershell_events` 4104-only Message.
- Patterns (bounded gaps, value pinned to yes|on|1 so `/enum` chatter never matches):
  `bcdedit ... testsigning (yes|on|1)` -> **'Test-signing enabled (bcdedit)'** high
  T1553.002; `bcdedit ... nointegritychecks (yes|on|1)` ->
  **'Integrity checks disabled (bcdedit)'** high T1553.002.
- Dedup per source; high rides the huntHi catch-all (house pattern).

## Wiring
- Insert R74/R75/R76 after the R73 trace (Ophira.ps1 ~L13215), before the v2.87 storm
  guard; `$huntHi` regex += 'Hidden run-key valuename write|Test-signing enabled|Integrity
  checks disabled' + comment.
- Tests: new `tests\test_v70.ps1` (test_v69 harness pattern), RED first.
- Pins expected to drift: test_v279 trace blocks 64->67, test_v280a literal-highs
  33->35, test_v220 huntHi term list.
- Version 6.8 -> 6.9 (header + $ScriptVersion + plain + escaped pin sweeps),
  CHANGELOG section, E2E on the 20261127 case, browser verify, release.
