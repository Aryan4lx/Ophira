# v6.8 design - hunt depth pack (DNS scoring, CI-blocklist tamper, 7045+T3 lateral join) + CI chore

Approved by user via ask_user_question: "Full hunt pack (Recommended)".

## Intent
Three hunt rules from the recorded Tier-2/3 backlog, all grounded in vendored Sigma rules
and existing case data shapes, plus the CI checkout@v4 (Node20 deprecation) bump.
No verdict-weight changes beyond adding the blocklist rule to the existing huntHi regex.

## R71 - DNS cache C2 scoring (dns_cache.csv: Entry/Data/Type/TimeToLive)
- Domain-shape gate: `^[a-z0-9\-\.]+\.[a-z]{2,}$` (skips IPs, non-domain entries);
  skip `in-addr.arpa` reverse rows; skip empty.
- Three tells, first per domain wins, dedup per domain:
  1. tunneling-shaped label (label > 40 chars, or hex-blob `^[0-9a-f]{32,}$`) -> medium
     'DNS tunneling-shaped query' T1071.004
  2. domain matches a Get-KnownBadRegexes pattern -> medium 'Known-bad pattern in DNS query'
     T1071.004
  3. public-suffix TLD in the Sigma sus_tld-family list (top xyz icu click rest buzz monster
     cam quest work country tk ml ga cf gq) -> info 'Suspicious-TLD DNS query' T1071.004
- No process attribution exists in the cache dump - that is why tunneling/bad-name are the
  medium tells and TLD-only is info (weak alone). Storm guard caps apply.

## R72 - vulnerable driver blocklist disable (high, T1685)
- Grounded: Sigma b8421346 registry_set_vulnerable_driver_blocklist_disable.yml
  (`\Control\CI\Config\VulnerableDriverBlocklistEnable`, NewValue `DWORD (0x00000000)`,
  level high, "Unlikely false positives") + sibling proc_creation rule 39a74164 (reg.exe add).
- Source A: sysmon_registry (EID 13) EventType SetValue + TargetObject endswith
  `\Control\CI\Config\VulnerableDriverBlocklistEnable` + Details zero
  (`0x00000000` / bare `0` / `0x0`) -> 'Vulnerable driver blocklist disabled (registry)' high.
  Value != 0 (e.g. 0x00000001) never flags - the disable is the event, not the key.
- Source B: command lines (security_proc_events/sysmon_proc_create CommandLine +
  powershell_events 4104-only Message) containing `vulnerabledriverblocklistenable` AND a
  write-zero tell (`/d 0` / `0x00000000` / `0x0`) -> 'Vulnerable driver blocklist write
  attempt (command line)' high; dedup per source.
- Verdict wiring: huntHi regex += `vulnerable driver blocklist` (floor-2 'Hunt techniques'
  signal, same path as R68/R64). No dedicated door.

## R73 - 7045 service install preceded by same-account network logon (medium, T1021.002)
- Collector: module 4.5 7045 parse gains `Acct` column (message tail
  `Account Name:\s+(.+?)\s*$` - Account Name is the last 7045 field). Additive CSV column;
  consumers (R57/R68/canary string-matches/entity switch) are field-based and safe.
- Join: for each 7045, find the 4624 LogonType 3 rows in security_auth_events with the same
  account (trim+lower), source IP non-empty/'-'/'LOCAL' excluded, whose time falls in
  [svcTime - 15 min, svcTime]; nearest wins. Times via Get-InvariantDate (MinValue skips).
- Account exclusions (house list): empty, system/local service/network service, dwm-N/umfd-N,
  window manager/font driver, machine `$`-suffix.
- Finding: 'Service install preceded by network logon (same account)' medium T1021.002,
  entity = account, evidence = service + binary + N min(s) before + source IP.
- Honest-zero on local workstations (no T3 logons / no 7045) - fixture-tested like the
  campaign ties.

## CI chore
- actions/checkout@v4 -> @v6 in .github/workflows/ci.yml + release.yml (Node20 runtime
  deprecation warnings; @v6 runs on node24).

## Non-goals
- No new CSVs, no coverage rows (all sources already collected + covered), no desc-map changes.
- No verdict doors: R71/R73 mediums ride the report/SIEM/entities paths (house precedent R62),
  R72 highs ride huntHi catch-all (R68 precedent).

## Acceptance
- tests/test_v69.ps1: R71 join positives/negatives/exclusions/window, R72 registry
  value-vs-1 negative + command-line surface + dedup, R73 three tells + skips + dedup,
  collector Acct pin, huntHi pin, trace pins.
- Pin updates: test_v279 trace blocks 61 -> 64; test_v280a literal-high += blocklist names;
  test_v220 huntHi-coverage pin += term.
- Version sweep 6.7 -> 6.8 (plain + escaped-regex v46-49/v400 forms).
- Full suite green; E2E -Mode Parse on OPHIRA_DESKTOP-88Q1H74_20261127_154513 (R73 DNS rules
  exercise on the 31 live cache rows; R71/R72 honest-zero locally); browser verify; release.
