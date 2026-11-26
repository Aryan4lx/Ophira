# Hunting R&D research pass - 2026-11-26 (post v6.3)

Sources: the Sigma HQ rule set shipped inside `tools\endpoint\hayabusa\rules\` (two rules
credit 13Cubed directly), the Elastic detection-rules TOML inventory, and the 13Cubed
Windows Event Logs / Process Genealogy material they cite. A research subagent salvaged
the category inventory before timing out on slow egress; details below are from the
salvaged output plus in-session verification against our own collector shapes.

## Shipped this release (v6.3)

| Rule | Source | Implementation |
|------|--------|----------------|
| R61 Audit-CVE exploitation events | Sigma `f1c99d55` (critical), 13Cubed "CVEs in Windows Event Logs" | Module 4.10 collects Application log via provider filter `Microsoft-Windows-Audit-CVE` (`Get-FilteredEvents -Provider`); one high finding per row + verdict floor-3 door; report desc/emptyWhy rows; supertimeline weave |
| R62 System process wrong parent | Sigma `cf1c2cd4`, 13Cubed Process Genealogy v2 PDF | Reads `security_proc_events` (4688) + `sysmon_proc_create` (EID 1); Sysmon parent-path filter (System32/SysWOW64/Defender), SavService/ngen/MsMpEng leaf filters, null-parent filter; dedup across sources; medium finding, T1036.005 |

## Backlog (prioritized, with concrete sources)

Tier 1 - high value, data we already collect:

1. **First-time-seen USB device then execution trail** (Elastic `initial_access_exfiltration_first_time_seen_usb`). We have `usb_devices` + R5's gate; add a "USB mounted -> executable ran within N min" window rule. Needs a per-device first-seen timestamp (R5 already stores Serial/FriendlyName/InstallDate).
2. **LSASS dump file created** (Elastic `credential_access_lsass_memdump_file_created`). We have Sysmon EID 11 (file create) in `sysmon_file_events`; match `*.dmp` near lsass PID or `lsass*.dmp` names. Currently only EID 10 handle access (R10) covers LSASS.
3. **Dump registry hives / hive moved via SMB** (Elastic `dump_registry_hives`, `moving_registry_hive_via_smb`). 4688/4104 command head scan: `reg save`, `reg.exe save`, `secretsdump`, `.hive` on network paths. Fits the existing R50 known-bad regex pack (`Get-KnownBadRegexes`) - cheapest of all to add.
4. **Defender disabled via registry / LSASS PPL disabled** (Elastic `defender_disabled_via_registry`, `lsass_ppl_disabled_registry`). We collect `sysmon_registry` EID 13/14 but only scan Run keys; add DisableAntiSpyware + `MitigationOptions\*LsaPPL` value patterns.
5. **Scheduled-task creation with LOLBin or suspicious path** (Sigma scheduled-task creation/update rules). We have task-cache + EID 4698 via `security_task_install.csv` (collected); R45 reads cache only - wiring 4698 command line in is a small join.

Tier 2 - needs modest collector additions:

6. **DNS C2 categories** (Elastic dns TOMLs: `command_and_control_dns_rmm_domains_non_browser`, `susp_tld`, `tunneling_nslookup`). We collect `sysmon_dns` (EID 22) and R30 already scans it; add non-browser process + suspicious-TLD scoring rather than new collection.
7. **ADIDNS wildcard/WPAD/dnsnode creation** (Elastic `credential_access_adidns_wildcard/wpad_record/dnsnode_creation`). Requires DNS Server event log or 5140/5136 SACL events - collector change in module 3.x; only useful in domain cases.
8. **Kerberos correlation** (Elastic `lateral_movement_kerberos_correlation`). Join 4768/4769/4776 within a window per account - we have `security_kerberos.csv` already; a per-account burst rule distinct from R11's brute-force view.
9. **Run-key breadth** (Elastic `persistence_run_key_and_startup_broad`, `runtime_run_key_startup_susp_procs`, `via_hidden_run_key_valuename`). R14/R19 cover known key paths; broaden to the Elastic startup-folder + Active Setup value set.
10. **Code signing policy / test-signing toggles** (Elastic `code_signing_policy_modification_registry`, `codeintegrity unsigned driver/image`). We already ship `loldrivers_hits`; the registry half (CI32/CI64 Options `Enabled`=0) is a one-pattern scan on existing EID 13 data.

Tier 3 - big lifts, park until asked:

- Remote service installs via Winlog-side correlation (`lateral_movement_remote_service_installed_winlog`) - overlaps R21's 7045 view; the Elastic angle is joining 7045 with 4624 Type 3 from the same source.
- DCOM lateral (MMC20/HTA) command-head patterns - fold into the R50 pack as plain regexes (cheap) rather than a dedicated rule.
- Downloaded `.url`/`.lnk` shortcut files (Elastic `execution_downloaded_shortcut_files/url_file`) - needs MOTW/Zone.Identifier reads; collector addition, Windows 10 only for Mark-of-the-Web via zone identifier ADS.

## Lessons from the research pass

- "13Cubed pool" is not a rule repo - it is YouTube/PDF content cited BY Sigma/Elastic rules. The two rules in our own shipped Sigma set crediting him (Audit-CVE, wrong parent) were the concrete entry points; both are now ported.
- Direct raw.githubusercontent/web.archive egress from this box times out (killed the research subagent after 30 min); GitHub API + in-session web tools work. Fetch inventory via API, not raw clones.
- CveEventWrite in practice fires almost exclusively for CVE-2020-0601-class crypto-dll abuse; empty is the normal state, so the verdict door must stay floor-3-with-rows (it only fires when rows exist).
