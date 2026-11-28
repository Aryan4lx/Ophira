# Ophira

**One PowerShell script** (5.1+, zero dependencies) for Windows incident response: collect evidence on an endpoint, push it across a fleet, analyze the results, and fetch companion tools.

## Vision & positioning

Built first for the **MSSP / fleet responder**: triage endpoints across many clients with no server, no agent, no console to buy. The one-liner: *KAPE's speed, Velociraptor's scale awareness, and a verdict neither gives you - from one file.*

- **The judgment step neither tool gives you**: every case ends with a deterministic verdict (rules + weighted signals + honest coverage - never a probability, never an LLM), per-host fleet rollups, and campaign clustering that answers "which hosts are ONE intrusion" across a fleet.
- **Zero infrastructure**: copy the script, run it, hand the report to a human. Optional REST-delivered analysis stays out of the judgment path (see ADR-0006); client-safe `-Redact` copies and a machine-readable `ophira_findings.json` per case make results deliverable and ingestable.
- **Honest scoping**: Windows endpoints only (a choice, see ADR-0005); pre-Win7 hosts get a dumb-collector shim later - parsing always happens on the analyst box.

## Get the kit

Three ready-to-run kits ship with every release (`SHA256SUMS` carries the hash of every asset). Pick the one that fits the job:

| Asset | Size | What's inside |
|---|---|---|
| `Ophira-vX.Y.zip` | <1 MB | script + `RUN-OPHIRA.bat` + docs - no tools |
| `Ophira-vX.Y-lite.zip` | ~34 MB | + hayabusa (incl. Sigma rules), the EZ parsers, LOLDrivers, winpmem |
| `Ophira-vX.Y-bundle.zip` | ~113 MB | + everything: chainsaw, YARA, vol3, SQLECmd, SrumECmd |

- **Bundle** is the out-of-the-box kit: collection, all offline parsing, memory triage and verdict work with zero downloads. If you might be offline - or need to email a kit to a first responder - take this one.
- **Lite** covers collection plus a standard `-Mode Parse` (filesystem, execution-timeline and Sigma evidence). chainsaw/YARA/vol3/SQLECmd can be fetched later with `-Mode Setup`.
- **Script-only** is the code-only kit. Pure-PowerShell collection works with no tools at all - every parser that needs a missing tool logs and skips, and the report's coverage table shows exactly what is missing (never a crash). `-Mode Setup` downloads whatever the case needs from official sources.

Long file paths in the bundled rule packs exceed Windows' 260-char ZIP limit in some locations, so extract with `tar -xf` or 7-Zip - **not** Explorer's built-in extractor:

```
tar -xf Ophira-v6.5-bundle.zip
```

`git clone` remains the reliable path for the full repo. A belt-and-braces `Get-ChildItem -Recurse | Unblock-File` on the extracted folder clears any mark-of-the-web the download carried (`RUN-OPHIRA.bat` unblocks the script itself regardless).

**Read-only by design** - never kills processes, never deletes files, never modifies the system. Only reads and copies.

## One script, every role covered

```powershell
# COLLECT (default) - triage the machine this runs on:
.\Ophira.ps1                                        # interactive: flash triage + module menu
.\Ophira.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
.\Ophira.ps1 -NoMenu -Preset Quick -SharePath \\IR-SRV\collections$
.\Ophira.ps1 -SimpleUI                              # owner-friendly guided run (what the .bat uses)

# DEPLOY - push the kit to remote hosts over WinRM (parallel, 8 by default):
.\Ophira.ps1 -Mode Deploy -ComputerName SRV01,SRV02 -Preset Quick -Credential (Get-Credential)
.\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -MaxThreads 16
.\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -PushTools   # Kansa-style: push hayabusa, run, remove after

# TIME WINDOW - limit log analysis to the timeframe that matters (default 168h = 7 days):
.\Ophira.ps1 -NoMenu -LogWindow 30d        # hours (168), days (30d), months (3m), 0 = all, or a start date
.\Ophira.ps1 -NoMenu -LogStart '2026-09-01 08:00' -LogEnd '2026-09-15 20:00'   # exact range

# DELTA - re-run later and see only what CHANGED (pseudo-monitoring without an agent):
.\Ophira.ps1 -NoMenu -Preset Standard           # auto-diffs against the newest previous OPHIRA_*.zip
.\Ophira.ps1 -NoMenu -Preset Quick -DeltaPath .\old-case.zip

# ANALYZE - merge any number of OPHIRA_*.zip into one fleet view (+ Sigma timeline):
.\Ophira.ps1 -Mode Analyze -AnalyzePath .\collections

# SETUP / LINKS / UPDATERULES / TUNE / PARSE:
.\Ophira.ps1 -Mode Setup -SetupTools hayabusa,AmcacheParser,RBCmd,loldrivers
.\Ophira.ps1 -Mode Links
.\Ophira.ps1 -Mode UpdateRules       # refresh hayabusa Sigma rules
.\Ophira.ps1 -Mode Tune              # pick noisy Sigma rules -> exclude/demote (travels with -PushTools)
.\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip   # finish a case on YOUR pc
.\Ophira.ps1 -Mode Focus -ParsePath .\OPHIRA_HOST_20260926_120000.zip -ProcessName evil.exe   # build the activity chain of one entity
#   (Focus accepts a name, PID, path, hash, IP, ip:port or port; -Mode Process is kept as an alias)
.\Ophira.ps1 -Mode Watch                            # live diff while a sample detonates (Ctrl+C to stop)
.\Ophira.ps1 -Mode SeedIocs -SeedValue <hash|ip|domain>   # validate + dedupe + append to tools\iocs.txt
.\Ophira.ps1 -Mode Parse -ParsePath <case> -ExitVerdict    # exit code = verdict rank (2/3/4 = alert)
```

**Owner handoff:** send the whole folder. They double-click `RUN-OPHIRA.bat`, accept UAC, wait 3-5 minutes. A folder window opens with the result file selected and its path is copied to the clipboard - they paste it into an email. If you pre-fill `ophira.config.txt` (SHARE=/CASE=/ANALYST=), results upload to your share automatically and there's literally nothing to send. Pre-fill `LOGWINDOW=30d` (or `LOGSTART=`/`LOGEND=` for an exact range) to widen the analysis window beyond the default 7 days - the owner's DONE screen prints the resolved range (`Checked: Last 30d`) so you can confirm it took.

## Run it headless: one-liners

Everything also runs without the TUI. Hand these to RMM agents, scheduled tasks, wrappers - or just paste them into a terminal. The only prompts you will ever see are the ones marked; `ophira.config.txt` pre-fills SHARE/CASE/ANALYST/LOGWINDOW so even these lines can run zero-argument. Add `-ExitVerdict` to any verdict-producing run and the process exit code carries the verdict rank (2 = SUSPICIOUS, 3 = LIKELY COMPROMISED, 4 = COMPROMISED, 0 = clean/not assessed), so a scheduler can sort hosts without reading reports.

### Collect this PC, unattended

```
.\Ophira.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
```

**What:** one command, zero clicks - Standard-depth collection (3-5 min) into `OPHIRA_<host>_<stamp>`, ending with the evidence zip, report.html and verdict. **Why:** this is the line you embed in GPO, an RMM agent, or paste to a first responder over chat. **When:** any collection you don't want to babysit. Tune depth with `-Preset Flash|Quick|Standard|Full`, widen the log analysis with `-LogWindow 30d`, push results to your share with `-SharePath \\SRV\collections$`, and run from a limited account with `-NoElevate` (skips show honestly in the coverage table).

### Finish a case on the analyst PC

```
.\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip -ExitVerdict
```

**What:** re-runs every raw-driven parser (Amcache, LECmd, SQLECmd, chainsaw, hayabusa, memory) over the case's `raw\` evidence and rebuilds supertimeline, verdict, SIEM export and report.html. **Why:** endpoints can collect Flash/Quick; heavy analytics happen later on YOUR hardware using tools\analyst. **When:** a case zip arrives by email or lands in your share - or whenever hunt rules improved, since re-parse upgrades old cases. Without `-ParsePath` it prompts for the newest case (marked prompt #1).

### Push-and-run across the fleet

```
.\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -PushTools -Credential (Get-Credential)
```

**What:** copies the script (plus tools\endpoint with `-PushTools`) to each host over WinRM, collects unattended in parallel (`-MaxThreads 8` default), pulls finished case zips back, removes itself. **Why:** N machines, one command - endpoints parse their own evidence when tools ride along. **When:** an incident with known scope; short lists can use `-ComputerName SRV01,SRV02`. Prompts once for credentials (marked prompt #2).

### Merge the fleet into one view

```
.\Ophira.ps1 -Mode Analyze -AnalyzePath .\collections
```

**What:** merges every `OPHIRA_*.zip` in the folder into `fleet_report.html` - per-host verdicts, worst-first ranking, fleet ATT&CK roll-up, cross-host campaign clustering. **Why:** one verdict is a story; twenty are a campaign (mass-deploy vs mass-infection, shared binaries, lateral chains). **When:** after a Deploy wave, or any time cases pile up in a share.

### One entity, full dossier

```
.\Ophira.ps1 -Mode Focus -ParsePath <case> -ProcessName evil.exe
```

**What:** the activity chain of ONE entity - seed with a name, PID, path, hash, IP, ip:port or port and it iteratively expands across every CSV into `focus\focus_report.html`; `-After`/`-Before` bound the window. **Why:** "what did THIS do" beats reading a 22-finding report linearly. **When:** triaging a specific hunt hit. `-Mode Timeline -TimelineStart/-TimelineEnd` cuts the master timeline to a UTC window the same way.

### Client-safe handoff

```
.\Ophira.ps1 -Mode Share -ParsePath <case> -Redact -ShareZip
```

**What:** builds the client-safe bundle - analyst-side files stripped, hosts/users/internal IPs/MACs tokenized (the map stays with you), the redacted report swapped in, one zip to attach. **Why:** clients don't need raw evidence or their users' names in a report. **When:** MSSP/customer hand-off.

### Install or update tools

```
.\Ophira.ps1 -Mode Setup        # ENTER = all; -SetupTools hayabusa,winpmem for a list
.\Ophira.ps1 -Mode UpdateRules  # refresh the Sigma rule pack
```

**What:** downloads companion tools into tools\ from their official sources (receipts recorded); `-Mode Links` prints the download pages only. **Why:** the script-only kit ships no tools by design - this fills the gaps. **When:** you took the script-only or lite zip and now need chainsaw/YARA/vol3/SQLECmd, or you want fresher Sigma rules.

### Prove the pipeline works

```
.\Ophira.ps1 -Mode Canary
```

**What:** plants harmless labeled test activity, runs the whole detect - parse - verdict chain over it, prints a FIRED/MISS/BLIND scorecard. **Why:** "tools downloaded" is not "detection works". **When:** after Setup, after rule updates, and before you trust the kit on a real case. Cousins: `-Mode Watch` (live read-only diff while a sample detonates), `-Mode Tune` (quiet noisy Sigma rules), `-Mode Help` (the full parameter reference).

## Interactive launcher (role gate + task menu)

Running `.\Ophira.ps1` bare (no flags) first asks **who is using the tool**:

- `[1] Run - check this PC now` - the full guided collection (Standard preset, UAC, about 5 minutes) ending in the friendly DONE screen: verdict, report path, zip to send to the IR team. `[2] Advanced mode` - **task menu**: collect this PC - push & run on remote PCs - analyze collected results - setup tools - update rules - **tune Sigma rules** - tool links - **finish a collected case (analyst-side parse)** - **focus on one entity (build its activity chain)**. Deploy and Analyze are guided wizards (targets, credentials, depth, share - plain questions with `[defaults]`, confirm summary, then the existing parallel engine runs). Deploy has an **advanced options** prompt (Full depth, log analysis window, host parallelism). Analyze auto-detects a single case (folder or zip) and finishes it analyst-side (parse + regenerate) instead of asking for the fleet merge. After each task you return to the menu.
- `[2] User` â†' the guided automatic owner flow (same as the .bat).

Flags always win: `-SimpleUI`, `-NoMenu`, or any explicit `-Mode` skips the gate entirely, so automation and `RUN-OPHIRA.bat` behave exactly as before. Non-interactive sessions never see the gate.

`ophira.config.txt` keys:

| Key | Effect |
|---|---|
| `SHARE=` / `CASE=` / `ANALYST=` | collect-mode defaults (as before) |
| `LOGWINDOW=` | analysis window for every collection from this folder (`30d`, `3m`, `90h`, `0` = all, or a start date) - **pre-fill before owner handoff**; default 7d |
| `LOGSTART=` / `LOGEND=` | explicit analysis range (e.g. `2026-09-20`, wins over `LOGWINDOW`) |
| `LOGHOURS=` | plain-hours alias for the window (e.g. `720`) |
| `ROLE=responder\|owner` | pre-selects the gate - never asked |
| `TARGETS=` | deploy wizard default (host list or `hosts.txt`) |
| `PRESET=Quick\|Standard` | deploy wizard depth default |
| `PUSHTOOLS=yes\|no` | deploy wizard hayabusa push default |
| `DEPLOYSHARE=` | deploy wizard upload share default |
| `THREADS=` | deploy parallelism default |

Wizard answers are remembered only when you answer **y** to "Remember these answers?" at the end of a deploy - they become the `[defaults]` shown next time.

## Collect mode

1. **Flash triage (auto, ~15s)** - process anomalies with **correlation scoring** (LOW/MEDIUM/HIGH verdicts), public IP connections, DNS/ARP, SMB + saved credentials, Defender last detection, **IOC matching**
2. **Deep modules** (menu or presets `Flash|Quick|Standard|Full`):
   - VOLATILE - processes, full hashing, connections, DNS+ARP, sessions, drivers
   - PERSISTENCE - Run keys, startup folders, services, scheduled tasks, WMI subscriptions, **ASEP deep sweep** (IFEO debuggers incl. sticky-keys, AppInit_DLLs, Winlogon Shell/Userinit/Notify, HKCU COM hijack suspects, netsh helpers, LSA packages, StartupApproved stamps â†' `asep_sweep.csv` with flags)
   - NETWORK MAP - interfaces, reachable subnets, SMB, saved creds, Kerberos, proxy/WPAD, opt-in active probes, **firewall profiles + `pfirewall.log` copy**
   - LOGS - Security (4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected, **EID 3 network + EID 22 DNS**), RDP, System 7045, raw evtx export, **detection pack** (hayabusa Sigma timeline with MITRE ATT&CK tags + HTML + logon summary with RDP sessions + **base64/obfuscated PowerShell command recovery**), **YARA scan of flagged/user-path binaries** (bundled rule pack, drop your own `*.yar` into `tools\yara\rules\`), **C2 beaconing analysis** (periodicity/jitter/regularity on Sysmon network **and DNS** events â†' `beacon_candidates.csv` + `dns_beacon_candidates.csv`, feeds verdict + report)
   - ARTIFACTS - Prefetch (copied **+ parsed run counts via PECmd**), registry hives (SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM, **chainsaw execution timeline + SRUM + evtx gap detection**, **NTFS forensics** (live `$MFT` filtered executable inventory + **USN journal ransomware-burst detection** with suspicious-extension matching via MFTECmd, **all fixed NTFS drives**)
   - CONTEXT - **attacker activity** (PowerShell console history, RDP client targets, recycle bin), **LNK + Jump Lists** (raw save + parse via LECmd/JLECmd), **ShellBags** (folder-browsing history via SBECmd), **browser artifacts** (Chrome/Edge raw save **+ SQLECmd parse**: history/downloads/searches + **IOC domain cross-check**), **certificate store inventory** (T1553: recent/self-signed root CAs flagged), **security posture audit** (LSA protection, SMBv1, RDP+NLA, PowerShell logging, UAC, Defender exclusions, BitLocker, WinRM â†' `posture.csv`), **LOLDrivers hash check** (all drivers SHA256-hashed Ã- malicious/vulnerable datasets â†' `loldrivers_hits.csv`, malicious = verdict signal), **user registry saves** (NTUSER.DAT/UsrClass.dat all profiles), **coverage & context** (Sysmon config, task XML, BITS jobs, domain info), **EZ parsers** (AmcacheParser execution inventory with SHA1Ã-IOC cross-check, RBCmd)
   - DEFENDER - detections, exclusions, status, operational log
   - MEMORY - optional RAM capture (winpmem), optional Volatility 3 quick pass (pslist/cmdline/svcscan + **malfind** â†' verdict signal + netscan on hits)
3. **Packaging** - SHA256 manifest (per file + package + script self-hash + tool inventory), `case.json`, **compromise verdict** (`verdict.json`: 5-level verdict + coverage-weighted confidence + signals + caveats), `report.html`, **supertimeline.csv** (all events merged chronologically), **delta_new.csv** (new findings vs previous collection), **siem_export.ndjson** (Splunk/Elastic-ready records incl. verdict/beacon/mass-modification), **attack_layer.json** (MITRE ATT&CK Navigator layer - load at navigator.mitre.org), **logging_gaps.csv** (log cleared/stopped + evtx gap tamper check), ZIP

## Endpoint vs analyst-side parsing

The bundled forensic parsers run **on the endpoint during collection** so the case zip arrives with ready-made CSVs, verdict and report. Their inputs are **also preserved raw**, so anything the endpoint couldn't finish (tool missing, .NET too old, module skipped, non-admin) can be finished on your PC:

```
.\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip
```

One command re-runs the raw-driven parsers from *your* kit (AmcacheParser, RBCmd, PECmd, LECmd, JLECmd, SQLECmd + chainsaw + the hayabusa detection pack) against the case's `raw\` evidence, then regenerates supertimeline, verdict, SIEM export and `report.html`. Zip inputs are repacked in place.

Every collection also writes **`csv\parse_needed.csv`**: for each missing artifact it names the parser, the .NET requirement, whether the raw evidence is even in the zip, and the exact way to finish it - so ".NET 9 missing on endpoint" is never confused with "module skipped". `case.json` records the endpoint's .NET inventory (`DotNet`).

| Parser | .NET need | Raw input shipped in the zip |
|---|---|---|
| AmcacheParser / RBCmd / PECmd / LECmd / JLECmd / SBECmd / MFTECmd | .NET 4.x (OS-built-in on Win8.1+) | yes (except MFTECmd: live-volume only) |
| SQLECmd | .NET 9 desktop runtime (often absent - parse analyst-side) | yes (`raw\browser\`) |
| hayabusa / chainsaw (Rust) | none | yes (`raw\evtx\`, `raw\registry\`) |

Full NTFS preservation: the `Full` preset additionally keeps the **unfiltered** `mft_full_<drive>.csv` / `usn_full_<drive>.csv` under `raw\analysis\` (auto-skipped if the endpoint has <10 GB free) - big servers on Standard stay lean, deep dives get everything.

## Compromise verdict (v2.6)

Every collection ends with `Get-CompromiseVerdict` correlating all findings into one call:

- **5 levels**: `COMPROMISED` â†' `LIKELY COMPROMISED` â†' `SUSPICIOUS` â†' `NO EVIDENCE OF COMPROMISE` â†' `INCONCLUSIVE`
- **Signal floors** - amcache IOC hit or high/critical YARA hit forces COMPROMISED; live IOC hit, critical Sigma, **C2 beaconing (high)** or **USN ransomware-style mass file modification** force â‰¥ LIKELY COMPROMISED; critical Sigma / HIGH process verdict / Defender history / log-tamper events / **uncommon persistence (IFEO/AppInit/Winlogon/netsh/LSA)** / **memory malfind** / **IOC domain in browser history** force â‰¥ SUSPICIOUS; two independent strong signals escalate to LIKELY COMPROMISED
- **Confidence %** = weighted coverage of evidence sources actually collected (volatile, persistence, evtx, Sigma, amcache, prefetch, USN journal, MFT timeline, YARA, Sysmon, RAM; âˆ'15 if not elevated)
- **Caveats** state what could *not* be ruled out (no Sysmon, short log window, no RAM capture...) - i.e., what would change the verdict
- Surfaced in: console summary, `verdict.json`, `case.json`, and a plain-language RESULT line on the owner screen

Verdicts are correlation heuristics over collected evidence - verify against raw CSV/evtx before acting.

## Debugging a suspicious number (v2.79)

Every report claim is backed by a CSV, a producer function and a line in the case's `collection.log` (console at `-LogLevel Verbose` for the chatty traces; Quiet still logs everything):

| Report claim | Backing CSV | Producer | Log line to grep |
|---|---|---|---|
| Verdict rank + signals | `verdict.json` (`Signals[]`) | `Get-CompromiseVerdict` | `verdict signal: <name> (floor W x N)` |
| Coverage % | `verdict.json` (`Coverage[]`) | `Get-CompromiseVerdict` | `verdict coverage miss: <source> (weight W)` |
| Hunt findings (R1-R38) | `csv\hunt_findings.csv` | `New-HuntFindings` | `R13 discovery command storm: 2 accounts x 22 cmds -> 1 finding` (per-rule in/out counts; skipped rules log their gate) |
| Sigma detections | `csv\hayabusa_timeline.csv` + `csv\sigma_rules\index.csv` | `New-SigmaRuleLogs` | `sigma rule logs: N rule(s)` |
| Process verdicts | `csv\flash_process_scored.csv` | flash scoring (module 1.2) | `saved N rows -> csv\volatile\...` |
| Leads | `csv\derived\leads.csv` | `Get-TriageLeads` | `[regen] triage leads ... Get-TriageLeads -> N lead(s)` |
| What ran during a parse | every derived artifact | `Invoke-RegenerateOutputs` | end-of-run `regen summary:` block, one `[regen] <step> ... <producer> -> <output> in X.Xs` line each |

A `0 rows` input on a rule trace means the source CSV was empty or absent - the technique did not "pass", it was blind. Same honesty rule as the report's evidence index.

## Delta collection (pseudo-monitoring)

Run Ophira again on the same box days later: it auto-finds the previous case, compares flagged processes / tasks / services / autoruns / Sigma alerts, and reports **only what's NEW** - in the console, the report ("NEW since previous collection"), the SIEM export, and the SimpleUI owner screen. Point-in-time triage becomes a lightweight watch without installing anything.

## FP/TP decision support

- **Correlation score** - evidence stacks per binary: user-path (+1), unsigned (+2), binary deleted (+3), public connection (+2), persistence refs (+2 each), IOC hash hit (+4) â†' verdict
- **Trusted publishers** - validly-signed binaries from known publishers (or your `tools\trusted.txt`) cap at LOW; IOC hits always override
- **`-Mode Tune`** - the FP feedback loop: shows your top-hit Sigma rules with counts, pick offenders, exclude them entirely or demote to informational. Written into hayabusa's native `exclude_rules.txt` / `level_tuning.txt`, so the tuning travels with Deploy `-PushTools` to every host you push to. `[V]`iew / `[ED]`it open the rule's actual .yml in Notepad so you can see (or adjust) exactly what it matches before deciding
- **Sigma rule logs** - every matched rule gets its own event log: `csv\sigma_rules\<rule>.csv` (time, host, event ID, RecordID, hayabusa-extracted details) + an index, and `report.html` lets you expand each rule to read the matched events inline. RecordID locates the exact record in the shipped `raw\evtx\`
- **`-Mode Focus`** (menu option 9, replaces the old `-Mode Process` flat pivot which stays as an alias) - entity dossier builder: seed it with a process **name, PID, path, hash, IP, ip:port or port** and it iteratively expands the entity set across every collected CSV (name â†' path â†' hash â†' parent/child â†' DLLs â†' network â†' remote IPs) until the activity chain closes, capped at 4 rounds with an OS-name guard (explorer/cmd/svchost etc. are matched as evidence but never seeded). Multiple instances of one process group **per path+hash** - a same-name binary at another path (masquerade) splits into its own group with a warning. Writes `focus\focus_report.html` - identity, instances with PID/ProcessGuid, an **inline SVG activity graph** (parents â†' instances â†' children â†' what each instance did), a **per-instance deep-dive** (children, network, DNS, loaded DLLs, file-time events, registry writes joined by ProcessGuid), activity chain from the master timeline and a detection-surface verdict hint - plus `focus_hits.csv` / `focus_chain.csv` / `focus_terms.json` / `focus_instances.csv`; the main report gains a Focus section once one exists. PID/ProcessGuid need a v2.40+ collection (Sysmon EID 1/2/3/7/13/22 + 4688 now capture them); older cases run in a flagged degraded mode
- **Verdict honesty on clean systems** (v2.41) - Defender-channel sigma rows no longer double-count with the dedicated Defender signal (one old AV alert used to declare LIKELY COMPROMISED); sigma-critical only reaches floor 3 as a multi-rule storm (>=3 events from >=2 rules), single-rule crit pairs demote to SUSPICIOUS; the confirmed clean-host noisy rules (`Suspicious Service Path`/`Name`, `Antivirus - Relevant File Paths Alerts Signature`) ship demoted to informational in the bundled hayabusa tuning. Real incidents still trip the storm gate - verified against synthetic cobaltstrike+mimikatz timelines
- **Amcache SHA1 Ã- IOC** - historical execution matched against your IOC list = near-certain TP with a timestamp
- **report.html** - **compromise assessment report v2**: verdict banner with confidence bar + contributing signals + "what would change this verdict" caveats, evidence coverage table, **MITRE ATT&CK grid** (tactic chips + technique table from hayabusa tags, with cannot-rule-out telemetry notes), findings grouped by tactic, defanged copy-ready IOC list, YARA findings, logon/account analysis, **recovered attacker commands** (decoded base64/obfuscated PowerShell), persistence inventory, **file-system evidence section** (USN mass-modification windows + ransomware extensions, most-run prefetch, MFT user-path executables), **C2 beaconing candidates (connections + DNS)**, **driver check (LOLDrivers)**, **host snapshot** (AV state + detections, stored credentials, outbound RDP, BITS, malfind, browser IOCs, **security posture audit**), recommendations incl. **hardening actions from BAD posture findings**, **evidence index** (every CSV with row counts + what to look for - the map into all collected artifacts), VT deep links
- **Raw evidence** - every flag is backed by raw CSV/evtx/hive so any verdict can be verified

## Analyze mode

Merges N case zips â†' `fleet_report.csv` + **`fleet_report.html`** (**per-host verdicts inherited from each case's `verdict.json`**: verdict chips, worst-first host matrix, ATTENTION FIRST list, **fleet ATT&CK roll-up** with `attack_layer_fleet.json`) + **`fleet_hosts.csv`** (host/verdict/confidence for SIEM), high-priority findings, cross-host indicator + hash dedup, top fleet Sigma detections, **baselining proposals** + one merged hayabusa timeline (**deduped via `sort-csv`** - overlapping/backup evtx no longer double-count). Accepts legacy `IRCASE_*` packages too (shown as "no verdict").

**Fleet baselining:** publishers present on â‰¥60% of hosts with zero HIGH verdicts are written to `proposed_trusted.txt` - review once, merge into `tools\trusted.txt`, and your false-positive rate drops with every host you scan.

## Companion tools

**`tools\endpoint\`** is what `Deploy -PushTools` ships to remote hosts (hayabusa, chainsaw, yara, the EZ parsers, LOLDrivers lists, winpmem - ~120 MB, 9,000+ files; also what the release **bundle** zip packs - the **lite** zip ships just hayabusa + EZ parsers + winpmem); **`tools\analyst\`** never leaves your PC (volatility3 memory analysis, SQLECmd browser parser - it needs .NET 9 which endpoints rarely have; its targets are parsed analyst-side via `-Mode Parse`). Ophira finds tools recursively in both. Refresh via `-Mode Setup` or each project's releases:

| Tool | Enables | Download |
|---|---|---|
| winpmem | RAM capture (7.1) - endpoint | https://github.com/Velocidex/winpmem/releases |
| hayabusa | Sigma timeline (4.6) + fleet + `-Mode UpdateRules` - endpoint | https://github.com/Yamato-Security/hayabusa/releases |
| Volatility 3 | offline memory analysis + optional on-host pass - analyst | https://github.com/volatilityfoundation/volatility3/releases |
| chainsaw | execution timeline, SRUM, evtx gaps (5.4) + offline Sigma - endpoint | https://github.com/WithSecureOpenSource/chainsaw/releases |
| AmcacheParser (EZ) | execution inventory + SHA1Ã-IOC (8.4) - endpoint | https://github.com/EricZimmerman/AmcacheParser/releases |
| RBCmd (EZ) | recycle bin parse (8.4) - endpoint | https://github.com/EricZimmerman/RBCmd/releases |
| MFTECmd (EZ) | live $MFT + USN journal forensics, all NTFS drives (5.5) - endpoint | https://download.ericzimmermanstools.com/MFTECmd.zip |
| PECmd (EZ) | prefetch run counts (5.1) - endpoint | https://download.ericzimmermanstools.com/PECmd.zip |
| LECmd / JLECmd (EZ) | LNK + Jump List parse (8.5) - endpoint | https://download.ericzimmermanstools.com/LECmd.zip |
| SBECmd (EZ) | ShellBags folder-browsing history (8.8) - endpoint | https://download.ericzimmermanstools.com/SBECmd.zip |
| SQLECmd (EZ, .NET 9) | browser History/Downloads SQLite parse (8.7) - analyst (.NET 9) | https://download.ericzimmermanstools.com/net9/SQLECmd.zip |
| LOLDrivers datasets | malicious/vulnerable driver hash xref (8.10) - endpoint | https://github.com/magicsword-io/LOLDrivers |
| yara-x | YARA scan of flagged binaries (4.7), MIT rule pack bundled - endpoint | https://github.com/VirusTotal/yara-x/releases |

**Push tools packaging is AV-resilient**: Defender flags a few bundled Sigma `.yml` files (rules that *describe* Defender tampering) and can block bulk archiving - `-PushTools` zips per-file and skips whatever AV objects to, with the skip count shown.

**KAPE and Kansa:** Ophira deliberately replaces Kansa (push/run/remove + log modules are built in, with verdicts and fleet on top). [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) is a great **complement, not a replacement**: when one box needs deep full-disk acquisition beyond triage scope, run KAPE separately on that box - our `raw\` evidence covers the common artifacts so you only escalate when needed.

**Analyst-side quick wins on a collected case:**
```
vol.exe -f memory\physmem.raw windows.pslist.PsList
chainsaw hunt raw\evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Sysmon telemetry (what Ophira parses, zero endpoint changes)

Ophira never installs, configures, or touches anything on the endpoint. If the host already runs Sysmon, module 4.3 parses whatever telemetry the endpoint's own config produces and the structured parsers consume these event IDs when present: process creations with hashes (1), file-creation-time changes (2), network connections (3), image loads (7), remote-thread creation (8 - the cross-process injection signal, R28), raw volume reads (9 - direct volume access, R31), ProcessAccess (10 - the LSASS-dump signal), registry events (13), Sysmon config changes (16 - anti-forensics tell, R33), WMI filter/consumer/binding registrations (19/20/21 - permanent subscription persistence, R32), named pipes created/connected (17/18 - C2 pipe channels, R29), DNS queries (22), file creates/deletes (11/23/26 - per-instance drops/cleanup in the Focus dossier), and process tampering (25 - hollowing detected by Sysmon itself, R30). Stock Sysmon defaults and broad community configs capture all of these; narrow configs simply produce fewer joins - and on hosts with no Sysmon at all, the conclusion stands on the execution-artifact spine (prefetch, amcache, BAM/DAM, shimcache, 4688, USN/$MFT, Defender history) with per-instance execution joins in the Focus dossier.

When a case shows Sysmon running but the expected telemetry is absent, the report's hunt section flags the config gap and names exactly which event classes the endpoint's config is not capturing and which rules run blind as a result - it is an observation for the Sysmon owner, never an action Ophira takes.

## Design rules

- Read-only; degrades gracefully without admin (logs what failed)
- **Seeing odd ASCII art when you launch `. \Ophira.ps1` directly?** That is your own PowerShell profile (`$PROFILE` - it loads for every script started in that console), not Ophira. `RUN-OPHIRA.bat` launches with `-NoProfile`, so the owner flow never shows it
- PowerShell 5.1 baseline (Win 2008 R2+ with updates), no dependencies. Hosts with PowerShell < 5.0 get a clear fail-fast message with remote-collection alternatives instead of cryptic errors
- Fallbacks for 2008-era boxes (netstat/arp/ipconfig parsing when cmdlets missing)
- Per-module failure isolation; speed/precision via presets (Flash 15s â†' Quick 1-2 min â†' Standard 3-5 min)
- **Phased parallel collection** - volatile first (order of volatility), then independent categories in parallel runspaces, then heavy analytics (hayabusa/chainsaw/EZ) in parallel; `-Sequential` forces the old serial behavior
- **hayabusa time-boxing** - scans only the configured log range (`--time-offset`) with eid-filter (`-E`); per-module timings recorded in `case.json` (`ModuleTimings`)
- Native tools launched console-less (`.NET CreateNoWindow`) - avoids console handshake stalls and runspace pipe overhead

## OS support

| OS | Status |
|---|---|
| Windows 10/11, Server 2016-2025 (PowerShell 5.1) | Full support |
| Windows 8/8.1, Server 2012/R2 (PS 5.0/5.1) | Full support |
| Windows 7 SP1 / 2008 R2 **with WMF 5.1** (needs .NET 4.5.2) | Supported - OS cmdlets missing on Win7 (Get-Net*, Get-Smb*, Defender) are guard-wrapped and skip gracefully; SQLECmd needs .NET 9 which does not install on Win7, so browser artifacts finish analyst-side via `-Mode Parse` |
| Any host with PowerShell < 5.0 (stock Win7 = PS 2.0) | Blocked by design with a clear fail-fast message (v2.21: the whole script parses under PS 2.0, so the friendly gate + WinRM-push guidance renders everywhere instead of parser errors) |

Role telemetry follows the host, not the preset: a DC auto-enables module 4.9 (Kerberos/DS), an IIS box auto-enables 8.12 (web artifacts) under Standard/Full; `-Preset DC` / `-Preset WebServer` force them on.

## Testing on a VM (safe demo recipe)

Snapshot first, host-only networking is enough (nothing below needs internet), revert after.

**Recommended MalwareBazaar sample: Mimikatz** (browse the `mimikatz` tag) - it lights up every detection surface:

1. Before running the collection, add the sample's hashes to `tools\iocs.txt` (one per line - the SHA256 **and** SHA1 shown on the MalwareBazaar page):
   ```
   <sha256 of sample>
   <sha1 of sample>
   ```
2. Run the sample on the VM, then collect (`RUN-OPHIRA.bat` or `.\Ophira.ps1 -NoMenu -Preset Standard`).
3. What you should see: flash-triage IOC hit (if still running), **amcache historical-execution hit** ("this exact hash executed on DATE" = verdict-forcing evidence), **YARA high hit** (bundled `ophira-pack.yar` has Mimikatz/Cobalt Strike/Metasploit/LaZagne/Rubeus/BloodHound rules) â†' verdict **COMPROMISED**.

Cobalt Strike beacon samples (tag `cobalt-strike`) also match the YARA pack; current families (tags `AgentTesla`, `Lumma`, `Remcos`...) are realistic but only light up the IOC path - add their hashes to `iocs.txt`.

**Beaconing demo without live C2** (most sample C2s are dead) - run this on the VM as the "malware", it generates a textbook periodic callback that module 4.8 flags `[high]`:

```powershell
while ($true) { try { (New-Object Net.Sockets.TcpClient('1.1.1.1', 443)).Close() } catch {}; Start-Sleep -Seconds 60 }
```

**Ransomware/USN demo without ransomware** - mass-create files with ransom extensions in a user folder; module 5.5 detects the write burst + extensions (verdict floor 3):

```powershell
1..3000 | ForEach-Object { Set-Content "C:\Users\$env:USERNAME\Documents\doc$_.docx.locked" 'x' }
```

**The real test**: while the sample detonates, run `-Mode Watch` (menu [W]) in a second console - a live read-only diff of new processes, external connections, autoruns and Defender detections, tick by tick. Then run a collection, re-run it and check the delta ("NEW findings"), and run `-Mode Focus -ProcessName <sample>` to see the engine build the full activity chain of that one entity (dormancy + prefetch-mismatch correlation notes included).

## Coverage vs Velociraptor (built-in Windows artifacts)

Ophira is a read-only single script (no resident agent, no driver), so Velociraptor's live-query artifacts are partially out of reach by design:

| Bucket | Share of VR's ~98 Windows artifacts | Examples |
|---|---|---|
| Full equivalent | ~45 | Amcache, Prefetch, USN, SRUM, ShellBags, LNK, JumpLists, RecycleBin, Timeline, DNS cache, hosts, services, tasks, WMI, certs, logon/process events, memory acquisition, hunt detections (R1-R3) |
| Partial | ~12 | SAM (hive saved, hashes not extracted), Signers, SVCHost anomalies, VAD (â†' minidumps), FilenameSearch |
| Live-only (VR's agent/driver moat) | ~10 | Handles, live DLL/Thread enumeration, Mutants, Impersonation, VBScript-in-proc, UEFI |
| Niche/campaign-specific | ~12 | Notepad tabs, RDP bitmap cache, PST search, BulkExtractor, campaign one-offs |

Everything in the "full" bucket produces parsed CSVs + verdict/report integration; partials preserve the raw evidence for analyst-side completion (`-Mode Parse`).

## License

MIT
