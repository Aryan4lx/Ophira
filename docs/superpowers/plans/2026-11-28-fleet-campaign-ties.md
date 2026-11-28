# Fleet campaign ties v2 (v6.7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `New-FleetCampaigns` with account, source-IP and USB ties plus per-campaign time spans and verdict detail, so campaigns form from evidence the stitcher currently ignores.

**Architecture:** Same union-find stitcher (v5.5, ADR-0006 client guard) gains three edge loops fed by two existing fleet harvest lists (`$fleetSess`, `$lateralRaw`) and one new small USB harvest. Report + CSV gain `Span` and verdict-count columns. No new CSVs, no verdict changes, no per-case report changes.

**Tech Stack:** PowerShell 5.1 (single-file `Ophira.ps1`), house fixture-test harness (regex function extraction + stubs), fleet analyze mode.

**Spec:** `docs/superpowers/specs/2026-11-28-fleet-campaign-ties-design.md`

## Global Constraints

- PS 5.1 only: no `-in @()` (PS3+; use `-contains`), no ternary, no PS6+ syntax.
- Single-file architecture (ADR-0001): everything lands in `Ophira.ps1`.
- Function must stay extractable by house regex `(?s)function New-FleetCampaigns \{.*?\r?\n\}` - no new column-0 closing braces inside, no nested named functions (use inline scriptblocks like the existing `$norm`/`$addEdge`).
- Client guard (ADR-0006) must apply to every new edge type: different clients never merge; the would-be tie lands in `$script:FleetCrossClientTies`.
- No new CSVs; `fleet_campaigns.csv` shape change is additive-only (new columns).
- Filters before edge creation: machine accounts (`*$`), SYSTEM/LOCAL SERVICE/NETWORK SERVICE/DWM-/UMFD-/Window Manager/Font Driver Host users, empty users, LOCAL/''/'-'/`127.`/`::1`/`169.254.` IPs, empty USB serials.
- Version sweep 6.6 -> 6.7 must cover BOTH plain pins and escaped-regex pins (`tests/test_v46.ps1`, `v47`, `v48`, `v49`, `v400` carry `'Ophira v6\.6'` / `'\$ScriptVersion = "6\.6"'` forms; use fixed-string replace).
- Verification per standing instruction: full suite + E2E + browser-level look at `fleet_report.html` before release.

## Review Focus

- Host names differing in case/whitespace (`WS-01 ` vs `ws-01`): expected to merge via `$norm`; pinned by T6 in test_v68.
- A session row with empty `User` or empty `Source`: expected to be skipped silently, never crash the stitcher; pinned by T1/T2 fixtures.
- Same indicator appearing many times (50 sessions, same user): expected to produce ONE deduped evidence line, not 50; pinned by T7 dedupe check.
- Campaign whose edges carry no times: expected honest empty `Span` (not `1970-01-01`); pinned by T4.
- Cross-client account tie: expected two campaigns + `fleet_cross_client_ties.csv` row, never one merged campaign (ADR-0006); pinned by T6.

---

### Task 1: Unit tests for the extended stitcher (`tests\test_v68.ps1`)

**Files:**
- Create: `tests/test_v68.ps1`
- Modify (pinned, not yet implemented): `Ophira.ps1` `New-FleetCampaigns` (~1774-1878)

**Interfaces:**
- Consumes: current `New-FleetCampaigns` signature (`-HashRows -CrossRows -Lateral -Waves -AllHosts -Verdicts -ClientBy`).
- Produces: the exact new parameter/return contract Task 2 implements and Tasks 3-4 wire: `-SessionRows` (Host/User/Start/Type/Source), `-UsbRows` (Host/Serial/FriendlyName/Stamp); rows gain `Span`, `Flagged` properties; evidence line formats `account: <user> on <A> + <B>`, `source IP <ip> -> <A> + <B>`, `USB <serial> on <A> + <B>`.

- [ ] **Step 1: Write the failing test**

Harness = house pattern: extract `New-FleetCampaigns` via `(?s)function New-FleetCampaigns \{.*?\r?\n\}` + `Invoke-Expression`; positional `Check` calls; `$script:FleetCrossClientTies = New-Object System.Collections.Generic.List[object]` initialized before cross-client test. Fixtures (all times ISO strings):

- T1 account tie: SessionRows jsmith console on H1 (Start `2026-11-24 09:12:00`) + H2 (`09:20:00`); machine account `WS-01$` on H1+H2 and `SYSTEM` on H2 must NOT tie; expect 1 campaign, 2 hosts, evidence contains `account: jsmith on`.
- T2 source-IP tie: SessionRows row H3 with Source `10.1.2.9`, plus Lateral row (FromHost H3, ToHost H4, SourceIp `10.1.2.9`); plus SessionRows row with Source `LOCAL` on H3+H5 that must NOT tie. Expect H3+H4 merged, evidence contains `source IP 10.1.2.9`.
- T3 USB tie: UsbRows Serial `SN123` FriendlyName `Kingston` on H1 (`2026-11-24 08:00:00`) + H2 (`2026-11-24 07:30:00`); different serial on single host must not tie; expect edge line contains `USB` and both hosts.
- T4 span: same campaign as T3 gets `Span` = `2026-11-24 07:30:00 - 2026-11-24 08:00:00`; a hash-only campaign (HashRows MultiHost YES, no times) gets empty `Span`.
- T5 verdict detail: Verdicts H1=SUSPICIOUS, H2=NO EVIDENCE, H3 absent -> row `WorstVerdict` SUSPICIOUS, `Flagged` = `1 of 3 host(s)`.
- T6 client guard: jsmith ties ClientA-host and ClientB-host with `-ClientBy` different labels -> two separate single-host roots (no 2-host campaign) and `$script:FleetCrossClientTies.Count -ge 1`. Also case/whitespace: SessionRows user `JSmith ` on `WS-01` and `jsmith` on `ws-01` still merges (T6b).
- T7 dedupe: 4 jsmith session rows across H1/H2 -> evidence contains `account: jsmith on` exactly once (`Select-String -SimpleMatch` count on the joined Evidence string).

- [ ] **Step 2: Run to verify it fails**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_v68.ps1`
Expected: FAIL (parameters `SessionRows`/`UsbRows` don't exist yet -> binding error, or missing properties).

- [ ] **Step 3: Commit the failing test**

```powershell
git add tests/test_v68.ps1
git commit -m 'v6.7: campaign ties v2 - failing unit tests first'
```

### Task 2: Implement the stitcher extension in `Ophira.ps1`

**Files:**
- Modify: `Ophira.ps1` `New-FleetCampaigns` (~1774-1878: param block + new edge loops after the Waves loop + span + Flagged in the row pscustomobject)

**Interfaces:**
- Consumes: `New-FleetCampaigns` existing params; new `-SessionRows`, `-UsbRows` (shapes from Task 1 Interfaces).
- Produces: rows `Campaign/Client/HostCount/Hosts/WorstVerdict/Flagged/Span/Evidence`; edge objects gain optional `Time`; `$script:FleetCrossClientTies` unchanged shape.

- [ ] **Step 1: Add params** `[object[]]$SessionRows = @()` and `[object[]]$UsbRows = @()` to the param block.

- [ ] **Step 2: Extend `$addEdge` with an optional third time arg** (edge objects gain `Time = $t`, default `''`) - update all existing call sites to keep behavior (pass nothing or move line to positional 3rd... keep `param($a, $b, $line, $t = '')` and existing calls untouched).

- [ ] **Step 3: New edge loops AFTER the Lateral loop, BEFORE HashRows** (strongest identity ties first):
  - Account: group `$SessionRows` by lower-cased User passing the user filter; 2+ distinct normalized hosts -> pair edges, line `account: {user} on {A} + {B}`, Time = earliest Start among those hosts' rows.
  - Source IP: build (Host, IP) pairs from `$SessionRows` Source (IP filter) and `$Lateral` SourceIp+ToHost; group by IP; 2+ hosts -> `source IP {ip} -> {A} + {B}`, Time = earliest matching row time (parse `Start`/`Time` as strings only - no date math beyond min/max string compare of ISO-ish formats is NOT valid; compare via `[datetime]` cast guarded by try/catch, skip unparseable).
  - USB: group `$UsbRows` by Serial (non-empty); 2+ hosts -> `USB {FriendlyName or serial} on {A} + {B}`, Time = earliest Stamp.

- [ ] **Step 4: Span + Flagged**: during row build, collect edge times per root (min/max via guarded `[datetime]` casts); `Span` = `"$($min.ToString('yyyy-MM-dd HH:mm')) - $($max.ToString('yyyy-MM-dd HH:mm'))"` when both exist else `''`; `Flagged` = `"{flaggedCount} of {n} host(s)"` where flaggedCount = members with verdict in `$rankMap` above NO EVIDENCE/INCONCLUSIVE.

- [ ] **Step 5: Run test to verify it passes**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_v68.ps1`
Expected: PASS all checks.

- [ ] **Step 6: Syntax gate + commit**

```powershell
$e=$null; [void][System.Management.Automation.PSParser]::Tokenize((Get-Content .\Ophira.ps1 -Raw),[ref]$e); if($e.Count){$e|select -First 5}
git add Ophira.ps1
git commit -m 'v6.7: stitcher gains account/source-IP/USB ties, span, flagged counts'
```

### Task 3: Fleet harvest + call-site wiring

**Files:**
- Modify: `Ophira.ps1` fleet harvest (~1902-1910 list init, ~2076-2085 after fleetSess block) and call site (~2189)

**Interfaces:**
- Consumes: `usb_devices.csv` columns `Serial`, `FriendlyName`, `LastWrite` (verified against collector at Ophira.ps1:5491); harvest pattern from the fleetTc/fleetSess blocks (Join-Path + `Get-CaseCsvPath` fallback + cap + List.Add).
- Produces: `$fleetUsb` list feeding `-UsbRows`; `$fleetSess` feeding `-SessionRows` at the call site.

- [ ] **Step 1: Init** `$fleetUsb = New-Object System.Collections.Generic.List[object]` next to `$fleetSess` init (~1905), comment `# v6.7: per-host USB devices for campaign ties`.

- [ ] **Step 2: Harvest block after the fleetSess block** (~2085): same shape - `Join-Path $csvDir 'usb_devices.csv'` + fallback, cap `$fleetUsb.Count -lt 5000`, rows `[pscustomobject]@{ Host = $host_; Serial = "$($r.Serial)"; FriendlyName = "$($r.FriendlyName)"; Stamp = "$($r.LastWrite)" }`, skip empty Serial, `try/catch` around Import-Csv.

- [ ] **Step 3: Call site** (~2189): append `-SessionRows $fleetSess.ToArray() -UsbRows $fleetUsb.ToArray()`.

- [ ] **Step 4: Verify** - run test_v68 (still passing), syntax gate clean.

- [ ] **Step 5: Commit**

```powershell
git add Ophira.ps1
git commit -m 'v6.7: fleet harvest reads usb_devices, wires sessions+USB into stitcher'
```

### Task 4: Fleet report + CSV columns

**Files:**
- Modify: `Ophira.ps1` campaigns table (~2299-2305), story card (~2306-2313)

**Interfaces:**
- Consumes: row properties `Span`, `Flagged` (Task 2).
- Produces: fleet report campaigns table with `Span` column; updated meta line naming all seven tie types.

- [ ] **Step 1: Table header** gains `<th>Span</th>` after `Worst verdict`; verdict cell renders `$($c.WorstVerdict) ($($c.Flagged))`; span cell `$(ConvertTo-HtmlEsc $c.Span)`.

- [ ] **Step 2: Meta line** (~2305) rewritten: seven tie types listed (lateral chains, shared binary hashes, shared indicators, deployment waves, shared accounts, shared source IPs, shared USB devices); note `Span` comes from tie evidence times and is empty when none carry one.

- [ ] **Step 3: Story card** (~2312): append span sentence when `$tc.Span` non-empty.

- [ ] **Step 4: Verify + commit** - syntax gate, test_v68 wiring pins now assert the new `<th>Span</th>` + meta wording (add pins to test_v68 first, then edit report - red/green).

```powershell
git add tests/test_v68.ps1 Ophira.ps1
git commit -m 'v6.7: campaign cards gain span + flagged-count, meta names 7 tie types'
```

### Task 5: Version sweep, docs, full verification, release

**Files:**
- Modify: `Ophira.ps1` (header L2 `Ophira v6.7`, `$ScriptVersion = "6.7"` ~L394), `README.md` (roadmap bullet), `CHANGELOG.md` (new section above `## v6.6`), 14 plain-pin test files + escaped-regex pins in `tests/test_v46.ps1`/`v47`/`v48`/`v49`/`v400`

- [ ] **Step 1: Sweep** `.Replace('Ophira v6.6','Ophira v6.7')` + `.Replace('$ScriptVersion = "6.6"','$ScriptVersion = "6.7"')` + `.Replace('"6.6"','"6.7"')` over the plain files; fixed-string `Select-String -SimpleMatch '6\.6'` to find the escaped pins; residual grep must show only historical `# v6.6` comments and CHANGELOG/README v6.6 lines.

- [ ] **Step 2: README** roadmap bullet (after the v6.6 line) + **CHANGELOG** `## v6.7` section (3 tie types, span, flagged, harvest note, ADR-0006 note that client guard covers the new ties).

- [ ] **Step 3: Full suite** `powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1` -> ALL SUITES PASSED (expect pin drift in coverage/nav counts only if touched - none planned).

- [ ] **Step 4: E2E** `-Mode Analyze -AnalyzePath` over the on-disk case folders (5 cases; only 20261127_154513 carries session_stories.csv - others tie via hashes/indicators/waves only; expect EXIT clean, fleet_campaigns.csv + fleet_report.html written, no crash on cases without the new data).

- [ ] **Step 5: Browser verify** `fleet_report.html` (agent-browser; single-quoted JS literals per MEMORY gotcha): campaigns section renders, Span/Flagged columns present, meta names 7 tie types, no console errors, screenshot pixel check.

- [ ] **Step 6: Release** single commit `v6.7: fleet campaign ties v2 - accounts, source IPs, USB, spans`, tag `v6.7`, `gh release create v6.7 --title 'Ophira v6.7' --notes-file <changelog section>`, watch CI (`gh run list`).

## Plan self-review notes

- Spec coverage: all four design bullets (ties/spans/flagged/USB harvest) map to Tasks 2-4; client guard + filters pinned in Task 1 tests; release chores in Task 5.
- Types consistent: `SessionRows`/`UsbRows` field names match harvest pscustomobject names (Task 3) and test fixtures (Task 1).
- Proportion: 5 tasks, plan stays under the spec's 3x.
