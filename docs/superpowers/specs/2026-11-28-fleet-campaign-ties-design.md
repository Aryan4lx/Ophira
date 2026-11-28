# Fleet campaign ties v2 (v6.7) - short design

Date: 2026-11-28
Status: approved direction (user picked "Campaign clusters"); doc pending approval
ADR links: extends ADR-0006 (campaigns never merge across clients); ADR-0002 read-only + derived artifacts

## Intent and why

The fleet report's Campaigns section stitches hosts into one investigation using
union-find over four tie types (lateral chains, shared binary hashes, shared
outbreak indicators, deployment waves). But three strong tie sources collected
since v5.5 are ignored: **accounts** (v6.6 session stories), **source IPs**
(lateral share access + RDP sources), and **USB devices** (never harvested
fleet-side). An analyst investigating "one intrusion, many boxes" currently
misses campaigns whose only evidence is "jsmith logged into 3 boxes" or "one
USB stick walked the floor". v6.7 adds those ties so the stitcher sees them.

## Goals

- New edge types in `New-FleetCampaigns`: account ties, source-IP ties, USB ties.
- Per-campaign time span on the card and CSV (min/max of tie evidence times).
- Verdict context per campaign: "SUSPICIOUS (2 of 3 hosts)" instead of bare worst.
- USB fleet harvest (small: read `usb_devices.csv` per host in the existing loop).

## Non-goals

- No per-case report changes, no verdict changes, no new CSVs
  (`fleet_campaigns.csv` and `fleet_cross_client_ties.csv` already exist).
- No findings-JSON change (campaigns are fleet-side only).
- No new clustering algorithm - same union-find, client guard untouched.

## Anti-goals

- No FP storm: single-host indicators never create ties; machine accounts
  (`*$`), SYSTEM/service accounts, LOCAL/loopback/link-local IPs, and
  unparseable USB rows are filtered before edge creation.

## Approaches considered

1. **Extend `New-FleetCampaigns` with new edge types (chosen)** - smallest
   diff, inherits the client guard, dedupe, caps, CSV and report plumbing.
2. New parallel "thread clusters" section - duplicates the stitcher, two
   answers for "how are these hosts related"; rejected.
3. Host-pair relatedness scoring (t-corr style for hosts) - harder to act on,
   no per-pair evidence lines; rejected for now.

## Design (chosen approach)

- `New-FleetCampaigns` gains `[object[]]$SessionRows` (fleetSess rows:
  Host/User/Start/Type/Source) and `[object[]]$UsbRows`
  (Host/Serial/FriendlyName/Stamp). Call site passes `$fleetSess.ToArray()`
  and the new list.
- **Account ties**: group SessionRows by lower-cased User where User is
  non-empty, not a machine account (`*$` suffix), not in
  SYSTEM/LOCAL SERVICE/NETWORK SERVICE/DWM-/UMFD-/Window Manager/Font Driver
  set; 2+ distinct hosts -> one edge per host pair,
  line `account: <user> on H1 + H2`.
- **Source-IP ties**: collect (Host, SourceIp) from SessionRows (skip
  LOCAL/''/'-'/loopback/`127.`/`::1`/`169.254.`) plus Lateral rows
  (SourceIp + FromHost as the touched host); group by IP; 2+ hosts ->
  edge `source IP <ip> -> H1 + H2`.
- **USB ties**: harvest `usb_devices.csv` per host in the fleet loop
  (Serial + FriendlyName + LastWrite, list cap 5000, after the t-corr block);
  group by Serial where Serial non-empty; 2+ hosts -> edge
  `USB <friendly/serial> on H1 + H2`; edge Time = both LastWrites.
- **Edge times**: edges carry an optional Time; account/source edges use the
  earliest matching row time, lateral uses its Time, USB uses LastWrites.
  Campaign Span = min-max over its edges' times, empty when no edge has one.
- **Card/CSV**: `fleet_campaigns.csv` gains `Span` (readable
  `2026-11-24 09:12 - 11:40` style, empty when unknown) and verdict detail
  becomes `WorstVerdict` + `Flagged` ("2 of 3 hosts"); fleet report table
  gains the Span column; meta line updated to name all seven tie types.
- **Caps/guards unchanged**: 8 evidence lines per campaign, 20-host pair
  expansion per indicator row, client-boundary guard (ADR-0006) applies to
  the new edges exactly as to the old ones.

## Left to the builder

- Exact insertion order of the new edge loops (account first: strongest
  identity tie; then source IP; then USB) ahead of the existing indicator loop.
- Test fixture shapes for `tests\test_v68.ps1` (house extraction + stubs).
- Version sweep 6.6 -> 6.7 (plain forms + escaped-regex pins in
  test_v46/47/48/49/v400), full suite, E2E `-Mode Analyze` over the on-disk
  cases, browser check of `fleet_report.html`, README + CHANGELOG, release.
