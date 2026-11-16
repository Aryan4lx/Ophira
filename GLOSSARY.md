# Ophira - Domain Glossary

Terms as used in this repo. Use these names in issues, specs, tests, and code comments.

## Product

- **Ophira** - the single-file PowerShell 5.1 Windows endpoint IR triage toolkit (`Ophira.ps1`). READ-ONLY by design.
- **Case** - one endpoint's collected package: `OPHIRA_<HOST>_<TIMESTAMP>/` containing `csv\`, `raw\`, `report.html`, `case.json`, `collection.log`.
- **Endpoint side / analyst side** - collection runs on the target host; Parse/Analyze/regeneration run on the analyst machine. Tool split mirrors this: `tools\endpoint\` (shipped) vs `tools\analyst\` (vol3, SQLECmd - never shipped).

## Workflow

- **Collect** - run modules on the endpoint, write CSVs + raw exports.
- **Parse** (`-Mode Parse -ParsePath <case>`) - analyst-side completion of a package collected elsewhere: re-runs derived artifacts, rebuilds the report.
- **Analyze** - full collect + parse + package in one run (used when the analyst is on the endpoint).
- **Derived artifacts** - outputs rebuilt from collected CSVs (supertimeline, gaps, verdict, report, connections_dns, exec stacks, recon sessions, ...). All rebuilt by `Invoke-RegenerateOutputs`.

## Verdict machinery

- **Verdict** - `Get-CompromiseVerdict`: NO EVIDENCE / SUSPICIOUS / LIKELY COMPROMISED / COMPROMISED, from weighted **signals** and **coverage**.
- **Signal** - a named, floor-weighted verdict input (`Add-Signal name floor count detail`; floors 0-4).
- **Coverage** - per-source collected/missing accounting with weights (`Add-Cov`); drives the "85% weighted (24/33 sources)" honesty line.
- **Lead** - ranked triage item from `Get-TriageLeads`; crit/high leads go on the report rail.
- **Hunt finding** - output row of `New-HuntFindings` rules R1-R51+; high findings may feed the verdict via the catch-all or dedicated doors.

## Report

- **Supertimeline** - woven chronology of all sources (`csv\derived\supertimeline.csv`); caps newest-per-source; optional **plaso** merge.
- **Focus dossier** - pivot report around one indicator (`-Focus`), expansion capped, degraded-mode noted.
- **Preset** - module selection profile (Flash / Quick / Standard / Deep).
- **Module** - a `[pscustomobject]` with `Id` (`2.x` persistence, `3.x` network, `4.x` logs, `5.x` artifacts, `6.x` defender, `7.x` memory, `8.x` context), `Run` scriptblock, `Default`/`Quick` flags.

## Conventions

- **Save-Rows** - the only CSV writer; `-Name x` lands in `csv\<category>\x.csv`; empty sets write a `# no entries` marker.
- **SharedFunctions** - function whitelist rehydrated into parallel pool workers; new worker-side helpers must be added there.
- **Fixture test** - regex-extracted function + stubbed IO + synthetic CSV rows (house pattern `(?s)function NAME \{.*?\r?\n\}`).
