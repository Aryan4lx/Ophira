# ADR-0001: Single-file PowerShell 5.1 architecture

- Status: accepted (project origin; reaffirmed every release)
- Context: Ophira is carried onto air-gapped/untrusted endpoints and run from a USB drop or file share. Installers, module trees, and runtime dependencies all fail in that environment; PowerShell 5.1 is the highest version guaranteed on stock Windows Server 2016/Win10 images.
- Decision: the entire toolkit lives in one `Ophira.ps1` (~15k lines). Companion binaries are versioned files under `tools\`, never code inside the script. The language floor is PowerShell 5.1 with no PS6+ syntax; .NET-native work goes through `Invoke-NativeTool`.
- Consequences: no module imports or package installs on the endpoint; test suites extract functions by regex anchors, which pins formatting conventions (column-0 closing braces, stable whitespace); every feature pays a size-tax and the AGENTS.md rules exist to keep the file maintainable.

# ADR-0002: Read-only collection, derived artifacts rebuilt on demand

- Status: accepted (v2.x)
- Context: an IR tool that writes to the host destroys evidence and taints testimony.
- Decision: collection only reads and copies. Everything downstream (supertimeline, verdict, report, DNS attribution, stacks, recon sessions) is a **derived artifact** rebuilt by `Invoke-RegenerateOutputs`, so any parser improvement retroactively upgrades existing packages via `-Mode Parse`.
- Consequences: fixes apply to old cases without recollection; the report must always render honestly from what exists (`# no entries` markers, honest empty states); verdicts are recomputable and comparable across versions (baseline-verdict stability is a release gate).

# ADR-0003: Honesty over signal volume

- Status: accepted (v2.86+, hardened v2.91-v2.93)
- Context: early releases over-claimed (fabricated timestomping findings, timezone split-brain, inflated nav counts, dishonest toast) and one shelf-aging bug flipped verdicts after the fact.
- Decision: correctness beats sensitivity. UTC-truth parsing per source dialect, verdicts anchored at collection time, caps surfaced with `+N more`, counts state total-vs-shown, every claim in the report must be traceable to a CSV row. False highs are treated as release-blocking bugs.
- Consequences: rules get pre-Win10 gates and benign-path whitelists; noise suppression is explicit (`suppress.txt` + honesty notes), never silent; the per-rule finding cap exists to stop storms from moving verdicts.

# ADR-0004: Prerelease-until-blessed release line

- Status: accepted (2026-11)
- Context: the report overhaul (v2.86+) reworked output the user had not yet reviewed; GitHub "Latest" pointed at stable v2.85.
- Decision: new releases are tagged but marked **prerelease**; v2.85 stays "Latest" until the user explicitly blesses the overhaul line, at which point the flag flips in the workflow.
- Consequences: users following releases never get unreviewed output as Latest; flipping to stable is a one-line workflow change.

# ADR-0005: MSSP fleet responder is the primary persona; scope boundaries are explicit

- Status: accepted (2026-11 vision round)
- Context: the tool outgrew "one endpoint at a time" (fleet waves, campaigns) and needed a stated audience to settle competing feature requests. Competitors anchor the space: Velociraptor owns agent/server fleet collection; KAPE owns curated single-host acquisition; neither owns the judgment step.
- Decision: Ophira is built first for the **MSSP/responder triaging fleets across clients with no spare infrastructure**; solo responders get the same UX for free. Positioning: "KAPE's speed, VRC's scale awareness, and a verdict neither gives you - from one file." The tool stays ONE file as the spine; heavy capability attaches at three contracts (evidence CSV schemas, per-case `ophira_findings.json`, `Invoke-NativeTool` adapter for external engines) rather than in-file rewrites. Explicit no-s: non-Windows endpoints are out of scope (documented as a choice; the JSON contract permits future VRC-interop without promising it); pre-Win7 support comes later as a separate dumb-collector shim (`Ophira-Legacy.ps1`, PS 2.0-compatible, raw copies only - parsing always happens on the analyst box); file growth is accepted with a purge-when-adding discipline instead of a refactor.
- Consequences: `ClientName` is part of the case schema and fleet rollups group per client (campaigns never cross client boundaries); every case emits a machine-readable findings JSON for SIEM/automation ingest; a `-Redact` pass produces client-safe report copies; the acceptance bar for the vision is "3 client fleets, under 10 minutes to answer which hosts are one intrusion, how it spread, and what to tell each client."

# ADR-0006: Verdicts are deterministic; AI-assisted narrative was considered and rejected

- Status: accepted (2026-11 vision round; revisit only by explicit user decision)
- Context: modern IR tools increasingly bolt on LLM analysis. An in-file AI narrative contract (compact evidence digest in, prose out, flag-gated with honest AiStatus) was designed and offered as a batch.
- Decision: rejected for now. The verdict stays 100% deterministic (rules + weighted signals). An MSSP must be able to defend every verdict line as reproducible; an LLM in the judgment path is indefensible in front of a client and violates ADR-0003's traceability law. A narrative-only, verdict-untouched integration remains possible later via the findings-JSON contract without any architecture change.
- Consequences: nobody should "add AI" to the verdict path without superseding this ADR; any future AI work stays outside judgment and is flag-gated + honestly labeled.
