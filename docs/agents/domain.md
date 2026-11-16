# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root (single-context layout - this repo is one PowerShell product, no sub-contexts).
- **`docs/adr/`**: read ADRs that touch the area you're about to work in.

If any of these files don't exist, **proceed silently**. The `/domain-modeling` skill creates them lazily when terms or decisions actually get resolved.

## Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids. Key house terms: *case*, *collect/parse/analyze*, *verdict*, *lead*, *hunt finding*, *module* (IDs `2.x`-`8.x`), *signal/coverage floor*, *derived artifact*, *supertimeline*, *focus dossier*, *preset*, *analyst side vs endpoint side*.

If the concept you need isn't in the glossary yet, note it for `/domain-modeling`.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0001 (single-file architecture), but worth reopening because…_
