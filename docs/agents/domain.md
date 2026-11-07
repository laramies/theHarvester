# Domain docs

This repository has a single domain context.

## Before exploring

Read the relevant sections of the root `GLOSSARY.md` and the ADRs in `docs/adr/` that touch the task. Product behavior and implementation rules live in `docs/architecture.md`.

If a domain document is absent, proceed silently. The `domain-modeling` skill creates glossary entries and ADRs lazily when terms or decisions are resolved.

## Use the glossary vocabulary

Use the terms defined in `GLOSSARY.md` when naming concepts in code, tests, issue titles, hypotheses, proposals, and operator-facing labels. Respect each entry's `_Avoid_` list. If a needed concept is missing, reconsider whether it belongs in the domain or note the gap for `domain-modeling`.

Keep definitions in `GLOSSARY.md`, implementation rules in the architecture guide, and consequential design decisions in ADRs. Read the relevant ADR before proposing a conflicting change and surface the conflict explicitly.
