---
target: HarvestView
total_score: 27
max_score: 40
na_heuristics:
p0_count: 0
p1_count: 4
post_fix_total_score: 36
post_fix_p1_count: 0
timestamp: 2026-08-16T05-48-26Z
slug: theharvester-lib-api-static-harvestview-index-html
---
# HarvestView critique

## Design Health Score

| # | Heuristic | Score | Key issue |
|---|---|---:|---|
| 1 | Visibility of system status | 4 | Lifecycle, evidence, loading, cancellation, and errors are explicit. |
| 2 | Match system / real world | 2 | Imported records show an impossible Submitted -> Started -> Completed chronology. |
| 3 | User control and freedom | 3 | Dialog and cancellation control are strong; row actions queue immediately. |
| 4 | Consistency and standards | 3 | Cohesive system, but narrow table behavior breaks the model. |
| 5 | Error prevention | 2 | Safe defaults help; exact authorization is hidden and active row actions lack review. |
| 6 | Recognition rather than recall | 2 | The selected source is not named and grid selection lacks row context. |
| 7 | Flexibility and efficiency | 3 | Search, filters, bulk selection, copy, export, and keyboard access are strong. |
| 8 | Aesthetic and minimalist design | 3 | Excellent desktop hierarchy; the source/action dialog overloads narrow screens. |
| 9 | Error recovery | 3 | Errors preserve context and generally name recovery. |
| 10 | Help and documentation | 2 | Tooltips help, but high-stakes authorization lacks a durable final summary. |
| **Total** | | **27/40** | **Acceptable; strong foundation with release-critical truth and authorization gaps.** |

## Design specificity verdict

HarvestView is strongly authored for its product: the mineral history rail, warm evidence surface, monospace lifecycle metadata, P0/P1/P2 language, and evidence-first ordering form a credible Run Desk rather than an interchangeable SaaS shell. The runtime detector found 51 rendered warnings, dominated by intentionally dense metadata text. Palette and font warnings are false positives against the approved design direction; undersized controls and text are actionable where they affect selection, filtering, or touch.

## Overall impression

The visual system and status model are unusually disciplined. The biggest opportunity is making authorization truth and imported lifecycle truth as precise as the surface looks.

## What's working

- Lifecycle and terminal evidence are visibly separate.
- Desktop evidence hierarchy and operator-specific visual language are strong.
- Native dialogs, Escape handling, focus restoration, and visible focus rings work.

## Priority issues

1. **[P1] Imported chronology is impossible.** Label local creation as Imported/Stored locally and keep original Started/Completed timestamps separate.
2. **[P1] P1/P2 row actions bypass authorization review.** Require a review dialog naming the hostname, activity band, network behavior, and child-run boundary.
3. **[P1] Tablet/landscape rail and mobile paginator are cramped or clipped.** Collapse the rail earlier and wrap/compact pagination.
4. **[P1] New-run authorization is not summarized before execution.** Name selected sources and activity bands beside the final CTA.
5. **[P2] Grid filters and selection checkboxes lack contextual accessible names.** Name filters by column and selectors by row value.

## Persona red flags

- **Alex:** Source selection requires excessive scanning despite strong filtering and bulk controls.
- **Sam:** Column filters and identical Select Row announcements impair the select-and-copy path.
- **Casey:** Header/history dominate mobile arrival, the CTA appears before authorization review, and pagination clips.
- **Riley:** Imported timestamp contradiction and one-click active work undermine fail-closed trust.

## Minor observations

- Advanced summaries fall below the 44px touch target.
- Sticky dialog actions can overlap content at tablet/landscape heights.
- Repeated help buttons add noise where compact inline guidance can carry the meaning.

## Questions to consider

- Should an evidence record draw a lifecycle line when its timestamps do not prove that sequence?
- If the selected sources are not named beside the CTA, has authorization actually been reviewed?
- Should retained evidence trigger P1/P2 work without the same review used by a new enumeration?

## Applied follow-up

All four P1 findings and the P2 accessibility finding were addressed in the same release slice:

- Imported evidence now separates original start/completion from local import time.
- Screenshot and DNS brute-force row actions require an explicit authorization review before a child run is queued.
- The history rail collapses at 940px; the mobile paginator wraps inside the evidence workbench.
- The final enumeration review names the target, selected sources, P bands, and deadline beside the CTA.
- Grid filters, route selection, and row checkboxes have contextual accessible names and larger checkbox controls.
- Advanced disclosure controls meet the 44px touch-target floor.

Post-fix assessment: **36/40**, with no remaining P1 findings. The remaining points reflect the intentionally dense expert workflow and the absence of a full screen-reader speech/200% zoom pass, not a known release blocker.

Verification: 29 Chromium E2E scenarios passed; unit/release checks passed; the post-edit static detector returned `[]`; and fresh rendered checks at 1440x900, 820x1180, 844x390, and 390x844 had no console/page/request errors, no document overflow, and no clipped paginator.
