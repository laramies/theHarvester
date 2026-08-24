# Keep run records separate with one isolated worker

Status: accepted

## Decision

The HTTP application owns a durable run record separate from theHarvester's optional terminal `RunResult` evidence. A submission receives its stable ID while queued. One local worker claims one queued run at a time and executes the finite theHarvester core in an isolated child process.

Lifecycle transitions are `queued -> running -> completed|failed`, `queued -> cancelled`, and `running -> cancelling -> cancelled`. A finite whole-run deadline applies when selected; resolution, reverse, and recursive DNS runs default to unlimited so their complete candidate sets can finish, while other runs retain the 1800-second default. A result limit of zero removes the shared per-source result-count cap and arbitrary local page-count ceilings without removing provider quotas, protocol maxima, response-size guards, or runtime safety bounds. Running cancellation first requests cooperative termination, waits a short grace period, and then forces termination if needed. Queued cancellation is an atomic transition that prevents the worker claim.

Evidence already persisted remains attached after failure or cancellation. Terminal evidence status (`complete`, `partial`, or `failed`) is reported independently from orchestration lifecycle status. On service restart, queued runs may resume; orphaned running or cancelling records become failed because their process ownership cannot be proven.

## Why

The existing core is a finite one-shot enumerator and its result object is created only when execution begins. Reusing it as queue state would conflate operator intent, process ownership, cancellation acknowledgement, and evidence quality. A single worker matches the local single-operator product, avoids concurrent output and credential contention, and can be widened later only if measured demand justifies it.

## Consequences

Run records need one small SQLite table and a lifecycle API. Child-process boundaries make deadline and forced cancellation reliable across blocking provider code. Work is serialized by design. Imported evidence enters as an already completed run record and never enters the queue. Portable database export copies finalized evidence with its original run IDs while omitting lifecycle, cancellation, and worker-lease state. A source stopped by a provider or safety boundary records partial evidence and its exact stop reason instead of presenting the run as complete.

Run details derive per-source observed, unique, shared, DNS-resolved, and unique DNS-resolved hostname counts from persisted result origins. DNS resolution therefore retains hostname origins alongside returned IP evidence. This adds no tracker table or second evidence path: imports and ordinary runs use the same provenance, sources with no matching hostnames remain visible with zero counts, and cross-run ranking or automatic source selection remains deferred.
