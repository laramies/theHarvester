# Schedule finite runs through a private control plane

Status: accepted

HarvestView stores authorized target inventories, recurrence policy, overlap policy, claims, and dispatch reservations in a private local SQLite control plane separate from portable completed-run evidence. Each occurrence reserves stable run IDs and submits ordinary finite runs through the existing durable queue and single worker; this preserves lifecycle, cancellation, attribution, and export behavior while keeping future automation policy out of evidence exports. The default overlap policy skips while a prior batch is active, and no external scheduler, second execution path, or distributed queue is introduced until measured demand justifies changing the local single-operator boundary.
