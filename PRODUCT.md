# HarvestView product context

## Product

HarvestView is the local web application for running theHarvester and analyzing its results. It turns finite enumeration runs and imported result files into durable, searchable evidence without turning theHarvester into a monitoring service.

## Operator

The operator is a technically capable security practitioner working at a desk, often under time pressure. They need to see exactly what was authorized, what ran, what failed, and what evidence remains.

## Core jobs

- Launch one explicitly authorized enumeration with P0/P1/P2 boundaries visible before execution.
- Cancel work and know whether cancellation is requested, in progress, or complete.
- Reopen prior runs and compare route-specific evidence without rerunning reconnaissance.
- Import existing versioned theHarvester JSONL evidence.
- Export normalized JSONL results and inspect managed screenshots.

## Product principles

- Local-first and fail-closed.
- Evidence before decoration.
- Passive by default; active work is explicit.
- One finite run at a time.
- Honest state: lifecycle status and evidence completeness are different facts.
- Dense enough for an expert, calm enough for long sessions.

## Platform

web

The app is served by the existing local FastAPI application. Desktop is primary; tablet and mobile remain fully operable.
