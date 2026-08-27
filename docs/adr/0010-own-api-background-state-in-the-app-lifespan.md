# Own API background state in the application lifespan

Status: accepted

## Decision

Each FastAPI application lifespan creates one `ApiRuntime` containing a `RunWorker` and a `SchedulerService`. The runtime is stored on that application instance, started before requests are served, and stopped before shared database engines are disposed.

`create_app()` accepts an optional `runtime_factory`, so tests and alternate embeddings construct an explicit service graph without monkeypatching module wiring. Run and schedule routes obtain the current services through FastAPI dependencies. The scheduler and dispatcher receive their worker explicitly through constructor injection.

Loop-bound mutable values—including background tasks, stop and wake events, lease/claim owner IDs, subprocess-group mappings, stores, and injected subprocess factories—are owned by service instances and their current session objects. They are not retained in module variables. The module-level ASGI `app = create_app()` remains only as the normal Uvicorn entry point.

Unexpected worker or scheduler task failures are logged immediately. Service shutdown awaits the owned task, and cancellation of child execution terminates the subprocess/process tree, consumes helper tasks, and re-propagates cancellation.

The durable SQLite worker lease remains the authority for single-worker execution. Separate application runtimes may exist in one interpreter, but only one owner may execute a queue backed by the same database.

## Why

Module globals made the initial local single-process lifecycle concise, but their import lifetime exceeded FastAPI lifespan and event-loop lifetime. They hid route and scheduler dependencies, forced tests to monkeypatch implementation details, and allowed one app/test lifecycle to retain or mutate another lifecycle's task, events, owner, process registry, or process factory.

Application-owned services align allocation and cleanup with the component that uses them. Constructor injection, one small worker protocol, an `ApiRuntime` dataclass, and FastAPI's existing dependency system expose the necessary boundaries without introducing a container framework.

## Consequences

Worker-before-scheduler startup, scheduler-before-worker shutdown, queue serialization, durable leases, orphan recovery, cancellation, deadlines, child-process isolation, and schedule dispatch behavior remain intact.

REST schemas, database schemas, environment names, and CLI flags are unchanged.

Internal callers use `ApiRuntime`, `RunWorker`, `SchedulerService`, or their FastAPI dependencies instead of the removed module lifecycle functions and variables. Tests create independent applications through `create_app(runtime_factory=...)` or instantiate independent services directly.

Each service still owns one long-lived task rather than a task group. This is deliberate: the task is strongly referenced and awaited during shutdown. A task group should be reconsidered only if a service later supervises several cooperating background tasks.
