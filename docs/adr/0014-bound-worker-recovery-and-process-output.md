# Bound worker recovery and process output

The API worker drains the child process streams to EOF while retaining a bounded log tail. Draining prevents a verbose child from blocking on a full pipe, and bounding the tail protects API-process memory. While the child runs, frequent cancellation checks read only its lifecycle row so they do not repeatedly build the full evidence projection.

A cancellation recorded before finalization takes precedence even if the last poll saw a running process. A child stopped by cancellation exits unsuccessfully so retained checkpoint evidence remains partial, and a late worker or recovery failure cannot overwrite a terminal run record.

During orphan recovery, an unreadable checkpoint affects only its own run. A checkpoint can pass a structural check and still fail evidence reconstruction. Storage access failures propagate so recovery can be retried without classifying a transient lock, connection, or I/O failure as corrupt evidence.
