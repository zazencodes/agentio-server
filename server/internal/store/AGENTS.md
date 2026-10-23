# Store migrations

Each schema (the core's, and an extension's) has its own migration list, applied in order and tracked under its name
in schema_migrations. Never infer an existing database's migration history from the current source or a fresh
fixture. Inspect schema_migrations and affected columns before an upgrade; back up and test on a copy.
A migration already applied to a retained database must keep its original meaning: add new entries, never edit
applied ones. Do not replay rename DDL or manually record versions to hide missing columns. Reset development
data only with its owner's authorization; preserve an inspectable snapshot before a reset.

The database is SQLite only: the server runs as a single instance (relay sockets, presence and pairings in
flight live in memory), so one file is all it needs. Concurrent one-time code consumption must be enforced by
database transactions/conditional writes, not process-only locks.
