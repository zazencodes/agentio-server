# Server context

Read the repository context and internal/store/AGENTS.md before schema changes. API contracts
live in docs/api.md; self-hosting configuration in docs/self-hosting.md (paths from repo root).
Keep wire documentation synchronized with changed behavior.

The server is a sealed relay: it stores nothing an agent or a person wrote (docs/self-hosting.md
"What the server keeps" lists everything it may keep) and holds no key that
can decrypt or sign. Never add a column or log field that carries content, names,
paths, frames, query strings, tokens or IP addresses; logs name the route template
(r.Pattern) only. TestZeroRetention guards this: extend it when the relay gains a feature.

Login only grants API access; agent actions still require paired-device signatures. Do not log
tokens or VAPID private keys. Schema changes are new migrations of the core schema in
internal/store/migrate.go.

internal/server/extension.go is the extension API: extra endpoints, fields in /api/v1/config and
/api/v1/account, a check on relayed frames and maintenance (docs/api.md section 8). Keep it small and
named for what it does; an extension never changes core behaviour. internal/command is the command
line, shared by binaries that add an extension.
