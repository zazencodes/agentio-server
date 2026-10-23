package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Schema is a set of tables with its own migrations, applied in order and each once, and tracked under Name in
// schema_migrations. The server's own tables are the "core" schema; an extension adds its tables as another schema,
// migrated after the core's, and may reference core tables.
type Schema struct {
	Name       string
	Migrations []string
}

// core is the server's schema: accounts, tokens, and the public keys and links of paired machines and browsers
// (docs/self-hosting.md, "What the server keeps"). Nothing an agent or a person wrote.
var core = Schema{Name: "core", Migrations: []string{
	// 1: accounts, tokens, machines, browsers, the links between them and Web Push subscriptions.
	`
CREATE TABLE users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL DEFAULT '',
	role TEXT NOT NULL,
	created BIGINT NOT NULL
);

CREATE TABLE tokens (
	id TEXT PRIMARY KEY,
	token TEXT NOT NULL UNIQUE,
	user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	host_id TEXT NOT NULL DEFAULT '',
	label TEXT NOT NULL DEFAULT '',
	last_access BIGINT NOT NULL DEFAULT 0,
	expires BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX idx_tokens_user ON tokens (user_id);

CREATE TABLE hosts (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	enc_key TEXT NOT NULL,
	created BIGINT NOT NULL
);
CREATE INDEX idx_hosts_user ON hosts (user_id);

CREATE TABLE devices (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	sensitive_key TEXT NOT NULL,
	enc_key TEXT NOT NULL,
	sensitive_origin TEXT NOT NULL,
	created BIGINT NOT NULL
);
CREATE INDEX idx_devices_user ON devices (user_id);

CREATE TABLE host_devices (
	host_id TEXT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
	PRIMARY KEY (host_id, device_id)
);
CREATE INDEX idx_host_devices_device ON host_devices (device_id);

CREATE TABLE webpush (
	device_id TEXT PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
	endpoint TEXT NOT NULL,
	auth TEXT NOT NULL,
	p256dh TEXT NOT NULL
);
`,
}}

const migrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	name TEXT NOT NULL,
	version INTEGER NOT NULL,
	PRIMARY KEY (name, version)
)`

// migrate applies the core schema's missing migrations, then each extension schema's.
func (s *Store) migrate(ctx context.Context, schemas ...Schema) error {
	if _, err := s.Exec(ctx, migrationsTable); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, schema := range append([]Schema{core}, schemas...) {
		if schema.Name == "" || seen[schema.Name] {
			return fmt.Errorf("schemas need unique, non-empty names (got %q twice or empty)", schema.Name)
		}
		seen[schema.Name] = true
		var version int
		if err := s.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations WHERE name = ?`, schema.Name).Scan(&version); err != nil {
			return err
		}
		if version > len(schema.Migrations) {
			return fmt.Errorf("the database's %s schema is at version %d, newer than this server's %d", schema.Name, version, len(schema.Migrations))
		}
		for i := version; i < len(schema.Migrations); i++ {
			err := s.Tx(ctx, func(tx *sql.Tx) error {
				for _, stmt := range strings.Split(schema.Migrations[i], ";") {
					if strings.TrimSpace(stmt) == "" {
						continue
					}
					if _, err := tx.ExecContext(ctx, stmt); err != nil {
						return err
					}
				}
				_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name, version) VALUES (?, ?)`, schema.Name, i+1)
				return err
			})
			if err != nil {
				return fmt.Errorf("%s migration %d: %w", schema.Name, i+1, err)
			}
		}
	}
	return nil
}

// TableExists reports whether the database has a table.
func (s *Store) TableExists(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.QueryRow(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}
