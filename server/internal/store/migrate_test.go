package store

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func (s *Store) strings(t *testing.T, q string, args ...any) []string {
	t.Helper()
	rows, err := s.Query(context.Background(), q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// A new database gets exactly the core tables and columns (docs/self-hosting.md, "What the server keeps").
func TestMigrateFresh(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "agentio.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := s.strings(t, `SELECT m.name || ': ' || p.name FROM sqlite_master m, pragma_table_info(m.name) p
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'`)
	want := map[string][]string{
		"devices":           {"created", "enc_key", "id", "key", "sensitive_key", "sensitive_origin", "user_id"},
		"host_devices":      {"device_id", "host_id"},
		"hosts":             {"created", "enc_key", "id", "key", "user_id"},
		"schema_migrations": {"name", "version"},
		"tokens":            {"expires", "host_id", "id", "kind", "label", "last_access", "token", "user_id"},
		"users":             {"created", "id", "password_hash", "role", "username"},
		"webpush":           {"auth", "device_id", "endpoint", "p256dh"},
	}
	var wanted []string
	for table, cols := range want {
		for _, c := range cols {
			wanted = append(wanted, table+": "+c)
		}
	}
	slices.Sort(wanted)
	if !slices.Equal(got, wanted) {
		t.Fatalf("columns:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wanted, "\n"))
	}
}

// An extension's schema is migrated after the core's under its own name, its new migrations apply on the next
// start, its tables cascade with the accounts they reference, and an older server refuses a newer database.
func TestMigrateExtensionSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agentio.db")
	ext := Schema{Name: "ext", Migrations: []string{
		`CREATE TABLE ext_notes (user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE, note TEXT NOT NULL)`,
	}}
	s, err := Open(path, ext)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, &User{ID: "usr_1", Username: "alex", Role: RoleUser, Created: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(ctx, `INSERT INTO ext_notes (user_id, note) VALUES ('usr_1', 'kept')`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	ext.Migrations = append(ext.Migrations, `ALTER TABLE ext_notes ADD COLUMN extra TEXT NOT NULL DEFAULT ''`)
	if s, err = Open(path, ext); err != nil {
		t.Fatal(err)
	}
	if got := s.strings(t, `SELECT note || extra FROM ext_notes`); !slices.Equal(got, []string{"kept"}) {
		t.Fatalf("ext_notes %v", got)
	}
	if got := s.strings(t, `SELECT name || ' ' || CAST(version AS TEXT) FROM schema_migrations`); !slices.Equal(got, []string{"core 1", "ext 1", "ext 2"}) {
		t.Fatalf("schema_migrations %v", got)
	}
	if err := s.DeleteUser(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	if got := s.strings(t, `SELECT note FROM ext_notes`); len(got) != 0 {
		t.Fatalf("ext_notes after deleting their account: %v", got)
	}
	s.Close()

	ext.Migrations = ext.Migrations[:1]
	if _, err := Open(path, ext); err == nil || !strings.Contains(err.Error(), "newer than this server's") {
		t.Fatalf("an older extension schema: %v", err)
	}
}
