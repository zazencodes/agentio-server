package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testPath returns the path of a new SQLite database in a temporary directory.
func testPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "agentio.db")
}

func open(t *testing.T, path string, schemas ...Schema) *Store {
	t.Helper()
	s, err := Open(path, schemas...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// tables returns the database's tables, and columns a table's columns, both sorted.
func (s *Store) tables(t *testing.T) []string {
	t.Helper()
	return s.strings(t, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
}

func (s *Store) columns(t *testing.T, table string) []string {
	t.Helper()
	return s.strings(t, `SELECT name FROM pragma_table_info(?)`, table)
}

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

func (s *Store) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// A new database gets exactly the core tables (docs/self-hosting.md, "What the server keeps"), and opening it again
// applies nothing twice.
func TestMigrateFresh(t *testing.T) {
	path := testPath(t)
	s := open(t, path)
	want := map[string][]string{
		"devices":           {"created", "enc_key", "id", "key", "sensitive_key", "sensitive_origin", "user_id"},
		"host_devices":      {"device_id", "host_id"},
		"hosts":             {"created", "enc_key", "id", "key", "user_id"},
		"schema_migrations": {"name", "version"},
		"tokens":            {"expires", "host_id", "id", "kind", "label", "last_access", "token", "user_id"},
		"users":             {"created", "id", "password_hash", "role", "username"},
		"webpush":           {"auth", "device_id", "endpoint", "p256dh"},
	}
	var names []string
	for name, cols := range want {
		names = append(names, name)
		if got := s.columns(t, name); !slices.Equal(got, cols) {
			t.Errorf("%s columns %v, want %v", name, got, cols)
		}
	}
	slices.Sort(names)
	if got := s.tables(t); !slices.Equal(got, names) {
		t.Fatalf("tables %v, want %v", got, names)
	}
	s.Close()
	s = open(t, path)
	if got := s.strings(t, `SELECT name || ' ' || CAST(version AS TEXT) FROM schema_migrations`); !slices.Equal(got, []string{"core 1"}) {
		t.Fatalf("schema_migrations %v", got)
	}
}

// An extension's schema is migrated after the core's, tracked under its own name, and its new migrations apply on
// the next start.
func TestMigrateExtensionSchema(t *testing.T) {
	ctx := context.Background()
	path := testPath(t)
	ext := Schema{Name: "ext", Migrations: []string{
		`CREATE TABLE ext_notes (user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE, note TEXT NOT NULL)`,
	}}
	s := open(t, path, ext)
	if err := s.AddUser(ctx, &User{ID: "usr_1", Username: "alex", Role: RoleUser, Created: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(ctx, `INSERT INTO ext_notes (user_id, note) VALUES ('usr_1', 'kept')`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	ext.Migrations = append(ext.Migrations, `ALTER TABLE ext_notes ADD COLUMN extra TEXT NOT NULL DEFAULT ''`)
	s = open(t, path, ext)
	if got := s.columns(t, "ext_notes"); !slices.Equal(got, []string{"extra", "note", "user_id"}) {
		t.Fatalf("ext_notes columns %v", got)
	}
	if n := s.count(t, `SELECT COUNT(*) FROM ext_notes`); n != 1 {
		t.Fatalf("ext_notes rows %d", n)
	}
	if got := s.strings(t, `SELECT name || ' ' || CAST(version AS TEXT) FROM schema_migrations`); !slices.Equal(got, []string{"core 1", "ext 1", "ext 2"}) {
		t.Fatalf("schema_migrations %v", got)
	}
	// Deleting an account cascades into extension tables that reference it.
	if err := s.DeleteUser(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	if n := s.count(t, `SELECT COUNT(*) FROM ext_notes`); n != 0 {
		t.Fatalf("ext_notes rows after deleting their account: %d", n)
	}
	s.Close()

	// A server older than the database refuses it rather than running against an unknown layout.
	ext.Migrations = ext.Migrations[:1]
	if _, err := Open(path, ext); err == nil || !strings.Contains(err.Error(), "newer than this server's") {
		t.Fatalf("an older extension schema: %v", err)
	}
	if _, err := Open(path, Schema{Name: "core"}); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("a schema named core: %v", err)
	}
}

// A conversion records the versions it leaves the database at, and Open continues from there.
// The core tables keep their constraints: unique usernames, and an account's deletion cascades.
func TestCoreConstraints(t *testing.T) {
	ctx := context.Background()
	s := open(t, testPath(t))
	if err := s.AddUser(ctx, &User{ID: "usr_1", Username: "alex", Role: RoleUser, Created: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, &User{ID: "usr_3", Username: "alex", Role: RoleUser}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
	rec := &PairingRecord{
		Host:      &Host{ID: "hst_9", UserID: "usr_1", Key: "hk", EncKey: "he", Created: 1},
		HostToken: &Token{Token: "aio_h9", UserID: "usr_1", Kind: TokenHost, HostID: "hst_9"},
		Device:    &Device{ID: "dev_9", Key: "dk", SensitiveKey: "ds", EncKey: "de", SensitiveOrigin: "https://app.example", Created: 1},
	}
	if err := s.CompletePairing(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWebPush(ctx, &WebPush{DeviceID: "dev_9", Endpoint: "https://push.example/1", Auth: "a", P256dh: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"hosts", "devices", "host_devices", "webpush", "tokens", "users"} {
		if n := s.count(t, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Fatalf("%s has %d rows after deleting their account", table, n)
		}
	}
}
