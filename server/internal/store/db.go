// Package store persists agentio state in one SQLite database. The server runs as a single instance (relay sockets,
// presence and pairings in flight live in its memory), so one file is all the database it needs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// migrationTimeout bounds migrating the database at startup.
const migrationTimeout = 30 * time.Minute

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a state transition is not allowed.
var ErrConflict = errors.New("conflict")

// Store wraps the database.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path, creating it if needed, and migrates the core schema, then the given
// extension schemas.
func Open(path string, schemas ...Schema) (*Store, error) {
	s, err := connect(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()
	if err := s.migrate(ctx, schemas...); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}
	return s, nil
}

// connect opens the SQLite database at path without migrating it.
func connect(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer avoids SQLITE_BUSY storms; reads are fast enough on a single connection.
	db.SetMaxOpenConns(1)
	s := Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	return &s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Exec runs a statement.
func (s *Store) Exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, q, args...)
}

// Query runs a query.
func (s *Store) Query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, q, args...)
}

// QueryRow runs a query that returns at most one row.
func (s *Store) QueryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, q, args...)
}

// Tx runs fn in a transaction, committed if fn returns nil.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// placeholders returns "?,?,?" for n arguments.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
