package store

import (
	"context"
	"database/sql"
	"strings"
)

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Token kinds.
const (
	TokenUser = "user"
	TokenHost = "host"
)

// User is an account.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	Created      int64
}

// Token is an access token: ID names it in listings and revocation, Token is the secret. HostID is set for host
// tokens.
type Token struct {
	ID         string
	Token      string
	UserID     string
	Kind       string
	HostID     string
	Label      string
	LastAccess int64
	Expires    int64
}

const userColumns = `id, username, password_hash, role, created`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Created); err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

// AddUser creates a user. Returns ErrConflict if the username exists.
func (s *Store) AddUser(ctx context.Context, u *User) error {
	_, err := s.Exec(ctx, `INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Role, u.Created)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
}

// UserByID returns a user.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// UserByUsername returns a user.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username))
}

// Users lists all users.
func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword updates a user's password hash.
func (s *Store) SetPassword(ctx context.Context, userID, hash string) error {
	_, err := s.Exec(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	return err
}

// SetRole updates a user's role.
func (s *Store) SetRole(ctx context.Context, userID, role string) error {
	_, err := s.Exec(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID)
	return err
}

// DeleteUser removes a user and everything they own: tokens, machines, devices, their links and the rows of
// extension tables that reference the account cascade.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	return s.Tx(ctx, func(tx *sql.Tx) error { return s.TxDeleteUser(ctx, tx, userID) })
}

// TxDeleteUser is DeleteUser in tx.
func (s *Store) TxDeleteUser(ctx context.Context, tx *sql.Tx, userID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

const tokenColumns = `id, token, user_id, kind, host_id, label, last_access, expires`

// AddToken stores a token.
func (s *Store) AddToken(ctx context.Context, t *Token) error {
	_, err := s.Exec(ctx, `INSERT INTO tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Token, t.UserID, t.Kind, t.HostID, t.Label, t.LastAccess, t.Expires)
	return err
}

// TxAddToken is AddToken in tx.
func (s *Store) TxAddToken(ctx context.Context, tx *sql.Tx, t *Token) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Token, t.UserID, t.Kind, t.HostID, t.Label, t.LastAccess, t.Expires)
	return err
}

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	if err := row.Scan(&t.ID, &t.Token, &t.UserID, &t.Kind, &t.HostID, &t.Label, &t.LastAccess, &t.Expires); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

// Token returns a token.
func (s *Store) Token(ctx context.Context, token string) (*Token, error) {
	return scanToken(s.QueryRow(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE token = ?`, token))
}

// Tokens lists a user's tokens.
func (s *Store) Tokens(ctx context.Context, userID string) ([]*Token, error) {
	rows, err := s.Query(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE user_id = ? ORDER BY kind DESC, label, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TouchToken records token use.
func (s *Store) TouchToken(ctx context.Context, token string, at int64) error {
	_, err := s.Exec(ctx, `UPDATE tokens SET last_access = ? WHERE token = ?`, at, token)
	return err
}

// DeleteToken removes a user's token by its ID.
func (s *Store) DeleteToken(ctx context.Context, userID, id string) error {
	res, err := s.Exec(ctx, `DELETE FROM tokens WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredTokens removes tokens past their expiry.
func (s *Store) DeleteExpiredTokens(ctx context.Context, now int64) error {
	_, err := s.Exec(ctx, `DELETE FROM tokens WHERE expires > 0 AND expires <= ?`, now)
	return err
}
