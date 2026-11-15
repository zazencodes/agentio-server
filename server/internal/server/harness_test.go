package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/config"
	"agentio.sh/server/internal/store"
)

const (
	testPassword = "password123"
	waitTimeout  = 5 * time.Second
	quietPeriod  = 300 * time.Millisecond
)

// testPasswordHash is a low-cost bcrypt hash of testPassword, so creating test users stays fast.
var testPasswordHash = sync.OnceValue(func() string {
	b, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(b)
})

// logBuffer collects log output safely across goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// harness is a running test server with a temp-dir SQLite store, logging at debug level into logs.
type harness struct {
	t    *testing.T
	srv  *Server
	db   *sql.DB // a second connection to the same database
	url  string
	logs *logBuffer
}

func newHarness(t *testing.T, configure ...func(*config.Config)) *harness {
	t.Helper()
	return newExtendedHarness(t, Extension{}, configure...)
}

func newExtendedHarness(t *testing.T, ext Extension, configure ...func(*config.Config)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.HTTPAddr, cfg.DataDir = "", t.TempDir()
	for _, f := range configure {
		f(cfg)
	}
	ts := httptest.NewUnstartedServer(nil)
	cfg.PublicURL = "http://" + ts.Listener.Addr().String()
	st, err := store.Open(cfg.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	srv, err := New(cfg, st, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	// Tests make many requests and failed logins from one address; the ones about limits set their own.
	srv.limiters.requestBurst, srv.limiters.requestRefill, srv.limiters.failureBurst = 1_000_000, time.Millisecond, 1_000_000
	srv.Extend(ext)
	ts.Config.Handler = srv.Handler()
	ts.Start()
	db, err := sql.Open("sqlite", "file:"+cfg.DatabasePath()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
		srv.wg.Wait()
		db.Close()
		st.Close()
	})
	return &harness{t: t, srv: srv, db: db, url: ts.URL, logs: logs}
}

// sqlInt runs a query returning one integer.
func (h *harness) sqlInt(q string, args ...any) int64 {
	h.t.Helper()
	var n int64
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("sql %q: %v", q, err)
	}
	return n
}

type response struct {
	t      *testing.T
	status int
	header http.Header
	body   []byte
}

// hdr is one request header: a name and a value.
type hdr [2]string

func bearer(token string) hdr { return hdr{"Authorization", "Bearer " + token} }

// auth is a bearer header for token, or none without one.
func auth(token string) []hdr {
	if token == "" {
		return nil
	}
	return []hdr{bearer(token)}
}

// do sends a request (body: nil, a string, or a value to encode as JSON) and reads the whole response.
func (h *harness) do(method, path string, body any, headers ...hdr) *response {
	h.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, h.url+path, r)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, kv := range headers {
		req.Header.Set(kv[0], kv[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("%s %s: reading body: %v", method, path, err)
	}
	return &response{t: h.t, status: resp.StatusCode, header: resp.Header, body: b}
}

func (r *response) expect(status int) *response {
	r.t.Helper()
	if r.status != status {
		r.t.Fatalf("status %d, want %d; body: %s", r.status, status, r.body)
	}
	return r
}

// expectError asserts an API error with the given status and code.
func (r *response) expectError(want *APIError) protocol.ErrorResponse {
	r.t.Helper()
	r.expect(want.Status)
	var e protocol.ErrorResponse
	r.decode(&e)
	if e.Code != want.Code || e.Error == "" {
		r.t.Fatalf("error %+v, want code %s", e, want.Code)
	}
	return e
}

func (r *response) decode(v any) {
	r.t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		r.t.Fatalf("decoding %s: %v", r.body, err)
	}
}

func (r *response) obj() map[string]any {
	r.t.Helper()
	var m map[string]any
	r.decode(&m)
	return m
}

// addUser creates a user directly in the store and returns it with a fresh user token.
func (h *harness) addUser(username string, mods ...func(*store.User)) (*store.User, string) {
	h.t.Helper()
	u := &store.User{ID: newID("usr_"), Username: username, PasswordHash: testPasswordHash(), Role: store.RoleUser, Created: time.Now().Unix()}
	for _, f := range mods {
		f(u)
	}
	ctx := context.Background()
	if err := h.srv.store.AddUser(ctx, u); err != nil {
		h.t.Fatal(err)
	}
	tok := NewToken(u.ID, store.TokenUser, "test", 0)
	if err := h.srv.store.AddToken(ctx, tok); err != nil {
		h.t.Fatal(err)
	}
	return u, tok.Token
}

func asAdmin(u *store.User) { u.Role = store.RoleAdmin }

// tokenID returns the public ID of a token.
func (h *harness) tokenID(token string) string {
	h.t.Helper()
	t, err := h.srv.store.Token(context.Background(), token)
	if err != nil {
		h.t.Fatal(err)
	}
	return t.ID
}

// login signs in with a password and returns the new token.
func (h *harness) login(username, password string) string {
	h.t.Helper()
	var tok issuedTokenJSON
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": username, "password": password}).expect(http.StatusOK).decode(&tok)
	return tok.Token
}

// eventually polls cond until it holds or waitTimeout passes.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustEqual[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// dump renders every table of the database, rows sorted, leaving out the listed "table.column" cells.
func (h *harness) dump(skip ...string) string {
	h.t.Helper()
	var tables []string
	rows, err := h.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		h.t.Fatal(err)
	}
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		tables = append(tables, name)
	}
	rows.Close()
	var out strings.Builder
	for _, table := range tables {
		rows, err := h.db.Query(`SELECT * FROM ` + table)
		if err != nil {
			h.t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var lines []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				h.t.Fatal(err)
			}
			var cells []string
			for i, c := range cols {
				if !slices.Contains(skip, table+"."+c) {
					cells = append(cells, fmt.Sprintf("%s=%v", c, vals[i]))
				}
			}
			lines = append(lines, strings.Join(cells, " "))
		}
		rows.Close()
		slices.Sort(lines)
		fmt.Fprintf(&out, "== %s\n%s\n", table, strings.Join(lines, "\n"))
	}
	return out.String()
}
