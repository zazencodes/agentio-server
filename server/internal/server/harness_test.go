package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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

	"github.com/coder/websocket"
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
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	cfg *config.Config
	db  *sql.DB // a second connection to the same database, for time travel
	url string

	logs *logBuffer // everything the server logged, at debug level
}

func newHarness(t *testing.T, configure ...func(*config.Config)) *harness {
	t.Helper()
	return newExtendedHarness(t, Extension{}, configure...)
}

// newExtendedHarness is newHarness with an extension.
func newExtendedHarness(t *testing.T, ext Extension, configure ...func(*config.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.HTTPAddr = ""
	cfg.DataDir = dir
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
	return &harness{t: t, srv: srv, ts: ts, cfg: cfg, db: db, url: ts.URL, logs: logs}
}

// sql runs a statement directly against the database (used to move times into the past).
func (h *harness) sql(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("sql %q: %v", q, err)
	}
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

// --- HTTP ---

type response struct {
	t      *testing.T
	status int
	header http.Header
	body   []byte
}

// hdr builds a header list from key/value pairs.
type hdr []string

func bearer(token string) hdr { return hdr{"Authorization", "Bearer " + token} }

func basic(user, pass string) hdr {
	return hdr{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
}

func (h *harness) newRequest(ctx context.Context, method, path string, body any, headers ...hdr) *http.Request {
	h.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		r = bytes.NewReader(j)
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = h.url + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, kv := range headers {
		for i := 0; i+1 < len(kv); i += 2 {
			req.Header.Set(kv[i], kv[i+1])
		}
	}
	return req
}

// do sends a request and reads the whole response.
func (h *harness) do(method, path string, body any, headers ...hdr) *response {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(h.newRequest(ctx, method, path, body, headers...))
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

// expect asserts the status code and returns the response.
func (r *response) expect(status int) *response {
	r.t.Helper()
	if r.status != status {
		r.t.Fatalf("status %d, want %d; body: %s", r.status, status, r.body)
	}
	return r
}

// expectError asserts an API error with the given code (http = code / 100).
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

// wsURL converts a server path to a WebSocket URL.
func (h *harness) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(h.url, "http") + path
}

func (h *harness) dialWS(path string, headers ...hdr) (*websocket.Conn, context.Context) {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hh := http.Header{}
	for _, kv := range headers {
		for i := 0; i+1 < len(kv); i += 2 {
			hh.Set(kv[i], kv[i+1])
		}
	}
	conn, resp, err := websocket.Dial(ctx, h.wsURL(path), &websocket.DialOptions{HTTPHeader: hh})
	if err != nil {
		cancel()
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		h.t.Fatalf("dial %s: %v (status %d)", path, err, status)
	}
	h.t.Cleanup(func() {
		conn.CloseNow()
		cancel()
	})
	return conn, ctx
}

func readWS(t *testing.T, ctx context.Context, conn *websocket.Conn, v any) {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	_, data, err := conn.Read(rctx)
	if err != nil {
		t.Fatalf("websocket read: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
}

// --- Users ---

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

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// dump renders every table of the database, rows sorted, leaving out the listed table.column pairs (or whole tables,
// as "table.*").
func (h *harness) dump(skip ...string) string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		h.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			h.t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	skipped := map[string]bool{}
	for _, s := range skip {
		skipped[s] = true
	}
	var out strings.Builder
	for _, table := range tables {
		if skipped[table+".*"] {
			continue
		}
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
				if !skipped[table+"."+c] {
					cells = append(cells, fmt.Sprintf("%s=%v", c, vals[i]))
				}
			}
			lines = append(lines, strings.Join(cells, " "))
		}
		rows.Close()
		slices.Sort(lines)
		fmt.Fprintf(&out, "== %s (%d rows)\n%s\n", table, len(lines), strings.Join(lines, "\n"))
	}
	return out.String()
}
