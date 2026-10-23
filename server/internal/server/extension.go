package server

import (
	"context"
	"net/http"
	"time"

	"agentio.sh/server/internal/store"
)

// Extension adds features to the server: more endpoints, more fields in two responses, a check on every relayed
// frame, periodic work, and accounts without passwords. Every hook is optional. The core server has none; docs/api.md §8 describes what an
// extension may change.
type Extension struct {
	// Routes registers the extension's endpoints with handle, which serves them like the core's: authentication,
	// rate limits, CORS, errors and request logs. Patterns are http.ServeMux patterns and must not overlap
	// the core's.
	Routes func(handle func(pattern string, fn HandlerFunc))
	// ClientConfig adds fields to GET /api/v1/config.
	ClientConfig func(out map[string]any)
	// Account adds fields to GET /api/v1/account for u.
	Account func(ctx context.Context, u *store.User, out map[string]any) error
	// RelayFrame runs before the relay delivers a frame of size bytes from one of u's machines or browsers. An error
	// refuses the frame: an *APIError goes to the sender as the refusal, any other error is logged and refused as
	// internal.
	RelayFrame func(ctx context.Context, u *store.User, size int64) error
	// NoPasswords means the server's accounts have no passwords (people sign in through the extension's endpoints):
	// password sign-in, sign-up, password changes and password-confirmed account deletion are refused, and
	// GET /api/v1/config says so.
	NoPasswords bool
	// Maintain runs with the server's maintenance (every minute) and once more at shutdown, after
	// every request has finished.
	Maintain func(ctx context.Context) error
}

// HandlerFunc serves a request; a returned error is rendered as the response (an *APIError, or 500).
type HandlerFunc func(w http.ResponseWriter, r *http.Request, v *Caller) error

// Extend adds an extension's features. Call it once, before Handler or Run.
func (s *Server) Extend(e Extension) {
	if s.extended {
		panic("server: Extend called twice")
	}
	s.extended = true
	s.ext = e
}

// Allow takes one token from key's rate-limit bucket: burst at first, then one per every. Keys share one namespace
// with the core's, so prefix them with what they limit.
func (s *Server) Allow(key string, every time.Duration, burst int) bool {
	return s.limiters.allowKey(key, every, burst)
}

// AuthAttemptAllowed reports whether ip may try another credential: failed password logins and failures an
// extension records share one budget per IP (login-failure-*).
func (s *Server) AuthAttemptAllowed(ip string) bool { return s.limiters.authAttemptAllowed(ip) }

// RecordAuthFailure counts a failed credential from ip against its budget.
func (s *Server) RecordAuthFailure(ip string) { s.limiters.recordAuthFailure(ip) }

// Go runs f in the background; shutdown waits for it before the last maintenance.
func (s *Server) Go(f func()) { s.wg.Go(f) }

// CloseAccount closes every relay socket of an account, for when an extension deletes it.
func (s *Server) CloseAccount(userID string) { s.relay.closeUser(userID) }
