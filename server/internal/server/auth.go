package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"agentio.sh/server/internal/store"
)

// Caller is who made a request.
type Caller struct {
	ip    string
	user  *store.User  // nil for anonymous
	token *store.Token // nil for anonymous
}

// IP is the caller's address (from the proxy's header with trust-proxy). Never log or store it.
func (v *Caller) IP() string { return v.ip }

// User is the caller's account, nil when anonymous.
func (v *Caller) User() *store.User { return v.user }

// rateKey identifies the caller for request rate limiting. Each paired machine gets its own bucket so busy
// agents never starve the user's browsers.
func (v *Caller) rateKey() string {
	switch {
	case v.isHost():
		return "h:" + v.token.HostID
	case v.user != nil:
		return "u:" + v.user.ID
	}
	return "ip:" + v.ip
}

func (v *Caller) isHost() bool { return v.token != nil && v.token.Kind == store.TokenHost }

func (v *Caller) isAdmin() bool { return v.user != nil && v.user.Role == store.RoleAdmin }

// clientIP returns the caller IP, honouring the forwarded header only when behind a proxy.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			parts := strings.Split(v, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticate resolves the request's token: an "Authorization: Bearer" header, or on the relay sockets (browsers
// can't set headers on WebSockets) a token query parameter. A malformed or invalid credential is an error, never
// anonymous.
func (s *Server) authenticate(r *http.Request) (*Caller, error) {
	v := &Caller{ip: s.clientIP(r)}
	header, query := r.Header.Get("Authorization"), r.URL.Query()
	switch {
	case header != "" && query.Has("token"):
		return nil, ErrUnauthorized.Wrap("send the token once, in the Authorization header or (relay sockets only) the token parameter")
	case header != "":
		scheme, token, _ := strings.Cut(header, " ")
		if !strings.EqualFold(scheme, "bearer") {
			return nil, ErrUnauthorized.Wrap("use Authorization: Bearer <token>")
		}
		return s.authToken(r.Context(), v, token)
	case query.Has("token"):
		if !strings.HasPrefix(r.Pattern, "GET /api/v1/relay/") {
			return nil, ErrUnauthorized.Wrap("the token parameter is only for relay sockets; use the Authorization header")
		}
		return s.authToken(r.Context(), v, query.Get("token"))
	}
	return v, nil
}

func (s *Server) authToken(ctx context.Context, v *Caller, token string) (*Caller, error) {
	t, err := s.store.Token(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthorized
	} else if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if t.Expires > 0 && t.Expires <= now {
		return nil, ErrUnauthorized
	}
	u, err := s.store.UserByID(ctx, t.UserID)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if now-t.LastAccess > 60 {
		_ = s.store.TouchToken(ctx, t.Token, now)
	}
	v.user, v.token = u, t
	return v, nil
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("agentio-timing-equalizer"), 10)

// hasCredentials reports whether a request carries a token.
func hasCredentials(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.URL.Query().Has("token")
}

// HashPassword checks a password (8 to 128 characters) and hashes it.
func HashPassword(p string) (string, error) {
	if len(p) < 8 || len(p) > 128 {
		return "", errBadPassword.Wrap("must be 8 to 128 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(p), 10)
	return string(b), err
}

func bcryptOK(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
