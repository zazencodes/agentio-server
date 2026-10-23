package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"agentio.sh/server/internal/store"
)

var usernameRegex = regexp.MustCompile(`^[-_.@+A-Za-z0-9]{3,64}$`)

// NewUser returns a new account with a checked username and, unless password is empty (an account without one), a
// checked and hashed password. It is the one place accounts are made, for sign-up and the admin command alike.
func NewUser(username, password, role string) (*store.User, error) {
	if !usernameRegex.MatchString(username) {
		return nil, errBadUsername
	}
	u := &store.User{ID: newID("usr_"), Username: username, Role: role, Created: time.Now().Unix()}
	if password != "" {
		hash, err := HashPassword(password)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = hash
	}
	return u, nil
}

// DecodeJSON decodes a JSON request body of at most 64 KiB into v.
func DecodeJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(v); err != nil {
		return ErrBadJSON
	}
	return nil
}

// requireUser returns ErrUnauthorized for anonymous callers.
func requireUser(v *Caller) error {
	if v.user == nil {
		return ErrUnauthorized
	}
	return nil
}

// RequireUserToken returns an error unless a person's account made the request: anonymous callers and machine
// (host) tokens, which can't manage the account, are refused.
func RequireUserToken(v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	if v.isHost() {
		return errHostTokenNotAllowed
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ *Caller) error {
	WriteJSON(w, http.StatusOK, map[string]bool{"healthy": s.store.Ping(r.Context()) == nil})
	return nil
}

// handleClientConfig serves GET /api/v1/config, with the extension's fields.
func (s *Server) handleClientConfig(w http.ResponseWriter, _ *http.Request, _ *Caller) error {
	webPushKey := ""
	if s.webpush != nil {
		webPushKey = s.webpush.PublicKey()
	}
	out := map[string]any{
		"version":               Version,
		"enable_password_login": !s.ext.NoPasswords,
		"enable_signup":         s.signupEnabled(),
		"web_push_public_key":   webPushKey,
	}
	if s.ext.ClientConfig != nil {
		s.ext.ClientConfig(out)
	}
	WriteJSON(w, http.StatusOK, out)
	return nil
}

// signupEnabled reports whether POST /api/v1/account creates accounts: allow-signup, on a server with passwords.
func (s *Server) signupEnabled() bool { return s.cfg.AllowSignup && !s.ext.NoPasswords }

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request, _ *Caller) error {
	if !s.signupEnabled() {
		return errSignupDisabled
	}
	var req struct{ Username, Password string }
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	u, err := NewUser(req.Username, req.Password, store.RoleUser)
	if err != nil {
		return err
	}
	if err := s.store.AddUser(r.Context(), u); errors.Is(err, store.ErrConflict) {
		return errUserExists
	} else if err != nil {
		return err
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// tokenJSON is a token as the account lists it (docs/api.md §3): never its secret.
type tokenJSON struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	LastAccess int64  `json:"last_access"`
	Expires    int64  `json:"expires"`
	Current    bool   `json:"current"`
}

// issuedTokenJSON is a token as a sign-in returns it: the only time its secret is shown.
type issuedTokenJSON struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Expires int64  `json:"expires"`
}

// IssuedToken returns a newly issued token as a sign-in returns it, with its secret.
func IssuedToken(t *store.Token) issuedTokenJSON {
	return issuedTokenJSON{ID: t.ID, Token: t.Token, Kind: t.Kind, Label: t.Label, Expires: t.Expires}
}

// handleAccountShow returns the account, with the extension's fields. A machine's token sees no tokens.
func (s *Server) handleAccountShow(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	ctx := r.Context()
	u := v.user
	tokens := []tokenJSON{}
	if !v.isHost() {
		ts, err := s.store.Tokens(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, t := range ts {
			tokens = append(tokens, tokenJSON{ID: t.ID, Kind: t.Kind, Label: t.Label, LastAccess: t.LastAccess, Expires: t.Expires, Current: t.ID == v.token.ID})
		}
	}
	out := map[string]any{
		"username": u.Username,
		"role":     u.Role,
		"tokens":   tokens,
	}
	if s.ext.Account != nil {
		if err := s.ext.Account(ctx, u, out); err != nil {
			return err
		}
	}
	WriteJSON(w, http.StatusOK, out)
	return nil
}

// handleAccountRemove deletes the calling account, confirmed with its password.
func (s *Server) handleAccountRemove(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	if s.ext.NoPasswords {
		return errNoPasswords
	}
	if v.user.Role == store.RoleAdmin {
		return ErrForbidden.Wrap("admins cannot delete their own account")
	}
	var req struct{ Password string }
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	if !checkPassword(v.user, req.Password) {
		return errBadPassword
	}
	if err := s.store.DeleteUser(r.Context(), v.user.ID); err != nil {
		return err
	}
	s.relay.closeUser(v.user.ID)
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// handleAccountPassword changes the password.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	if s.ext.NoPasswords {
		return errNoPasswords
	}
	var req struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	if !checkPassword(v.user, req.Password) {
		return errBadPassword
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(r.Context(), v.user.ID, hash); err != nil {
		return err
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// handlePasswordLogin exchanges a username and password for a sign-in token. It is the only endpoint that takes a
// password for signing in; failures count against the IP's login budget.
func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if s.ext.NoPasswords {
		return errNoPasswords
	}
	if !s.limiters.authAttemptAllowed(v.ip) {
		return ErrTooManyRequests
	}
	var req struct{ Username, Password string }
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	u, err := s.store.UserByUsername(ctx, req.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err != nil {
		// Spend the same time as a real check so usernames can't be discovered by timing.
		_ = bcryptOK(string(dummyHash), req.Password)
	}
	if err != nil || !checkPassword(u, req.Password) {
		s.limiters.recordAuthFailure(v.ip)
		return errBadLogin
	}
	t := SignInToken(u.ID, "Password sign-in")
	if err := s.store.AddToken(ctx, t); err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, IssuedToken(t))
	return nil
}

// handleTokenDelete revokes a token of the account by its ID (signing that browser or computer out, or this one) and
// closes its relay sockets.
func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	id := r.PathValue("id")
	if err := s.store.DeleteToken(r.Context(), v.user.ID, id); errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	s.relay.closeToken(id)
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

func checkPassword(u *store.User, password string) bool {
	if u.PasswordHash == "" {
		return false
	}
	return bcryptOK(u.PasswordHash, password)
}
