package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"agentio.sh/server/internal/store"
)

func TestAuthMethods(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, tok := h.addUser("maya")
	username := func(r *response) string {
		r.t.Helper()
		return r.expect(http.StatusOK).obj()["username"].(string)
	}
	mustEqual(t, "bearer", username(h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok))), "maya")
	mustEqual(t, "case-insensitive scheme", username(h.do(http.MethodGet, "/api/v1/account", nil, hdr{"Authorization", "bearer " + tok})), "maya")

	// A bad credential is always 401, even for an endpoint that needs none.
	ctx := context.Background()
	expired := NewToken(mustUser(t, h, "maya").ID, store.TokenUser, "", time.Now().Unix()-1)
	if err := h.srv.store.AddToken(ctx, expired); err != nil {
		t.Fatal(err)
	}
	for name, hd := range map[string]hdr{
		"unknown token":  bearer("aio_" + randomString(32)),
		"expired token":  bearer(expired.Token),
		"basic password": basic("maya", testPassword),
		"basic token":    basic("", tok),
		"unknown scheme": {"Authorization", "Digest abc"},
	} {
		t.Run(name, func(t *testing.T) {
			h.do(http.MethodGet, "/api/v1/health", nil, hd).expectError(ErrUnauthorized)
		})
	}
	// The token parameter is for relay sockets only, and a token is sent once.
	h.do(http.MethodGet, "/api/v1/account?token="+tok, nil).expect(http.StatusUnauthorized)
	h.do(http.MethodGet, "/api/v1/relay/host?token="+tok, nil, bearer(tok)).expect(http.StatusUnauthorized)
	h.do(http.MethodGet, "/api/v1/health?auth=x", nil).expect(http.StatusOK) // no longer a credential: just a parameter
}

func mustUser(t *testing.T, h *harness, username string) *store.User {
	t.Helper()
	u, err := h.srv.store.UserByUsername(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Password sign-in is one endpoint that exchanges a username and password for a 30-day token.
func TestPasswordLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.addUser("maya")
	var tok issuedTokenJSON
	r := h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "maya", "password": testPassword}).expect(http.StatusOK)
	mustEqual(t, "cache", r.header.Get("Cache-Control"), "no-store")
	r.decode(&tok)
	in30 := time.Now().Add(30 * 24 * time.Hour).Unix()
	if len(tok.ID) != 24 || tok.ID[:4] != "tok_" || len(tok.Token) != 36 || tok.Kind != "user" || tok.Label != "Password sign-in" || tok.Expires < in30-5 || tok.Expires > in30+5 {
		t.Fatalf("token %+v", tok)
	}
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok.Token)).expect(http.StatusOK)
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "maya", "password": "wrong-password"}).expectError(errBadLogin)
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "nobody", "password": testPassword}).expectError(errBadLogin)
	h.do(http.MethodPost, "/api/v1/auth/password", "{").expectError(ErrBadJSON)
}

// Signing in sees a list of the account's tokens, never their secrets, and revokes them by ID.
func TestAccountTokens(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, tok := h.addUser("maya")
	second := h.login("maya", testPassword)
	var shown struct{ Tokens []map[string]any }
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK).decode(&shown)
	if len(shown.Tokens) != 2 {
		t.Fatalf("tokens %+v", shown.Tokens)
	}
	var secondID string
	for _, st := range shown.Tokens {
		if _, ok := st["token"]; ok {
			t.Fatalf("a listed token carries its secret: %+v", st)
		}
		if st["label"] == "Password sign-in" {
			secondID = st["id"].(string)
			mustEqual(t, "current", st["current"], any(false))
		} else {
			mustEqual(t, "current", st["current"], any(true))
		}
	}
	h.do(http.MethodDelete, "/api/v1/account/tokens/"+secondID, nil, bearer(tok)).expect(http.StatusOK)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(second)).expectError(ErrUnauthorized)
	h.do(http.MethodDelete, "/api/v1/account/tokens/"+secondID, nil, bearer(tok)).expectError(ErrNotFound)

	// Another account's token can't be revoked.
	_, other := h.addUser("sam")
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(other)).expect(http.StatusOK).decode(&shown)
	h.do(http.MethodDelete, "/api/v1/account/tokens/"+shown.Tokens[0]["id"].(string), nil, bearer(tok)).expectError(ErrNotFound)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(other)).expect(http.StatusOK)
}
