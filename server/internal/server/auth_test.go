package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"agentio.sh/server/internal/store"
)

// A bad credential is always 401, even for an endpoint that needs none; the token parameter is for relay sockets only.
func TestAuthMethods(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	u, tok := h.addUser("maya")
	mustEqual(t, "bearer", h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK).obj()["username"], any("maya"))
	expired := NewToken(u.ID, store.TokenUser, "", time.Now().Unix()-1)
	if err := h.srv.store.AddToken(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	for _, hd := range []hdr{bearer("aio_" + randomString(32)), bearer(expired.Token), {"Authorization", "Digest abc"}} {
		h.do(http.MethodGet, "/api/v1/health", nil, hd).expectError(ErrUnauthorized)
	}
	h.do(http.MethodGet, "/api/v1/account?token="+tok, nil).expectError(ErrUnauthorized)
}

// Password sign-in exchanges a username and password for a 30-day user token.
func TestPasswordLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.addUser("maya")
	login := func(user, password string) *response {
		return h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": user, "password": password})
	}
	var tok issuedTokenJSON
	login("maya", testPassword).expect(http.StatusOK).decode(&tok)
	in30 := time.Now().Add(30 * 24 * time.Hour).Unix()
	if tok.Kind != "user" || tok.Expires < in30-5 || tok.Expires > in30+5 {
		t.Fatalf("token %+v", tok)
	}
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok.Token)).expect(http.StatusOK)
	login("maya", "wrong-password").expectError(errBadLogin)
	login("nobody", testPassword).expectError(errBadLogin)
}

// The account lists its tokens without their secrets and revokes its own by ID, never another account's.
func TestAccountTokens(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, tok := h.addUser("maya")
	second := h.login("maya", testPassword)
	var shown struct{ Tokens []map[string]any }
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK).decode(&shown)
	if len(shown.Tokens) != 2 || shown.Tokens[0]["token"] != nil || shown.Tokens[1]["token"] != nil {
		t.Fatalf("tokens %+v", shown.Tokens)
	}
	h.do(http.MethodDelete, "/api/v1/account/tokens/"+h.tokenID(second), nil, bearer(tok)).expect(http.StatusOK)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(second)).expectError(ErrUnauthorized)

	_, other := h.addUser("sam")
	h.do(http.MethodDelete, "/api/v1/account/tokens/"+h.tokenID(other), nil, bearer(tok)).expectError(ErrNotFound)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(other)).expect(http.StatusOK)
}
