package server

import (
	"net/http"
	"testing"
	"time"

	"agentio.sh/server/internal/config"
)

func TestAccountSignup(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	creds := map[string]string{"username": "newbie", "password": "supersecret"}
	h.do(http.MethodPost, "/api/v1/account", creds).expect(http.StatusOK)
	h.do(http.MethodPost, "/api/v1/account", creds).expectError(errUserExists)
	h.do(http.MethodPost, "/api/v1/account", map[string]string{"username": "ab", "password": "supersecret"}).expectError(errBadUsername)
	h.do(http.MethodPost, "/api/v1/account", map[string]string{"username": "shorty", "password": "short"}).expectError(errBadPassword)
	h.do(http.MethodPost, "/api/v1/account", "{").expectError(ErrBadJSON)

	acct := h.do(http.MethodGet, "/api/v1/account", nil, bearer(h.login("newbie", "supersecret"))).expect(http.StatusOK).obj()
	if acct["username"] != "newbie" || acct["role"] != "user" || len(acct["tokens"].([]any)) != 1 {
		t.Fatalf("account %+v", acct)
	}
	h.do(http.MethodGet, "/api/v1/account", nil).expectError(ErrUnauthorized)

	off := newHarness(t, func(c *config.Config) { c.AllowSignup = false })
	off.do(http.MethodPost, "/api/v1/account", creds).expectError(errSignupDisabled)
}

func TestAccountPasswordChange(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, tok := h.addUser("maya")
	h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": "wrong", "new_password": "newpassword1"}, bearer(tok)).expectError(errBadPassword)
	h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": testPassword, "new_password": "short"}, bearer(tok)).expectError(errBadPassword)
	h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": testPassword, "new_password": "newpassword1"}, bearer(tok)).expect(http.StatusOK)
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "maya", "password": testPassword}).expectError(errBadLogin)
	h.login("maya", "newpassword1")
}

// A machine's token reads the account but can't manage it or see its tokens.
func TestHostTokenLimits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	p := h.pairedUser("maya")
	var acct struct {
		Username string
		Tokens   []tokenJSON
	}
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.host.token)).expect(http.StatusOK).decode(&acct)
	if acct.Username != "maya" || len(acct.Tokens) != 0 {
		t.Fatalf("account seen by a machine %+v", acct)
	}
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.token)).expect(http.StatusOK).decode(&acct)
	if len(acct.Tokens) != 2 || acct.Tokens[0].Kind != "user" || acct.Tokens[1].Kind != "host" || acct.Tokens[1].Label != "Machine" {
		t.Fatalf("tokens %+v", acct.Tokens)
	}
	for _, r := range []*response{
		h.do(http.MethodDelete, "/api/v1/account/tokens/"+acct.Tokens[0].ID, nil, bearer(p.host.token)),
		h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": testPassword, "new_password": "newpassword1"}, bearer(p.host.token)),
		h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(p.host.token)),
		h.do(http.MethodDelete, "/api/v1/devices/"+p.device.id, nil, bearer(p.host.token)),
		h.do(http.MethodPut, "/api/v1/devices/"+p.device.id+"/webpush", map[string]string{}, bearer(p.host.token)),
		h.do(http.MethodPost, "/api/v1/pair/pair_x/claim", map[string]string{}, bearer(p.host.token)),
	} {
		r.expectError(errHostTokenNotAllowed)
	}
}

func TestAccountDelete(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	p := h.pairedUser("maya")
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": "wrong"}, bearer(p.token)).expectError(errBadPassword)
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(p.token)).expect(http.StatusOK)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.token)).expectError(ErrUnauthorized)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.host.token)).expectError(ErrUnauthorized)
	for _, table := range []string{"hosts", "devices", "host_devices", "tokens"} {
		mustEqual(t, table, h.sqlInt(`SELECT COUNT(*) FROM `+table), 0)
	}
	h.do(http.MethodPost, "/api/v1/account", map[string]string{"username": "maya", "password": "anotherpass"}).expect(http.StatusOK)

	_, adminTok := h.addUser("admin", asAdmin)
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(adminTok)).expectError(ErrForbidden)
}

func TestFailedLoginsAreLimited(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.srv.limiters.failureBurst = 3
	h.addUser("victim")
	login := func(password string) *response {
		return h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "victim", "password": password})
	}
	for i := 0; i < 3; i++ {
		login("wrong-password").expect(http.StatusUnauthorized)
	}
	login("wrong-password").expect(http.StatusTooManyRequests)
	login(testPassword).expect(http.StatusTooManyRequests)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer("aio_"+randomString(32))).expect(http.StatusTooManyRequests) // tokens share the budget
	h.do(http.MethodGet, "/api/v1/health", nil).expect(http.StatusOK)                                                // anonymous requests are unaffected
}

func TestRateLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.srv.limiters.requestBurst, h.srv.limiters.requestRefill = 3, time.Hour
	for range 3 {
		h.do(http.MethodGet, "/api/v1/health", nil).expect(http.StatusOK)
	}
	h.do(http.MethodGet, "/api/v1/health", nil).expectError(ErrTooManyRequests)
	_, tok := h.addUser("maya")
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK) // users have their own bucket
}
