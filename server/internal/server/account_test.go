package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"agentio.sh/server/internal/config"
)

// Sign-up needs a username and a password within bcrypt's limits: 8 to 72 UTF-8 bytes.
func TestSignup(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	signup := func(body map[string]string) *response { return h.do(http.MethodPost, "/api/v1/account", body) }
	for _, body := range []map[string]string{
		{"username": "nopass"},
		{"username": "nopass", "password": ""},
		{"username": "nopass", "password": "ééé" + "a"},                   // 7 bytes
		{"username": "nopass", "password": strings.Repeat("é", 36) + "a"}, // 73 bytes
	} {
		signup(body).expectError(errBadPassword)
	}
	mustEqual(t, "users after refused sign-ups", h.sqlInt(`SELECT COUNT(*) FROM users`), 0)
	for user, password := range map[string]string{"eight": "ééé" + "ab", "seventytwo": strings.Repeat("é", 36)} {
		signup(map[string]string{"username": user, "password": password}).expect(http.StatusOK)
		h.login(user, password)
	}
	signup(map[string]string{"username": "eight", "password": "supersecret"}).expectError(errUserExists)
	signup(map[string]string{"username": "ab", "password": "supersecret"}).expectError(errBadUsername)

	off := newHarness(t, func(c *config.Config) { c.AllowSignup = false })
	off.do(http.MethodPost, "/api/v1/account", map[string]string{"username": "newbie", "password": "supersecret"}).expectError(errSignupDisabled)
}

// Only NewPasswordlessUser makes an account without a password: NewUser, which the admin command's user add
// also calls, refuses an empty one.
func TestNewUserNeedsPassword(t *testing.T) {
	t.Parallel()
	var apiErr *APIError
	if _, err := NewUser("nopass", "", "user"); !errors.As(err, &apiErr) || apiErr.Code != errBadPassword.Code {
		t.Fatalf("NewUser with no password: %v", err)
	}
	if u, err := NewPasswordlessUser("emailuser@example.com", "user"); err != nil || u.PasswordHash != "" {
		t.Fatalf("NewPasswordlessUser: %+v %v", u, err)
	}
}

// A new password needs the current one and bcrypt's limits; a refused change leaves the old password working.
func TestPasswordChange(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, tok := h.addUser("maya")
	change := func(from, to string) *response {
		return h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": from, "new_password": to}, bearer(tok))
	}
	change("wrong", "newpassword1").expectError(errBadPassword)
	for _, bad := range []string{"", "short", strings.Repeat("é", 36) + "a"} {
		change(testPassword, bad).expectError(errBadPassword)
	}
	h.login("maya", testPassword)
	long := strings.Repeat("é", 36)
	change(testPassword, long).expect(http.StatusOK)
	h.login("maya", long)
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "maya", "password": testPassword}).expectError(errBadLogin)
}

// A machine's token reads the account but can't manage it or see its tokens.
func TestHostTokenLimits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	p := h.pairedUser("maya")
	acct := h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.host.token)).expect(http.StatusOK).obj()
	if acct["username"] != "maya" || len(acct["tokens"].([]any)) != 0 {
		t.Fatalf("account seen by a machine %+v", acct)
	}
	for _, r := range []*response{
		h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": testPassword, "new_password": "newpassword1"}, bearer(p.host.token)),
		h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(p.host.token)),
		h.do(http.MethodDelete, "/api/v1/devices/"+p.device.id, nil, bearer(p.host.token)),
	} {
		r.expectError(errHostTokenNotAllowed)
	}
}

// Deleting an account takes its password and removes its machines, browsers, links and tokens.
func TestAccountDelete(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	p := h.pairedUser("maya")
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": "wrong"}, bearer(p.token)).expectError(errBadPassword)
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(p.token)).expect(http.StatusOK)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(p.host.token)).expectError(ErrUnauthorized)
	for _, table := range []string{"users", "hosts", "devices", "host_devices", "tokens"} {
		mustEqual(t, table, h.sqlInt(`SELECT COUNT(*) FROM `+table), 0)
	}
	_, adminTok := h.addUser("admin", asAdmin)
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(adminTok)).expectError(ErrForbidden)
}

// Failed credentials share a per-address budget that also stops a right password; plain requests have their own
// per-address budget, and a signed-in user a separate one.
func TestRateLimits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.srv.limiters.failureBurst = 3
	h.addUser("victim")
	login := func(password string) *response {
		return h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "victim", "password": password})
	}
	for range 3 {
		login("wrong-password").expect(http.StatusUnauthorized)
	}
	login(testPassword).expectError(ErrTooManyRequests)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer("aio_"+randomString(32))).expectError(ErrTooManyRequests)

	h = newHarness(t)
	h.srv.limiters.requestBurst, h.srv.limiters.requestRefill = 3, time.Hour
	for range 3 {
		h.do(http.MethodGet, "/api/v1/health", nil).expect(http.StatusOK)
	}
	h.do(http.MethodGet, "/api/v1/health", nil).expectError(ErrTooManyRequests)
	_, tok := h.addUser("maya")
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK)
}
