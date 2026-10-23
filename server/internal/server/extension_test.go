package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"agentio.sh/server/internal/store"
)

// An extension's endpoints are served like the core's, and its fields join the config and the account.
func TestExtensionRoutesAndFields(t *testing.T) {
	t.Parallel()
	var maintained atomic.Int32
	h := newExtendedHarness(t, Extension{
		Routes: func(handle func(string, HandlerFunc)) {
			handle("GET /api/v1/greeting", func(w http.ResponseWriter, _ *http.Request, v *Caller) error {
				if err := RequireUserToken(v); err != nil {
					return err
				}
				WriteJSON(w, http.StatusOK, map[string]string{"hello": v.User().Username})
				return nil
			})
			handle("POST /api/v1/greeting", func(http.ResponseWriter, *http.Request, *Caller) error {
				return NewError(418, "teapot", "Short and stout").Wrap("%s", "spout")
			})
		},
		ClientConfig: func(out map[string]any) { out["enable_greeting"] = true },
		Account: func(_ context.Context, u *store.User, out map[string]any) error {
			out["greeting"] = "hi " + u.Username
			return nil
		},
		Maintain: func(context.Context) error { maintained.Add(1); return nil },
	})
	_, tok := h.addUser("maya")
	mustEqual(t, "greeting", h.do(http.MethodGet, "/api/v1/greeting", nil, bearer(tok)).expect(http.StatusOK).obj()["hello"], any("maya"))
	h.do(http.MethodGet, "/api/v1/greeting", nil).expectError(ErrUnauthorized)
	h.do(http.MethodGet, "/api/v1/greeting", nil, bearer("aio_nope")).expectError(ErrUnauthorized)
	e := h.do(http.MethodPost, "/api/v1/greeting", nil).expectError(NewError(418, "teapot", ""))
	mustEqual(t, "error message", e.Error, "Short and stout: spout")
	mustEqual(t, "CORS", h.do(http.MethodOptions, "/api/v1/greeting", nil).expect(http.StatusOK).header.Get("Access-Control-Allow-Origin"), "*")
	mustEqual(t, "config field", h.do(http.MethodGet, "/api/v1/config", nil).expect(http.StatusOK).obj()["enable_greeting"], any(true))
	mustEqual(t, "account field", h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK).obj()["greeting"], any("hi maya"))

	h.srv.maintain()
	h.srv.shutdown(nil)
	mustEqual(t, "maintenance runs", maintained.Load(), 2)
}

// An extension whose accounts have no passwords turns off every password endpoint and says so in the config.
func TestExtensionNoPasswords(t *testing.T) {
	t.Parallel()
	h := newExtendedHarness(t, Extension{NoPasswords: true})
	_, tok := h.addUser("maya")
	c := h.do(http.MethodGet, "/api/v1/config", nil).expect(http.StatusOK).obj()
	mustEqual(t, "password login", c["enable_password_login"], any(false))
	mustEqual(t, "signup", c["enable_signup"], any(false))
	h.do(http.MethodPost, "/api/v1/auth/password", map[string]string{"username": "maya", "password": testPassword}).expectError(errNoPasswords)
	h.do(http.MethodPost, "/api/v1/account", map[string]string{"username": "newbie", "password": "supersecret"}).expectError(errSignupDisabled)
	h.do(http.MethodPost, "/api/v1/account/password", map[string]string{"password": testPassword, "new_password": "newpassword1"}, bearer(tok)).expectError(errNoPasswords)
	h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(tok)).expectError(errNoPasswords)
	h.do(http.MethodGet, "/api/v1/account", nil, bearer(tok)).expect(http.StatusOK)
}

func TestExtendTwicePanics(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	defer func() {
		if recover() == nil {
			t.Fatal("a second Extend didn't panic")
		}
	}()
	h.srv.Extend(Extension{})
}
