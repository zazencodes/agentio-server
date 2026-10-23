package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	mustEqual(t, "healthy", h.do(http.MethodGet, "/api/v1/health", nil).expect(http.StatusOK).obj()["healthy"], any(true))
}

func TestClientConfig(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	c := h.do(http.MethodGet, "/api/v1/config", nil).expect(http.StatusOK).obj()
	want := map[string]any{"version": Version, "enable_password_login": true, "enable_signup": true, "web_push_public_key": ""}
	if len(c) != len(want) {
		t.Fatalf("config %v, want exactly %v", c, want)
	}
	for k, v := range want {
		if c[k] != v {
			t.Fatalf("config %s = %v, want %v", k, c[k], v)
		}
	}
}

func TestCORS(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, path := range []string{"/api/v1/account", "/api/v1/pair", "/"} {
		r := h.do(http.MethodOptions, path, nil, hdr{"Origin", "https://app.example.com", "Access-Control-Request-Method", "PUT"}).expect(http.StatusOK)
		mustEqual(t, path+" allow origin", r.header.Get("Access-Control-Allow-Origin"), "*")
		for _, m := range []string{"GET", "PUT", "POST", "DELETE"} {
			if !strings.Contains(r.header.Get("Access-Control-Allow-Methods"), m) {
				t.Fatalf("%s: methods %q lack %s", path, r.header.Get("Access-Control-Allow-Methods"), m)
			}
		}
		mustEqual(t, path+" allowed headers", r.header.Get("Access-Control-Allow-Headers"), "Authorization, Content-Type")
	}
	mustEqual(t, "error response", h.do(http.MethodGet, "/api/v1/account", nil).header.Get("Access-Control-Allow-Origin"), "*")
}

// The server is an API and relay only: it serves no web pages, and says so in JSON; unknown paths are JSON 404s.
func TestNoWebPages(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	html := hdr{"Accept", "text/html,application/xhtml+xml"}
	h.do(http.MethodGet, "/", nil, html).expectError(errNoWebApp)
	r := h.do(http.MethodGet, "/install.sh", nil, html)
	mustEqual(t, "content type", r.header.Get("Content-Type"), "application/json")
	r.expectError(ErrNotFound)
}
