package server

import (
	"net/http"
	"testing"
)

// The config names exactly what a client needs, and the server serves no web pages: unknown paths are JSON 404s.
func TestConfigAndNoWebPages(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	c := h.do(http.MethodGet, "/api/v1/config", nil).expect(http.StatusOK).obj()
	want := map[string]any{"version": Version, "enable_password_login": true, "enable_signup": true, "web_push_public_key": ""}
	if len(c) != len(want) {
		t.Fatalf("config %v, want exactly %v", c, want)
	}
	for k, v := range want {
		mustEqual(t, "config "+k, c[k], v)
	}
	html := hdr{"Accept", "text/html"}
	h.do(http.MethodGet, "/", nil, html).expectError(errNoWebApp)
	h.do(http.MethodGet, "/install.sh", nil, html).expectError(ErrNotFound)
}
