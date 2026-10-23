package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string, ext Section) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p, ext)
}

func TestEnvironment(t *testing.T) {
	t.Setenv("AGENTIO_PUBLIC_URL", "https://api.example.com/")
	t.Setenv("AGENTIO_RATE_LIMIT_EXEMPT_IPS", "127.0.0.1, ::1")
	t.Setenv("AGENTIO_ALLOW_SIGNUP", "false")
	c, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://api.example.com" || len(c.RateLimitExemptIPs) != 2 || c.RateLimitExemptIPs[1] != "::1" || c.AllowSignup {
		t.Fatalf("config %+v", c)
	}
}

// A misspelt or removed key in the environment, and an unknown log level, are errors, not ignored.
func TestUnknownEnvironmentAndLogLevelFail(t *testing.T) {
	t.Setenv("AGENTIO_PUBLIC_URL", "https://api.example.com")
	t.Setenv("AGENTIO_PUBLC_URL", "https://typo.example.com")
	if _, err := Load("", nil); err == nil || !strings.Contains(err.Error(), "AGENTIO_PUBLC_URL") {
		t.Fatalf("misspelt variable: %v", err)
	}
	os.Unsetenv("AGENTIO_PUBLC_URL")
	t.Setenv("AGENTIO_LOG_LEVEL", "trace")
	if _, err := Load("", nil); err == nil || !strings.Contains(err.Error(), "log-level") {
		t.Fatalf("log level trace: %v", err)
	}
	t.Setenv("AGENTIO_LOG_LEVEL", "debug")
	t.Setenv("AGENTIO_PASSWORD", "for the user command")
	if _, err := Load("", nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTIO_GREETING", "hello")
	if _, err := Load("", nil); err == nil {
		t.Fatal("an extension's key without the extension was accepted")
	}
	if _, err := Load("", &testSection{}); err != nil {
		t.Fatal(err)
	}
}

type room struct {
	Name  string `yaml:"name"`
	Limit int64  `yaml:"limit"`
}

// testSection is an extension's configuration.
type testSection struct {
	Greeting string            `yaml:"greeting"`
	Rooms    []room            `yaml:"rooms"`
	Mapping  map[string]string `yaml:"mapping"`
	checked  *Config
}

func (s *testSection) Check(core *Config) error {
	s.checked = core
	if s.Greeting == "fail" {
		return errors.New("greeting must not be fail")
	}
	return nil
}

// An extension's keys are read from the same file and environment, strictly, and checked after the core's.
func TestSection(t *testing.T) {
	var ext testSection
	c, err := load(t, "public-url: https://api.example.com\ngreeting: hi\nrooms:\n  - name: free\n    limit: 5\n", &ext)
	if err != nil {
		t.Fatal(err)
	}
	if ext.Greeting != "hi" || len(ext.Rooms) != 1 || ext.Rooms[0].Limit != 5 || ext.checked != c {
		t.Fatalf("section %+v", ext)
	}
	for yaml, want := range map[string]string{
		"public-url: https://api.example.com\nrooms:\n  - name: free\n    limitt: 5\n": "limitt",
		"public-url: https://api.example.com\nfarewell: bye\n":                         "unknown key \"farewell\"",
		"public-url: https://api.example.com\nhttp-addr: [1]\n":                        "cannot unmarshal",
		"public-url: https://api.example.com\ngreeting: fail\n":                        "greeting must not be fail",
	} {
		if _, err := load(t, yaml, &testSection{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", yaml, err, want)
		}
	}
	t.Setenv("AGENTIO_MAPPING", `{"a@example.com":"a"}`)
	t.Setenv("AGENTIO_GREETING", "hello")
	ext = testSection{}
	if _, err := load(t, "public-url: https://api.example.com\n", &ext); err != nil || ext.Mapping["a@example.com"] != "a" || ext.Greeting != "hello" {
		t.Fatalf("section from the environment %+v %v", ext, err)
	}
}
