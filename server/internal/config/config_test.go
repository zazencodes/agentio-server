package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The environment configures the server, strictly: a misspelt key or an unknown log level is an error.
func TestEnvironment(t *testing.T) {
	t.Setenv("AGENTIO_PUBLIC_URL", "https://api.example.com/")
	t.Setenv("AGENTIO_ALLOW_SIGNUP", "false")
	c, err := Load("", nil)
	if err != nil || c.PublicURL != "https://api.example.com" || c.AllowSignup {
		t.Fatalf("config %+v %v", c, err)
	}
	t.Setenv("AGENTIO_PUBLC_URL", "https://typo.example.com")
	if _, err := Load("", nil); err == nil || !strings.Contains(err.Error(), "AGENTIO_PUBLC_URL") {
		t.Fatalf("misspelt variable: %v", err)
	}
	os.Unsetenv("AGENTIO_PUBLC_URL")
	t.Setenv("AGENTIO_LOG_LEVEL", "trace")
	if _, err := Load("", nil); err == nil || !strings.Contains(err.Error(), "log-level") {
		t.Fatalf("log level trace: %v", err)
	}
}

// testSection is an extension's configuration.
type testSection struct {
	Greeting string            `yaml:"greeting"`
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

// An extension's keys are read from the same file and environment, strictly, and checked after the core's; without
// the extension they are unknown.
func TestSection(t *testing.T) {
	load := func(yaml string, ext Section) (*Config, error) {
		p := filepath.Join(t.TempDir(), "server.yml")
		if err := os.WriteFile(p, []byte("public-url: https://api.example.com\n"+yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(p, ext)
	}
	var ext testSection
	if c, err := load("greeting: hi\n", &ext); err != nil || ext.Greeting != "hi" || ext.checked != c {
		t.Fatalf("section %+v %v", ext, err)
	}
	for yaml, want := range map[string]string{
		"farewell: bye\n":  `unknown key "farewell"`,
		"greeting: fail\n": "greeting must not be fail",
	} {
		if _, err := load(yaml, &testSection{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", yaml, err, want)
		}
	}
	if _, err := load("greeting: hi\n", nil); err == nil {
		t.Fatal("an extension's key without the extension was accepted")
	}
	t.Setenv("AGENTIO_MAPPING", `{"a@example.com":"a"}`)
	ext = testSection{}
	if _, err := load("", &ext); err != nil || ext.Mapping["a@example.com"] != "a" {
		t.Fatalf("section from the environment %+v %v", ext, err)
	}
}
