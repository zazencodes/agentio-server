// Package config loads the server configuration from defaults, an optional YAML file and AGENTIO_* environment
// variables, with an extension's keys (Section) beside the core's.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the full server configuration. Every key can be set in YAML or as AGENTIO_<KEY> (upper snake case).
type Config struct {
	PublicURL   string `yaml:"public-url"`
	HTTPAddr    string `yaml:"http-addr"`
	TrustProxy  bool   `yaml:"trust-proxy"` // take the client IP from the proxy's X-Forwarded-For
	DataDir     string `yaml:"data-dir"`
	LogLevel    string `yaml:"log-level"`  // debug, info, warn or error
	LogFormat   string `yaml:"log-format"` // text or json
	AllowSignup bool   `yaml:"allow-signup"`

	// RateLimitExemptIPs skip the per-caller request limit (tests/e2e.sh runs a real server from one address).
	RateLimitExemptIPs []string `yaml:"rate-limit-exempt-ips"`

	WebPushPublicKey  string `yaml:"webpush-public-key"`
	WebPushPrivateKey string `yaml:"webpush-private-key"`
	WebPushContact    string `yaml:"webpush-contact"`
}

// Default returns the default configuration, suitable for a small self-hosted server.
func Default() *Config {
	return &Config{
		PublicURL:   "http://localhost:2586",
		HTTPAddr:    ":2586",
		DataDir:     "./data",
		LogLevel:    "info",
		LogFormat:   "text",
		AllowSignup: true,
	}
}

// DatabasePath is the server's SQLite database, agentio.db in data-dir.
func (c *Config) DatabasePath() string { return filepath.Join(c.DataDir, "agentio.db") }

// Section is an extension's configuration: more keys of the same file and environment, decoded into the struct it
// points to. Check validates it once both are read.
type Section interface {
	Check(core *Config) error
}

// Load reads defaults, then the YAML file at path (if non-empty), then AGENTIO_* environment variables. Keys of ext
// (nil for none) are read into it; any other key is an error.
func Load(path string, ext Section) (*Config, error) {
	c := Default()
	if path != "" {
		if err := decodeFile(path, c, ext); err != nil {
			return nil, err
		}
	}
	if err := checkEnv(os.Environ(), c, ext); err != nil {
		return nil, err
	}
	if err := applyEnv(c, os.Environ()); err != nil {
		return nil, err
	}
	if ext != nil {
		if err := applyEnv(ext, os.Environ()); err != nil {
			return nil, err
		}
	}
	if err := c.finish(); err != nil {
		return nil, err
	}
	if ext != nil {
		if err := ext.Check(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// decodeFile splits the file's top-level keys between the core configuration and ext, and decodes each part
// strictly, so an unknown key anywhere is an error.
func decodeFile(path string, c *Config, ext Section) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("parsing %s: the configuration must be a mapping of keys to values", path)
	}
	coreKeys, extKeys := yamlKeys(c), map[string]bool{}
	if ext != nil {
		extKeys = yamlKeys(ext)
	}
	corePart, extPart := &yaml.Node{Kind: yaml.MappingNode}, &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		switch {
		case coreKeys[key]:
			corePart.Content = append(corePart.Content, root.Content[i], root.Content[i+1])
		case extKeys[key]:
			extPart.Content = append(extPart.Content, root.Content[i], root.Content[i+1])
		default:
			return fmt.Errorf("parsing %s: unknown key %q (line %d)", path, key, root.Content[i].Line)
		}
	}
	if err := decodeStrict(corePart, c); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(extPart.Content) > 0 {
		if err := decodeStrict(extPart, ext); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	}
	return nil
}

// decodeStrict decodes a node into v, failing on any key v doesn't have (yaml.Node.Decode would ignore them).
func decodeStrict(n *yaml.Node, v any) error {
	raw, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// yamlKeys returns the top-level keys of a configuration struct.
func yamlKeys(v any) map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(v).Elem()
	for i := 0; i < t.NumField(); i++ {
		keys[t.Field(i).Tag.Get("yaml")] = true
	}
	return keys
}

func (c *Config) finish() error {
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	if c.PublicURL == "" {
		return fmt.Errorf("public-url is required")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log-level must be debug, info, warn or error (got %q)", c.LogLevel)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("log-format must be text or json (got %q)", c.LogFormat)
	}
	if (c.WebPushPublicKey == "") != (c.WebPushPrivateKey == "") {
		return fmt.Errorf("webpush-public-key and webpush-private-key must be set together")
	}
	return nil
}

// commandEnv are the AGENTIO_* variables the command line reads itself, not configuration keys.
var commandEnv = map[string]bool{"AGENTIO_CONFIG": true, "AGENTIO_PASSWORD": true}

// checkEnv fails on an AGENTIO_* variable that names no key of the configuration or ext (nil for none), so a misspelt
// or removed key is an error rather than nothing.
func checkEnv(environ []string, c *Config, ext Section) error {
	known := map[string]bool{}
	structs := []any{c}
	if ext != nil {
		structs = append(structs, ext)
	}
	for _, v := range structs {
		for key := range yamlKeys(v) {
			known[envName(key)] = true
		}
	}
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "AGENTIO_") && !known[k] && !commandEnv[k] {
			return fmt.Errorf("unknown environment variable %s: it names no configuration key", k)
		}
	}
	return nil
}

func envName(key string) string {
	return "AGENTIO_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// applyEnv overrides the fields of a configuration struct (a pointer) from AGENTIO_<YAML_KEY> variables.
func applyEnv(c any, environ []string) error {
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "AGENTIO_") {
			env[k] = v
		}
	}
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		key := t.Field(i).Tag.Get("yaml")
		name := envName(key)
		val, ok := env[name]
		if !ok {
			continue
		}
		f := v.Field(i)
		if err := yaml.Unmarshal([]byte(key+": "+yamlQuote(val, f.Kind())), c); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
	}
	return nil
}

func yamlQuote(s string, k reflect.Kind) string {
	switch k {
	case reflect.Map:
		return s
	case reflect.Bool, reflect.Int, reflect.Int64, reflect.Slice:
		if k == reflect.Slice && !strings.HasPrefix(s, "[") {
			parts := strings.Split(s, ",")
			for i := range parts {
				parts[i] = strconv.Quote(strings.TrimSpace(parts[i]))
			}
			return "[" + strings.Join(parts, ",") + "]"
		}
		return s
	}
	return strconv.Quote(s)
}
