package protocol

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var updateSettings = flag.Bool("update-settings", false, "rewrite the Go entry of testdata/settings-vectors.json")

// settingsVectors are shared with the web tests: a Go-signed settings snapshot (the bridge's side) and a web-signed
// settings change (the browser's side), both with the signing-vectors.json test key. Each implementation verifies
// both and regenerates its own.
type settingsVectors struct {
	PrivateKey string        `json:"private_key"` // P-256 scalar, hex (test key only)
	PublicKey  string        `json:"public_key"`
	HostID     string        `json:"host_id"`   // KeyID("hst_", public_key)
	DeviceID   string        `json:"device_id"` // KeyID("dev_", public_key)
	Settings   settingsEntry `json:"settings"`
	Change     settingsEntry `json:"settings_change"`
}

type settingsEntry struct {
	Source      string   `json:"source"` // go or web
	Envelope    Envelope `json:"envelope"`
	Payload     string   `json:"payload"`      // the payload bytes as a string
	PayloadHash string   `json:"payload_hash"` // hex sha256 of the payload bytes
}

const settingsVectorFile = "testdata/settings-vectors.json"

// vectorSettings is the snapshot the Go entry signs.
var vectorSettings = SignedSettings{Host: "hst_vector", Revision: "5f13d8ae942a7e3e5830ee397e9fb0dbccea46e7bf74763ed81e9643bb97b68d",
	Time: 1760659150, IdleTime: true, Builtin: map[string]string{"notify": "2m", "progress": "15m", "requests": "never"},
	Defaults: map[string]string{"notify": "always"}, Projects: []SettingsProject{{ID: "prj_vector", Path: "~/pro/Ünïcödé ✓ <&>",
		Values: map[string]string{"requests": "5m"}}}, Change: &SettingsOutcome{ID: "chg_vector", Result: SettingsRejected,
		Reason: "its settings changed since you looked"}}

func TestSettingsVectors(t *testing.T) {
	if *updateSettings {
		writeSettingsVectors(t)
	}
	data, err := os.ReadFile(settingsVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v settingsVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	key := testKey(t, v.PrivateKey)
	if EncodePublicKey(&key.PublicKey) != v.PublicKey || KeyID("hst_", v.PublicKey) != v.HostID || KeyID("dev_", v.PublicKey) != v.DeviceID {
		t.Fatal("the vector key doesn't match its public key and IDs")
	}
	var s SignedSettings
	if err := v.Settings.Envelope.Open(KindSettings, &key.PublicKey, &s); err != nil || v.Settings.Envelope.Signer != v.HostID {
		t.Fatalf("%s settings: %v", v.Settings.Source, err)
	}
	if s.Projects[0].Path != "~/pro/Ünïcödé ✓ <&>" || s.Change.Result != SettingsRejected || s.Builtin["requests"] != "never" {
		t.Fatalf("%s settings payload %+v", v.Settings.Source, s)
	}
	var c SignedSettingsChange
	if err := v.Change.Envelope.Open(KindSettingsChange, &key.PublicKey, &c); err != nil || v.Change.Envelope.Signer != v.DeviceID {
		t.Fatalf("%s settings change: %v", v.Change.Source, err)
	}
	if c.ID != "chg_vector" || c.Host != v.HostID || c.Projects[0].Values["requests"] != "always" || c.Expires != c.Created+SettingsChangeLifetime {
		t.Fatalf("%s settings change payload %+v", v.Change.Source, c)
	}
	for _, e := range []settingsEntry{v.Settings, v.Change} {
		if got := e.Envelope.PayloadHash(); got != e.PayloadHash {
			t.Fatalf("%s payload hash %s, want %s", e.Source, got, e.PayloadHash)
		}
		if raw, _ := b64.DecodeString(e.Envelope.Payload); string(raw) != e.Payload {
			t.Fatalf("%s payload bytes differ from the recorded payload", e.Source)
		}
	}
	// A signature for one kind is never valid for the other.
	if err := v.Settings.Envelope.Open(KindSettingsChange, &key.PublicKey, &c); err == nil {
		t.Fatal("a settings snapshot verified as a change")
	}
	swapped := v.Change.Envelope
	swapped.Kind = KindSettings
	if err := swapped.Open(KindSettings, &key.PublicKey, &s); err == nil {
		t.Fatal("a settings change verified as a snapshot")
	}
}

func writeSettingsVectors(t *testing.T) {
	var v settingsVectors
	if data, err := os.ReadFile(settingsVectorFile); err == nil {
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
	} else {
		v.PrivateKey = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" // RFC 6979 A.2.5 test key
	}
	key := testKey(t, v.PrivateKey)
	v.PublicKey = EncodePublicKey(&key.PublicKey)
	v.HostID, v.DeviceID = KeyID("hst_", v.PublicKey), KeyID("dev_", v.PublicKey)
	payload := vectorSettings
	payload.Host = v.HostID
	env, err := Sign(key, v.HostID, KindSettings, payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b64.DecodeString(env.Payload)
	v.Settings = settingsEntry{"go", *env, string(raw), env.PayloadHash()}
	data, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(settingsVectorFile, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
