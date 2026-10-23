package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/signing-vectors.json with fresh Go signatures")

// Vectors are shared with the Swift and Kotlin tests: each implementation must verify every signature in the file,
// and each adds one envelope of its own (signatures are randomized, so they are generated once and committed).
type vectors struct {
	PrivateKey string `json:"private_key"` // P-256 scalar, hex (test key only)
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"` // KeyID("dev_", public_key)
	Envelopes  []struct {
		Source      string   `json:"source"` // implementation that produced it: go, swift, kotlin
		Envelope    Envelope `json:"envelope"`
		Payload     string   `json:"payload"`      // the payload bytes as a string
		PayloadHash string   `json:"payload_hash"` // hex sha256 of the payload bytes
	} `json:"envelopes"`
	Pair struct {
		K                  string `json:"k"`
		PairID             string `json:"pair_id"`
		HostKey            string `json:"host_key"`
		DeviceKey          string `json:"device_key"`
		DeviceSensitiveKey string `json:"device_sensitive_key"`
		DeviceEncKey       string `json:"device_enc_key"`
		DeviceName         string `json:"device_name"`
		SensitiveOrigin    string `json:"device_sensitive_origin"`
		MAC                string `json:"mac"`
	} `json:"pair"`
}

const vectorFile = "testdata/signing-vectors.json"

func testKey(t *testing.T, scalar string) *ecdsa.PrivateKey {
	t.Helper()
	d, err := hex.DecodeString(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVectors(t *testing.T) {
	if *update {
		writeVectors(t)
	}
	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	key := testKey(t, v.PrivateKey)
	if got := EncodePublicKey(&key.PublicKey); got != v.PublicKey {
		t.Fatalf("public key %s, want %s", got, v.PublicKey)
	}
	if got := KeyID("dev_", v.PublicKey); got != v.KeyID {
		t.Fatalf("key ID %s, want %s", got, v.KeyID)
	}
	for _, e := range v.Envelopes {
		var out SignedCommand
		if err := e.Envelope.Open(KindCommand, &key.PublicKey, &out); err != nil {
			t.Fatalf("%s envelope: %v", e.Source, err)
		}
		if out.Text != "Use PostgreSQL. Ünïcödé ✓ <&>" {
			t.Fatalf("%s envelope text %q", e.Source, out.Text)
		}
		if got := e.Envelope.PayloadHash(); got != e.PayloadHash {
			t.Fatalf("%s payload hash %s, want %s", e.Source, got, e.PayloadHash)
		}
		if err := e.Envelope.Open(KindResponse, &key.PublicKey, &out); err == nil {
			t.Fatalf("%s envelope verified as another kind", e.Source)
		}
	}
	p := v.Pair
	if !CheckPairMAC(p.MAC, p.K, p.PairID, p.HostKey, p.DeviceKey, p.DeviceSensitiveKey, p.DeviceEncKey, p.DeviceName, p.SensitiveOrigin) {
		t.Fatal("pair MAC does not verify")
	}
}

func writeVectors(t *testing.T) {
	var v vectors
	if data, err := os.ReadFile(vectorFile); err == nil {
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
	} else {
		v.PrivateKey = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" // RFC 6979 A.2.5 test key
	}
	key := testKey(t, v.PrivateKey)
	v.PublicKey = EncodePublicKey(&key.PublicKey)
	v.KeyID = KeyID("dev_", v.PublicKey)
	env, err := Sign(key, v.KeyID, KindCommand, SignedCommand{ID: "cmd_vector", Host: "hst_vector", Session: "ses_vector",
		Text: "Use PostgreSQL. Ünïcödé ✓ <&>", Created: 1760659150, Expires: 1760745550})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := b64.DecodeString(env.Payload)
	kept := v.Envelopes[:0]
	for _, e := range v.Envelopes {
		if e.Source != "go" {
			kept = append(kept, e)
		}
	}
	v.Envelopes = append(kept, struct {
		Source      string   `json:"source"`
		Envelope    Envelope `json:"envelope"`
		Payload     string   `json:"payload"`
		PayloadHash string   `json:"payload_hash"`
	}{"go", *env, string(payload), env.PayloadHash()})
	p := &v.Pair
	p.K, p.PairID, p.HostKey, p.DeviceKey, p.DeviceSensitiveKey, p.DeviceEncKey, p.DeviceName, p.SensitiveOrigin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"pair_vector", v.PublicKey, v.PublicKey, v.PublicKey, v.PublicKey, "Alex's browser", "https://app.agentio.sh"
	if p.MAC, err = PairMAC(p.K, p.PairID, p.HostKey, p.DeviceKey, p.DeviceSensitiveKey, p.DeviceEncKey, p.DeviceName, p.SensitiveOrigin); err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorFile, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignOpen(t *testing.T) {
	a, _ := NewKey()
	b, _ := NewKey()
	env, err := Sign(a, KeyID("hst_", EncodePublicKey(&a.PublicKey)), KindAway, SignedAway{Host: "hst_x", Mode: "on", Time: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out SignedAway
	if err := env.Open(KindAway, &a.PublicKey, &out); err != nil || out.Mode != "on" {
		t.Fatalf("open: %v %+v", err, out)
	}
	if err := env.Open(KindAway, &b.PublicKey, &out); err == nil {
		t.Fatal("verified with the wrong key")
	}
	tampered := *env
	tampered.Payload = b64.EncodeToString([]byte(`{"host":"hst_x","mode":"off","time":1}`))
	if err := tampered.Open(KindAway, &a.PublicKey, &out); err == nil {
		t.Fatal("verified a tampered payload")
	}
	if _, err := ParsePublicKey(EncodePublicKey(&a.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Fatal("parsed garbage as a key")
	}
}
